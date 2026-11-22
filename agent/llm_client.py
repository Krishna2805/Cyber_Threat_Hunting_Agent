"""
llm_client.py - Ollama LLM Integration
---------------------------------------
Handles ALL communication with the local Ollama model (llama3.1:8b).
This module is used in TWO places by the agent:

  1. generate_hypothesis()  → Called right after a rule fires. Turns a raw
                              observation string into a human-like attack
                              scenario description.  The threat type is passed
                              explicitly so the LLM knows exactly which of the
                              8 attack categories it is annotating.

  2. generate_incident_report() → Called after the agent has made its final
                                   deterministic decision. Takes the hard facts
                                   (threat type, IP, observation, mitigations)
                                   and formats them into a polished SOC
                                   paragraph for the dashboard. The LLM adds
                                   NO new logic here — it is purely a text
                                   formatter.

The AI never makes security decisions. It only talks.

Caching
-------
Both hypothesis and incident-report responses are cached in memory, keyed on
(threat_type, source_ip, kind) with separate TTLs:

  "hyp" → 60 s  (_CACHE_HYP_TTL_SECONDS)
  "rep" → 360 s (_CACHE_REP_TTL_SECONDS)

IMPORTANT — why threat_type is part of the hypothesis key
----------------------------------------------------------
An earlier version keyed the hypothesis cache on (source_ip, kind) only,
intentionally sharing one Ollama call across all rules that fire for the same
IP in a single cycle.  That optimisation is incorrect when *different* threat
types fire for the same IP (e.g. Brute Force + Credential Stuffing + Auth Scan
all from 192.168.1.4 in the same 5-second poll).  Without threat_type in the
key every subsequent alert gets the cached hypothesis from the first rule that
fired — completely wrong context for the dashboard.

The fix: key on (threat_type, source_ip, kind) for both hypothesis and report.
Each unique (attack-type, attacker-IP) pair now gets its own targeted Ollama
call the first time and a cache hit on the second.
"""

import json
import os
import time
from datetime import datetime, timedelta, timezone

import requests
from dotenv import load_dotenv

# Load <project root>/.env only (a bare load_dotenv() would walk up parent
# directories). override=True: values in .env win over the shell environment.
load_dotenv(
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"),
    override=True,
)

# ── Groq connection settings (Cloud Provider) ────────────────────────────────
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
GROQ_API_URL = os.getenv("GROQ_API_URL", "https://api.groq.com/openai/v1/chat/completions")
GROQ_MODELS_URL = GROQ_API_URL.rsplit("/chat/completions", 1)[0] + "/models"
# USE_GROQ=false forces the local Ollama path even when a key is configured.
USE_GROQ = os.getenv("USE_GROQ", "true").strip().lower() not in ("0", "false", "no")
LLM_PROVIDER = "Groq" if (GROQ_API_KEY and USE_GROQ) else "Ollama"

# LLM call outcome, stored in alerts.llm_status:
#   "ok"        → complete text
#   "truncated" → the model hit its token limit; partial text is discarded
#   "error"     → HTTP / network / rate-limit failure; nothing stored
LLMResult = tuple[str | None, str]  # (text, status)

# ── Ollama connection settings (Local Fallback) ──────────────────────────────
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_GENERATE_URL = f"{OLLAMA_BASE_URL}/api/generate"
OLLAMA_TAGS_URL = f"{OLLAMA_BASE_URL}/api/tags"  # used for health-check

MODEL_NAME = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

# Generation options
DEFAULT_OPTIONS = {
    "temperature": 0.3,
    "num_predict": 250,
    "top_p": 0.9,
    "repeat_penalty": 1.1,
    "num_ctx": 2048,
}

REQUEST_TIMEOUT = 30


# ── In-memory LLM response cache ─────────────────────────────────────────────
#
# Structure:
#   key   → (threat_type: str, source_ip: str, kind: str)
#              where kind is "hyp" (hypothesis) or "rep" (incident report)
#   value → (response_text: str, unix_timestamp: float)
#
# Both "hyp" and "rep" use the same three-part key so that:
#   • Multiple different threat types firing for the same IP each get their
#     own hypothesis — no cross-contamination between attack categories.
#   • The per-threat-type report cache still outlasts the 300 s alert cooldown
#     (TTL = 360 s) so a re-alert finds a warm cache entry.
#
# This is a plain module-level dict — it is shared across all calls within
# the same agent process and requires no locking (the agent is single-threaded).

_LLM_CACHE: dict[tuple, tuple] = {}

# Hypothesis TTL — 60 s is short enough to stay fresh across adjacent cycles
# while still preventing duplicate calls within the same 5-second poll window.
_CACHE_HYP_TTL_SECONDS: int = 60

# Report TTL — intentionally 60 s LONGER than the 300 s alert cooldown.
# This guarantees a cache hit when the same alert re-fires after the cooldown
# lifts: cooldown expires at t=300, cache expires at t=360, so the re-alert
# at t=300 still finds a warm cache entry.
_CACHE_REP_TTL_SECONDS: int = 360


def _cache_get(threat_type: str, source_ip: str, kind: str) -> str | None:
    """
    Return a cached LLM response if a fresh entry exists, otherwise None.

    Cache key: (threat_type, source_ip, kind) for BOTH hypothesis and report.

    Including threat_type in the hypothesis key ensures that when multiple
    different attack types fire for the same IP in the same agent cycle
    (e.g. Brute Force + Credential Stuffing + DoS Flood all from 10.0.0.5),
    each one gets its own correctly-contextualised Ollama call rather than
    every alert after the first receiving the cached response of whichever
    rule happened to fire first.

    TTL:
      "hyp" → _CACHE_HYP_TTL_SECONDS (60 s)
      "rep" → _CACHE_REP_TTL_SECONDS (360 s)

    Args:
        threat_type: e.g. "Brute Force Attack"
        source_ip:   e.g. "192.168.1.4"
        kind:        "hyp" for hypothesis, "rep" for incident report

    Returns:
        Cached response string, or None if no valid entry exists.
    """
    if not source_ip or not threat_type:
        return None

    key = (threat_type, source_ip, kind)
    ttl = _CACHE_HYP_TTL_SECONDS if kind == "hyp" else _CACHE_REP_TTL_SECONDS

    entry = _LLM_CACHE.get(key)
    if entry is None:
        return None

    text, ts = entry
    if (time.time() - ts) < ttl:
        return text

    # Expired — evict so the dict doesn't grow unboundedly
    del _LLM_CACHE[key]
    return None


def _cache_set(threat_type: str, source_ip: str, kind: str, value: str) -> None:
    """Store a fresh LLM response in the cache using the same key logic as _cache_get."""
    if not source_ip or not threat_type:
        return
    key = (threat_type, source_ip, kind)
    _LLM_CACHE[key] = (value, time.time())


# ── Internal helpers ─────────────────────────────────────────────────────────


def _query_groq(prompt: str, system_prompt: str = "") -> LLMResult:
    """
    Low-level POST to the Groq OpenAI-compatible chat completions endpoint.
    Retries once: after a 429 it waits for Retry-After (capped at 10 s),
    after a network error it waits 0.5 s.
    """
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    payload = {
        "model": GROQ_MODEL,
        "messages": messages,
        "temperature": 0.3,
        # gpt-oss counts hidden reasoning tokens against max_tokens, so the
        # budget must cover reasoning + the 2-3 sentence answer.
        "max_tokens": 1024,
    }
    if "gpt-oss" in GROQ_MODEL:
        payload["reasoning_effort"] = "low"

    for attempt in range(2):
        try:
            response = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=15)
            if response.status_code == 429:
                if attempt == 0:
                    # A malformed header raises here and takes the 0.5 s retry below.
                    time.sleep(min(float(response.headers.get("retry-after", 2)), 10.0))
                    continue
                return None, "error"
            response.raise_for_status()
            choice = response.json()["choices"][0]
            text = (choice["message"].get("content") or "").strip()
            if choice.get("finish_reason") == "length":
                return None, "truncated"
            return (text, "ok") if text else (None, "error")
        except Exception:
            if attempt == 1:
                return None, "error"
            time.sleep(0.5)

    return None, "error"


def _query_llm(prompt: str, system_prompt: str = "") -> LLMResult:
    """Dispatches to Groq if GROQ_API_KEY is set and USE_GROQ is not false, else to local Ollama."""
    if LLM_PROVIDER == "Groq":
        return _query_groq(prompt, system_prompt)
    return _query_ollama(prompt, system_prompt)


def _is_ollama_running() -> bool:
    """Quick ping to see if the Ollama server is up."""
    try:
        r = requests.get(OLLAMA_TAGS_URL, timeout=3)
        return r.status_code == 200
    except requests.exceptions.ConnectionError:
        return False


def _query_ollama(prompt: str, system_prompt: str = "") -> LLMResult:
    """
    Low-level POST to the Ollama /api/generate endpoint.

    Returns (text, "ok"), or (None, "truncated"/"error").  The agent keeps
    working when the LLM is offline — the alert just has no AI text.
    """
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "system": system_prompt,
        "stream": False,  # wait for full response before returning
        "options": DEFAULT_OPTIONS,
    }

    try:
        response = requests.post(OLLAMA_GENERATE_URL, json=payload, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        result = response.json()
    except Exception:
        return None, "error"

    if result.get("done_reason") == "length":
        return None, "truncated"
    text = (result.get("response") or "").strip()
    return (text, "ok") if text else (None, "error")


# ── Public API ────────────────────────────────────────────────────────────────


def check_ollama_health() -> dict:
    """
    Returns a status dict so main.py can log a friendly startup message.
    Supports both Groq and Ollama.
    """
    if LLM_PROVIDER == "Groq":
        # Real (token-free) call: list models with the configured key.
        try:
            r = requests.get(
                GROQ_MODELS_URL,
                headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
                timeout=10,
            )
        except Exception as e:
            return {"status": "error", "message": f"Cannot reach Groq API ({type(e).__name__})."}
        if r.status_code == 401:
            return {"status": "error", "message": "Groq rejected GROQ_API_KEY (HTTP 401)."}
        if r.status_code != 200:
            return {"status": "warning", "message": f"Groq API returned HTTP {r.status_code}."}
        ids = {m.get("id") for m in r.json().get("data", [])}
        if GROQ_MODEL not in ids:
            return {"status": "warning", "message": f"Groq key OK, but model '{GROQ_MODEL}' is not available."}
        return {
            "status": "ok",
            "message": f"Groq Cloud LLM reachable, key accepted, model {GROQ_MODEL} available [OK]",
        }

    if not _is_ollama_running():
        return {
            "status": "error",
            "message": (
                f"Cannot connect to Ollama on {OLLAMA_BASE_URL} and Groq is not in use "
                "(GROQ_API_KEY unset or USE_GROQ=false). Set GROQ_API_KEY in .env or run: ollama serve"
            ),
        }

    # Check that our specific model is available locally
    try:
        r = requests.get(OLLAMA_TAGS_URL, timeout=3)
        models = [m["name"] for m in r.json().get("models", [])]
        model_present = any(MODEL_NAME.split(":")[0] in m for m in models)
        if model_present:
            return {
                "status": "ok",
                "message": f"Ollama is running with model {MODEL_NAME} [OK]",
            }
        else:
            return {
                "status": "warning",
                "message": (
                    f"Ollama is running but '{MODEL_NAME}' is not pulled yet. "
                    f"Run: ollama pull {MODEL_NAME}"
                ),
            }
    except Exception:
        return {"status": "ok", "message": "Ollama is running (model check skipped)."}


check_llm_health = check_ollama_health


# ── Per-threat-type hypothesis context ───────────────────────────────────────
# These one-line descriptions are injected into the hypothesis system prompt
# so the LLM immediately understands which of the 8 attack categories it is
# analysing — without having to infer it from the observation alone.

_THREAT_CONTEXT: dict[str, str] = {
    "Brute Force Attack": (
        "A brute force attack is an automated, repeated attempt to guess "
        "credentials by cycling through passwords against a single target account."
    ),
    "Endpoint Reconnaissance": (
        "Endpoint reconnaissance involves systematically probing restricted or "
        "admin paths to map the application's attack surface before a deeper intrusion."
    ),
    "Unauthorized Access Scan": (
        "An unauthorized access scan is a broad sweep of application endpoints "
        "to find weakly-protected resources, identified by a flood of 401/403 responses."
    ),
    "Credential Stuffing": (
        "Credential stuffing uses a leaked credentials list to test many different "
        "usernames against the login endpoint — each attempt uses a distinct account, "
        "unlike brute force which hammers a single account."
    ),
    "Account Takeover": (
        "An account takeover is confirmed when prior failed login attempts from an IP "
        "are followed by a successful authentication — the attacker found a valid credential."
    ),
    "Data Exfiltration": (
        "Data exfiltration is high-volume automated retrieval of data from API or "
        "download endpoints, indicating bulk data theft or scraping."
    ),
    "Path Traversal Attack": (
        "A path traversal attack uses ../ or URL-encoded sequences in request paths "
        "to escape the web root and read arbitrary server-side files (e.g. /etc/passwd)."
    ),
    "DoS Rate Flood": (
        "A denial-of-service rate flood overwhelms the server by sending an extreme "
        "volume of requests per minute from a single IP, exhausting resources."
    ),
}


def generate_hypothesis(
    observation: str,
    threat_type: str = "",
    source_ip: str = "",
) -> tuple[str | None, bool, str]:
    """
    Step 2 of the agent loop: Hypothesize.

    Takes the plain-English observation produced by _build_observation() and
    asks the LLM to explain what this specific attack is doing and why it is
    dangerous.  Unlike the old version, the threat_type is injected into both
    the system prompt (via _THREAT_CONTEXT) and the user prompt, so the LLM
    produces a precisely-targeted explanation for each of the 8 attack categories
    rather than a generic guess.

    Cache behaviour:
        Keyed on (threat_type, source_ip, "hyp") — TTL 60 s.
        Each unique (attack-type, IP) pair caches independently, so Brute Force
        and Credential Stuffing firing from the same IP in the same cycle each
        get their own correctly-contextualised hypothesis.

    Args:
        observation:  Plain-English summary from _build_observation(), e.g.:
                      "45 failed login attempts from IP 192.168.1.4 in 60 s
                       targeting account(s): admin."
        threat_type:  One of the 8 canonical threat-type strings.
        source_ip:    The attacker's IP — used as part of the cache key.

    Returns:
        (hypothesis_text, from_cache, status)
        hypothesis_text: 1-2 sentence explanation, or None if the call failed.
        from_cache:      True if the response came from the in-memory cache.
        status:          "ok" | "truncated" | "error" (failures are never cached).
    """
    # ── Cache lookup ─────────────────────────────────────────────────────────
    cached = _cache_get(threat_type, source_ip, "hyp")
    if cached is not None:
        return cached, True, "ok"  # served from cache — no LLM call made

    # ── Build threat-type-aware prompts ──────────────────────────────────────
    threat_context = _THREAT_CONTEXT.get(
        threat_type,
        "This is a suspicious security event that requires investigation.",
    )

    system = (
        "You are a concise SOC analyst assistant. "
        "You will be given the confirmed detection type and a precise observation "
        "captured from live traffic logs. "
        "Respond with exactly ONE to TWO sentences that explain what the attacker "
        "is doing, why this specific technique is dangerous, and what asset or "
        "capability is at immediate risk. "
        "Do not re-state the detection type label verbatim. "
        "Do not include greetings, bullet points, or extra explanation. "
        "Be direct, technical, and specific to the evidence provided."
    )

    prompt = (
        f"Detection Type: {threat_type}\n"
        f"Attack Context: {threat_context}\n"
        f"Live Observation: {observation}\n\n"
        "In 1-2 sentences, explain what this attacker is doing and the immediate risk."
    )

    text, status = _query_llm(prompt, system)

    # ── Cache store (successful responses only) ──────────────────────────────
    if status == "ok":
        _cache_set(threat_type, source_ip, "hyp", text)

    return text, False, status


def generate_incident_report(
    threat_type: str,
    source_ip: str,
    details: dict,
    mitigation: str,
    hypothesis: str = "",
    observation: str = "",
) -> tuple[str | None, bool, str]:
    """
    Final step of the agent loop: Explain.

    The agent has already made ALL security decisions deterministically.
    This function hands those pre-calculated facts to the LLM and asks it
    to write a polished incident report paragraph for the dashboard.

    The LLM adds NO new logic. It is a text formatter only.

    Compared to the previous version, the prompt now includes:
      • observation  — the plain-English summary from _build_observation(),
                       giving the LLM a narrative starting point specific to
                       the attack type rather than only a raw JSON evidence blob.
      • threat_type  — already included; ensures the report is titled and
                       framed correctly for each of the 8 attack categories.

    Cache behaviour:
        Keyed on (threat_type, source_ip, "rep") — TTL 360 s.
        360 s > 300 s alert cooldown so a re-alert after the cooldown lifts
        still finds a warm cache entry.

    Args:
        threat_type:  "Brute Force Attack", "Endpoint Reconnaissance", etc.
        source_ip:    The attacker's IP address.
        details:      Dict of supporting evidence (counts, endpoints, etc.)
        mitigation:   The exact mitigation string decided by the rules engine.
        hypothesis:   (Optional) The hypothesis generated earlier in the loop.
        observation:  (Optional) Plain-English summary from _build_observation().
                      Included in the prompt for richer, more specific output.

    Returns:
        (report_text, from_cache, status)
        report_text: 2-3 sentence SOC report paragraph, or None if the call failed.
        from_cache:  True if the response came from the in-memory cache.
        status:      "ok" | "truncated" | "error" (failures are never cached).
    """
    # ── Cache lookup ─────────────────────────────────────────────────────────
    cached = _cache_get(threat_type, source_ip, "rep")
    if cached is not None:
        return cached, True, "ok"  # served from cache — no LLM call made

    # ── Build prompt ─────────────────────────────────────────────────────────
    IST = timezone(timedelta(hours=5, minutes=30))
    detected_at = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")

    system = (
        "You are a professional SOC analyst writing a concise incident report. "
        "You will receive the confirmed threat type, the exact detection timestamp, "
        "a plain-English observation of the live traffic, supporting evidence, "
        "an analyst hypothesis, and the recommended mitigation. "
        "Write a 2-3 sentence incident report paragraph that covers: "
        "(1) what happened and from which IP, "
        "(2) what the attack technique is and what it targets, "
        "(3) what immediate action should be taken. "
        "Always use the provided Detection Time value exactly as given — "
        "never write [date], [time], or any placeholder. "
        "Be factual, professional, and concise. No bullet points. No headings."
    )

    details_str = json.dumps(details, indent=None)
    observation_line = f"Observation: {observation}\n" if observation else ""
    hypothesis_line = f"Analyst Hypothesis: {hypothesis}\n" if hypothesis else ""

    prompt = (
        f"Detection Time: {detected_at}\n"
        f"Threat Type: {threat_type}\n"
        f"Source IP: {source_ip}\n"
        f"{observation_line}"
        f"Evidence: {details_str}\n"
        f"{hypothesis_line}"
        f"Recommended Mitigation: {mitigation}\n\n"
        "Write a 2-3 sentence incident report paragraph using the exact "
        "Detection Time above and referencing the specific evidence provided."
    )

    text, status = _query_llm(prompt, system)

    # ── Cache store (successful responses only) ──────────────────────────────
    if status == "ok":
        _cache_set(threat_type, source_ip, "rep", text)

    return text, False, status
