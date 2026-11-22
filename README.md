# 🛡️ AI-Driven Autonomous Cyber Threat Hunting Agent

A real-time Security Operations Centre (SOC) simulation built for the HackNocturn hackathon.
The system monitors a live "victim" web application, applies deterministic rules to detect 8 distinct attack types, automatically blocks high-risk source IPs, uses the Groq Cloud API (`openai/gpt-oss-120b`) or a local Ollama model to write human-readable incident reports, and streams everything to an interactive Streamlit dashboard.

---

## Architecture

```text
Attacker (Requestly browser extension / mock_generator.py)
         │
         ▼
 Victim App  ─── FastAPI (backend/api.py)   ← returns 403 to IPs in blocked_ips
         │
         ▼
 data/logs.sqlite   ◄── logs table written by backend (or mock_generator.py)
         │
         ▼
 Threat Hunting Agent (agent/main.py)
   ├── Rule Engine  (agent/rules_engine.py)   ← 100 % deterministic
   └── LLM Client   (agent/llm_client.py)     ← Groq Cloud (openai/gpt-oss-120b) / Ollama
         │
         ▼
 data/logs.sqlite   ◄── alerts + blocked_ips tables written by agent
         │
         ▼
 Streamlit Dashboard (dashboard/app.py)       ← auto-refresh every 3 s
```

**Key design principle:** The AI makes *zero* security decisions.
All detection, scoring, blocking, and mitigation logic lives in the deterministic rule engine and agent.
The LLM only translates rule output into SOC-report prose.

---

## Detected Threat Types

| # | Threat Type | Trigger |
|---|-------------|---------|
| 1 | **Brute Force Attack** | > 5 failed logins / min, same IP |
| 2 | **Endpoint Reconnaissance** | > 3 restricted-path hits / min |
| 3 | **Unauthorized Access Scan** | > 6 HTTP 401/403 responses / min |
| 4 | **Credential Stuffing** | > 8 distinct usernames failing / min |
| 5 | **Account Takeover** | ≥ 3 failures → successful login, same IP, 5 min window |
| 6 | **Data Exfiltration** | > 20 successful GETs to data endpoints / min |
| 7 | **Path Traversal Attack** | any `../` or URL-encoded traversal in request path |
| 8 | **DoS Rate Flood** | > 100 total requests / min from one IP |

Rules are evaluated independently, so one attacker can trigger several types at once
(e.g. a credential-stuffing IP also trips Brute Force and Unauthorized Access Scan).
`mock_generator.py --once` fires 8 scenarios. If the agent sees the whole burst in one poll it raises 16–17 alerts covering all 8 types.
If it polls mid-burst, an IP blocked by its first detected rule gets no further alert types (blocked IPs are not re-alerted), so you see fewer alerts and labels; all 8 attacker IPs are blocked either way.

Each confirmed alert has a confidence score (rule base + bonuses) and a risk level:
CRITICAL ≥ 80, HIGH ≥ 60, MEDIUM ≥ 40 (alerts below 40 are dropped).

---

## Automatic IP Blocking

- When the agent confirms a **HIGH** or **CRITICAL** alert it writes the source IP to the `blocked_ips` table.
- The backend middleware checks that table on every request and answers blocked IPs with **HTTP 403** (the attempt is still logged with status `blocked`).
- IPs listed in `BASELINE["trusted_ips"]` (default `10.0.0.1`, `127.0.0.1`) are still alerted on — the dashboard tags them `TRUSTED IP · NOT AUTO-BLOCKED` — but are never blocked automatically, so the machine running the demo cannot lock itself out.
- The dashboard's **Blocked IPs** panel has an **Unblock** button. An unblocked IP skips the alert cooldown, so if it keeps attacking it is re-detected (and, if HIGH/CRITICAL, re-blocked) on the next cycle.

---

## Project Structure

```text
Cyber_Threat_Hunting_Agent/
│
├── backend/
│   ├── api.py          FastAPI victim app (login, admin, data endpoints + catch-all) + IP-block middleware
│   ├── db.py           SQLite helpers (init_db, get_connection)
│   ├── logger.py       log_event() — writes every request to the DB
│   └── main.py         Entry point: init DB + start uvicorn
│
├── agent/
│   ├── main.py         Core loop: Observe → Hypothesize → Investigate → Decide → Explain; IP blocking
│   ├── rules_engine.py All 8 detection rules + ThreatAlert dataclass + mitigations
│   └── llm_client.py   Groq / Ollama integration (generate_hypothesis, generate_incident_report)
│
├── dashboard/
│   └── app.py          Streamlit SOC watch view (auto-refreshes via @st.fragment)
│
├── data/
│   ├── logs.sqlite     Shared SQLite database (created at first run, git-ignored)
│   └── schema.sql      Table definitions for logs, alerts, blocked_ips
│
├── mock_generator.py   Standalone traffic simulator: writes logs straight to the DB (no backend needed)
├── pyproject.toml      Python dependencies (managed with uv; pip also works)
├── hacknocturn.md      Original hackathon design notes (historical)
├── project_structure.md Original team folder plan (historical)
└── README.md           This file
```

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.11+ | Tested on 3.11.9 and 3.13.12 |
| [uv](https://docs.astral.sh/uv/) or pip | recent | Dependency management |
| Groq Cloud API key | optional | Default model `openai/gpt-oss-120b` |
| [Ollama](https://ollama.com) | optional | Local fallback (`llama3.1:8b`) when no Groq key is set |

Without either LLM the system still detects, blocks, and alerts; cards just show "AI summary unavailable".

---

## Setup

```bash
# 1. Clone the repository
git clone https://github.com/Krishna2805/Cyber_Threat_Hunting_Agent.git
cd Cyber_Threat_Hunting_Agent

# 2. Install dependencies
uv sync
# Or with pip (inside a virtual environment): pip install -e .
#   (this installs the dependencies; the code itself runs from the source tree)

# 3. Configure the LLM
cp .env.example .env
# Set GROQ_API_KEY in .env. The agent loads <project root>/.env at startup;
# values in .env override variables already set in your shell.

# 4. Optional: use local Ollama instead of Groq
# Set USE_GROQ=false in .env (or leave GROQ_API_KEY empty), then:
# ollama pull llama3.1:8b && ollama serve
```

---

## Quick Verification Commands

**LLM health check** (for Groq this makes a real, token-free `GET /models` call and checks the key and model):
```bash
uv run python -c "import sys; sys.path.insert(0, 'agent'); import llm_client; print(llm_client.check_llm_health()['message'])"
```

**Headless traffic simulation** (writes attack logs; run the agent afterwards to detect them):
```bash
uv run python mock_generator.py --once
```

---

## Running the Full Stack

Open **three separate terminals** from the project root.

### Terminal 1 — Backend (Victim App)

```bash
uv run python -m backend.main
```

The FastAPI server starts at `http://localhost:8000` (bound to `0.0.0.0`, auto-reload on).
Interactive API docs: `http://localhost:8000/docs`

### Terminal 2 — Threat Hunting Agent

```bash
uv run python agent/main.py
```

The agent polls the database every 5 seconds.
Detections are printed to the console with colour-coded banners and written to the `alerts` table; HIGH/CRITICAL source IPs are written to `blocked_ips`.
LLM enrichment runs on a background thread, so detection never waits for the LLM.

### Terminal 3 — Dashboard

```bash
uv run streamlit run dashboard/app.py
```

Dashboard opens at `http://localhost:8501`.
It auto-refreshes every 3 seconds via Streamlit's `@st.fragment`.

---

## Demo Workflow

1. Start all three components above.
2. Open the Victim App (`http://localhost:8000`) and the Dashboard (`http://localhost:8501`) side by side.
3. **Teammate / Attacker** activates Requestly rules in their browser to simulate attacks.
   The backend takes the client IP from `X-Forwarded-For` (then `X-Real-IP`), so Requestly can impersonate many attacker IPs from one machine:

   | Attack | Requestly Action |
   |--------|-----------------|
   | Brute Force | Loop-fire `POST /login` with wrong passwords |
   | Recon | Rapid-fire `GET /admin`, `/config`, `/internal`, `/.env` |
   | Data Exfiltration | Loop-fire `GET /api/users`, `/export`, `/download` |

4. Watch the Dashboard detect each attack in real time, assign a risk level and confidence score, block the IP, and display the LLM-generated incident report.

> This is a deliberately vulnerable demo app: trusting `X-Forwarded-For` lets any client choose its IP. Do not expose it to the internet.

---

## Developing Without a Full Stack (Mock Generator)

`mock_generator.py` writes realistic normal and attack traffic directly into the `logs` table of `data/logs.sqlite`, bypassing the backend. It writes no alerts — start the agent to detect the attacks.

```bash
# Continuous mode — fire attacks on a schedule (Ctrl-C to stop)
uv run python mock_generator.py

# Fire all 8 attack scenarios once then exit
uv run python mock_generator.py --once

# Wipe logs, alerts and blocked_ips from the DB (use between demo runs)
uv run python mock_generator.py --reset
```

---

## Dashboard Controls

The dashboard is mostly a watch view, but it writes to the database in two places:

- **Unblock** (Blocked IPs panel): sets the row's `status='unblocked'` and `unblocked_at`; the backend stops returning 403 for that IP.
- **Log cleanup tab**: deletes `logs` rows older than 15 minutes after a Delete → Confirm step (Cancel aborts). Alerts and blocked IPs are kept.

---

## Configuration

### Agent thresholds (`agent/rules_engine.py → BASELINE`)

```python
BASELINE = {
    "max_failed_logins_per_min":    5,    # Brute Force trigger
    "max_restricted_hits_per_min":  3,    # Recon trigger
    "max_401_403_per_min":          6,    # Auth Scan trigger
    "max_distinct_users_per_min":   8,    # Credential Stuffing trigger
    "account_takeover_min_failures":3,    # Account Takeover: failures before success counts
    "account_takeover_window_seconds": 300,
    "max_data_requests_per_min":   20,    # Data Exfiltration trigger
    "path_traversal_min_attempts":  1,    # Path Traversal: any single hit fires
    "max_requests_per_min":       100,    # DoS Flood trigger
    "alert_cooldown_seconds":     300,    # suppress re-alerts for 5 min per (IP, threat)
    "trusted_ips": ["10.0.0.1", "127.0.0.1"],  # alerted on, never auto-blocked
}
```

The cooldown does not apply to an IP that is currently blocked (no new alerts at all) or that an analyst has unblocked (re-detected immediately).

### Agent polling interval (`agent/main.py`)

```python
POLL_INTERVAL_SECONDS   = 5   # how often to query the DB
MIN_CONFIDENCE_TO_ALERT = 40  # drop alerts below this threshold
```

### LLM settings (environment variables / `.env`)

| Variable | Default | Meaning |
|----------|---------|---------|
| `GROQ_API_KEY` | *(empty)* | Groq key; when set (and `USE_GROQ` is not false) Groq is used |
| `GROQ_MODEL` | `openai/gpt-oss-120b` | Groq model ID |
| `USE_GROQ` | `true` | `false` forces the Ollama path even if a key is set |
| `OLLAMA_MODEL` | `llama3.1:8b` | Local model name |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server |

Successful LLM responses are cached in memory per (threat type, IP): hypotheses for 60 s, reports for 360 s. Failed calls are never cached. On a Groq rate limit (HTTP 429) the client waits for `Retry-After` (max 10 s) and retries once.

---

## Answering "How Can You Trust AI?"

> **The AI makes zero security decisions.**
>
> Every detection, every confidence score, every block, and every mitigation recommendation is produced by the deterministic rule engine using explicit thresholds and verifiable SQL queries.
>
> The LLM's only job is to read those pre-calculated facts and format them into a readable paragraph for the dashboard — the same way a human analyst would write up a report after reviewing the logs.
>
> If the LLM is offline, rate-limited, or returns a truncated answer, the agent keeps detecting, blocking, and alerting; no AI text is stored, `alerts.llm_status` records `error` or `truncated`, and the dashboard card shows "AI SUMMARY UNAVAILABLE".

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `fastapi` | Victim web application |
| `uvicorn` | ASGI server for FastAPI |
| `streamlit` | SOC Watch View dashboard |
| `altair` | Timeline and attack-distribution charts |
| `pandas` | DataFrame queries for the dashboard |
| `requests` | HTTP calls from the agent to Groq / Ollama |
| `python-dotenv` | Loads `.env` for the agent |
| `sqlite3` | Built-in — shared data layer |

---

## Team Roles

| Role | Owns | Files |
|------|------|-------|
| Backend | Victim App + Event Logging | `backend/` |
| Agent | Rule Engine + LLM Integration | `agent/` |
| Dashboard | SOC Watch View | `dashboard/` |

**Data layer contract:**
- `backend/` **writes** `logs`; **reads** `blocked_ips` (403 middleware).
- `agent/` **reads** `logs`, **writes** `alerts` and `blocked_ips`.
- `dashboard/` **reads** all three; **writes** only via Unblock (`blocked_ips`) and log cleanup (`logs`).
- `mock_generator.py` **writes** `logs` (and `--reset` clears all three tables).
