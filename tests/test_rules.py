"""Detection-rule tests.

Every test runs against a fresh temporary SQLite file (never data/logs.sqlite),
the LLM calls are stubbed, and the developer's .env is never loaded.
Run: uv run pytest   (or: pip install pytest && pytest)
"""
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "agent"), str(ROOT)]

import dotenv  # noqa: E402

# agent/llm_client.py loads <root>/.env at import time; make that a no-op.
dotenv.load_dotenv = lambda *a, **k: False

import main as agent  # noqa: E402
import mock_generator as mock  # noqa: E402
import rules_engine as rules  # noqa: E402

ATTACKER = "203.0.113.50"


class _InlineExecutor:
    """Runs the LLM worker synchronously so tests see the final row."""

    def submit(self, fn, *args):
        fn(*args)


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = str(tmp_path / "logs.sqlite")
    conn = sqlite3.connect(path)
    conn.executescript((ROOT / "data" / "schema.sql").read_text(encoding="utf-8"))
    monkeypatch.setattr(agent, "DB_PATH", path)
    monkeypatch.setattr(mock, "DB_PATH", path)
    monkeypatch.setattr(mock.time, "sleep", lambda s: None)
    monkeypatch.setattr(agent, "_LLM_EXECUTOR", _InlineExecutor())
    monkeypatch.setattr(agent, "generate_hypothesis", lambda *a, **k: ("Stub hypothesis.", False, "ok"))
    monkeypatch.setattr(agent, "generate_incident_report", lambda *a, **k: ("Stub report.", False, "ok"))
    yield conn
    conn.close()


def log(conn, ip, n=1, *, event="login_attempt", method="POST", endpoint="/login",
        user=None, code=401, status="fail"):
    conn.executemany(
        "INSERT INTO logs (event_type, method, endpoint, username, ip, status_code, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(event, method, endpoint, user, ip, code, status)] * n,
    )
    conn.commit()


def logins(conn, ip, sequence):
    """sequence: [(username, 'fail' | 'success'), ...] written in order (ascending ids)."""
    for user, status in sequence:
        log(conn, ip, user=user, code=200 if status == "success" else 401, status=status)


def iso_ago(seconds):
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()


# ── One seeded case per detection rule ───────────────────────────────────────

def _seed_recon(conn):
    for path in ("/admin", "/config", "/internal", "/env"):
        log(conn, ATTACKER, event="page_access", method="GET", endpoint=path, code=403)


RULE_CASES = [
    ("Brute Force Attack", rules.check_brute_force,
     lambda c: log(c, ATTACKER, 6, user="admin")),
    ("Endpoint Reconnaissance", rules.check_recon, _seed_recon),
    ("Unauthorized Access Scan", rules.check_auth_scan,
     lambda c: log(c, ATTACKER, 7, event="api_call", method="GET", endpoint="/api/private")),
    ("Credential Stuffing", rules.check_credential_stuffing,
     lambda c: logins(c, ATTACKER, [(f"user{i}", "fail") for i in range(9)])),
    ("Account Takeover", rules.check_account_takeover,
     lambda c: logins(c, ATTACKER, [("alice", "fail")] * 3 + [("alice", "success")])),
    ("Data Exfiltration", rules.check_data_exfiltration,
     lambda c: log(c, ATTACKER, 21, event="api_call", method="GET", endpoint="/api/data",
                   code=200, status="success")),
    ("Path Traversal Attack", rules.check_path_traversal,
     lambda c: log(c, ATTACKER, event="page_access", method="GET",
                   endpoint="/static/../../etc/passwd", code=404)),
    ("DoS Rate Flood", rules.check_dos_flood,
     lambda c: log(c, ATTACKER, 101, event="page_access", method="GET", endpoint="/",
                   code=200, status="success")),
]


@pytest.mark.parametrize("threat_type, check, seed", RULE_CASES, ids=[c[0] for c in RULE_CASES])
def test_each_rule_detects_its_seeded_attack(db, threat_type, check, seed):
    seed(db)
    alerts = check(db)
    assert [(a.threat_type, a.source_ip) for a in alerts] == [(threat_type, ATTACKER)]


# ── Account Takeover: same (ip, username), >= min failures before the success ─

ATO_CASES = [
    ("same user: F,F,F,S", [("alice", "fail")] * 3 + [("alice", "success")], True),
    ("different user", [("bob", "fail")] * 3 + [("alice", "success")], False),
    ("success before failures", [("alice", "success")] + [("alice", "fail")] * 3, False),
    ("F,S,F,F", [("alice", "fail"), ("alice", "success"), ("alice", "fail"), ("alice", "fail")], False),
]


@pytest.mark.parametrize("sequence, expected", [c[1:] for c in ATO_CASES], ids=[c[0] for c in ATO_CASES])
def test_account_takeover_ordering(db, sequence, expected):
    logins(db, ATTACKER, sequence)
    alerts = rules.check_account_takeover(db)
    assert bool(alerts) is expected
    if expected:
        assert alerts[0].details["compromised_account"] == "alice"
        assert alerts[0].details["failures_before_success"] == 3


def test_account_takeover_one_alert_per_ip_lists_all_accounts(db):
    logins(db, ATTACKER, [("alice", "fail")] * 3 + [("alice", "success")]
           + [("bob", "fail")] * 3 + [("bob", "success")])
    alerts = rules.check_account_takeover(db)
    assert len(alerts) == 1
    assert set(alerts[0].details["compromised_account"].split(",")) == {"alice", "bob"}


def test_failure_spray_ending_in_success_is_credential_stuffing_not_takeover(db):
    logins(db, ATTACKER, [(f"user{i}", "fail") for i in range(9)] + [("user3", "success")])
    assert rules.check_account_takeover(db) == []
    assert [a.threat_type for a in rules.check_credential_stuffing(db)] == ["Credential Stuffing"]


def test_mock_account_takeover_scenario_still_detected(db):
    mock.simulate_account_takeover("198.51.100.14")
    failures = db.execute(
        "SELECT COUNT(*) FROM logs WHERE ip = '198.51.100.14' AND status = 'fail'"
    ).fetchone()[0]
    (alert,) = rules.check_account_takeover(db)
    assert (alert.source_ip, alert.risk_level) == ("198.51.100.14", "CRITICAL")
    assert alert.details["compromised_account"] == "alice"
    assert alert.details["failures_before_success"] == failures


# ── Regression: cooldown, trusted IPs, Unblock ───────────────────────────────

def test_cooldown_lasts_300_seconds_not_until_midnight(db):
    agent._ensure_alerts_table(db)
    for ip, age in (("203.0.113.10", 600), ("203.0.113.11", 60)):
        db.execute(
            "INSERT INTO alerts (timestamp, threat_type, risk_level, confidence, source_ip) "
            "VALUES (?, 'Brute Force Attack', 'MEDIUM', 50, ?)", (iso_ago(age), ip))
    assert rules._already_alerted(db, "Brute Force Attack", "203.0.113.10") is False
    assert rules._already_alerted(db, "Brute Force Attack", "203.0.113.11") is True


def test_trusted_ip_takeover_alerts_but_is_never_blocked(db):
    logins(db, "127.0.0.1", [("admin", "fail")] * 4 + [("admin", "success")])
    alerts = agent._run_agent_cycle()
    assert [(a.threat_type, a.risk_level) for a in alerts] == [("Account Takeover", "CRITICAL")]
    assert db.execute("SELECT COUNT(*) FROM blocked_ips WHERE ip = '127.0.0.1'").fetchone()[0] == 0
    assert db.execute("SELECT llm_status FROM alerts").fetchall() == [("ok",)]


def test_unblocked_ip_cooldown_restarts_at_unblock(db):
    """Before the fix an unblocked IP skipped the cooldown forever, so an alert
    that does not re-block it (here MEDIUM, from trusted 10.0.0.1) repeated on
    every 5 s poll. Now: one alert right after the unblock, then cooldown."""
    ip = "10.0.0.1"
    agent._ensure_alerts_table(db)
    agent._ensure_blocked_ips_table(db)
    db.execute(
        "INSERT INTO blocked_ips (ip, reason, risk_level, blocked_at, status, unblocked_at) "
        "VALUES (?, 'old block', 'HIGH', ?, 'unblocked', datetime('now', '-60 seconds'))",
        (ip, iso_ago(600)))
    # An alert from BEFORE the unblock (inside the 300 s window) must not suppress.
    db.execute(
        "INSERT INTO alerts (timestamp, threat_type, risk_level, confidence, source_ip) "
        "VALUES (?, 'Unauthorized Access Scan', 'MEDIUM', 50, ?)", (iso_ago(120), ip))
    db.commit()
    log(db, ip, 7, event="api_call", method="GET", endpoint="/api/private")

    first = agent._run_agent_cycle()
    second = agent._run_agent_cycle()

    assert [(a.threat_type, a.risk_level) for a in first] == [("Unauthorized Access Scan", "MEDIUM")]
    assert second == []
