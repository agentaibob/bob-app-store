#!/usr/bin/env python3
"""
Hermes Monitor — serwer HTTP (stdlib) dla apki UmbrelOS bob-hermes-monitor.
Czyta dane Hermesa z /hermes-data (mount RO), zapisuje do /data.
Bez zewnętrznych zależności — tylko stdlib Pythona.
Endpoints: /, /api/*, /widgets/hermes
"""

import base64
import json
import os
import re
import sqlite3
import threading
import time
import urllib.parse
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# --- Konfiguracja ------------------------------------------------------------
PORT = int(os.environ.get("HERMES_PORT", "8126"))
DATA_DIR = os.environ.get("HERMES_DATA_DIR", "/data")
HERMES_DATA = os.environ.get("HERMES_ROOT", "/hermes-data")
PROFILES_ROOT = os.path.join(HERMES_DATA, "profiles")

APP_VERSION = "1.10.0"

STATUS_POLL_SECONDS = 10
METRICS_POLL_SECONDS = 30
CET = timezone(timedelta(hours=2))  # CEST

def _detect_profiles():
    '''Auto-detekcja profili z filesystemu. Zawsze zawiera "default" + katalogi profiles/.'''
    profiles = ["default"]
    if os.path.isdir(PROFILES_ROOT):
        for p in Path(PROFILES_ROOT).iterdir():
            if p.is_dir():
                profiles.append(p.name)
    return sorted(profiles)

MONITORED_PROFILES = _detect_profiles()

# --- Strefy czasowe ---------------------------------------------------------
def _ts_to_iso(ts):
    if ts is None:
        return None
    if isinstance(ts, str):
        return ts
    return datetime.fromtimestamp(ts, tz=CET).isoformat()

def _now_iso():
    return datetime.now(CET).isoformat()

# --- Helpers -----------------------------------------------------------------
def _read_json(path):
    try:
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
    except Exception:
        pass
    return None

def _get_profile_home(profile):
    if profile == "default":
        return HERMES_DATA
    return os.path.join(PROFILES_ROOT, profile)

def _get_state_db_path(profile):
    return os.path.join(_get_profile_home(profile), "state.db")

# --- Baza dashboardu ---------------------------------------------------------
def _get_dashboard_db():
    return os.path.join(DATA_DIR, "dashboard.db")

def _db_connect(path=None, mode="rw"):
    """Otwiera połączenie SQLite. mode='ro' dla odczytu, 'rw' dla zapisu."""
    if path is None:
        path = _get_dashboard_db()
    if mode == "ro":
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    else:
        conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    if mode == "rw":
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
    return conn

def init_dashboard_db():
    conn = _db_connect()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS metrics_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            metric TEXT NOT NULL,
            value REAL,
            extra TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics_snapshots(ts);
        CREATE INDEX IF NOT EXISTS idx_metrics_name_ts ON metrics_snapshots(metric, ts);

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            level TEXT NOT NULL,
            alert_id TEXT NOT NULL,
            message TEXT NOT NULL,
            acknowledged INTEGER DEFAULT 0,
            acknowledged_at REAL
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
    """)
    conn.commit()
    conn.close()

# --- Kolektor ----------------------------------------------------------------
def _get_uptime_sec(start_time):
    """start_time w gateway_state.json to pole 22 /proc/<pid>/stat (clock ticks od
    bootu), NIE epoch. Przelicz na sekundy pracy procesu (HZ + uptime)."""
    if start_time is None:
        return None
    try:
        hz = os.sysconf("SC_CLK_TCK") or 100
        up_ticks = float(open("/proc/uptime").read().split()[0]) * hz
        sec = (up_ticks - float(start_time)) / hz
        return max(0.0, sec)
    except Exception:
        return None

def _parse_gateway_state(profile):
    home = _get_profile_home(profile)
    state_path = os.path.join(home, "gateway_state.json")
    data = _read_json(state_path) or {}
    gw_state = data.get("gateway_state") or data.get("state", "unknown")
    pid = data.get("pid")
    start_time = data.get("start_time")
    uptime = _get_uptime_sec(start_time)
    # Wiek danych (sekundy od updated_at)
    age_seconds = None
    updated_ts = data.get("updated_at")
    if updated_ts:
        try:
            dt = datetime.fromisoformat(str(updated_ts).replace("Z", "+00:00"))
            age_seconds = time.time() - dt.timestamp()
        except Exception:
            age_seconds = None
    # Platformy z zachowaniem error_code i error_message
    platforms_in = data.get("platforms", {}) or {}
    platforms_out = []
    for name, pinfo in platforms_in.items():
        if isinstance(pinfo, dict):
            platforms_out.append({
                "name": name,
                "state": pinfo.get("state", "unknown"),
                "error_code": pinfo.get("error_code"),
                "error_message": pinfo.get("error_message"),
                "updated_at": _ts_to_iso(pinfo.get("updated_at")),
            })
        else:
            platforms_out.append({
                "name": name, "state": str(pinfo),
                "error_code": None, "error_message": None, "updated_at": None,
            })
    return {
        "profile": profile,
        "running": gw_state == "running",
        "pid": pid,
        "state": gw_state,
        "desired_state": data.get("desired_state"),
        "start_time": start_time,
        "uptime": uptime,
        "age_seconds": age_seconds,
        "exit_reason": data.get("exit_reason"),
        "restart_requested": data.get("restart_requested", False),
        "active_agents": data.get("active_agents", 0),
        "updated_at": _ts_to_iso(updated_ts),
        "platforms": platforms_out,
    }

def _parse_cron_ticker(profile):
    home = _get_profile_home(profile)
    result = {"heartbeat_age_seconds": None, "last_success_age_seconds": None, "alive": False}
    hb_path = os.path.join(home, "cron", "ticker_heartbeat")
    if os.path.exists(hb_path):
        try:
            hb = float(open(hb_path).read().strip())
            result["heartbeat_age_seconds"] = time.time() - hb
            result["alive"] = result["heartbeat_age_seconds"] < 120
        except Exception:
            pass
    return result

def _read_env_names(profile):
    env_path = os.path.join(_get_profile_home(profile), ".env")
    if not os.path.exists(env_path):
        return []
    names = []
    try:
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    names.append(line.split("=", 1)[0])
    except Exception:
        pass
    return names

def _parse_auth_status(profile):
    auth_path = os.path.join(_get_profile_home(profile), "auth.json")
    data = _read_json(auth_path) or {}
    creds = data.get("credential_pool", {})
    result = []
    for provider, info in creds.items():
        if isinstance(info, dict):
            result.append({
                "provider": provider,
                "auth_type": info.get("auth_type"),
                "last_status": info.get("last_status"),
                "expires_at": _ts_to_iso(info.get("expires_at")),
                "request_count": info.get("request_count", 0),
                "last_error": info.get("last_error_message") or info.get("last_error"),
            })
    return result

def _read_log_summary(profile, log_name, since_hours=1):
    log_path = os.path.join(_get_profile_home(profile), "logs", log_name)
    result = {"errors": 0, "warnings": 0, "last_entries": [], "path": str(log_path)}
    if not os.path.exists(log_path):
        return result
    cutoff = time.time() - since_hours * 3600
    try:
        with open(log_path, errors="replace") as f:
            lines = f.readlines()
        recent = []
        for line in reversed(lines[-500:]):
            try:
                parts = line.split(" ", 3)
                if len(parts) >= 3:
                    ts_str = f"{parts[0]} {parts[1].split(',')[0]}"
                    dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                    dt = dt.replace(tzinfo=CET)
                    if dt.timestamp() < cutoff:
                        break
                    if "ERROR" in line:
                        result["errors"] += 1
                    elif "WARNING" in line:
                        result["warnings"] += 1
                    if len(recent) < 20:
                        recent.append(line.strip())
            except (ValueError, IndexError):
                pass
        result["last_entries"] = list(reversed(recent))
    except Exception:
        pass
    return result

def _get_sessions(profile, limit=20):
    db_path = _get_state_db_path(profile)
    if not os.path.exists(db_path):
        return []
    try:
        conn = _db_connect(db_path, mode="ro")
        rows = conn.execute(
            """SELECT id, source, model, title, message_count, tool_call_count,
                      input_tokens, output_tokens, cache_read_tokens, reasoning_tokens,
                      estimated_cost_usd, actual_cost_usd, cost_status,
                      started_at, ended_at, end_reason, last_activity_at,
                      display_name, billing_provider, api_call_count
               FROM sessions ORDER BY started_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        sessions = []
        for r in rows:
            sessions.append({
                "id": r["id"],
                "source": r["source"],
                "model": r["model"],
                "title": r["title"] or "(bez tytułu)",
                "display_name": r["display_name"],
                "message_count": r["message_count"],
                "tool_call_count": r["tool_call_count"],
                "api_call_count": r["api_call_count"],
                "tokens": {
                    "input": r["input_tokens"],
                    "output": r["output_tokens"],
                    "cache_read": r["cache_read_tokens"],
                    "reasoning": r["reasoning_tokens"],
                    "total": (r["input_tokens"] or 0) + (r["output_tokens"] or 0),
                },
                "cost": {
                    "estimated_usd": r["estimated_cost_usd"],
                    "actual_usd": r["actual_cost_usd"],
                    "status": r["cost_status"],
                },
                "billing_provider": r["billing_provider"],
                "started_at": _ts_to_iso(r["started_at"]),
                "ended_at": _ts_to_iso(r["ended_at"]),
                "end_reason": r["end_reason"],
                "last_activity_at": _ts_to_iso(r["last_activity_at"]),
            })
        conn.close()
        return sessions
    except Exception:
        return []

def _get_usage_stats(profile, days=7):
    db_path = _get_state_db_path(profile)
    if not os.path.exists(db_path):
        return {"daily": [], "by_model": []}
    try:
        conn = _db_connect(db_path, mode="ro")
        cutoff = time.time() - days * 86400
        daily_rows = conn.execute(
            """SELECT date(started_at, 'unixepoch') as day,
                      COUNT(*) as session_count,
                      SUM(input_tokens) as input_tokens,
                      SUM(output_tokens) as output_tokens,
                      SUM(reasoning_tokens) as reasoning_tokens,
                      SUM(estimated_cost_usd) as estimated_cost_usd,
                      SUM(actual_cost_usd) as actual_cost_usd
               FROM sessions WHERE started_at >= ?
               GROUP BY day ORDER BY day""",
            (cutoff,),
        ).fetchall()
        daily = [{
            "day": r["day"],
            "session_count": r["session_count"],
            "tokens": {"input": r["input_tokens"] or 0, "output": r["output_tokens"] or 0, "reasoning": r["reasoning_tokens"] or 0},
            "cost": {"estimated_usd": r["estimated_cost_usd"] or 0, "actual_usd": r["actual_cost_usd"] or 0},
        } for r in daily_rows]

        model_rows = conn.execute(
            """SELECT model, billing_provider,
                      SUM(api_call_count) as calls,
                      SUM(input_tokens) as input_tokens,
                      SUM(output_tokens) as output_tokens,
                      SUM(reasoning_tokens) as reasoning_tokens,
                      SUM(estimated_cost_usd) as estimated_cost_usd
               FROM session_model_usage WHERE last_seen >= ?
               GROUP BY model ORDER BY estimated_cost_usd DESC""",
            (cutoff,),
        ).fetchall()
        by_model = [{
            "model": r["model"], "provider": r["billing_provider"],
            "api_calls": r["calls"],
            "tokens": {"input": r["input_tokens"] or 0, "output": r["output_tokens"] or 0, "reasoning": r["reasoning_tokens"] or 0},
            "estimated_cost_usd": r["estimated_cost_usd"] or 0,
        } for r in model_rows]

        conn.close()
        return {"daily": daily, "by_model": by_model}
    except Exception:
        return {"daily": [], "by_model": []}

def _get_cron_jobs(profile):
    home = _get_profile_home(profile)
    exec_db = os.path.join(home, "cron", "executions.db")
    if not os.path.exists(exec_db):
        return []
    jobs = []
    try:
        conn = _db_connect(exec_db, mode="ro")
        job_ids = conn.execute("SELECT DISTINCT job_id FROM executions ORDER BY job_id").fetchall()
        for jr in job_ids:
            jid = jr["job_id"]
            last_run = conn.execute(
                "SELECT status, started_at, finished_at, error FROM executions WHERE job_id=? ORDER BY started_at DESC LIMIT 1",
                (jid,),
            ).fetchone()
            cutoff = time.time() - 86400
            stats = conn.execute(
                """SELECT COUNT(*) as total,
                          SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) as success,
                          SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) as errors
                   FROM executions WHERE job_id=? AND started_at>=?""",
                (jid, cutoff),
            ).fetchone()
            jobs.append({
                "job_id": jid, "name": jid, "schedule": None, "enabled": True,
                "last_run": {
                    "status": last_run["status"] if last_run else "unknown",
                    "started_at": _ts_to_iso(last_run["started_at"]) if last_run else None,
                    "finished_at": _ts_to_iso(last_run["finished_at"]) if last_run else None,
                    "error": last_run["error"] if last_run else None,
                } if last_run else None,
                "stats_24h": {
                    "total": stats["total"] if stats else 0,
                    "success": stats["success"] if stats else 0,
                    "errors": stats["errors"] if stats else 0,
                } if stats else None,
            })
        conn.close()
    except Exception:
        pass
    return jobs

def _get_kanban_summary():
    kanban_path = os.path.join(HERMES_DATA, "kanban", "boards", "hermes-monitor", "kanban.db")
    if not os.path.exists(kanban_path):
        return {"tasks_by_status": {}, "recent_events": []}
    try:
        conn = _db_connect(kanban_path, mode="ro")
        counts = conn.execute("SELECT status, COUNT(*) as cnt FROM tasks GROUP BY status").fetchall()
        tasks_by_status = {r["status"]: r["cnt"] for r in counts}
        recent = conn.execute(
            """SELECT te.id, te.task_id, te.kind, te.created_at, t.title
               FROM task_events te JOIN tasks t ON t.id=te.task_id
               ORDER BY te.created_at DESC LIMIT 20"""
        ).fetchall()
        recent_events = [{
            "id": r["id"], "task_id": r["task_id"], "task_title": r["title"],
            "event": r["kind"], "ts": _ts_to_iso(r["created_at"]),
        } for r in recent]
        conn.close()
        return {"tasks_by_status": tasks_by_status, "recent_events": recent_events}
    except Exception:
        return {"tasks_by_status": {}, "recent_events": []}

# --- Alerty (dashboard.db) ---------------------------------------------------
def _save_alert(alert_id, level, message):
    conn = _db_connect()
    existing = conn.execute("SELECT id FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO alerts (ts, level, alert_id, message) VALUES (?,?,?,?)",
            (time.time(), level, alert_id, message),
        )
        conn.commit()
    conn.close()

def _cleanup_resolved_alerts(active_ids):
    conn = _db_connect()
    all_alerts = conn.execute("SELECT id, alert_id FROM alerts").fetchall()
    for row in all_alerts:
        if row["alert_id"] not in active_ids:
            conn.execute("DELETE FROM alerts WHERE id=?", (row["id"],))
    conn.commit()
    conn.close()

def _get_active_alerts():
    conn = _db_connect()
    rows = conn.execute(
        "SELECT * FROM alerts WHERE acknowledged=0 ORDER BY ts DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def _acknowledge_alert(db_id):
    conn = _db_connect()
    conn.execute("UPDATE alerts SET acknowledged=1, acknowledged_at=? WHERE id=?", (time.time(), db_id))
    conn.commit()
    conn.close()

def _save_metrics_batch(metrics):
    if not metrics:
        return
    conn = _db_connect()
    ts = time.time()
    conn.executemany(
        "INSERT INTO metrics_snapshots (ts, metric, value) VALUES (?,?,?)",
        [(ts, k, v) for k, v in metrics.items()],
    )
    conn.commit()
    conn.close()

def _get_metric_history(metric, hours=24):
    conn = _db_connect()
    cutoff = time.time() - hours * 3600
    rows = conn.execute(
        "SELECT ts, value FROM metrics_snapshots WHERE metric=? AND ts>=? ORDER BY ts",
        (metric, cutoff),
    ).fetchall()
    conn.close()
    return [{"ts": r["ts"], "value": r["value"]} for r in rows]

# --- Kolektor (główna pętla) -------------------------------------------------
_snapshot = {}
_snapshot_lock = threading.Lock()

def _check_alerts(snapshot):
    alerts = []
    for prof in snapshot.get("profiles", []):
        gw = prof.get("gateway", {})
        if not gw.get("running"):
            aid = f"A1-{prof['profile']}"
            alerts.append({"id": aid, "level": "critical",
                           "message": f"Gateway profilu {prof['profile']} NIE DZIAŁA (state={gw.get('state')})"})
        ticker = prof.get("cron_ticker", {})
        if ticker.get("heartbeat_age_seconds") and ticker["heartbeat_age_seconds"] > 120:
            aid = f"A3-{prof['profile']}"
            alerts.append({"id": aid, "level": "critical",
                           "message": f"Cron scheduler {prof['profile']}: ticker martwy ({ticker['heartbeat_age_seconds']:.0f}s)"})
        logs = prof.get("logs", {})
        if logs.get("errors", {}).get("errors", 0) > 5:
            aid = f"A5-{prof['profile']}"
            alerts.append({"id": aid, "level": "warning",
                           "message": f"Profil {prof['profile']}: {logs['errors']['errors']} ERRORÓW w errors.log (1h)"})
    for a in alerts:
        _save_alert(a["id"], a["level"], a["message"])
    active_ids = {a["id"] for a in alerts}
    _cleanup_resolved_alerts(active_ids)
    return alerts

def collect_all():
    global _snapshot, MONITORED_PROFILES
    MONITORED_PROFILES = _detect_profiles()  # dynamiczna re-detekcja
    profiles_data = []
    for profile in MONITORED_PROFILES:
        try:
            home = _get_profile_home(profile)
            if not os.path.isdir(home):
                continue
            gw = _parse_gateway_state(profile)
            ticker = _parse_cron_ticker(profile)
            auth = _parse_auth_status(profile)
            env_names = _read_env_names(profile)
            errors_log = _read_log_summary(profile, "errors.log", 1)
            agent_log = _read_log_summary(profile, "agent.log", 1)
            # Wzbogać obiekt gateway: aliveness cron-tickera + liczba błędów 1h
            gw["cron_alive"] = ticker.get("alive", False)
            gw["cron_heartbeat_age_seconds"] = ticker.get("heartbeat_age_seconds")
            gw["errors_1h"] = errors_log.get("errors", 0)
            profiles_data.append({
                "profile": profile, "home": str(home),
                "gateway": gw, "cron_ticker": ticker,
                "auth_providers": auth, "api_keys_set": env_names,
                "logs": {"errors": errors_log, "agent_tracebacks": agent_log.get("errors", 0)},
            })
        except Exception:
            pass

    active = [p for p in profiles_data if p["gateway"]["running"]]
    total_agents = sum(p["gateway"]["active_agents"] for p in profiles_data)
    total_errors = sum(p["logs"]["errors"]["errors"] for p in profiles_data)
    total_warnings = sum(p["logs"]["errors"]["warnings"] for p in profiles_data)

    snapshot = {
        "ts": time.time(), "ts_iso": _ts_to_iso(time.time()),
        "summary": {
            "profiles_total": len(profiles_data),
            "profiles_running": len(active),
            "active_agents": total_agents,
            "errors_1h": total_errors,
            "warnings_1h": total_warnings,
        },
        "profiles": profiles_data,
        "kanban": _get_kanban_summary(),
    }
    _check_alerts(snapshot)
    _save_metrics_batch({
        "profiles_running": len(active),
        "active_agents": total_agents,
        "errors_1h": total_errors,
        "warnings_1h": total_warnings,
    })
    with _snapshot_lock:
        _snapshot = snapshot
    return snapshot

def get_snapshot():
    with _snapshot_lock:
        return _snapshot.copy() if _snapshot else None

def collector_loop():
    time.sleep(2)
    try:
        collect_all()
    except Exception:
        pass
    while True:
        try:
            collect_all()
        except Exception:
            pass
        time.sleep(STATUS_POLL_SECONDS)

# --- Widget ----------------------------------------------------------------
def widget_data():
    snap = get_snapshot() or {}
    summary = snap.get("summary", {})

    def _fmt_tokens(n):
        n = n or 0
        if n >= 1_000_000:
            return f"{n/1_000_000:.1f}M"
        if n >= 1_000:
            return f"{n/1_000:.1f}k"
        return str(int(n))

    # Tokeny + koszty LĄCZNIE agregowane po wszystkich profilach (30 dni)
    total_tokens_in = 0
    total_tokens_out = 0
    total_cost = 0.0
    for profile in MONITORED_PROFILES:
        try:
            usage = _get_usage_stats(profile, 30)
            for d in usage.get("daily", []):
                total_tokens_in += d["tokens"].get("input") or 0
                total_tokens_out += d["tokens"].get("output") or 0
                total_cost += d["cost"].get("estimated_usd") or 0
        except Exception:
            pass
    total_tokens = total_tokens_in + total_tokens_out

    profiles_text = f"{summary.get('profiles_running', 0)}/{summary.get('profiles_total', 0)}"
    profiles_sub = "aktywne" if summary.get('profiles_running') == summary.get('profiles_total') else "niepełne"

    return {
        "type": "three-stats",
        "refresh": "5s",
        "link": "",
        "items": [
            {"icon": "user", "text": profiles_text, "subtext": "Profile online"},
            {"icon": "coin", "text": _fmt_tokens(total_tokens), "subtext": "Tokeny łącznie"},
            {"icon": "currency-dollar", "text": f"{total_cost:.2f}", "subtext": "Koszty łącznie (est.)"},
        ],
    }

# --- HTML frontend -----------------------------------------------------------
# Osadzony base64 — ten sam index.html co na hoście, ale z API_BASE='' (względne)
# Skrypt startowy w kontenerze podmieni API_BASE
HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9InBsIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+SGVybWVzIE1vbml0b3I8L3RpdGxlPgo8bGluayByZWw9InByZWNvbm5lY3QiIGhyZWY9Imh0dHBzOi8vZm9udHMuZ29vZ2xlYXBpcy5jb20iPgo8bGluayByZWw9InByZWNvbm5lY3QiIGhyZWY9Imh0dHBzOi8vZm9udHMuZ3N0YXRpYy5jb20iIGNyb3Nzb3JpZ2luPgo8bGluayBocmVmPSJodHRwczovL2ZvbnRzLmdvb2dsZWFwaXMuY29tL2NzczI/ZmFtaWx5PUludGVyOndnaHRANDAwOzUwMDs2MDA7NzAwJmZhbWlseT1KZXRCcmFpbnMrTW9ubzp3Z2h0QDQwMDs1MDA7NjAwOzcwMCZkaXNwbGF5PXN3YXAiIHJlbD0ic3R5bGVzaGVldCI+CjxsaW5rIGhyZWY9Imh0dHBzOi8vZm9udHMuZ29vZ2xlYXBpcy5jb20vY3NzMj9mYW1pbHk9U2hhcmUrVGVjaCtNb25vJmRpc3BsYXk9c3dhcCIgcmVsPSJzdHlsZXNoZWV0Ij4KPHNjcmlwdCBzcmM9Imh0dHBzOi8vY2RuLmpzZGVsaXZyLm5ldC9ucG0vZWNoYXJ0c0A1LjUuMS9kaXN0L2VjaGFydHMubWluLmpzIj48L3NjcmlwdD4KPHN0eWxlPgovKiA9PT09PSBERVNJR04gVE9LRU5TID09PT09ICovCjpyb290IHsKICAvKiBDb2xvcnMgKi8KICAtLXByaW1hcnk6ICM5ZWE4YTA7CiAgLS1zZWNvbmRhcnk6ICM4Yjk2OGU7CiAgLS1zdWNjZXNzOiAjOWZkMGEwOwogIC0td2FybmluZzogI2Q5Yjg0YTsKICAtLWNyaXRpY2FsOiAjZTA3YTVmOwogIC0taW5mbzogIzllYThhMDsKICAtLW5ldXRyYWw6ICM2MTZiNjQ7CiAgLS1iZ1Jvb3Q6ICMwNDFjMWM7CiAgLS1iZ1N1cmZhY2U6ICMwNjFmMWY7CiAgLS1iZ0NhcmQ6ICMwODIzMjI7CiAgLS1iZ0hvdmVyOiAjMGMyYTI5OwogIC0tYm9yZGVyOiAjMGUzMDJlOwogIC0tYm9yZGVyTGlnaHQ6ICMxNjNhMzc7CiAgLS10ZXh0UHJpbWFyeTogI2VmZTlkOTsKICAtLXRleHRTZWNvbmRhcnk6ICNiOGIyYTI7CiAgLS10ZXh0TXV0ZWQ6ICM3YTgxNzg7CiAgLS10ZXh0T25QcmltYXJ5OiAjMDQxYzFjOwoKICAvKiBTcGFjaW5nICovCiAgLS1zcGFjZS14czogNHB4OwogIC0tc3BhY2Utc206IDhweDsKICAtLXNwYWNlLW1kOiAxMnB4OwogIC0tc3BhY2UtbGc6IDE2cHg7CiAgLS1zcGFjZS14bDogMjRweDsKICAtLXNwYWNlLTJ4bDogMzJweDsKICAtLXNwYWNlLTN4bDogNDhweDsKCiAgLyogUmFkaXVzICovCiAgLS1yYWRpdXMtc206IDRweDsKICAtLXJhZGl1cy1tZDogOHB4OwogIC0tcmFkaXVzLWxnOiAxMnB4OwogIC0tcmFkaXVzLXhsOiAxNnB4OwogIC0tcmFkaXVzLWZ1bGw6IDk5OTlweDsKfQoKLyogPT09PT0gUkVTRVQgPT09PT0gKi8KKiwqOjpiZWZvcmUsKjo6YWZ0ZXJ7Ym94LXNpemluZzpib3JkZXItYm94O21hcmdpbjowO3BhZGRpbmc6MH0KaHRtbHtmb250LXNpemU6MTZweDstd2Via2l0LWZvbnQtc21vb3RoaW5nOmFudGlhbGlhc2VkfQpib2R5ewogIGZvbnQtZmFtaWx5OidJbnRlcicsc2Fucy1zZXJpZjsKICBiYWNrZ3JvdW5kOnZhcigtLWJnUm9vdCk7CiAgY29sb3I6dmFyKC0tdGV4dFByaW1hcnkpOwogIGxpbmUtaGVpZ2h0OjEuNTsKICBtaW4taGVpZ2h0OjEwMHZoOwp9CgovKiA9PT09PSBUWVBPR1JBUEhZID09PT09ICovCi5oZWFkaW5nLXhse2ZvbnQtZmFtaWx5OidJbnRlcicsc2Fucy1zZXJpZjtmb250LXNpemU6MS43NXJlbTtmb250LXdlaWdodDo3MDA7bGluZS1oZWlnaHQ6MS4yO2xldHRlci1zcGFjaW5nOi0wLjAyZW19Ci5oZWFkaW5nLWxne2ZvbnQtZmFtaWx5OidJbnRlcicsc2Fucy1zZXJpZjtmb250LXNpemU6MS4yNXJlbTtmb250LXdlaWdodDo2MDA7bGluZS1oZWlnaHQ6MS4zO2xldHRlci1zcGFjaW5nOi0wLjAxZW19Ci5oZWFkaW5nLW1ke2ZvbnQtZmFtaWx5OidJbnRlcicsc2Fucy1zZXJpZjtmb250LXNpemU6MXJlbTtmb250LXdlaWdodDo2MDA7bGluZS1oZWlnaHQ6MS40fQouYm9keS1tZHtmb250LWZhbWlseTonSW50ZXInLHNhbnMtc2VyaWY7Zm9udC1zaXplOjAuODc1cmVtO2ZvbnQtd2VpZ2h0OjQwMDtsaW5lLWhlaWdodDoxLjV9Ci5ib2R5LXNte2ZvbnQtZmFtaWx5OidJbnRlcicsc2Fucy1zZXJpZjtmb250LXNpemU6MC43NXJlbTtmb250LXdlaWdodDo0MDA7bGluZS1oZWlnaHQ6MS41fQoubGFiZWwtbWR7Zm9udC1mYW1pbHk6J0ludGVyJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZTowLjc1cmVtO2ZvbnQtd2VpZ2h0OjUwMDtsaW5lLWhlaWdodDoxLjQ7bGV0dGVyLXNwYWNpbmc6MC4wNWVtO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZX0KLmxhYmVsLWxne2ZvbnQtZmFtaWx5OidJbnRlcicsc2Fucy1zZXJpZjtmb250LXNpemU6MC44NzVyZW07Zm9udC13ZWlnaHQ6NjAwO2xpbmUtaGVpZ2h0OjEuNDtsZXR0ZXItc3BhY2luZzowLjAyZW19Ci5tZXRyaWMteGx7Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjIuMjVyZW07Zm9udC13ZWlnaHQ6NzAwO2xpbmUtaGVpZ2h0OjEuMTtsZXR0ZXItc3BhY2luZzotMC4wM2VtfQoubWV0cmljLWxne2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxLjVyZW07Zm9udC13ZWlnaHQ6NjAwO2xpbmUtaGVpZ2h0OjEuMjtsZXR0ZXItc3BhY2luZzotMC4wMmVtfQoubWV0cmljLW1ke2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxcmVtO2ZvbnQtd2VpZ2h0OjUwMDtsaW5lLWhlaWdodDoxLjN9Ci5tb25vLXNte2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZTowLjc1cmVtO2ZvbnQtd2VpZ2h0OjQwMDtsaW5lLWhlaWdodDoxLjZ9CgovKiA9PT09PSBMQVlPVVQgPT09PT0gKi8KLmNvbnRhaW5lcnttYXgtd2lkdGg6MTQwMHB4O21hcmdpbjowIGF1dG87cGFkZGluZzowIHZhcigtLXNwYWNlLXhsKX0KQG1lZGlhKG1heC13aWR0aDo3NjhweCl7LmNvbnRhaW5lcntwYWRkaW5nOjAgdmFyKC0tc3BhY2UtbWQpfX0KCi8qID09PT09IFRPUCBCQVIgPT09PT0gKi8KI3RvcGJhcnsKICBwb3NpdGlvbjpzdGlja3k7dG9wOjA7ei1pbmRleDoxMDA7CiAgYmFja2dyb3VuZDp2YXIoLS1iZ1N1cmZhY2UpOwogIGJvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgaGVpZ2h0OjU2cHg7Cn0KI3RvcGJhciAuY29udGFpbmVyewogIGRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47CiAgaGVpZ2h0OjEwMCU7Cn0KLnRvcGJhci1sZWZ0e2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOnZhcigtLXNwYWNlLW1kKX0KLnRvcGJhci1sb2dvewogIHdpZHRoOjEwcHg7aGVpZ2h0OjEwcHg7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtZnVsbCk7CiAgYmFja2dyb3VuZDp2YXIoLS1zdWNjZXNzKTsKICBhbmltYXRpb246cHVsc2UgMnMgaW5maW5pdGU7Cn0KLnRvcGJhci1yaWdodHtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDp2YXIoLS1zcGFjZS1sZyl9CiNjbG9ja3tmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MC44NzVyZW07Y29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSl9Ci5yZWZyZXNoLWluZGljYXRvcntkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDp2YXIoLS1zcGFjZS14cyk7Y29sb3I6dmFyKC0tdGV4dE11dGVkKX0KLnJlZnJlc2gtaW5kaWNhdG9yIC5kb3R7d2lkdGg6NnB4O2hlaWdodDo2cHg7Ym9yZGVyLXJhZGl1czo1MCU7YmFja2dyb3VuZDp2YXIoLS1wcmltYXJ5KX0KCi8qID09PT09IFJFRlJFU0ggUFJPR1JFU1MgQkFSICsgREFUQSBUSU1FU1RBTVAgPT09PT0gKi8KI3JlZnJlc2gtYmFyewogIGJhY2tncm91bmQ6dmFyKC0tYmdTdXJmYWNlKTsKICBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIHBhZGRpbmc6N3B4IDAgOXB4Owp9CiNyZWZyZXNoLWJhciAuY29udGFpbmVye2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjVweH0KLnJlZnJlc2gtcHJvZ3Jlc3N7CiAgcG9zaXRpb246cmVsYXRpdmU7aGVpZ2h0OjVweDtib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cy1mdWxsKTsKICBiYWNrZ3JvdW5kOnZhcigtLWJnQ2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO292ZXJmbG93OmhpZGRlbjsKfQoucmVmcmVzaC1wcm9ncmVzcyAuZmlsbHsKICBwb3NpdGlvbjphYnNvbHV0ZTt0b3A6MDtsZWZ0OjA7Ym90dG9tOjA7d2lkdGg6MCU7CiAgYmFja2dyb3VuZDp2YXIoLS1wcmltYXJ5KTt0cmFuc2l0aW9uOndpZHRoIDAuNHMgbGluZWFyOwp9Ci5yZWZyZXNoLXByb2dyZXNzIC5maWxsLndhcm57YmFja2dyb3VuZDp2YXIoLS13YXJuaW5nKX0KLnJlZnJlc2gtcHJvZ3Jlc3MgLmZpbGwuY3JpdHtiYWNrZ3JvdW5kOnZhcigtLWNyaXRpY2FsKX0KLnJlZnJlc2gtcHJvZ3Jlc3MtbGFiZWx7CiAgZGlzcGxheTpmbGV4O2p1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuO2dhcDp2YXIoLS1zcGFjZS1tZCk7CiAgZm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjAuNjVyZW07Y29sb3I6dmFyKC0tdGV4dE11dGVkKTsKfQoucmVmcmVzaC1wcm9ncmVzcy1sYWJlbCAucGN0e2NvbG9yOnZhcigtLXRleHRTZWNvbmRhcnkpfQoKLyogPT09PT0gTEFZT1VUIFNXSVRDSEVSID09PT09ICovCi5sYXlvdXQtc3dpdGNoZXJ7CiAgZGlzcGxheTpmbGV4O2dhcDoycHg7YmFja2dyb3VuZDp2YXIoLS1iZ0NhcmQpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTtib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cy1mdWxsKTsKICBwYWRkaW5nOjJweDsKfQoubGF5b3V0LXN3aXRjaGVyIGJ1dHRvbnsKICBiYWNrZ3JvdW5kOnRyYW5zcGFyZW50O2JvcmRlcjpub25lO2JvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLWZ1bGwpOwogIHBhZGRpbmc6NHB4IDEycHg7Y3Vyc29yOnBvaW50ZXI7CiAgZm9udC1mYW1pbHk6J0ludGVyJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZTowLjc1cmVtO2ZvbnQtd2VpZ2h0OjUwMDsKICBjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO3RyYW5zaXRpb246YWxsIDAuMnM7CiAgd2hpdGUtc3BhY2U6bm93cmFwOwp9Ci5sYXlvdXQtc3dpdGNoZXIgYnV0dG9uLmFjdGl2ZXsKICBiYWNrZ3JvdW5kOnZhcigtLXByaW1hcnkpO2NvbG9yOnZhcigtLXRleHRPblByaW1hcnkpOwp9Ci5sYXlvdXQtc3dpdGNoZXIgYnV0dG9uOmhvdmVyOm5vdCguYWN0aXZlKXtjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KX0KCi8qID09PT09IFNUQVRVUyBTVFJJUCA9PT09PSAqLwojc3RhdHVzLXN0cmlwewogIGJhY2tncm91bmQ6dmFyKC0tYmdTdXJmYWNlKTsKICBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwp9CiNzdGF0dXMtc3RyaXAgLmNvbnRhaW5lcnsKICBkaXNwbGF5OmZsZXg7Z2FwOnZhcigtLXNwYWNlLXNtKTtwYWRkaW5nOnZhcigtLXNwYWNlLXNtKSAwOwogIG92ZXJmbG93LXg6YXV0bzsKfQouc3RhdHVzLWNoaXB7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6dmFyKC0tc3BhY2UteHMpOwogIHBhZGRpbmc6NHB4IDEwcHg7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtZnVsbCk7CiAgYmFja2dyb3VuZDp2YXIoLS1iZ0NhcmQpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICB3aGl0ZS1zcGFjZTpub3dyYXA7Cn0KLnN0YXR1cy1jaGlwIC5kb3R7d2lkdGg6OHB4O2hlaWdodDo4cHg7Ym9yZGVyLXJhZGl1czo1MCU7ZmxleC1zaHJpbms6MH0KLnN0YXR1cy1jaGlwIC5kb3Qub25saW5le2JhY2tncm91bmQ6dmFyKC0tc3VjY2Vzcyl9Ci5zdGF0dXMtY2hpcCAuZG90Lm9mZmxpbmV7YmFja2dyb3VuZDp2YXIoLS1jcml0aWNhbCl9Ci5zdGF0dXMtY2hpcCAubmFtZXtmb250LXNpemU6MC43NXJlbTtmb250LXdlaWdodDo1MDA7Y29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSl9Ci5zdGF0dXMtY2hpcHtjdXJzb3I6cG9pbnRlcn0KLnN0YXR1cy1jaGlwLmFjdGl2ZXtib3JkZXItY29sb3I6dmFyKC0tcHJpbWFyeSk7YmFja2dyb3VuZDp2YXIoLS1iZ0hvdmVyKTtib3gtc2hhZG93OjAgMCAwIDFweCB2YXIoLS1wcmltYXJ5KX0KLnN0YXR1cy1jaGlwLmFjdGl2ZSAubmFtZXtjb2xvcjp2YXIoLS1wcmltYXJ5KX0KLnN0YXR1cy1jaGlwIC5wbGF0Zm9ybXtmb250LXNpemU6MC42NXJlbTtjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO21hcmdpbi1sZWZ0OjJweH0KCi8qIFNrZWxldG9uIGNoaXAgZm9yIGxvYWRpbmcgc3RhdGUgKi8KLnN0YXR1cy1jaGlwLnNrZWxldG9uLWNoaXB7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO29wYWNpdHk6MC42fQouc3RhdHVzLWNoaXAuc2tlbGV0b24tY2hpcCAuc2tlbGV0b257YmFja2dyb3VuZDp2YXIoLS1iZ0hvdmVyKX0KCi8qID09PT09IFBST0ZJTEUgQ0FSRFMgPT09PT0gKi8KLnByb2ZpbGUtY2FyZHMtc2VjdGlvbntwYWRkaW5nOnZhcigtLXNwYWNlLWxnKSAwfQoucHJvZmlsZS1jYXJkcy1ncmlkewogIGRpc3BsYXk6Z3JpZDsKICBncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KGF1dG8tZmlsbCxtaW5tYXgoMTcwcHgsMWZyKSk7CiAgZ2FwOnZhcigtLXNwYWNlLW1kKTsKfQpAbWVkaWEobWF4LXdpZHRoOjc2OHB4KXsucHJvZmlsZS1jYXJkcy1ncmlke2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoMiwxZnIpfX0KQG1lZGlhKG1heC13aWR0aDo0ODBweCl7LnByb2ZpbGUtY2FyZHMtZ3JpZHtncmlkLXRlbXBsYXRlLWNvbHVtbnM6MWZyfX0KCi5wcm9maWxlLWNhcmR7CiAgYmFja2dyb3VuZDp2YXIoLS1iZ0NhcmQpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cy1sZyk7CiAgcGFkZGluZzp2YXIoLS1zcGFjZS1sZyk7CiAgZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6dmFyKC0tc3BhY2UteHMpOwogIHRyYW5zaXRpb246Ym9yZGVyLWNvbG9yIDAuM3M7CiAgY3Vyc29yOmRlZmF1bHQ7Cn0KLnByb2ZpbGUtY2FyZDpob3Zlcntib3JkZXItY29sb3I6dmFyKC0tYm9yZGVyTGlnaHQpfQoucHJvZmlsZS1jYXJke2N1cnNvcjpwb2ludGVyfQoucHJvZmlsZS1jYXJkLmFjdGl2ZXtib3JkZXItY29sb3I6dmFyKC0tcHJpbWFyeSk7Ym94LXNoYWRvdzowIDAgMCAxcHggdmFyKC0tcHJpbWFyeSl9Ci5wcm9maWxlLWNhcmQuYWN0aXZlIC5wYy1uYW1le2NvbG9yOnZhcigtLXByaW1hcnkpfQoucHJvZmlsZS1jYXJkIC5wYy1oZWFkZXJ7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6dmFyKC0tc3BhY2Utc20pO21hcmdpbi1ib3R0b206dmFyKC0tc3BhY2Utc20pfQoucHJvZmlsZS1jYXJkIC5wYy1kb3R7d2lkdGg6MTBweDtoZWlnaHQ6MTBweDtib3JkZXItcmFkaXVzOjUwJTtmbGV4LXNocmluazowfQoucHJvZmlsZS1jYXJkIC5wYy1kb3Qub25saW5le2JhY2tncm91bmQ6dmFyKC0tc3VjY2Vzcyk7YW5pbWF0aW9uOnB1bHNlIDJzIGluZmluaXRlfQoucHJvZmlsZS1jYXJkIC5wYy1kb3Qub2ZmbGluZXtiYWNrZ3JvdW5kOnZhcigtLWNyaXRpY2FsKX0KLnByb2ZpbGUtY2FyZCAucGMtZG90LnN0YWxle2JhY2tncm91bmQ6dmFyKC0td2FybmluZyk7YW5pbWF0aW9uOnB1bHNlIDFzIGluZmluaXRlfQoucHJvZmlsZS1jYXJkIC5wYy1uYW1le2ZvbnQtd2VpZ2h0OjYwMDtmb250LXNpemU6MC45cmVtO2NvbG9yOnZhcigtLXRleHRQcmltYXJ5KTtvdmVyZmxvdzpoaWRkZW47dGV4dC1vdmVyZmxvdzplbGxpcHNpczt3aGl0ZS1zcGFjZTpub3dyYXB9Ci5wcm9maWxlLWNhcmQgLnBjLW1ldGF7ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6MnB4fQoucHJvZmlsZS1jYXJkIC5wYy1tZXRhLWl0ZW17Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjAuN3JlbTtjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KTt3aGl0ZS1zcGFjZTpub3dyYXB9Ci5wcm9maWxlLWNhcmQgLnBjLW1ldGEtaXRlbTo6YmVmb3Jle2NvbnRlbnQ6J+KWuCAnO2NvbG9yOnZhcigtLXByaW1hcnkpO21hcmdpbi1yaWdodDoycHh9Ci5wcm9maWxlLWNhcmQgLnBjLXBsYXRmb3Jtc3tkaXNwbGF5OmZsZXg7ZmxleC13cmFwOndyYXA7Z2FwOjNweDttYXJnaW4tdG9wOmF1dG87cGFkZGluZy10b3A6dmFyKC0tc3BhY2Utc20pO2JvcmRlci10b3A6MXB4IHNvbGlkIHZhcigtLWJvcmRlcil9Ci5wcm9maWxlLWNhcmQgLnBjLXBsYXQtY2hpcHtmb250LXNpemU6MC42cmVtO3BhZGRpbmc6MXB4IDVweDtiYWNrZ3JvdW5kOnZhcigtLWJnSG92ZXIpO2JvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLXNtKTtjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZX0KLnByb2ZpbGUtY2FyZCAucGMtcGxhdC1jaGlwLmNvbm5lY3RlZHtjb2xvcjp2YXIoLS1zdWNjZXNzKTtiYWNrZ3JvdW5kOnJnYmEoMzQsMTk3LDk0LDAuMDgpfQoucHJvZmlsZS1jYXJkIC5wYy1mb290ZXJ7Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjAuNnJlbTtjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO3BhZGRpbmctdG9wOnZhcigtLXNwYWNlLXhzKTtib3JkZXItdG9wOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpfQoucHJvZmlsZS1jYXJkLnNrZWxldG9uLWNhcmR7b3BhY2l0eTowLjY7cG9pbnRlci1ldmVudHM6bm9uZX0KLnByb2ZpbGUtY2FyZC5za2VsZXRvbi1jYXJkIC5za2VsZXRvbntiYWNrZ3JvdW5kOnZhcigtLWJnSG92ZXIpfQoKLyogPT09PT0gTUFJTiBDT05URU5UID09PT09ICovCiNtYWlue3BhZGRpbmc6dmFyKC0tc3BhY2UteGwpIDB9CgovKiBLUEkgR3JpZCAqLwoua3BpLWdyaWR7CiAgZGlzcGxheTpncmlkOwogIGdyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoNCwxZnIpOwogIGdhcDp2YXIoLS1zcGFjZS1sZyk7CiAgbWFyZ2luLWJvdHRvbTp2YXIoLS1zcGFjZS14bCk7Cn0KQG1lZGlhKG1heC13aWR0aDoxMjgwcHgpey5rcGktZ3JpZHtncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KDIsMWZyKX19CkBtZWRpYShtYXgtd2lkdGg6NzY4cHgpey5rcGktZ3JpZHtncmlkLXRlbXBsYXRlLWNvbHVtbnM6MWZyfX0KCi5tZXRyaWMtdGlsZXsKICBiYWNrZ3JvdW5kOnZhcigtLWJnQ2FyZCk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLWxnKTsKICBwYWRkaW5nOnZhcigtLXNwYWNlLWxnKTsKICBkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2dhcDp2YXIoLS1zcGFjZS1zbSk7CiAgdHJhbnNpdGlvbjpib3JkZXItY29sb3IgMC4zczsKfQoubWV0cmljLXRpbGU6aG92ZXJ7Ym9yZGVyLWNvbG9yOnZhcigtLWJvcmRlckxpZ2h0KX0KLm1ldHJpYy10aWxlLmNyaXRpY2Fse2JvcmRlci1sZWZ0OjNweCBzb2xpZCB2YXIoLS1jcml0aWNhbCl9Ci5tZXRyaWMtdGlsZS53YXJuaW5ne2JvcmRlci1sZWZ0OjNweCBzb2xpZCB2YXIoLS13YXJuaW5nKX0KLm1ldHJpYy10aWxlIC50aWxlLWxhYmVse2NvbG9yOnZhcigtLXRleHRTZWNvbmRhcnkpfQoubWV0cmljLXRpbGUgLnRpbGUtdmFsdWV7Y29sb3I6dmFyKC0tdGV4dFByaW1hcnkpfQoubWV0cmljLXRpbGUgLnRpbGUtc3Vie2NvbG9yOnZhcigtLXRleHRNdXRlZCl9CgovKiBDaGFydHMgUm93ICovCi5jaGFydHMtcm93ewogIGRpc3BsYXk6Z3JpZDsKICBncmlkLXRlbXBsYXRlLWNvbHVtbnM6MmZyIDFmcjsKICBnYXA6dmFyKC0tc3BhY2UtbGcpOwogIG1hcmdpbi1ib3R0b206dmFyKC0tc3BhY2UteGwpOwp9CkBtZWRpYShtYXgtd2lkdGg6NzY4cHgpey5jaGFydHMtcm93e2dyaWQtdGVtcGxhdGUtY29sdW1uczoxZnJ9fQoKLmNoYXJ0LWNhcmR7CiAgYmFja2dyb3VuZDp2YXIoLS1iZ0NhcmQpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cy1sZyk7CiAgcGFkZGluZzp2YXIoLS1zcGFjZS1sZyk7Cn0KLmNoYXJ0LWNhcmQgLmNoYXJ0LWhlYWRlcnttYXJnaW4tYm90dG9tOnZhcigtLXNwYWNlLW1kKX0KLmNoYXJ0LWNhcmQgLmNoYXJ0LWJvZHl7aGVpZ2h0OjMwMHB4fQoKLyogVG9wIG1vZGVsZSDigJQgdGFiZWxhICovCi5tb2RlbHMtdGFibGV7d2lkdGg6MTAwJTtib3JkZXItY29sbGFwc2U6Y29sbGFwc2U7Zm9udC1zaXplOjAuNzhyZW19Ci5tb2RlbHMtdGFibGUgdGh7CiAgdGV4dC1hbGlnbjpsZWZ0O3BhZGRpbmc6OHB4IDEycHg7Zm9udC1zaXplOjAuNjVyZW07dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlOwogIGxldHRlci1zcGFjaW5nOjAuMDVlbTtjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlckxpZ2h0KTsKICBmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTt3aGl0ZS1zcGFjZTpub3dyYXA7Cn0KLm1vZGVscy10YWJsZSB0ZHtwYWRkaW5nOjhweCAxMnB4O2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7dmVydGljYWwtYWxpZ246bWlkZGxlfQoubW9kZWxzLXRhYmxlIHRyOmxhc3QtY2hpbGQgdGR7Ym9yZGVyLWJvdHRvbTpub25lfQoubW9kZWxzLXRhYmxlIHRyOmhvdmVyIHRke2JhY2tncm91bmQ6dmFyKC0tYmdIb3Zlcil9Ci5tb2RlbHMtdGFibGUgLm0tcmFua3tjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlO3dpZHRoOjMwcHh9Ci5tb2RlbHMtdGFibGUgLm0tbmFtZXtjb2xvcjp2YXIoLS10ZXh0UHJpbWFyeSk7Zm9udC13ZWlnaHQ6NTAwfQoubW9kZWxzLXRhYmxlIC5tLXRva2VucywubW9kZWxzLXRhYmxlIC5tLWNvc3QsLm1vZGVscy10YWJsZSAubS1jYWxsc3tmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTtjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KTt3aGl0ZS1zcGFjZTpub3dyYXA7dGV4dC1hbGlnbjpyaWdodH0KLm1vZGVscy10YWJsZSAubS1jb3N0e2NvbG9yOnZhcigtLXRleHRQcmltYXJ5KTtmb250LXdlaWdodDo2MDB9Ci5tb2RlbHMtdGFibGUgLm0tY2FsbHN7Y29sb3I6dmFyKC0tdGV4dE11dGVkKX0KCi8qIERldGFpbCBSb3cgKi8KLmRldGFpbC1yb3d7CiAgZGlzcGxheTpncmlkOwogIGdyaWQtdGVtcGxhdGUtY29sdW1uczozZnIgMmZyOwogIGdhcDp2YXIoLS1zcGFjZS1sZyk7CiAgbWFyZ2luLWJvdHRvbTp2YXIoLS1zcGFjZS14bCk7Cn0KQG1lZGlhKG1heC13aWR0aDo3NjhweCl7LmRldGFpbC1yb3d7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOjFmcn19CgovKiBTZXNzaW9ucyAqLwouc2Vzc2lvbnMtY2FyZHsKICBiYWNrZ3JvdW5kOnZhcigtLWJnQ2FyZCk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLWxnKTsKfQouc2Vzc2lvbnMtY2FyZCAuY2FyZC1oZWFkZXJ7CiAgcGFkZGluZzp2YXIoLS1zcGFjZS1sZyk7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47YWxpZ24taXRlbXM6Y2VudGVyOwp9Ci5zZXNzaW9uLXJvd3sKICBkaXNwbGF5OmdyaWQ7CiAgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOmF1dG8gYXV0byAxZnIgYXV0byBhdXRvIGF1dG8gYXV0byBhdXRvOwogIGdhcDp2YXIoLS1zcGFjZS1tZCk7YWxpZ24taXRlbXM6Y2VudGVyOwogIHBhZGRpbmc6dmFyKC0tc3BhY2UtbWQpIHZhcigtLXNwYWNlLWxnKTsKICBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIHRyYW5zaXRpb246YmFja2dyb3VuZCAwLjE1czsKfQouc2Vzc2lvbi1yb3c6aG92ZXJ7YmFja2dyb3VuZDp2YXIoLS1iZ0hvdmVyKX0KLnNlc3Npb24tcm93Omxhc3QtY2hpbGR7Ym9yZGVyLWJvdHRvbTpub25lfQpAbWVkaWEobWF4LXdpZHRoOjc2OHB4KXsKICAuc2Vzc2lvbi1yb3d7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOmF1dG8gMWZyIGF1dG87Z2FwOnZhcigtLXNwYWNlLXNtKX0KICAuc2Vzc2lvbi1yb3cgLmhpZGUtbW9iaWxle2Rpc3BsYXk6bm9uZX0KfQoucHJvZmlsZS1jaGlwLW1pbml7CiAgZGlzcGxheTppbmxpbmUtYmxvY2s7cGFkZGluZzoxcHggNnB4OwogIGJhY2tncm91bmQ6dmFyKC0tYmdIb3Zlcik7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtZnVsbCk7CiAgZm9udC1zaXplOjAuNnJlbTtmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTsKICBjb2xvcjp2YXIoLS1wcmltYXJ5KTt3aGl0ZS1zcGFjZTpub3dyYXA7Cn0KCi8qIEdhdGV3YXkgKi8KLmdhdGV3YXktY2FyZHsKICBiYWNrZ3JvdW5kOnZhcigtLWJnQ2FyZCk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLWxnKTsKfQouZ2F0ZXdheS1jYXJkIC5jYXJkLWhlYWRlcnsKICBwYWRkaW5nOnZhcigtLXNwYWNlLWxnKTtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGRpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjthbGlnbi1pdGVtczpjZW50ZXI7Cn0KLmdhdGV3YXktcm93ewogIGRpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjthbGlnbi1pdGVtczpjZW50ZXI7CiAgcGFkZGluZzp2YXIoLS1zcGFjZS1tZCkgdmFyKC0tc3BhY2UtbGcpOwogIGJvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgdHJhbnNpdGlvbjpiYWNrZ3JvdW5kIDAuMTVzOwp9Ci5nYXRld2F5LXJvdzpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLWJnSG92ZXIpfQouZ2F0ZXdheS1yb3c6bGFzdC1jaGlsZHtib3JkZXItYm90dG9tOm5vbmV9Ci5nYXRld2F5LXJvdyAuZ3ctbGVmdHtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDp2YXIoLS1zcGFjZS1zbSk7bWluLXdpZHRoOjB9Ci5nYXRld2F5LXJvdyAuZ3ctbmFtZXtmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MC43NXJlbTtmb250LXdlaWdodDo1MDA7Y29sb3I6dmFyKC0tdGV4dFByaW1hcnkpO292ZXJmbG93OmhpZGRlbjt0ZXh0LW92ZXJmbG93OmVsbGlwc2lzO3doaXRlLXNwYWNlOm5vd3JhcH0KLmdhdGV3YXktcm93IC5ndy1zdWJ7Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjAuNjVyZW07Y29sb3I6dmFyKC0tdGV4dE11dGVkKTttYXJnaW4tbGVmdDoycHh9Ci5nYXRld2F5LXJvdyAuZ3ctc3RhdHVze2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOnZhcigtLXNwYWNlLXhzKTtmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MC43cmVtO2ZvbnQtd2VpZ2h0OjYwMH0KCi8qIFN0YXR1cyBrcm9wa2kgZ2F0ZXdheSDigJQgNCBzdGFueTogb2sgLyB3YXJuIC8gZXJyIC8gbm9uZSAqLwpAa2V5ZnJhbWVzIGd3UHVsc2V7MCUsMTAwJXtvcGFjaXR5OjE7Ym94LXNoYWRvdzowIDAgOHB4IGN1cnJlbnRDb2xvcn01MCV7b3BhY2l0eTowLjU1O2JveC1zaGFkb3c6MCAwIDNweCBjdXJyZW50Q29sb3J9fQpAa2V5ZnJhbWVzIGd3QmxpbmtTb2Z0ezAlLDEwMCV7b3BhY2l0eToxO2JveC1zaGFkb3c6MCAwIDZweCBjdXJyZW50Q29sb3J9NTAle29wYWNpdHk6MC42Mjtib3gtc2hhZG93OjAgMCAycHggY3VycmVudENvbG9yfX0KQGtleWZyYW1lcyBnd0JsaW5rRmFzdHswJSwxMDAle29wYWNpdHk6MTtib3gtc2hhZG93OjAgMCAxMHB4IGN1cnJlbnRDb2xvcn01MCV7b3BhY2l0eTowLjEyO2JveC1zaGFkb3c6bm9uZX19Ci5ndy1kb3R7d2lkdGg6OXB4O2hlaWdodDo5cHg7Ym9yZGVyLXJhZGl1czo1MCU7ZmxleC1zaHJpbms6MDttYXJnaW4tdG9wOjFweH0KLmd3LWRvdC5va3tiYWNrZ3JvdW5kOnZhcigtLXN1Y2Nlc3MpO2NvbG9yOnZhcigtLXN1Y2Nlc3MpO2FuaW1hdGlvbjpnd1B1bHNlIDJzIGVhc2UtaW4tb3V0IGluZmluaXRlfQouZ3ctZG90Lndhcm57YmFja2dyb3VuZDojZWFiMzA4O2NvbG9yOiNlYWIzMDg7YW5pbWF0aW9uOmd3QmxpbmtTb2Z0IDJzIGVhc2UtaW4tb3V0IGluZmluaXRlfQouZ3ctZG90LmVycntiYWNrZ3JvdW5kOnZhcigtLWNyaXRpY2FsKTtjb2xvcjp2YXIoLS1jcml0aWNhbCk7YW5pbWF0aW9uOmd3QmxpbmtGYXN0IDAuNXMgc3RlcHMoMSkgaW5maW5pdGV9Ci5ndy1kb3Qubm9uZXtiYWNrZ3JvdW5kOnZhcigtLXRleHRNdXRlZCk7b3BhY2l0eTowLjQ1O2FuaW1hdGlvbjpub25lfQouZ2F0ZXdheS1yb3cgLmd3LWluZm97ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6MnB4O21pbi13aWR0aDowfQouZ2F0ZXdheS1yb3cgLmd3LWFnZW50c3tmb250LXNpemU6MC42MnJlbTtjb2xvcjp2YXIoLS1wcmltYXJ5KTttYXJnaW4tbGVmdDo2cHg7Zm9udC13ZWlnaHQ6NTAwfQouZ2F0ZXdheS1yb3cgLmd3LW1ldGF7Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjAuNjJyZW07Y29sb3I6dmFyKC0tdGV4dE11dGVkKTtkaXNwbGF5OmZsZXg7ZmxleC13cmFwOndyYXA7Z2FwOjhweDttYXJnaW4tdG9wOjJweH0KLmdhdGV3YXktcm93IC5ndy1tZXRhIC5mbGFne2NvbG9yOiNlYWIzMDg7Zm9udC13ZWlnaHQ6NjAwfQouZ2F0ZXdheS1yb3cgLmd3LW1ldGEgLmZsYWctcmVzdGFydHtjb2xvcjojZjU5ZTBiO2ZvbnQtd2VpZ2h0OjcwMH0KLmdhdGV3YXktcm93IC5ndy1tZXRhIC5mbGFnLWV4aXR7Y29sb3I6dmFyKC0tY3JpdGljYWwpfQouZ2F0ZXdheS1yb3cgLmd3LW1ldGEgLmJhZHtjb2xvcjp2YXIoLS1jcml0aWNhbCl9Ci5nYXRld2F5LXJvdyAuZ3ctbWV0YSAub2t2e2NvbG9yOnZhcigtLXN1Y2Nlc3MpfQouZ3ctZXhwYW5ke2JhY2tncm91bmQ6dmFyKC0tYmdIb3Zlcik7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXJMaWdodCk7Y29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSk7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtZnVsbCk7Zm9udC1zaXplOjAuNjJyZW07Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7cGFkZGluZzoycHggOHB4O2N1cnNvcjpwb2ludGVyO3doaXRlLXNwYWNlOm5vd3JhcH0KLmd3LWV4cGFuZDpob3Zlcntjb2xvcjp2YXIoLS10ZXh0UHJpbWFyeSk7Ym9yZGVyLWNvbG9yOnZhcigtLXByaW1hcnkpfQouZ3ctcGxhdGZvcm1ze2Rpc3BsYXk6bm9uZTtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC4xNSk7cGFkZGluZzo0cHggdmFyKC0tc3BhY2UtbGcpIDhweDtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpfQouZ2F0ZXdheS1yb3cgfiAuZ3ctcGxhdGZvcm1zLm9wZW57ZGlzcGxheTpibG9ja30KLmd3LXBsYXRmb3JtLXJvd3tkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47YWxpZ24taXRlbXM6Y2VudGVyO3BhZGRpbmc6M3B4IDA7Ym9yZGVyLWJvdHRvbToxcHggZGFzaGVkIHZhcigtLWJvcmRlcik7Zm9udC1zaXplOjAuNjJyZW07Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2V9Ci5ndy1wbGF0Zm9ybS1yb3c6bGFzdC1jaGlsZHtib3JkZXItYm90dG9tOm5vbmV9Ci5ndy1wbGF0Zm9ybS1yb3cgLnBsLXN0YXRle2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjZweH0KLmd3LXBsLWRvdHt3aWR0aDo2cHg7aGVpZ2h0OjZweDtib3JkZXItcmFkaXVzOjUwJTtmbGV4LXNocmluazowfQouZ3ctcGwtZG90LmNvbm5lY3RlZHtiYWNrZ3JvdW5kOnZhcigtLXN1Y2Nlc3MpfQouZ3ctcGwtZG90LmRpc2Nvbm5lY3RlZHtiYWNrZ3JvdW5kOnZhcigtLWNyaXRpY2FsKX0KLmd3LXBsLWRvdC5zdGFydGluZ3tiYWNrZ3JvdW5kOiNlYWIzMDh9Ci5ndy1wbC1kb3QudW5rbm93bntiYWNrZ3JvdW5kOnZhcigtLXRleHRNdXRlZCl9Ci5ndy1wbGF0Zm9ybS1yb3cgLnBsLWVycntjb2xvcjp2YXIoLS1jcml0aWNhbCk7Zm9udC1zaXplOjAuNThyZW07bWF4LXdpZHRoOjE4MHB4O292ZXJmbG93OmhpZGRlbjt0ZXh0LW92ZXJmbG93OmVsbGlwc2lzO3doaXRlLXNwYWNlOm5vd3JhcH0KCi8qIEZvb3RlciAqLwojZm9vdGVyewogIGJhY2tncm91bmQ6dmFyKC0tYmdTdXJmYWNlKTsKICBib3JkZXItdG9wOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIHBhZGRpbmc6dmFyKC0tc3BhY2UtbGcpIDA7Cn0KLmZvb3Rlci1jYXJkc3tkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCgzLDFmcik7Z2FwOnZhcigtLXNwYWNlLWxnKX0KQG1lZGlhKG1heC13aWR0aDo3NjhweCl7LmZvb3Rlci1jYXJkc3tncmlkLXRlbXBsYXRlLWNvbHVtbnM6MWZyfX0KLmZvb3Rlci1jYXJke2JhY2tncm91bmQ6dmFyKC0tYmdDYXJkKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtbGcpO3BhZGRpbmc6dmFyKC0tc3BhY2UtbGcpfQouZm9vdGVyLWNhcmQgLmZjLWhlYWRlcnttYXJnaW4tYm90dG9tOnZhcigtLXNwYWNlLXNtKX0KLmtleS1jaGlwewogIGRpc3BsYXk6aW5saW5lLWJsb2NrO3BhZGRpbmc6MnB4IDhweDttYXJnaW46MnB4OwogIGJhY2tncm91bmQ6dmFyKC0tYmdIb3Zlcik7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtc20pOwogIGZvbnQtc2l6ZTowLjdyZW07Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7CiAgY29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSk7Cn0KLmJhZGdlewogIGRpc3BsYXk6aW5saW5lLWJsb2NrO3BhZGRpbmc6MnB4IDhweDtib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cy1mdWxsKTsKICBmb250LXNpemU6MC43cmVtO2ZvbnQtd2VpZ2h0OjUwMDsKfQouYmFkZ2Uub2t7YmFja2dyb3VuZDojMDUyRTE2O2NvbG9yOnZhcigtLXN1Y2Nlc3MpfQouYmFkZ2Uud2FybntiYWNrZ3JvdW5kOiM0MjIwMDY7Y29sb3I6dmFyKC0td2FybmluZyl9Ci5iYWRnZS5lcnJ7YmFja2dyb3VuZDojMkUwODE1O2NvbG9yOnZhcigtLWNyaXRpY2FsKX0KCi8qID09PT09IFNUQVRFUyA9PT09PSAqLwouc3RhdGUtbXNnewogIGRpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7CiAgcGFkZGluZzp2YXIoLS1zcGFjZS0zeGwpO3RleHQtYWxpZ246Y2VudGVyO2dhcDp2YXIoLS1zcGFjZS1tZCk7CiAgbWluLWhlaWdodDoyMDBweDsKfQouc3RhdGUtbXNnIC5pY29ue2ZvbnQtc2l6ZToyLjVyZW19Ci5zdGF0ZS1tc2cgLnRpdGxle2NvbG9yOnZhcigtLXRleHRQcmltYXJ5KX0KLnN0YXRlLW1zZyAuZGVzY3tjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KX0KCi8qIFNrZWxldG9uIGxvYWRpbmcgKi8KQGtleWZyYW1lcyBzaGltbWVyezAle29wYWNpdHk6MC4zfTUwJXtvcGFjaXR5OjAuNn0xMDAle29wYWNpdHk6MC4zfX0KLnNrZWxldG9uewogIGJhY2tncm91bmQ6dmFyKC0tYmdIb3Zlcik7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtbWQpOwogIGFuaW1hdGlvbjpzaGltbWVyIDEuNXMgaW5maW5pdGU7Cn0KLnNrZWxldG9uLXRleHR7aGVpZ2h0OjFyZW07d2lkdGg6NjAlO21hcmdpbi1ib3R0b206dmFyKC0tc3BhY2Utc20pfQouc2tlbGV0b24tdmFsdWV7aGVpZ2h0OjIuMjVyZW07d2lkdGg6NDAlfQoKLyogUHVsc2UgYW5pbWF0aW9uIGZvciBzdGF0dXMgZG90cyAqLwpAa2V5ZnJhbWVzIHB1bHNlewogIDAlLDEwMCV7b3BhY2l0eToxfQogIDUwJXtvcGFjaXR5OjAuNH0KfQoKLyogPT09PT0gUElQLUJPWSBUSEVNRSAoVkFVTFQtVEVDIGluc3BpcmVkKSA9PT09PSAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXXsKICAtLXByaW1hcnk6ICMxNEZGMTc7CiAgLS1zZWNvbmRhcnk6ICMwRUJEMEY7CiAgLS1zdWNjZXNzOiAjMTRGRjE3OwogIC0td2FybmluZzogI0M4RkYwMDsKICAtLWNyaXRpY2FsOiAjRkYzQjNCOwogIC0taW5mbzogIzE0RkYxNzsKICAtLW5ldXRyYWw6ICMyQTRBMjA7CiAgLS1iZ1Jvb3Q6ICMwNTA4MDM7CiAgLS1iZ1N1cmZhY2U6ICMwODBDMDU7CiAgLS1iZ0NhcmQ6ICMwQTEyMDc7CiAgLS1iZ0hvdmVyOiAjMEYxRDBBOwogIC0tYm9yZGVyOiAjMUE1QTEyOwogIC0tYm9yZGVyTGlnaHQ6ICMyMjhBMTg7CiAgLS10ZXh0UHJpbWFyeTogIzE0RkYxNzsKICAtLXRleHRTZWNvbmRhcnk6ICMwRUJEMEY7CiAgLS10ZXh0TXV0ZWQ6ICMyQTdBMjA7CiAgLS10ZXh0T25QcmltYXJ5OiAjMDUwODAzOwogIGZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsJ0NvdXJpZXIgTmV3Jyxtb25vc3BhY2U7Cn0KCi8qID09PT09IFBJUC1CT1k6IEdsb2JhbCB0ZXh0IGdsb3cgPT09PT0gKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmhlYWRpbmcteGwsCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5oZWFkaW5nLWxnLApib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuaGVhZGluZy1tZCwKYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmJvZHktbWQsCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5ib2R5LXNtLApib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAubGFiZWwtbWQsCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5sYWJlbC1sZywKYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLm1vbm8tc217CiAgZm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJywnQ291cmllciBOZXcnLG1vbm9zcGFjZTsKICB0ZXh0LXNoYWRvdzowIDAgNHB4IHJnYmEoMjAsMjU1LDIzLDAuNCksIDAgMCAxMnB4IHJnYmEoMjAsMjU1LDIzLDAuMTUpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tZXRyaWMteGwsCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tZXRyaWMtbGcsCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tZXRyaWMtbWR7CiAgdGV4dC1zaGFkb3c6MCAwIDhweCByZ2JhKDIwLDI1NSwyMywwLjUpLCAwIDAgMjBweCByZ2JhKDIwLDI1NSwyMywwLjIpOwp9CgovKiA9PT09PSBQSVAtQk9ZOiBUaGljayBDUlQgYmV6ZWwgZnJhbWUgPT09PT0gKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il17CiAgYm9yZGVyOjEwcHggc29saWQgIzFBM0ExMjsKICBib3JkZXItaW1hZ2U6bGluZWFyLWdyYWRpZW50KDEzNWRlZywjMEQyMDA4LCMxQTNBMTIgMzAlLCMyQTVBMjAgNTAlLCMxQTNBMTIgNzAlLCMwRDIwMDgpIDE7CiAgYm94LXNoYWRvdzppbnNldCAwIDAgODBweCByZ2JhKDAsMCwwLDAuNyk7CiAgbWluLWhlaWdodDoxMDB2aDsKfQpAbWVkaWEobWF4LXdpZHRoOjc2OHB4KXsKICBib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXXtib3JkZXItd2lkdGg6NnB4fQp9CgovKiA9PT09PSBQSVAtQk9ZOiBDUlQgdmlnbmV0dGUgb3ZlcmxheSA9PT09PSAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXTo6YmVmb3JlewogIGNvbnRlbnQ6Jyc7cG9zaXRpb246Zml4ZWQ7aW5zZXQ6MDtwb2ludGVyLWV2ZW50czpub25lO3otaW5kZXg6OTk5NzsKICBiYWNrZ3JvdW5kOnJhZGlhbC1ncmFkaWVudChlbGxpcHNlIGF0IDUwJSA1MCUsdHJhbnNwYXJlbnQgNTAlLHJnYmEoMCwwLDAsMC41KSAxMDAlKTsKfQoKLyogPT09PT0gUElQLUJPWTogQ1JUIHNjYW5saW5lcyA9PT09PSAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXTo6YWZ0ZXJ7CiAgY29udGVudDonJztwb3NpdGlvbjpmaXhlZDt0b3A6MDtsZWZ0OjA7cmlnaHQ6MDtib3R0b206MDsKICBiYWNrZ3JvdW5kOnJlcGVhdGluZy1saW5lYXItZ3JhZGllbnQoMGRlZywKICAgIHJnYmEoMjAsMjU1LDIzLDAuMDE1KSAwcHgsCiAgICByZ2JhKDIwLDI1NSwyMywwLjAxNSkgMXB4LAogICAgdHJhbnNwYXJlbnQgMXB4LAogICAgdHJhbnNwYXJlbnQgM3B4KTsKICBwb2ludGVyLWV2ZW50czpub25lO3otaW5kZXg6OTk5ODsKICBhbmltYXRpb246Y3JmRmxpY2tlciA2cyBpbmZpbml0ZTsKfQpAa2V5ZnJhbWVzIGNyZkZsaWNrZXJ7CiAgMCUsMTAwJXtvcGFjaXR5OjF9CiAgOTEle29wYWNpdHk6MX0KICA5MiV7b3BhY2l0eTowLjkyfQogIDkzJXtvcGFjaXR5OjAuNzV9CiAgOTQle29wYWNpdHk6MC45OH0KICA5NiV7b3BhY2l0eTowLjg4fQogIDk3JXtvcGFjaXR5OjF9Cn0KCi8qID09PT09IFBJUC1CT1k6IENvbXBvbmVudCBvdmVycmlkZXMgPT09PT0gKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gI3RvcGJhcnsKICBiYWNrZ3JvdW5kOnJnYmEoMTAsMTgsNywwLjk1KTsKICBib3JkZXItYm90dG9tOjJweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJveC1zaGFkb3c6MCAycHggMTJweCByZ2JhKDIwLDI1NSwyMywwLjA4KTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAjc3RhdHVzLXN0cmlwewogIGJhY2tncm91bmQ6cmdiYSg4LDEyLDUsMC45NSk7CiAgYm9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAubGF5b3V0LXN3aXRjaGVyewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4wNik7CiAgYm9yZGVyLWNvbG9yOnZhcigtLWJvcmRlcik7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmxheW91dC1zd2l0Y2hlciBidXR0b24uYWN0aXZlewogIGJhY2tncm91bmQ6dmFyKC0tcHJpbWFyeSk7CiAgY29sb3I6IzA1MDgwMzsKICB0ZXh0LXNoYWRvdzpub25lOwogIGJveC1zaGFkb3c6MCAwIDEycHggcmdiYSgyMCwyNTUsMjMsMC41KTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAubGF5b3V0LXN3aXRjaGVyIGJ1dHRvbjpob3Zlcjpub3QoLmFjdGl2ZSl7CiAgY29sb3I6dmFyKC0tcHJpbWFyeSk7CiAgdGV4dC1zaGFkb3c6MCAwIDZweCB2YXIoLS1wcmltYXJ5KTsKfQoKLyogS1BJIGNhcmRzICovCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tZXRyaWMtdGlsZXsKICBiYWNrZ3JvdW5kOnJnYmEoMTAsMTgsNywwLjg1KTsKICBib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgYm94LXNoYWRvdzppbnNldCAwIDAgMTVweCByZ2JhKDIwLDI1NSwyMywwLjAzKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAubWV0cmljLXRpbGU6aG92ZXJ7CiAgYm9yZGVyLWNvbG9yOnZhcigtLXByaW1hcnkpOwogIGJveC1zaGFkb3c6aW5zZXQgMCAwIDIwcHggcmdiYSgyMCwyNTUsMjMsMC4wNiksIDAgMCAxMnB4IHJnYmEoMjAsMjU1LDIzLDAuMSk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLm1ldHJpYy10aWxlLmNyaXRpY2Fse2JvcmRlci1sZWZ0OjNweCBzb2xpZCB2YXIoLS1jcml0aWNhbCl9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tZXRyaWMtdGlsZS53YXJuaW5ne2JvcmRlci1sZWZ0OjNweCBzb2xpZCAjQzhGRjAwfQoKLyogQ2hhcnQgY2FyZHMgKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmNoYXJ0LWNhcmR7CiAgYmFja2dyb3VuZDpyZ2JhKDEwLDE4LDcsMC44NSk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5zZXNzaW9ucy1jYXJkLApib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuZ2F0ZXdheS1jYXJkewogIGJhY2tncm91bmQ6cmdiYSgxMCwxOCw3LDAuODUpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuc2Vzc2lvbi1yb3c6aG92ZXJ7YmFja2dyb3VuZDp2YXIoLS1iZ0hvdmVyKX0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnNlc3Npb24tcm93e2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHJnYmEoMjYsOTAsMTgsMC40KX0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmdhdGV3YXktcm93e2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHJnYmEoMjYsOTAsMTgsMC40KX0KCi8qIEZvb3RlciAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAjZm9vdGVyewogIGJhY2tncm91bmQ6cmdiYSg4LDEyLDUsMC45NSk7CiAgYm9yZGVyLXRvcDoycHggc29saWQgdmFyKC0tYm9yZGVyKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuZm9vdGVyLWNhcmR7CiAgYmFja2dyb3VuZDpyZ2JhKDEwLDE4LDcsMC44NSk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwp9CgovKiBCYWRnZXMgKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmJhZGdlLm9re2JhY2tncm91bmQ6IzBBMkUwNjtjb2xvcjp2YXIoLS1zdWNjZXNzKTt0ZXh0LXNoYWRvdzowIDAgNnB4IHJnYmEoMjAsMjU1LDIzLDAuNSl9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5iYWRnZS53YXJue2JhY2tncm91bmQ6IzJFMjAwMDtjb2xvcjojQzhGRjAwO3RleHQtc2hhZG93OjAgMCA2cHggcmdiYSgyMDAsMjU1LDAsMC41KX0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmJhZGdlLmVycntiYWNrZ3JvdW5kOiMyRTA4MTU7Y29sb3I6dmFyKC0tY3JpdGljYWwpO3RleHQtc2hhZG93OjAgMCA2cHggcmdiYSgyNTUsNTksNTksMC41KX0KCi8qIFN0YXR1cyBjaGlwcyAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuc3RhdHVzLWNoaXB7CiAgYmFja2dyb3VuZDpyZ2JhKDEwLDE4LDcsMC44NSk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5zdGF0dXMtY2hpcCAuZG90Lm9ubGluZXsKICBiYWNrZ3JvdW5kOnZhcigtLXN1Y2Nlc3MpOwogIGJveC1zaGFkb3c6MCAwIDEwcHggdmFyKC0tc3VjY2VzcyksIDAgMCAyMHB4IHJnYmEoMjAsMjU1LDIzLDAuNCk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnN0YXR1cy1jaGlwIC5kb3Qub2ZmbGluZXsKICBiYWNrZ3JvdW5kOnZhcigtLWNyaXRpY2FsKTsKICBib3gtc2hhZG93OjAgMCA2cHggdmFyKC0tY3JpdGljYWwpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5zdGF0dXMtY2hpcC5za2VsZXRvbi1jaGlwe29wYWNpdHk6MC41fQoKLyogPT09PT0gUElQLUJPWTogUHJvZmlsZSBDYXJkcyA9PT09PSAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAucHJvZmlsZS1jYXJkewogIGJhY2tncm91bmQ6cmdiYSgxMCwxOCw3LDAuODUpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBib3JkZXItcmFkaXVzOjJweDsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAucHJvZmlsZS1jYXJkOmhvdmVyewogIGJvcmRlci1jb2xvcjp2YXIoLS1wcmltYXJ5KTsKICBib3gtc2hhZG93Omluc2V0IDAgMCAyMHB4IHJnYmEoMjAsMjU1LDIzLDAuMDYpLDAgMCAxMnB4IHJnYmEoMjAsMjU1LDIzLDAuMSk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2FyZCAucGMtaGVhZGVyewogIGJvcmRlci1ib3R0b206MXB4IHNvbGlkIHJnYmEoMjAsMjU1LDIzLDAuMTUpOwogIHBhZGRpbmctYm90dG9tOnZhcigtLXNwYWNlLXNtKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAucHJvZmlsZS1jYXJkIC5wYy1kb3Qub25saW5lewogIGJveC1zaGFkb3c6MCAwIDEwcHggdmFyKC0tc3VjY2VzcyksMCAwIDIwcHggcmdiYSgyMCwyNTUsMjMsMC40KTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAucHJvZmlsZS1jYXJkIC5wYy1kb3Qub2ZmbGluZXsKICBib3gtc2hhZG93OjAgMCA2cHggdmFyKC0tY3JpdGljYWwpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5wcm9maWxlLWNhcmQgLnBjLWRvdC5zdGFsZXsKICBib3gtc2hhZG93OjAgMCA2cHggdmFyKC0td2FybmluZyk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2FyZCAucGMtbmFtZXsKICB0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7CiAgZm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7CiAgdGV4dC1zaGFkb3c6MCAwIDRweCByZ2JhKDIwLDI1NSwyMywwLjQpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5wcm9maWxlLWNhcmQgLnBjLW1ldGEtaXRlbXsKICBmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTsKICB0ZXh0LXNoYWRvdzowIDAgNHB4IHJnYmEoMjAsMjU1LDIzLDAuMTUpOwogIHRleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAucHJvZmlsZS1jYXJkIC5wYy1tZXRhLWl0ZW06OmJlZm9yZXtjb250ZW50Oic+ICd9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5wcm9maWxlLWNhcmQgLnBjLXBsYXRmb3Jtc3tib3JkZXItdG9wOjFweCBzb2xpZCByZ2JhKDIwLDI1NSwyMywwLjEyKX0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2FyZCAucGMtcGxhdC1jaGlwewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4wNik7CiAgYm9yZGVyOjFweCBzb2xpZCByZ2JhKDIwLDI1NSwyMywwLjE1KTsKICBjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KTsKICB0ZXh0LXNoYWRvdzowIDAgM3B4IHJnYmEoMjAsMjU1LDIzLDAuMik7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2FyZCAucGMtcGxhdC1jaGlwLmNvbm5lY3RlZHsKICBjb2xvcjp2YXIoLS1zdWNjZXNzKTsKICB0ZXh0LXNoYWRvdzowIDAgNnB4IHJnYmEoMjAsMjU1LDIzLDAuNCk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2FyZCAucGMtZm9vdGVyewogIGJvcmRlci10b3A6MXB4IHNvbGlkIHJnYmEoMjAsMjU1LDIzLDAuMTIpOwogIHRleHQtc2hhZG93OjAgMCAzcHggcmdiYSgyMCwyNTUsMjMsMC4xNSk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2FyZCAucGMtc3RhdHVzLXByZWZpeHsKICBmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTsKICBmb250LXNpemU6MC42NXJlbTsKICBmb250LXdlaWdodDo3MDA7CiAgbWFyZ2luLXJpZ2h0OnZhcigtLXNwYWNlLXhzKTsKfQoKLyogVG9wYmFyIGVsZW1lbnRzICovCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC50b3BiYXItbG9nb3sKICBib3gtc2hhZG93OjAgMCAxMnB4IHZhcigtLXN1Y2Nlc3MpLCAwIDAgMjRweCByZ2JhKDIwLDI1NSwyMywwLjQpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5yZWZyZXNoLWluZGljYXRvciAuZG90ewogIGJveC1zaGFkb3c6MCAwIDhweCB2YXIoLS1wcmltYXJ5KTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAjY2xvY2t7CiAgdGV4dC1zaGFkb3c6MCAwIDZweCByZ2JhKDIwLDI1NSwyMywwLjQpOwp9CgovKiBCdXR0b25zICovCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5jdHJsLWJ0bnsKICBiYWNrZ3JvdW5kOnJnYmEoMjAsMjU1LDIzLDAuMTUpOwogIGNvbG9yOnZhcigtLXByaW1hcnkpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICB0ZXh0LXNoYWRvdzowIDAgNnB4IHJnYmEoMjAsMjU1LDIzLDAuMyk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmN0cmwtYnRuOmhvdmVyewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4yNSk7CiAgYm94LXNoYWRvdzowIDAgMTVweCByZ2JhKDIwLDI1NSwyMywwLjMpOwogIGNvbG9yOiMyMEZGMjQ7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmN0cmwtc2VsZWN0ewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4wOCk7CiAgY29sb3I6dmFyKC0tcHJpbWFyeSk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIHRleHQtc2hhZG93OjAgMCA2cHggcmdiYSgyMCwyNTUsMjMsMC4zKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuY3RybC1idG4uYWN0aXZle2JhY2tncm91bmQ6dmFyKC0tcHJpbWFyeSk7Y29sb3I6IzAzMTQwMztib3JkZXItY29sb3I6dmFyKC0tcHJpbWFyeSl9CgovKiBHYXRld2F5IHJvd3MgKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmdhdGV3YXktcm93e2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHJnYmEoMjYsOTAsMTgsMC4zKX0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmdhdGV3YXktcm93IC5ndy1uYW1le3RleHQtc2hhZG93OjAgMCA0cHggcmdiYSgyMCwyNTUsMjMsMC4zKX0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmd3LWRvdC51cHtib3gtc2hhZG93OjAgMCAwIHJnYmEoMjAsMjU1LDIzLDApfQoKLyogTW9kZWxzIHRhYmxlICovCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tb2RlbHMtdGFibGUgdGh7Y29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSl9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tb2RlbHMtdGFibGUgdGR7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgcmdiYSgyNiw5MCwxOCwwLjMpfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAubW9kZWxzLXRhYmxlIHRyOmhvdmVyIHRke2JhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4wNil9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tb2RlbHMtdGFibGUgLm0tbmFtZXt0ZXh0LXNoYWRvdzowIDAgNHB4IHJnYmEoMjAsMjU1LDIzLDAuMyl9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tLWNvc3R7dGV4dC1zaGFkb3c6MCAwIDRweCByZ2JhKDIwLDI1NSwyMywwLjMpfQoKLyogUHJvZmlsZSBjaGlwIG1pbmkgKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2hpcC1taW5pewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4wOCk7CiAgYm9yZGVyOjFweCBzb2xpZCByZ2JhKDIwLDI1NSwyMywwLjIpOwogIGNvbG9yOnZhcigtLXByaW1hcnkpOwogIHRleHQtc2hhZG93OjAgMCA0cHggcmdiYSgyMCwyNTUsMjMsMC4zKTsKfQoKLyogS2V5IGNoaXAgKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmtleS1jaGlwewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4wNSk7CiAgYm9yZGVyOjFweCBzb2xpZCByZ2JhKDIwLDI1NSwyMywwLjE1KTsKICBjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KTsKfQoKLyogVG9hc3QgKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnRvYXN0ewogIGJhY2tncm91bmQ6cmdiYSgxMCwxOCw3LDAuOTUpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBib3gtc2hhZG93OjAgMCAyMHB4IHJnYmEoMjAsMjU1LDIzLDAuMSk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnRvYXN0LmNyaXRpY2FsewogIGJhY2tncm91bmQ6cmdiYSgzMCw1LDUsMC45NSk7CiAgYm9yZGVyLWxlZnQ6M3B4IHNvbGlkIHZhcigtLWNyaXRpY2FsKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAudG9hc3Qud2FybmluZ3sKICBib3JkZXItbGVmdDozcHggc29saWQgI0M4RkYwMDsKfQoKLyogSGVhZGVyIGJsaW5raW5nIGN1cnNvciAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAjdG9wYmFyIC5oZWFkaW5nLW1kOjphZnRlcnsKICBjb250ZW50OidcMjU4Qyc7CiAgZGlzcGxheTppbmxpbmUtYmxvY2s7CiAgbWFyZ2luLWxlZnQ6NnB4OwogIGNvbG9yOnZhcigtLXByaW1hcnkpOwogIHRleHQtc2hhZG93OjAgMCA4cHggdmFyKC0tcHJpbWFyeSk7CiAgYW5pbWF0aW9uOnBpcEJsaW5rIDEuMXMgc3RlcHMoMSkgaW5maW5pdGU7CiAgdmVydGljYWwtYWxpZ246LTFweDsKfQpAa2V5ZnJhbWVzIHBpcEJsaW5rezUwJXtvcGFjaXR5OjB9fQoKLyogU2tlbGV0b24gKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnNrZWxldG9uewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4xKTsKfQoKLyogQ29udHJvbCBidXR0b25zIChyZWZyZXNoICsgYWxsLXByb2ZpbGVzKSAqLwouY3RybC1idG57CiAgYmFja2dyb3VuZDp2YXIoLS1iZ0NhcmQpO2NvbG9yOnZhcigtLXRleHRQcmltYXJ5KTsKICBib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtbWQpOwogIHBhZGRpbmc6NnB4IDE0cHg7Y3Vyc29yOnBvaW50ZXI7CiAgZm9udC1mYW1pbHk6J0ludGVyJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZTowLjhyZW07Zm9udC13ZWlnaHQ6NjAwOwogIHRyYW5zaXRpb246YmFja2dyb3VuZCAwLjJzLGJvcmRlci1jb2xvciAwLjJzOwp9Ci5jdHJsLWJ0bjpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLWJnSG92ZXIpO2JvcmRlci1jb2xvcjp2YXIoLS1ib3JkZXJMaWdodCl9Ci5jdHJsLWJ0bi5hY3RpdmV7YmFja2dyb3VuZDp2YXIoLS1wcmltYXJ5KTtjb2xvcjp2YXIoLS10ZXh0T25QcmltYXJ5KTtib3JkZXItY29sb3I6dmFyKC0tcHJpbWFyeSl9CgouY3RybC1zZWxlY3R7CiAgYmFja2dyb3VuZDp2YXIoLS1iZ0NhcmQpO2NvbG9yOnZhcigtLXRleHRQcmltYXJ5KTsKICBib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtbWQpOwogIHBhZGRpbmc6NnB4IDhweDtjdXJzb3I6cG9pbnRlcjsKICBmb250LWZhbWlseTonSW50ZXInLHNhbnMtc2VyaWY7Zm9udC1zaXplOjAuOHJlbTtmb250LXdlaWdodDo2MDA7Cn0KLmN0cmwtc2VsZWN0OmhvdmVye2JvcmRlci1jb2xvcjp2YXIoLS1ib3JkZXJMaWdodCl9CgovKiBUb2FzdCBub3RpZmljYXRpb24gKi8KLnRvYXN0LWNvbnRhaW5lcntwb3NpdGlvbjpmaXhlZDt0b3A6dmFyKC0tc3BhY2UtbGcpO3JpZ2h0OnZhcigtLXNwYWNlLWxnKTt6LWluZGV4OjIwMDtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2dhcDp2YXIoLS1zcGFjZS1zbSl9Ci50b2FzdHsKICBiYWNrZ3JvdW5kOnZhcigtLWJnQ2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLW1kKTtwYWRkaW5nOnZhcigtLXNwYWNlLW1kKSB2YXIoLS1zcGFjZS1sZyk7CiAgbWF4LXdpZHRoOjM2MHB4O2FuaW1hdGlvbjpzbGlkZUluIDAuM3MgZWFzZTsKfQoudG9hc3QuY3JpdGljYWx7Ym9yZGVyLWxlZnQ6M3B4IHNvbGlkIHZhcigtLWNyaXRpY2FsKX0KLnRvYXN0Lndhcm5pbmd7Ym9yZGVyLWxlZnQ6M3B4IHNvbGlkIHZhcigtLXdhcm5pbmcpfQpAa2V5ZnJhbWVzIHNsaWRlSW57ZnJvbXt0cmFuc2Zvcm06dHJhbnNsYXRlWCgxMDAlKTtvcGFjaXR5OjB9dG97dHJhbnNmb3JtOnRyYW5zbGF0ZVgoMCk7b3BhY2l0eToxfX0KCi8qID09PT09IEFDQ0VTU0lCSUxJVFkgPT09PT0gKi8KQG1lZGlhKHByZWZlcnMtcmVkdWNlZC1tb3Rpb246cmVkdWNlKXsKICAudG9wYmFyLWxvZ28sLnN0YXR1cy1jaGlwIC5kb3QsLnByb2ZpbGUtY2FyZCAucGMtZG90e2FuaW1hdGlvbjpub25lfQogIGJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdOjphZnRlcnthbmltYXRpb246bm9uZX0KICBib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAudG9wYmFyLWxvZ297YW5pbWF0aW9uOm5vbmV9Cn0KLnZlci1iYWRnZXtkaXNwbGF5OmlubGluZS1ibG9jazttYXJnaW4tbGVmdDo4cHg7cGFkZGluZzoycHggOXB4O2JvcmRlci1yYWRpdXM6OTk5cHg7CiAgYmFja2dyb3VuZDpyZ2JhKDU2LDE4OSwyNDgsLjEyKTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoNTYsMTg5LDI0OCwuMzUpOwogIGNvbG9yOnZhcigtLXByaW1hcnksIzM4YmRmOCk7Zm9udC1zaXplOjExcHg7Zm9udC13ZWlnaHQ6NjAwO2xldHRlci1zcGFjaW5nOi40cHg7CiAgZm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7dmVydGljYWwtYWxpZ246MnB4fQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAudmVyLWJhZGdle2JhY2tncm91bmQ6cmdiYSgzNCwxOTcsOTQsLjEwKTtib3JkZXItY29sb3I6cmdiYSgzNCwxOTcsOTQsLjQpO2NvbG9yOiM0YWRlODB9CgovKiA9PT09PSBQSVAtQk9ZOiBDUlQgRlJBTUUgKHd6b3J6ZWMgTmV0d29yayBNb25pdG9yKSA9PT09PSAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXXtmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJywnSmV0QnJhaW5zIE1vbm8nLCdDb3VyaWVyIE5ldycsbW9ub3NwYWNlfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuaGVhZGluZy1tZCxib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuaGVhZGluZy1sZywKYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmhlYWRpbmcteGwsYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmJvZHktbWQsCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5ib2R5LXNtLGJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5sYWJlbC1tZCwKYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmxhYmVsLWxnLGJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tb25vLXNtLApib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAubWV0cmljLXhsLGJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5rcGktdmFsdWV7CiAgZm9udC1mYW1pbHk6aW5oZXJpdH0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gI21haW57CiAgcG9zaXRpb246cmVsYXRpdmU7CiAgYm9yZGVyOjhweCBzb2xpZCAjMjIzMjFjO2JvcmRlci1yYWRpdXM6MThweDsKICBiYWNrZ3JvdW5kOnJnYmEoNSw4LDMsLjkyKTsKICBib3gtc2hhZG93OjAgMCAzMHB4IHJnYmEoMjAsMjU1LDIzLC4xMCksaW5zZXQgMCAwIDUwcHggcmdiYSgwLDAsMCwuOSk7CiAgcGFkZGluZzoxNnB4IDE4cHh9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdICNtYWluOjpiZWZvcmV7Y29udGVudDonJztwb3NpdGlvbjphYnNvbHV0ZTtpbnNldDowO3BvaW50ZXItZXZlbnRzOm5vbmU7CiAgYmFja2dyb3VuZDpyZXBlYXRpbmctbGluZWFyLWdyYWRpZW50KDBkZWcscmdiYSgwLDAsMCwuMzApIDAgMXB4LHRyYW5zcGFyZW50IDFweCAzcHgpOwogIHotaW5kZXg6NTtib3JkZXItcmFkaXVzOmluaGVyaXR9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdICNtYWluOjphZnRlcntjb250ZW50OicnO3Bvc2l0aW9uOmFic29sdXRlO2luc2V0OjA7cG9pbnRlci1ldmVudHM6bm9uZTsKICBiYWNrZ3JvdW5kOnJhZGlhbC1ncmFkaWVudChlbGxpcHNlIGF0IDUwJSA1MCUsdHJhbnNwYXJlbnQgNTUlLHJnYmEoMCwwLDAsLjUpIDEwMCUpOwogIGFuaW1hdGlvbjpmbGlja2VyIDhzIGluZmluaXRlO3otaW5kZXg6Njtib3JkZXItcmFkaXVzOmluaGVyaXR9CkBrZXlmcmFtZXMgZmxpY2tlcnswJSwxMDAle29wYWNpdHk6Ljk3fTkyJXtvcGFjaXR5Oi45N305MyV7b3BhY2l0eTouODB9OTQle29wYWNpdHk6Ljk3fTk3JXtvcGFjaXR5Oi45fTk4JXtvcGFjaXR5Oi45N319CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdICNtYWluPiosYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gI21haW4gLmNvbnRhaW5lcntwb3NpdGlvbjpyZWxhdGl2ZTt6LWluZGV4OjJ9Cgo8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5PgoKPCEtLSA9PT09PSBUT1AgQkFSID09PT09IC0tPgo8ZGl2IGlkPSJ0b3BiYXIiPgogIDxkaXYgY2xhc3M9ImNvbnRhaW5lciI+CiAgICA8ZGl2IGNsYXNzPSJ0b3BiYXItbGVmdCI+CiAgICAgIDxkaXYgY2xhc3M9InRvcGJhci1sb2dvIiBpZD0idG9wYmFyLWRvdCI+PC9kaXY+CiAgICAgIDxzcGFuIGNsYXNzPSJoZWFkaW5nLW1kIj5IZXJtZXMgTW9uaXRvciA8c3BhbiBjbGFzcz0idmVyLWJhZGdlIiBpZD0idmVyLWJhZGdlIj52X19WRVJfXzwvc3Bhbj48L3NwYW4+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InRvcGJhci1yaWdodCI+CiAgICAgIDxidXR0b24gY2xhc3M9ImN0cmwtYnRuIiBpZD0iYWxsLXByb2ZpbGVzLWJ0biIgc3R5bGU9ImRpc3BsYXk6bm9uZSIgdGl0bGU9IlByenl3csOzxIcgZGFuZSB6YmlvcmN6ZSBkbGEgd3N6eXN0a2ljaCBwcm9maWxpIj5BbGw8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iY3RybC1idG4iIGlkPSJtYW51YWwtcmVmcmVzaCIgdGl0bGU9Ik9kxZt3aWXFvCBkYW5lIG5hIMW8xIVkYW5pZSI+T2TFm3dpZcW8PC9idXR0b24+CiAgICAgIDxzZWxlY3QgY2xhc3M9ImN0cmwtc2VsZWN0IiBpZD0icmVmcmVzaC1pbnRlcnZhbCIgdGl0bGU9IkludGVyd2HFgiBhdXRvbWF0eWN6bmVnbyBvZMWbd2llxbxhbmlhIj4KICAgICAgICA8b3B0aW9uIHZhbHVlPSI5MDAiPjE1IG1pbjwvb3B0aW9uPgogICAgICAgIDxvcHRpb24gdmFsdWU9IjE4MDAiPjMwIG1pbjwvb3B0aW9uPgogICAgICAgIDxvcHRpb24gdmFsdWU9IjM2MDAiPjYwIG1pbjwvb3B0aW9uPgogICAgICA8L3NlbGVjdD4KICAgICAgPGRpdiBjbGFzcz0ibGF5b3V0LXN3aXRjaGVyIiBpZD0ibGF5b3V0LXN3aXRjaGVyIj4KICAgICAgICA8YnV0dG9uIGRhdGEtbGF5b3V0PSJkZWZhdWx0IiBjbGFzcz0iYWN0aXZlIj5IZXJtZXM8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGRhdGEtbGF5b3V0PSJwaXBib3kiPlBpcC1Cb3k8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InJlZnJlc2gtaW5kaWNhdG9yIj48ZGl2IGNsYXNzPSJkb3QiPjwvZGl2PjxzcGFuIGNsYXNzPSJtb25vLXNtIiBpZD0ibGFzdC1yZWZyZXNoIj4tLTwvc3Bhbj48L2Rpdj4KICAgICAgPHNwYW4gaWQ9ImNsb2NrIiBjbGFzcz0ibW9uby1zbSI+LS06LS06LS08L3NwYW4+CiAgICA8L2Rpdj4KICA8L2Rpdj4KPC9kaXY+Cgo8IS0tID09PT09IFJFRlJFU0ggUFJPR1JFU1MgQkFSICsgREFUQSBUSU1FU1RBTVAgPT09PT0gLS0+CjxkaXYgaWQ9InJlZnJlc2gtYmFyIj4KICA8ZGl2IGNsYXNzPSJjb250YWluZXIiPgogICAgPGRpdiBjbGFzcz0icmVmcmVzaC1wcm9ncmVzcyI+PGRpdiBjbGFzcz0iZmlsbCIgaWQ9InJlZnJlc2gtYmFyLWZpbGwiPjwvZGl2PjwvZGl2PgogICAgPGRpdiBjbGFzcz0icmVmcmVzaC1wcm9ncmVzcy1sYWJlbCI+CiAgICAgIDxzcGFuIGlkPSJyZWZyZXNoLWJhci1wY3QiPjAlPC9zcGFuPgogICAgICA8c3Bhbj5EbyBuYXN0xJlwbmVnbzogPHNwYW4gaWQ9InJlZnJlc2gtYmFyLW5leHQiIGNsYXNzPSJwY3QiPi0tPC9zcGFuPjwvc3Bhbj4KICAgICAgPHNwYW4+RGFuZSB6OiA8c3BhbiBpZD0icmVmcmVzaC1iYXItZGF0YSIgY2xhc3M9InBjdCI+LS08L3NwYW4+PC9zcGFuPgogICAgPC9kaXY+CiAgPC9kaXY+CjwvZGl2PgoKPCEtLSA9PT09PSBTVEFUVVMgU1RSSVAgPT09PT0gLS0+CjxkaXYgaWQ9InN0YXR1cy1zdHJpcCI+PGRpdiBjbGFzcz0iY29udGFpbmVyIiBpZD0ic3RhdHVzLXN0cmlwLWlubmVyIj48L2Rpdj48L2Rpdj4KCjwhLS0gPT09PT0gUFJPRklMRSBDQVJEUyA9PT09PSAtLT4KPGRpdiBjbGFzcz0icHJvZmlsZS1jYXJkcy1zZWN0aW9uIj48ZGl2IGNsYXNzPSJjb250YWluZXIiPjxkaXYgY2xhc3M9InByb2ZpbGUtY2FyZHMtZ3JpZCIgaWQ9InByb2ZpbGUtY2FyZHMtZ3JpZCI+PC9kaXY+PC9kaXY+PC9kaXY+Cgo8IS0tID09PT09IE1BSU4gQ09OVEVOVCA9PT09PSAtLT4KPGRpdiBjbGFzcz0iY29udGFpbmVyIiBpZD0ibWFpbiI+CgogIDwhLS0gS1BJIEdyaWQgLS0+CiAgPGRpdiBjbGFzcz0ia3BpLWdyaWQiIGlkPSJrcGktZ3JpZCI+PC9kaXY+CgogIDwhLS0gQ2hhcnRzIFJvdyAtLT4KICA8ZGl2IGNsYXNzPSJjaGFydHMtcm93Ij4KICAgIDxkaXYgY2xhc3M9ImNoYXJ0LWNhcmQiPgogICAgICA8ZGl2IGNsYXNzPSJjaGFydC1oZWFkZXIgaGVhZGluZy1tZCI+V3lrb3J6eXN0YW5pZSB0b2tlbsOzdyAvIGtvc3p0w7N3PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LWJvZHkiIGlkPSJjaGFydC11c2FnZSI+PC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNoYXJ0LWNhcmQiPgogICAgICA8ZGl2IGNsYXNzPSJjaGFydC1oZWFkZXIgaGVhZGluZy1tZCI+VG9wIG1vZGVsZSA8c3BhbiBjbGFzcz0iYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRNdXRlZCkiPihvZCBuYWpiYXJkemllaiBkbyBuYWptbmllaiB1xbx5d2FuZWdvKTwvc3Bhbj48L2Rpdj4KICAgICAgPGRpdiBpZD0iY2hhcnQtbW9kZWxzIj48L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8IS0tIERldGFpbCBSb3cgLS0+CiAgPGRpdiBjbGFzcz0iZGV0YWlsLXJvdyI+CiAgICA8ZGl2IGNsYXNzPSJzZXNzaW9ucy1jYXJkIj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZC1oZWFkZXIiPjxzcGFuIGNsYXNzPSJoZWFkaW5nLW1kIj5Pc3RhdG5pZSBzZXNqZSAod3N6eXN0a2llIHByb2ZpbGUpPC9zcGFuPjxzcGFuIGNsYXNzPSJib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSIgaWQ9InNlc3Npb24tY291bnQiPi0tPC9zcGFuPjwvZGl2PgogICAgICA8ZGl2IGlkPSJzZXNzaW9ucy1saXN0Ij48L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iZ2F0ZXdheS1jYXJkIj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZC1oZWFkZXIiPjxzcGFuIGNsYXNzPSJoZWFkaW5nLW1kIj5HYXRld2F5PC9zcGFuPjxzcGFuIGNsYXNzPSJib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSIgaWQ9ImdhdGV3YXktY291bnQiPi0tPC9zcGFuPjwvZGl2PgogICAgICA8ZGl2IGlkPSJnYXRld2F5LWxpc3QiPjwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDwhLS0gRm9vdGVyIC0tPgogIDxkaXYgaWQ9ImZvb3Rlci1zZWN0aW9uIj4KICAgIDxkaXYgY2xhc3M9ImZvb3Rlci1jYXJkcyI+CiAgICAgIDxkaXYgY2xhc3M9ImZvb3Rlci1jYXJkIj4KICAgICAgICA8ZGl2IGNsYXNzPSJmYy1oZWFkZXIgbGFiZWwtbWQiIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KSI+S2x1Y3plIEFQSSAod3N6eXN0a2llIHByb2ZpbGUpPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZm9vdGVyLWtleXMiPjwvZGl2PgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iZm9vdGVyLWNhcmQiPgogICAgICAgIDxkaXYgY2xhc3M9ImZjLWhlYWRlciBsYWJlbC1tZCIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRTZWNvbmRhcnkpIj5LYW5iYW48L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJmb290ZXIta2FuYmFuIj48L2Rpdj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImZvb3Rlci1jYXJkIj4KICAgICAgICA8ZGl2IGNsYXNzPSJmYy1oZWFkZXIgbGFiZWwtbWQiIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KSI+U3lzdGVtPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZm9vdGVyLXN5c3RlbSI+PC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+Cgo8L2Rpdj4KCjwhLS0gVG9hc3QgY29udGFpbmVyIC0tPgo8ZGl2IGNsYXNzPSJ0b2FzdC1jb250YWluZXIiIGlkPSJ0b2FzdHMiPjwvZGl2PgoKPHNjcmlwdD4KLy8gPT09PT0gQ09ORklHID09PT09CmNvbnN0IEFQSV9CQVNFID0gJ2h0dHA6Ly8xMjcuMC4wLjE6OTExOCc7CmNvbnN0IEFQSV9WRVJTSU9OID0gJzEuMTAuMCc7CmNvbnN0IFJFRlJFU0hfT1BUSU9OUyA9IHs5MDA6JzE1IG1pbicsMTgwMDonMzAgbWluJywzNjAwOic2MCBtaW4nfTsKbGV0IFJFRlJFU0hfSU5URVJWQUwgPSA5MDA7IC8vIGRvbXlzbG5pZSAxNSBtaW4KY29uc3QgTEFZT1VUX0tFWSA9ICdoZXJtZXMtbW9uaXRvci1sYXlvdXQnOwoKbGV0IHVzYWdlQ2hhcnQgPSBudWxsOwpsZXQgbW9kZWxzQ2hhcnQgPSBudWxsOwpsZXQgcmVmcmVzaFRpbWVyID0gbnVsbDsKbGV0IGxhc3RSZWZyZXNoQXQgPSAwOyAgICAgICAgICAgLy8gdGltZXN0YW1wIChtcykgd2hlbiBkYXRhIHdhcyBsYXN0IGZldGNoZWQKbGV0IHByb2dyZXNzVGltZXIgPSBudWxsOyAgICAgICAgLy8gY291bnRkb3duIHByb2dyZXNzIGJhciB0aW1lcgovLyBGaWx0ciBwcm9maWx1OiBudWxsID0gd3N6eXN0a2llIHByb2ZpbGUsIGluYWN6ZWogbmF6d2EgcHJvZmlsdQpsZXQgYWN0aXZlUHJvZmlsZSA9IG51bGw7CgovLyA9PT09PSBIRUxQRVJTID09PT09CmZ1bmN0aW9uIGZvcm1hdE51bWJlcihuKSB7CiAgaWYgKG4gPT0gbnVsbCkgcmV0dXJuICctLSc7CiAgaWYgKG4gPj0gMV8wMDBfMDAwKSByZXR1cm4gKG4gLyAxXzAwMF8wMDApLnRvRml4ZWQoMSkgKyAnTSc7CiAgaWYgKG4gPj0gMV8wMDApIHJldHVybiAobiAvIDFfMDAwKS50b0ZpeGVkKDEpICsgJ2snOwogIHJldHVybiBuLnRvTG9jYWxlU3RyaW5nKCdwbC1QTCcpOwp9CgpmdW5jdGlvbiBmb3JtYXRDb3N0KHVzZCkgewogIGlmICh1c2QgPT0gbnVsbCkgcmV0dXJuICctLSc7CiAgcmV0dXJuICckJyArIHVzZC50b0ZpeGVkKDIpOwp9CgpmdW5jdGlvbiBmb3JtYXREdXJhdGlvbihzZWNvbmRzKSB7CiAgaWYgKHNlY29uZHMgPT0gbnVsbCkgcmV0dXJuICctLSc7CiAgaWYgKHNlY29uZHMgPCA2MCkgcmV0dXJuIE1hdGgucm91bmQoc2Vjb25kcykgKyAncyc7CiAgaWYgKHNlY29uZHMgPCAzNjAwKSByZXR1cm4gTWF0aC5yb3VuZChzZWNvbmRzIC8gNjApICsgJ20nOwogIHJldHVybiAoc2Vjb25kcyAvIDM2MDApLnRvRml4ZWQoMSkgKyAnaCc7Cn0KCmZ1bmN0aW9uIHRpbWVBZ28oaXNvU3RyKSB7CiAgaWYgKCFpc29TdHIpIHJldHVybiAnLS0nOwogIGNvbnN0IG1zID0gRGF0ZS5ub3coKSAtIG5ldyBEYXRlKGlzb1N0cikuZ2V0VGltZSgpOwogIHJldHVybiBmb3JtYXREdXJhdGlvbihtcyAvIDEwMDApICsgJyB0ZW11JzsKfQoKZnVuY3Rpb24gZXNjYXBlSHRtbChzKSB7CiAgaWYgKCFzKSByZXR1cm4gJyc7CiAgY29uc3QgZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogIGQudGV4dENvbnRlbnQgPSBzOwogIHJldHVybiBkLmlubmVySFRNTDsKfQoKLy8gPT09PT0gQ0xPQ0sgPT09PT0KZnVuY3Rpb24gdXBkYXRlQ2xvY2soKSB7CiAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTsKICBjb25zdCBjZXQgPSBuZXcgRGF0ZShub3cudG9Mb2NhbGVTdHJpbmcoJ2VuLVVTJywge3RpbWVab25lOidFdXJvcGUvV2Fyc2F3J30pKTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY2xvY2snKS50ZXh0Q29udGVudCA9CiAgICBjZXQudG9Mb2NhbGVUaW1lU3RyaW5nKCdwbC1QTCcsIHtob3VyOicyLWRpZ2l0JyxtaW51dGU6JzItZGlnaXQnfSkgKyAnIENFVCc7Cn0Kc2V0SW50ZXJ2YWwodXBkYXRlQ2xvY2ssIDEwMDApOwp1cGRhdGVDbG9jaygpOwoKLy8gPT09PT0gVE9BU1RTID09PT09CmZ1bmN0aW9uIHNob3dUb2FzdChtc2csIGxldmVsKSB7CiAgY29uc3QgY29udGFpbmVyID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RvYXN0cycpOwogIGNvbnN0IGVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgZWwuY2xhc3NOYW1lID0gJ3RvYXN0ICcgKyAobGV2ZWx8fCcnKTsKICBlbC50ZXh0Q29udGVudCA9IG1zZzsKICBjb250YWluZXIuYXBwZW5kQ2hpbGQoZWwpOwogIHNldFRpbWVvdXQoKCkgPT4gZWwucmVtb3ZlKCksIDUwMDApOwp9CgovLyA9PT09PSBMQVlPVVQgU1dJVENIRVIgPT09PT0KZnVuY3Rpb24gc3dpdGNoTGF5b3V0KGxheW91dCkgewogIGRvY3VtZW50LmJvZHkuc2V0QXR0cmlidXRlKCdkYXRhLWxheW91dCcsIGxheW91dCk7CiAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oTEFZT1VUX0tFWSwgbGF5b3V0KTsKCiAgLy8gVXBkYXRlIGJ1dHRvbnMKICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcjbGF5b3V0LXN3aXRjaGVyIGJ1dHRvbicpLmZvckVhY2goYnRuID0+IHsKICAgIGJ0bi5jbGFzc0xpc3QudG9nZ2xlKCdhY3RpdmUnLCBidG4uZGF0YXNldC5sYXlvdXQgPT09IGxheW91dCk7CiAgfSk7CgogIC8vIFBpcC1Cb3k6IGRpc3Bvc2UgRUNoYXJ0cywgSGVybWVzOiByZWluaXRpYWxpemUKICBpZiAobGF5b3V0ID09PSAncGlwYm95JykgewogICAgaWYgKHVzYWdlQ2hhcnQpIHsgdXNhZ2VDaGFydC5kaXNwb3NlKCk7IHVzYWdlQ2hhcnQgPSBudWxsOyB9CiAgICBpZiAobW9kZWxzQ2hhcnQpIHsgbW9kZWxzQ2hhcnQuZGlzcG9zZSgpOyBtb2RlbHNDaGFydCA9IG51bGw7IH0KICB9CgogIC8vIFJlZnJlc2ggYWxsIGRhdGEgKHJlLXJlbmRlcnMgZXZlcnl0aGluZyBmb3IgbmV3IGxheW91dCkKICAvLyBaYWNob3dhaiB0aW1lciBvZMWbd2llxbxhbmlhIOKAlCB6bWlhbmEgbGF5b3V0dSBuaWUgcG93aW5uYSBnbyByZXNldG93YcSHCiAgdmFyIHNhdmVkUmVmcmVzaEF0ID0gbGFzdFJlZnJlc2hBdDsKICByZWZyZXNoQWxsKCk7CiAgbGFzdFJlZnJlc2hBdCA9IHNhdmVkUmVmcmVzaEF0OwogIHVwZGF0ZVByb2dyZXNzQmFyKCk7Cn0KCmZ1bmN0aW9uIGluaXRMYXlvdXRTd2l0Y2hlcigpIHsKICBjb25zdCBzYXZlZCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKExBWU9VVF9LRVkpIHx8ICdkZWZhdWx0JzsKICBjb25zdCBidXR0b25zID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnI2xheW91dC1zd2l0Y2hlciBidXR0b24nKTsKICAKICAvLyBBcHBseSBzYXZlZCBsYXlvdXQKICBzd2l0Y2hMYXlvdXQoc2F2ZWQpOwogIAogIC8vIENsaWNrIGhhbmRsZXJzCiAgYnV0dG9ucy5mb3JFYWNoKGJ0biA9PiB7CiAgICBidG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiBzd2l0Y2hMYXlvdXQoYnRuLmRhdGFzZXQubGF5b3V0KSk7CiAgfSk7Cn0KCi8vID09PT09IEZFVENIIFdJVEggRVJST1IgSEFORExJTkcgPT09PT0KYXN5bmMgZnVuY3Rpb24gYXBpRmV0Y2gocGF0aCkgewogIHRyeSB7CiAgICBjb25zdCBzZXAgPSBwYXRoLmluY2x1ZGVzKCc/JykgPyAnJicgOiAnPyc7CiAgICBjb25zdCB1cmwgPSBBUElfQkFTRSArIHBhdGggKyBzZXAgKyAndj0nICsgQVBJX1ZFUlNJT047CiAgICBjb25zdCByZXNwID0gYXdhaXQgZmV0Y2godXJsKTsKICAgIGlmICghcmVzcC5vaykgdGhyb3cgbmV3IEVycm9yKCdIVFRQICcgKyByZXNwLnN0YXR1cyk7CiAgICByZXR1cm4gYXdhaXQgcmVzcC5qc29uKCk7CiAgfSBjYXRjaChlKSB7CiAgICByZXR1cm4ge19lcnJvcjogZS5tZXNzYWdlfTsKICB9Cn0KCi8vID09PT09IFJFRlJFU0ggUFJPR1JFU1MgQkFSID09PT09Ci8vIFBhc2VrIG9kbWllcnphIG9kc2V0ZWsgY3phc3UsIGt0w7NyeSBtaW7EhcWCIG9kIG9zdGF0bmllZ28gb2TFm3dpZcW8ZW5pYQovLyB3emdsxJlkZW0gYmllxbzEhWNlZ28gaW50ZXJ3YcWCdSBSRUZSRVNIX0lOVEVSVkFMLiBSZXNldHVqZSBzacSZIHBvIGthxbxkeW0KLy8gb2TFm3dpZcW8ZW5pdSAoYXV0b21hdHljem55bSwgcsSZY3pueW0gbHViIHptaWFuaWUgaW50ZXJ3YcWCdSkuCmZ1bmN0aW9uIHVwZGF0ZVByb2dyZXNzQmFyKCkgewogIGNvbnN0IGJhciA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyZWZyZXNoLWJhci1maWxsJyk7CiAgY29uc3QgcGN0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncmVmcmVzaC1iYXItcGN0Jyk7CiAgY29uc3QgbmV4dEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3JlZnJlc2gtYmFyLW5leHQnKTsKICBpZiAoIWJhcikgcmV0dXJuOwogIGlmIChsYXN0UmVmcmVzaEF0ID09PSAwKSB7CiAgICBiYXIuc3R5bGUud2lkdGggPSAnMCUnOyBiYXIuY2xhc3NOYW1lID0gJ2ZpbGwnOwogICAgaWYgKHBjdEVsKSBwY3RFbC50ZXh0Q29udGVudCA9ICcwJSc7CiAgICBpZiAobmV4dEVsKSBuZXh0RWwudGV4dENvbnRlbnQgPSAnLS0nOwogICAgcmV0dXJuOwogIH0KICBjb25zdCB0b3RhbCA9IFJFRlJFU0hfSU5URVJWQUw7CiAgY29uc3QgZWxhcHNlZCA9IERhdGUubm93KCkgLSBsYXN0UmVmcmVzaEF0OwogIGNvbnN0IHJlbWFpbmluZyA9IE1hdGgubWF4KDAsIE1hdGgucm91bmQoKHRvdGFsICogMTAwMCAtIGVsYXBzZWQpIC8gMTAwMCkpOwogIGNvbnN0IHBjdCA9IE1hdGgubWluKDEwMCwgTWF0aC5tYXgoMCwgTWF0aC5yb3VuZChlbGFwc2VkIC8gdG90YWwgLyAxMCkpKTsKICBiYXIuc3R5bGUud2lkdGggPSBwY3QgKyAnJSc7CiAgYmFyLmNsYXNzTmFtZSA9ICdmaWxsJyArIChwY3QgPj0gMTAwID8gJyBjcml0JyA6IChwY3QgPj0gODUgPyAnIHdhcm4nIDogJycpKTsKICBpZiAocGN0RWwpIHBjdEVsLnRleHRDb250ZW50ID0gcGN0ICsgJyUnOwogIC8vIFBva2F6dWogY3phcyBkbyBuYXN0ZXBuZWdvIG9kc3dpZXplbmlhCiAgaWYgKG5leHRFbCkgewogICAgaWYgKHJlbWFpbmluZyA8PSAwKSB7CiAgICAgIG5leHRFbC50ZXh0Q29udGVudCA9ICdvZHN3aWV6YW5pZS4uLic7CiAgICAgIG5leHRFbC5zdHlsZS5jb2xvciA9ICd2YXIoLS13YXJuaW5nKSc7CiAgICB9IGVsc2UgewogICAgICBjb25zdCBybSA9IE1hdGguZmxvb3IocmVtYWluaW5nIC8gNjApOwogICAgICBjb25zdCBycyA9IHJlbWFpbmluZyAlIDYwOwogICAgICBuZXh0RWwudGV4dENvbnRlbnQgPSBybSArICc6JyArIFN0cmluZyhycykucGFkU3RhcnQoMiwgJzAnKTsKICAgICAgbmV4dEVsLnN0eWxlLmNvbG9yID0gJyc7CiAgICB9CiAgfQogIC8vIHBvIHByemVrcm9jemVuaXUgMTAwJSAoc3Bvem5pb25lIG9kc3dpZXplbmllKSDigJQgd3NrYXogInRlcmF6IG9kc3dpZXphbSIKICBpZiAocGN0ID49IDEwMCAmJiBwY3RFbCkgcGN0RWwudGV4dENvbnRlbnQgPSAnMTAwJSc7Cn0KCmZ1bmN0aW9uIHN0YXJ0UHJvZ3Jlc3NUaW1lcigpIHsKICBpZiAocHJvZ3Jlc3NUaW1lcikgY2xlYXJJbnRlcnZhbChwcm9ncmVzc1RpbWVyKTsKICB1cGRhdGVQcm9ncmVzc0JhcigpOwogIHByb2dyZXNzVGltZXIgPSBzZXRJbnRlcnZhbCh1cGRhdGVQcm9ncmVzc0JhciwgMjUwKTsKfQoKZnVuY3Rpb24gbWFya0RhdGFUcyhpc29TdHIpIHsKICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyZWZyZXNoLWJhci1kYXRhJyk7CiAgaWYgKCFlbCkgcmV0dXJuOwogIGlmIChpc29TdHIpIHsKICAgIGNvbnN0IGQgPSBuZXcgRGF0ZShpc29TdHIpOwogICAgaWYgKCFpc05hTihkLmdldFRpbWUoKSkpIHsKICAgICAgZWwudGV4dENvbnRlbnQgPSBkLnRvTG9jYWxlRGF0ZVN0cmluZygncGwtUEwnLCB7ZGF5OicyLWRpZ2l0Jyxtb250aDonMi1kaWdpdCcseWVhcjonbnVtZXJpYyd9KSArCiAgICAgICAgJyAnICsgZC50b0xvY2FsZVRpbWVTdHJpbmcoJ3BsLVBMJywge2hvdXI6JzItZGlnaXQnLG1pbnV0ZTonMi1kaWdpdCcsc2Vjb25kOicyLWRpZ2l0J30pOwogICAgICByZXR1cm47CiAgICB9CiAgfQogIGVsLnRleHRDb250ZW50ID0gJy0tJzsKfQoKLy8gPT09PT0gUkVOREVSOiBTVEFUVVMgU1RSSVAgPT09PT0KZnVuY3Rpb24gcmVuZGVyU3RhdHVzU3RyaXAoc3RhdHVzRGF0YSkgewogIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3N0YXR1cy1zdHJpcC1pbm5lcicpOwogIGlmICghc3RhdHVzRGF0YSB8fCBzdGF0dXNEYXRhLl9lcnJvciB8fCAhc3RhdHVzRGF0YS5wcm9maWxlcykgewogICAgZWwuaW5uZXJIVE1MID0gJzxkaXYgY2xhc3M9InN0YXRlLW1zZyI+PGRpdiBjbGFzcz0iYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRNdXRlZCkiPkJyYWsgZGFueWNoIG8gc3RhdHVzaWU8L2Rpdj48L2Rpdj4nOwogICAgcmV0dXJuOwogIH0KCiAgLy8gVXBkYXRlIHRvcGJhciBkb3QKICBjb25zdCBhbGxSdW5uaW5nID0gc3RhdHVzRGF0YS5zdW1tYXJ5Py5wcm9maWxlc190b3RhbCA9PT0gc3RhdHVzRGF0YS5zdW1tYXJ5Py5wcm9maWxlc19ydW5uaW5nOwogIGNvbnN0IGRvdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0b3BiYXItZG90Jyk7CiAgZG90LnN0eWxlLmJhY2tncm91bmQgPSBhbGxSdW5uaW5nID8gJ3ZhcigtLXN1Y2Nlc3MpJyA6ICd2YXIoLS13YXJuaW5nKSc7CgogIGVsLmlubmVySFRNTCA9IHN0YXR1c0RhdGEucHJvZmlsZXMubWFwKHAgPT4gewogICAgY29uc3QgZ3dSdW5uaW5nID0gcC5nYXRld2F5Py5ydW5uaW5nOwogICAgY29uc3Qgc3RhdGUgPSBnd1J1bm5pbmcgPyAnb25saW5lJyA6ICdvZmZsaW5lJzsKICAgIGNvbnN0IG5hbWUgPSBwLnByb2ZpbGU7CiAgICBjb25zdCBhY3RpdmVDbHMgPSAoYWN0aXZlUHJvZmlsZSA9PT0gbmFtZSkgPyAnIGFjdGl2ZScgOiAnJzsKICAgIAogICAgLy8gQ291bnQgY29ubmVjdGVkIHBsYXRmb3JtcwogICAgY29uc3QgcGxhdGZvcm1zID0gKHAuZ2F0ZXdheSAmJiBwLmdhdGV3YXkucGxhdGZvcm1zKSA/IHAuZ2F0ZXdheS5wbGF0Zm9ybXMgOiBbXTsKICAgIGNvbnN0IGNvbm5lY3RlZENvdW50ID0gcGxhdGZvcm1zLmZpbHRlcihwbCA9PiBwbC5zdGF0ZSA9PT0gJ2Nvbm5lY3RlZCcpLmxlbmd0aDsKICAgIGNvbnN0IHRvdGFsUGxhdHMgPSBwbGF0Zm9ybXMubGVuZ3RoOwogICAgY29uc3QgcGxhdGZvcm1JbmZvID0gdG90YWxQbGF0cyA+IDAgPyBjb25uZWN0ZWRDb3VudCArICcvJyArIHRvdGFsUGxhdHMgKyAnIHBsYXRmLicgOiAnJzsKICAgIAogICAgcmV0dXJuICc8ZGl2IGNsYXNzPSJzdGF0dXMtY2hpcCcgKyBhY3RpdmVDbHMgKyAnIiBvbmNsaWNrPSJzZXRQcm9maWxlRmlsdGVyKFwnJyArIGVuY29kZVVSSUNvbXBvbmVudChuYW1lKSArICdcJykiIHRpdGxlPSJQb2thxbwgZGFuZSB0eWxrbyBkbGEgdGVnbyBwcm9maWx1Ij4nICsKICAgICAgJzxkaXYgY2xhc3M9ImRvdCAnICsgc3RhdGUgKyAnIicgKyAoZ3dSdW5uaW5nID8gJyBzdHlsZT0iYW5pbWF0aW9uOnB1bHNlIDJzIGluZmluaXRlIicgOiAnJykgKyAnPjwvZGl2PicgKwogICAgICAnPHNwYW4gY2xhc3M9Im5hbWUiPicgKyBlc2NhcGVIdG1sKG5hbWUpICsgJzwvc3Bhbj4nICsKICAgICAgKHAuZ2F0ZXdheT8uYWN0aXZlX2FnZW50cyA+IDAgPyAnPHNwYW4gY2xhc3M9Im1vbm8tc20iIHN0eWxlPSJjb2xvcjp2YXIoLS1wcmltYXJ5KSI+JyArIHAuZ2F0ZXdheS5hY3RpdmVfYWdlbnRzICsgJyBhZy48L3NwYW4+JyA6ICcnKSArCiAgICAgIChwbGF0Zm9ybUluZm8gPyAnPHNwYW4gY2xhc3M9InBsYXRmb3JtIj4nICsgcGxhdGZvcm1JbmZvICsgJzwvc3Bhbj4nIDogJycpICsKICAgICc8L2Rpdj4nOwogIH0pLmpvaW4oJycpIHx8ICc8c3BhbiBjbGFzcz0iYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRNdXRlZCk7cGFkZGluZzowIHZhcigtLXNwYWNlLXNtKSI+QnJhayBwcm9maWxpPC9zcGFuPic7Cn0KCi8vID09PT09IFJFTkRFUjogUFJPRklMRSBDQVJEUyA9PT09PQpmdW5jdGlvbiByZW5kZXJQcm9maWxlQ2FyZHMoc3RhdHVzRGF0YSwgc2Vzc2lvbnNEYXRhLCB1c2FnZURhdGEpIHsKICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwcm9maWxlLWNhcmRzLWdyaWQnKTsKICBpZiAoIXN0YXR1c0RhdGEgfHwgc3RhdHVzRGF0YS5fZXJyb3IgfHwgIXN0YXR1c0RhdGEucHJvZmlsZXMpIHsKICAgIGVsLmlubmVySFRNTCA9ICcnOwogICAgcmV0dXJuOwogIH0KCiAgdmFyIGlzUGlwQm95ID0gZG9jdW1lbnQuYm9keS5nZXRBdHRyaWJ1dGUoJ2RhdGEtbGF5b3V0JykgPT09ICdwaXBib3knOwoKICAvLyBCdWlsZCBwZXItcHJvZmlsZSBsb29rdXAgbWFwcyBmcm9tIHNlc3Npb25zL3VzYWdlIGRhdGEKICB2YXIgcHJvZmlsZVNlc3Npb25zID0ge307CiAgdmFyIHByb2ZpbGVVc2FnZSA9IHt9OwoKICAvLyBNYXAgc2Vzc2lvbnMgdG8gcHJvZmlsZXMKICAoc3RhdHVzRGF0YS5wcm9maWxlcyB8fCBbXSkuZm9yRWFjaChmdW5jdGlvbihwKSB7CiAgICBwcm9maWxlU2Vzc2lvbnNbcC5wcm9maWxlXSA9IDA7CiAgICBwcm9maWxlVXNhZ2VbcC5wcm9maWxlXSA9IHt0b2tlbnM6IDAsIGNvc3Q6IDB9OwogIH0pOwoKICBpZiAoc2Vzc2lvbnNEYXRhICYmIHNlc3Npb25zRGF0YS5zZXNzaW9ucykgewogICAgc2Vzc2lvbnNEYXRhLnNlc3Npb25zLmZvckVhY2goZnVuY3Rpb24ocykgewogICAgICBpZiAocy5fcHJvZmlsZSAmJiBwcm9maWxlU2Vzc2lvbnMuaGFzT3duUHJvcGVydHkocy5fcHJvZmlsZSkpIHsKICAgICAgICBwcm9maWxlU2Vzc2lvbnNbcy5fcHJvZmlsZV0rKzsKICAgICAgfQogICAgfSk7CiAgfQoKICBpZiAodXNhZ2VEYXRhICYmIHVzYWdlRGF0YS5fcHJvZmlsZVVzYWdlKSB7CiAgICBPYmplY3Qua2V5cyh1c2FnZURhdGEuX3Byb2ZpbGVVc2FnZSkuZm9yRWFjaChmdW5jdGlvbihwKSB7CiAgICAgIHByb2ZpbGVVc2FnZVtwXSA9IHVzYWdlRGF0YS5fcHJvZmlsZVVzYWdlW3BdOwogICAgfSk7CiAgfQoKICBlbC5pbm5lckhUTUwgPSAoc3RhdHVzRGF0YS5wcm9maWxlcyB8fCBbXSkubWFwKGZ1bmN0aW9uKHApIHsKICAgIHZhciBndyA9IHAuZ2F0ZXdheSB8fCB7fTsKICAgIHZhciBydW5uaW5nID0gZ3cucnVubmluZzsKICAgIHZhciBzdGF0ZUNscyA9IHJ1bm5pbmcgPyAnb25saW5lJyA6IChndy5zdGF0ZSA9PT0gJ3N0YWxlJyA/ICdzdGFsZScgOiAnb2ZmbGluZScpOwogICAgdmFyIHBsYXRJbmZvID0gKGd3LnBsYXRmb3JtcyAmJiBBcnJheS5pc0FycmF5KGd3LnBsYXRmb3JtcykpID8gZ3cucGxhdGZvcm1zIDogW107CiAgICB2YXIgY29ubmVjdGVkUGxhdHMgPSBwbGF0SW5mby5maWx0ZXIoZnVuY3Rpb24oaykgeyByZXR1cm4gay5zdGF0ZSA9PT0gJ2Nvbm5lY3RlZCc7IH0pOwogICAgdmFyIGFnZW50cyA9IGd3LmFjdGl2ZV9hZ2VudHMgfHwgMDsKCiAgICB2YXIgcHJlZml4SHRtbCA9ICcnOwogICAgdmFyIGNhcmRBY3RpdmVDbHMgPSAoYWN0aXZlUHJvZmlsZSA9PT0gcC5wcm9maWxlKSA/ICcgYWN0aXZlJyA6ICcnOwogICAgaWYgKGlzUGlwQm95KSB7CiAgICAgIHZhciBwcmVmaXhDb2xvciA9IHJ1bm5pbmcgPyAndmFyKC0tc3VjY2VzcyknIDogKHN0YXRlQ2xzID09PSAnc3RhbGUnID8gJ3ZhcigtLXdhcm5pbmcpJyA6ICd2YXIoLS1jcml0aWNhbCknKTsKICAgICAgdmFyIHByZWZpeCA9IHJ1bm5pbmcgPyAnW09OTF0nIDogKHN0YXRlQ2xzID09PSAnc3RhbGUnID8gJ1tTVExdJyA6ICdbT0ZGXScpOwogICAgICBwcmVmaXhIdG1sID0gJzxzcGFuIGNsYXNzPSJwYy1zdGF0dXMtcHJlZml4IiBzdHlsZT0iY29sb3I6JyArIHByZWZpeENvbG9yICsgJyI+JyArIHByZWZpeCArICc8L3NwYW4+JzsKICAgIH0KCiAgICB2YXIgc2VzaENvdW50ID0gcHJvZmlsZVNlc3Npb25zW3AucHJvZmlsZV0gfHwgMDsKICAgIHZhciB0b2tDb3VudCA9IHByb2ZpbGVVc2FnZVtwLnByb2ZpbGVdID8gcHJvZmlsZVVzYWdlW3AucHJvZmlsZV0udG9rZW5zIDogMDsKICAgIHZhciBjb3N0VmFsID0gcHJvZmlsZVVzYWdlW3AucHJvZmlsZV0gPyBwcm9maWxlVXNhZ2VbcC5wcm9maWxlXS5jb3N0IDogMDsKCiAgICByZXR1cm4gJzxkaXYgY2xhc3M9InByb2ZpbGUtY2FyZCcgKyBjYXJkQWN0aXZlQ2xzICsgJyIgb25jbGljaz0ic2V0UHJvZmlsZUZpbHRlcihcJycgKyBlbmNvZGVVUklDb21wb25lbnQocC5wcm9maWxlKSArICdcJykiIHRpdGxlPSJQb2thxbwgZGFuZSB0eWxrbyBkbGEgdGVnbyBwcm9maWx1Ij4nICsKICAgICAgJzxkaXYgY2xhc3M9InBjLWhlYWRlciI+JyArCiAgICAgICAgKGlzUGlwQm95ID8gcHJlZml4SHRtbCA6ICc8ZGl2IGNsYXNzPSJwYy1kb3QgJyArIHN0YXRlQ2xzICsgJyI+PC9kaXY+JykgKwogICAgICAgICc8c3BhbiBjbGFzcz0icGMtbmFtZSI+JyArIGVzY2FwZUh0bWwocC5wcm9maWxlKSArICc8L3NwYW4+JyArCiAgICAgICc8L2Rpdj4nICsKICAgICAgJzxkaXYgY2xhc3M9InBjLW1ldGEiPicgKwogICAgICAgICc8c3BhbiBjbGFzcz0icGMtbWV0YS1pdGVtIj5BR0VOVFM6JyArIGFnZW50cyArICc8L3NwYW4+JyArCiAgICAgICAgJzxzcGFuIGNsYXNzPSJwYy1tZXRhLWl0ZW0iPlNFU1NJT05TOicgKyBzZXNoQ291bnQgKyAnPC9zcGFuPicgKwogICAgICAgICc8c3BhbiBjbGFzcz0icGMtbWV0YS1pdGVtIj5UT0tFTlM6JyArIGZvcm1hdE51bWJlcih0b2tDb3VudCkgKyAnPC9zcGFuPicgKwogICAgICAgICc8c3BhbiBjbGFzcz0icGMtbWV0YS1pdGVtIj5DT1NUOicgKyBmb3JtYXRDb3N0KGNvc3RWYWwpICsgJzwvc3Bhbj4nICsKICAgICAgJzwvZGl2PicgKwogICAgICAoY29ubmVjdGVkUGxhdHMubGVuZ3RoID4gMCA/CiAgICAgICAgJzxkaXYgY2xhc3M9InBjLXBsYXRmb3JtcyI+JyArCiAgICAgICAgICBwbGF0SW5mby5tYXAoZnVuY3Rpb24ocGwpIHsKICAgICAgICAgICAgdmFyIGNscyA9IHBsLnN0YXRlID09PSAnY29ubmVjdGVkJyA/ICdjb25uZWN0ZWQnIDogJyc7CiAgICAgICAgICAgIHJldHVybiAnPHNwYW4gY2xhc3M9InBjLXBsYXQtY2hpcCAnICsgY2xzICsgJyI+JyArIGVzY2FwZUh0bWwoKHBsLm5hbWV8fCcnKS5zdWJzdHJpbmcoMCw2KSkgKyAnPC9zcGFuPic7CiAgICAgICAgICB9KS5qb2luKCcnKSArCiAgICAgICAgJzwvZGl2PicgOiAnJykgKwogICAgICAnPGRpdiBjbGFzcz0icGMtZm9vdGVyIj4nICsKICAgICAgICAoZ3cudXBkYXRlZF9hdCA/ICdVUEQ6JyArIHRpbWVBZ28oZ3cudXBkYXRlZF9hdCkgOiAnJykgKwogICAgICAgIChndy5wcm9jZXNzX2NtZGxpbmUgPyAnIHwgJyArIChndy5wcm9jZXNzX2NtZGxpbmUgfHwgJycpLnNwbGl0KCcvJykucG9wKCkuc3Vic3RyaW5nKDAsMjApIDogJycpICsKICAgICAgJzwvZGl2PicgKwogICAgJzwvZGl2Pic7CiAgfSkuam9pbignJyk7Cn0KCi8vID09PT09IFBST0ZJTEUgRklMVEVSID09PT09CmZ1bmN0aW9uIHNldFByb2ZpbGVGaWx0ZXIoZW5jb2RlZE5hbWUpIHsKICBjb25zdCBuYW1lID0gYWN0aXZlUHJvZmlsZSAmJiBhY3RpdmVQcm9maWxlID09PSBkZWNvZGVVUklDb21wb25lbnQoZW5jb2RlZE5hbWUpID8gbnVsbCA6IGRlY29kZVVSSUNvbXBvbmVudChlbmNvZGVkTmFtZSk7CiAgYWN0aXZlUHJvZmlsZSA9IG5hbWU7CiAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYWxsLXByb2ZpbGVzLWJ0bicpOwogIGlmIChlbCkgZWwuc3R5bGUuZGlzcGxheSA9IGFjdGl2ZVByb2ZpbGUgPyAnaW5saW5lLWJsb2NrJyA6ICdub25lJzsKICByZWZyZXNoQWxsKCk7Cn0KCi8vID09PT09IFJFTkRFUjogS1BJIEdSSUQgPT09PT0KZnVuY3Rpb24gcmVuZGVyS3BpR3JpZChzdGF0dXNEYXRhLCB1c2FnZURhdGEsIHNlc3Npb25zRGF0YSwga2FuYmFuRGF0YSwgYWxlcnRzRGF0YSwga2V5c0RhdGEpIHsKICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdrcGktZ3JpZCcpOwogIGlmIChzdGF0dXNEYXRhPy5fZXJyb3IgJiYgdXNhZ2VEYXRhPy5fZXJyb3IpIHsKICAgIGVsLmlubmVySFRNTCA9ICc8ZGl2IGNsYXNzPSJzdGF0ZS1tc2ciPjxkaXYgY2xhc3M9Imljb24iPiYjeDI2QTA7JiN4RkUwRjs8L2Rpdj48ZGl2IGNsYXNzPSJ0aXRsZSBoZWFkaW5nLW1kIj5OaWUgbW8mI3gxN0M7bmEgemEmI3gxNDI7YWRvd2EmI3gxMDc7IG1ldHJ5azwvZGl2PjxkaXYgY2xhc3M9ImRlc2MgYm9keS1zbSI+QmFja2VuZCBuaWUgb2Rwb3dpYWRhPC9kaXY+PC9kaXY+JzsKICAgIHJldHVybjsKICB9CgogIGNvbnN0IHN1bW1hcnkgPSBzdGF0dXNEYXRhPy5zdW1tYXJ5IHx8IHt9OwogIGNvbnN0IHNlc3Npb25zID0gc2Vzc2lvbnNEYXRhPy5zZXNzaW9ucyB8fCBbXTsKICBjb25zdCB1c2FnZSA9IHVzYWdlRGF0YT8uZGFpbHkgfHwgW107CiAgY29uc3QgdG9kYXlVc2FnZSA9IHVzYWdlLmxlbmd0aCA+IDAgPyB1c2FnZVt1c2FnZS5sZW5ndGggLSAxXSA6IG51bGw7CgogIC8vIEFjdGl2ZSBwcm9maWxlIGZpbHRlcjogaWYgYSBwcm9maWxlIGlzIHNlbGVjdGVkLCBzaG93IG9ubHkgaXRzIGRhdGEKICBjb25zdCBwcm9maWxlTGlzdCA9IChzdGF0dXNEYXRhPy5wcm9maWxlcyB8fCBbXSkuZmlsdGVyKHAgPT4gIWFjdGl2ZVByb2ZpbGUgfHwgcC5wcm9maWxlID09PSBhY3RpdmVQcm9maWxlKTsKCiAgLy8gVG9kYXk6IHVzYWdlRGF0YS5kYWlseSBpcyBhbHJlYWR5IGFnZ3JlZ2F0ZWQgYWNyb3NzIHRoZSBzY29wZSAoYWxsIHByb2ZpbGVzLCBvciB0aGUgc2luZ2xlCiAgLy8gc2VsZWN0ZWQgcHJvZmlsZSB3aGVuIGZpbHRlcmVkIOKAlCByZWZyZXNoQWxsIG9ubHkgZmV0Y2hlcyB0aGF0IHByb2ZpbGUpLiBMYXN0IGVudHJ5ID0gdG9kYXkuCiAgY29uc3QgdG9kYXlEYXRhID0gdG9kYXlVc2FnZSB8fCB7dG9rZW5zOntpbnB1dDowLG91dHB1dDowfSwgY29zdDp7ZXN0aW1hdGVkX3VzZDowfSwgc2Vzc2lvbl9jb3VudDowLCBkYXk6IG51bGx9OwogIGNvbnN0IGRheUxhYmVsID0gdG9kYXlEYXRhLmRheSA/IHRvZGF5RGF0YS5kYXkgOiAnLS0nOwoKICAvLyBBY3RpdmUgYWdlbnRzIGFjcm9zcyAoZmlsdGVyZWQgb3IgYWxsKSBwcm9maWxlcwogIGxldCBhY3RpdmVBZ2VudHMgPSAwOwogIHByb2ZpbGVMaXN0LmZvckVhY2gocCA9PiB7IGFjdGl2ZUFnZW50cyArPSBwLmdhdGV3YXk/LmFjdGl2ZV9hZ2VudHMgfHwgMDsgfSk7CgogIC8vIEFnZ3JlZ2F0ZWQgdG90YWxzIG92ZXIgdGhlIGRhaWx5IHdpbmRvdyAoYWxsIGRheXMpIGZvciB0aGUgInJhemVtIiB0aWxlcwogIGxldCB0b3RhbFRva2Vuc0luID0gMCwgdG90YWxUb2tlbnNPdXQgPSAwLCB0b3RhbENvc3RFc3QgPSAwOwogICh1c2FnZSB8fCBbXSkuZm9yRWFjaChkYXkgPT4gewogICAgdG90YWxUb2tlbnNJbiArPSBkYXkudG9rZW5zPy5pbnB1dCB8fCAwOwogICAgdG90YWxUb2tlbnNPdXQgKz0gZGF5LnRva2Vucz8ub3V0cHV0IHx8IDA7CiAgICB0b3RhbENvc3RFc3QgKz0gZGF5LmNvc3Q/LmVzdGltYXRlZF91c2QgfHwgMDsKICB9KTsKCiAgLy8gU2Vzc2lvbiBjb3VudCBmb3IgdGhlIGRhdGEgc2NvcGUgKGFsbCBwcm9maWxlcyB2cyBzaW5nbGUgcHJvZmlsZSkKICBjb25zdCBzZXNzaW9uc1Njb3BlID0gYWN0aXZlUHJvZmlsZQogICAgPyAodG9kYXlVc2FnZSA/IHRvZGF5VXNhZ2Uuc2Vzc2lvbl9jb3VudCB8fCAwIDogMCkKICAgIDogKHNlc3Npb25zLmxlbmd0aCk7CgogIGNvbnN0IHRpbGVzID0gWwogICAgewogICAgICBsYWJlbDogJ1Byb2ZpbGUgb25saW5lJywKICAgICAgdmFsdWU6IChzdW1tYXJ5LnByb2ZpbGVzX3J1bm5pbmcgfHwgMCkgKyAnLycgKyAoc3VtbWFyeS5wcm9maWxlc190b3RhbCB8fCAwKSwKICAgICAgc3ViOiBzdW1tYXJ5LnByb2ZpbGVzX3J1bm5pbmcgPT09IHN1bW1hcnkucHJvZmlsZXNfdG90YWwgPyAnV3N6eXN0a2llIE9LJyA6ICdOaWVrdG9yZSBvZmZsaW5lJywKICAgICAgY2xzOiAnJwogICAgfSwKICAgIHsKICAgICAgbGFiZWw6ICdBa3R5d25lIFByb2ZpbGUnLAogICAgICB2YWx1ZTogYWN0aXZlQWdlbnRzLAogICAgICBzdWI6IGFjdGl2ZVByb2ZpbGUgPyAoJ3Byb2ZpbDogJyArIGFjdGl2ZVByb2ZpbGUpIDogJ3N1YnByb2Nlc3N5IGdhdGV3YXknLAogICAgICBjbHM6ICcnCiAgICB9LAogICAgewogICAgICBsYWJlbDogJ1Rva2VueSBsYWN6bmllJywKICAgICAgdmFsdWU6IGZvcm1hdE51bWJlcih0b3RhbFRva2Vuc0luICsgdG90YWxUb2tlbnNPdXQpLAogICAgICBzdWI6IGZvcm1hdE51bWJlcih0b3RhbFRva2Vuc0luKSArICcgaW4gLyAnICsgZm9ybWF0TnVtYmVyKHRvdGFsVG9rZW5zT3V0KSArICcgb3V0JywKICAgICAgY2xzOiAnJwogICAgfSwKICAgIHsKICAgICAgbGFiZWw6ICdUb2tlbnkgKG91dHB1dCxzdW1hKScsCiAgICAgIHZhbHVlOiBmb3JtYXROdW1iZXIodG9kYXlVc2FnZT8udG9rZW5zPy5vdXRwdXQgfHwgMCksCiAgICAgIHN1YjogJ3Nlc2phOiAnICsgc2Vzc2lvbnNTY29wZSArICcgwrcgZHppZcWEOiAnICsgZGF5TGFiZWwsCiAgICAgIGNsczogJycKICAgIH0sCiAgICB7CiAgICAgIGxhYmVsOiAnVG9rZW55IChpbnB1dCxzdW1hKScsCiAgICAgIHZhbHVlOiBmb3JtYXROdW1iZXIodG9kYXlVc2FnZT8udG9rZW5zPy5pbnB1dCB8fCAwKSwKICAgICAgc3ViOiAnc2VzamE6ICcgKyBzZXNzaW9uc1Njb3BlICsgKGFjdGl2ZVByb2ZpbGUgPyAnIMK3ICcgKyBhY3RpdmVQcm9maWxlIDogJycpICsgJyDCtyBkemllxYQ6ICcgKyBkYXlMYWJlbCwKICAgICAgY2xzOiAnJwogICAgfSwKICAgIHsKICAgICAgbGFiZWw6ICdLb3N6dCBsYWN6bmllIChlc3QuKScsCiAgICAgIHZhbHVlOiBmb3JtYXRDb3N0KHRvdGFsQ29zdEVzdCksCiAgICAgIHN1YjogYWN0aXZlUHJvZmlsZSA/ICdwcm9maWw6ICcgKyBhY3RpdmVQcm9maWxlIDogJ1dzenlzdGtpZSBwcm9maWxlJywKICAgICAgY2xzOiAnJwogICAgfSwKICAgIHsKICAgICAgbGFiZWw6ICdLb3N6dCBkemlzIChlc3QuKScsCiAgICAgIHZhbHVlOiBmb3JtYXRDb3N0KHRvZGF5VXNhZ2U/LmNvc3Q/LmVzdGltYXRlZF91c2QgfHwgMCksCiAgICAgIHN1YjogKHVzYWdlRGF0YT8uYnlfbW9kZWw/Lmxlbmd0aCB8fCAwKSArICcgbW9kZWxlJywKICAgICAgY2xzOiAnJwogICAgfSwKICAgIHsKICAgICAgbGFiZWw6ICdCbGVkeSAoMWgpJywKICAgICAgdmFsdWU6IHN1bW1hcnkuZXJyb3JzXzFoIHx8IDAsCiAgICAgIHN1Yjogc3VtbWFyeS5lcnJvcnNfMWggPiAwID8gJ1d5bWFnYSB1d2FnaScgOiAnQ3p5c3RvJywKICAgICAgY2xzOiBzdW1tYXJ5LmVycm9yc18xaCA+IDAgPyAnY3JpdGljYWwnIDogJycKICAgIH0KICBdOwoKICBlbC5pbm5lckhUTUwgPSB0aWxlcy5tYXAodCA9PiAnJwogICAgKyAnPGRpdiBjbGFzcz0ibWV0cmljLXRpbGUgJyArIHQuY2xzICsgJyI+JwogICAgKyAnPGRpdiBjbGFzcz0idGlsZS1sYWJlbCBib2R5LXNtIj4nICsgdC5sYWJlbCArICc8L2Rpdj4nCiAgICArICc8ZGl2IGNsYXNzPSJ0aWxlLXZhbHVlIG1ldHJpYy14bCI+JyArIHQudmFsdWUgKyAnPC9kaXY+JwogICAgKyAnPGRpdiBjbGFzcz0idGlsZS1zdWIgYm9keS1zbSI+JyArIHQuc3ViICsgJzwvZGl2PicKICAgICsgJzwvZGl2PicKICApLmpvaW4oJycpOwp9CgovLyA9PT09PSBSRU5ERVI6IFVTQUdFIENIQVJUIChFQ2hhcnRzIG9yIEFTQ0lJIGZvciBQaXAtQm95KSA9PT09PQpmdW5jdGlvbiByZW5kZXJVc2FnZUNoYXJ0KHVzYWdlRGF0YSkgewogIGNvbnN0IGRvbSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjaGFydC11c2FnZScpOwogIHZhciBpc1BpcEJveSA9IGRvY3VtZW50LmJvZHkuZ2V0QXR0cmlidXRlKCdkYXRhLWxheW91dCcpID09PSAncGlwYm95JzsKCiAgaWYgKGlzUGlwQm95KSB7CiAgICByZW5kZXJVc2FnZUFzY2lpKHVzYWdlRGF0YSwgZG9tKTsKICAgIHJldHVybjsKICB9CiAgaWYgKCF1c2FnZURhdGEgfHwgdXNhZ2VEYXRhLl9lcnJvciB8fCAhdXNhZ2VEYXRhLmRhaWx5Py5sZW5ndGgpIHsKICAgIGlmICh1c2FnZUNoYXJ0KSB7IHVzYWdlQ2hhcnQuZGlzcG9zZSgpOyB1c2FnZUNoYXJ0ID0gbnVsbDsgfQogICAgZG9tLmlubmVySFRNTCA9ICc8ZGl2IGNsYXNzPSJzdGF0ZS1tc2ciIHN0eWxlPSJtaW4taGVpZ2h0OjIwMHB4Ij48ZGl2IGNsYXNzPSJkZXNjIGJvZHktc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpIj5CcmFrIGRhbnljaCBvIHp1enljaXU8L2Rpdj48L2Rpdj4nOwogICAgcmV0dXJuOwogIH0KCiAgaWYgKCF1c2FnZUNoYXJ0KSB7CiAgICBkb20uaW5uZXJIVE1MID0gJyc7CiAgICB1c2FnZUNoYXJ0ID0gZWNoYXJ0cy5pbml0KGRvbSwgbnVsbCwge3JlbmRlcmVyOidjYW52YXMnfSk7CiAgfSBlbHNlIHsKICAgIHVzYWdlQ2hhcnQucmVzaXplKCk7CiAgfQoKICBjb25zdCBkYXlzID0gdXNhZ2VEYXRhLmRhaWx5LnNsaWNlKCkucmV2ZXJzZSgpOwogIGNvbnN0IGRhdGVzID0gZGF5cy5tYXAoZCA9PiBkLmRheS5zbGljZSg1KSk7CiAgY29uc3QgaW5wdXRzID0gZGF5cy5tYXAoZCA9PiBkLnRva2Vucz8uaW5wdXQgfHwgMCk7CiAgY29uc3Qgb3V0cHV0cyA9IGRheXMubWFwKGQgPT4gZC50b2tlbnM/Lm91dHB1dCB8fCAwKTsKICBjb25zdCBjb3N0cyA9IGRheXMubWFwKGQgPT4gZC5jb3N0Py5lc3RpbWF0ZWRfdXNkIHx8IDApOwoKICB1c2FnZUNoYXJ0LnNldE9wdGlvbih7CiAgICBkYXJrTW9kZTogdHJ1ZSwKICAgIGJhY2tncm91bmRDb2xvcjogJ3RyYW5zcGFyZW50JywKICAgIHRvb2x0aXA6IHsKICAgICAgdHJpZ2dlcjonYXhpcycsCiAgICAgIGZvcm1hdHRlcjogZnVuY3Rpb24ocGFyYW1zKSB7CiAgICAgICAgdmFyIGFyciA9IEFycmF5LmlzQXJyYXkocGFyYW1zKSA/IHBhcmFtcyA6IFtwYXJhbXNdOwogICAgICAgIHJldHVybiBhcnIubWFwKGZ1bmN0aW9uKHApIHsKICAgICAgICAgIHZhciBtYXJrZXIgPSBwLm1hcmtlciB8fCAnJzsKICAgICAgICAgIGlmIChwLnNlcmllc05hbWUgPT09ICdLb3N6dCAoJCknKSB7CiAgICAgICAgICAgIHJldHVybiBtYXJrZXIgKyBwLnNlcmllc05hbWUgKyAnOiA8Yj4kJyArIChOdW1iZXIocC52YWx1ZSl8fDApLnRvRml4ZWQoMikgKyAnPC9iPic7CiAgICAgICAgICB9CiAgICAgICAgICByZXR1cm4gbWFya2VyICsgcC5zZXJpZXNOYW1lICsgJzogPGI+JyArIGZvcm1hdE51bWJlcihwLnZhbHVlKSArICc8L2I+JzsKICAgICAgICB9KS5qb2luKCc8YnIvPicpOwogICAgICB9CiAgICB9LAogICAgbGVnZW5kOiB7ZGF0YTpbJ0lucHV0IHRva2VucycsJ091dHB1dCB0b2tlbnMnLCdLb3N6dCAoJCknXSx0ZXh0U3R5bGU6e2NvbG9yOicjOTRBM0I4J30sYm90dG9tOjB9LAogICAgZ3JpZDoge2xlZnQ6MTIsIHJpZ2h0OjEyLCB0b3A6MTIsIGJvdHRvbTozMn0sCiAgICB4QXhpczoge3R5cGU6J2NhdGVnb3J5JyxkYXRhOmRhdGVzLGF4aXNMaW5lOntsaW5lU3R5bGU6e2NvbG9yOicjMUUzMzRGJ319LGF4aXNMYWJlbDp7Y29sb3I6JyM2NDc0OEInLGZvbnRTaXplOjEwfX0sCiAgICB5QXhpczogWwogICAgICB7dHlwZTondmFsdWUnLGF4aXNMYWJlbDp7Y29sb3I6JyM2NDc0OEInLGZvbnRTaXplOjEwLGZvcm1hdHRlcjp2PT5mb3JtYXROdW1iZXIodil9LHNwbGl0TGluZTp7bGluZVN0eWxlOntjb2xvcjonIzFFMzM0Rid9fX0sCiAgICAgIHt0eXBlOid2YWx1ZScsYXhpc0xhYmVsOntjb2xvcjonIzY0NzQ4QicsZm9udFNpemU6MTAsZm9ybWF0dGVyOnY9PickJyt2LnRvRml4ZWQoMil9LHNwbGl0TGluZTp7c2hvdzpmYWxzZX19CiAgICBdLAogICAgc2VyaWVzOiBbCiAgICAgIHtuYW1lOidJbnB1dCB0b2tlbnMnLHR5cGU6J2JhcicsZGF0YTppbnB1dHMsaXRlbVN0eWxlOntjb2xvcjonIzM4QkRGOCd9LGJhck1heFdpZHRoOjIwfSwKICAgICAge25hbWU6J091dHB1dCB0b2tlbnMnLHR5cGU6J2JhcicsZGF0YTpvdXRwdXRzLGl0ZW1TdHlsZTp7Y29sb3I6JyM4MThDRjgnfSxiYXJNYXhXaWR0aDoyMH0sCiAgICAgIHtuYW1lOidLb3N6dCAoJCknLHR5cGU6J2xpbmUnLHlBeGlzSW5kZXg6MSxkYXRhOmNvc3RzLGxpbmVTdHlsZTp7Y29sb3I6JyNGNTlFMEInLHdpZHRoOjJ9LHN5bWJvbDonY2lyY2xlJyxzeW1ib2xTaXplOjYsaXRlbVN0eWxlOntjb2xvcjonI0Y1OUUwQid9fQogICAgXQogIH0pOwp9CgovLyA9PT09PSBSRU5ERVI6IE1PREVMUyBUQUJMRSAoYm90aCBsYXlvdXRzIOKAlCB0YWJsZSBzb3J0ZWQgYnkgY29zdCBkZXNjKSA9PT09PQpmdW5jdGlvbiByZW5kZXJNb2RlbHNDaGFydCh1c2FnZURhdGEpIHsKICBjb25zdCBkb20gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY2hhcnQtbW9kZWxzJyk7CiAgaWYgKG1vZGVsc0NoYXJ0KSB7IG1vZGVsc0NoYXJ0LmRpc3Bvc2UoKTsgbW9kZWxzQ2hhcnQgPSBudWxsOyB9CgogIGlmICghdXNhZ2VEYXRhIHx8IHVzYWdlRGF0YS5fZXJyb3IgfHwgIXVzYWdlRGF0YS5ieV9tb2RlbD8ubGVuZ3RoKSB7CiAgICBkb20uaW5uZXJIVE1MID0gJzxkaXYgY2xhc3M9InN0YXRlLW1zZyIgc3R5bGU9Im1pbi1oZWlnaHQ6MTUwcHgiPjxkaXYgY2xhc3M9ImRlc2MgYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRNdXRlZCkiPkJyYWsgZGFueWNoIG8gbW9kZWxhY2g8L2Rpdj48L2Rpdj4nOwogICAgcmV0dXJuOwogIH0KCiAgLy8gU29ydHVqIG9kIG5hamJhcmR6aWVqIGRvIG5ham1uaWVqIHXFvHl3YW5lZ28gcG9kIFdaR0zEmERFTSBLT1NaVMOTVyAoZGVzYykKICBjb25zdCBtb2RlbHMgPSAodXNhZ2VEYXRhLmJ5X21vZGVsIHx8IFtdKS5zbGljZSgpLnNvcnQoZnVuY3Rpb24oYSxiKSB7CiAgICByZXR1cm4gKE51bWJlcihiLmVzdGltYXRlZF9jb3N0X3VzZCl8fDApIC0gKE51bWJlcihhLmVzdGltYXRlZF9jb3N0X3VzZCl8fDApOwogIH0pOwoKICBmdW5jdGlvbiBubShtKSB7CiAgICByZXR1cm4gKChtLm1vZGVsfHwnPycpLnJlcGxhY2UoL15kZWVwc2Vlay0vLCcnKS5yZXBsYWNlKC9eb3BlbmFpXC8vLCcnKS5zdWJzdHJpbmcoMCwzMikpOwogIH0KCiAgZG9tLmlubmVySFRNTCA9CiAgICAnPHRhYmxlIGNsYXNzPSJtb2RlbHMtdGFibGUiPicgKwogICAgJzx0aGVhZD48dHI+JyArCiAgICAgICc8dGggY2xhc3M9Im0tcmFuayI+IzwvdGg+PHRoPk1vZGVsPC90aD4nICsKICAgICAgJzx0aCBjbGFzcz0ibS10b2tlbnMiPlRva2VueTwvdGg+PHRoIGNsYXNzPSJtLWNvc3QiPktvc3p0IChlc3QuKTwvdGg+PHRoIGNsYXNzPSJtLWNhbGxzIj5XeXdvxYJhbmlhPC90aD4nICsKICAgICc8L3RyPjwvdGhlYWQ+PHRib2R5PicgKwogICAgbW9kZWxzLnNsaWNlKDAsIDE1KS5tYXAoZnVuY3Rpb24obSwgaSkgewogICAgICB2YXIgdCA9IChtLnRva2Vucz8uaW5wdXR8fDApICsgKG0udG9rZW5zPy5vdXRwdXR8fDApOwogICAgICByZXR1cm4gJzx0cj4nICsKICAgICAgICAnPHRkIGNsYXNzPSJtLXJhbmsiPicgKyAoaSsxKSArICc8L3RkPicgKwogICAgICAgICc8dGQgY2xhc3M9Im0tbmFtZSI+JyArIGVzY2FwZUh0bWwobm0obSkpICsgJzwvdGQ+JyArCiAgICAgICAgJzx0ZCBjbGFzcz0ibS10b2tlbnMiPicgKyBmb3JtYXROdW1iZXIodCkgKyAnPC90ZD4nICsKICAgICAgICAnPHRkIGNsYXNzPSJtLWNvc3QiPicgKyBmb3JtYXRDb3N0KG0uZXN0aW1hdGVkX2Nvc3RfdXNkKSArICc8L3RkPicgKwogICAgICAgICc8dGQgY2xhc3M9Im0tY2FsbHMiPicgKyBmb3JtYXROdW1iZXIobS5hcGlfY2FsbHMpICsgJzwvdGQ+JyArCiAgICAgICc8L3RyPic7CiAgICB9KS5qb2luKCcnKSArCiAgICAnPC90Ym9keT48L3RhYmxlPic7Cn0KCi8vID09PT09IFBJUC1CT1k6IEFTQ0lJIFVTQUdFIENIQVJUID09PT09CmZ1bmN0aW9uIHJlbmRlclVzYWdlQXNjaWkodXNhZ2VEYXRhLCBkb20pIHsKICBpZiAodXNhZ2VDaGFydCkgeyB1c2FnZUNoYXJ0LmRpc3Bvc2UoKTsgdXNhZ2VDaGFydCA9IG51bGw7IH0KICBkb20uaW5uZXJIVE1MID0gJyc7CgogIGlmICghdXNhZ2VEYXRhIHx8IHVzYWdlRGF0YS5fZXJyb3IgfHwgIXVzYWdlRGF0YS5kYWlseT8ubGVuZ3RoKSB7CiAgICBkb20uaW5uZXJIVE1MID0gJzxwcmUgY2xhc3M9ImFzY2lpLWNoYXJ0IiBzdHlsZT0ibWluLWhlaWdodDoyMDBweDtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7Y29sb3I6dmFyKC0tdGV4dE11dGVkKTtmb250LWZhbWlseTpcJ0pldEJyYWlucyBNb25vXCcsbW9ub3NwYWNlO2ZvbnQtc2l6ZTowLjdyZW07cGFkZGluZzp2YXIoLS1zcGFjZS1sZykiPkJSQUsgREFOWUNIIE8gWlVaWUNJVTwvcHJlPic7CiAgICByZXR1cm47CiAgfQoKICBjb25zdCBkYXlzID0gdXNhZ2VEYXRhLmRhaWx5LnNsaWNlKCkucmV2ZXJzZSgpLnNsaWNlKC0xNCk7CiAgY29uc3QgbWF4VG9rZW5zID0gTWF0aC5tYXguYXBwbHkobnVsbCwgZGF5cy5tYXAoZnVuY3Rpb24oZCkgeyByZXR1cm4gKGQudG9rZW5zPy5pbnB1dHx8MCkgKyAoZC50b2tlbnM/Lm91dHB1dHx8MCk7IH0pKSB8fCAxOwogIGNvbnN0IG1heENvc3QgPSBNYXRoLm1heC5hcHBseShudWxsLCBkYXlzLm1hcChmdW5jdGlvbihkKSB7IHJldHVybiBkLmNvc3Q/LmVzdGltYXRlZF91c2R8fDA7IH0pKSB8fCAxOwogIGNvbnN0IGJhckNoYXJzID0gWyfiloEnLCfiloInLCfiloMnLCfiloQnLCfiloUnLCfiloYnLCfilocnLCfilognXTsKCiAgdmFyIGxpbmVzID0gW107CiAgbGluZXMucHVzaCgnICBUT0tFTiBVU0FHRSAob3N0LiAnICsgZGF5cy5sZW5ndGggKyAnIGRuaSknKTsKICBsaW5lcy5wdXNoKCcgICcgKyAn4pSAJy5yZXBlYXQoNTApKTsKICBkYXlzLmZvckVhY2goZnVuY3Rpb24oZCkgewogICAgdmFyIHRvdGFsID0gKGQudG9rZW5zPy5pbnB1dHx8MCkgKyAoZC50b2tlbnM/Lm91dHB1dHx8MCk7CiAgICB2YXIgaWR4ID0gTWF0aC5taW4oTWF0aC5mbG9vcih0b3RhbCAvIG1heFRva2VucyAqIDcpLCA3KTsKICAgIHZhciBiYXIgPSBiYXJDaGFyc1tpZHhdLnJlcGVhdChNYXRoLm1heCgxLCBNYXRoLmZsb29yKHRvdGFsIC8gbWF4VG9rZW5zICogMzApKSk7CiAgICB2YXIgbGFiZWwgPSAoZC5kYXl8fCcnKS5zbGljZSg1KTsKICAgIGxpbmVzLnB1c2goJyAgJyArIGxhYmVsICsgJyDilIInICsgYmFyICsgJyAnICsgZm9ybWF0TnVtYmVyKHRvdGFsKSk7CiAgfSk7CiAgbGluZXMucHVzaCgnICAnICsgJ+KUgCcucmVwZWF0KDUwKSk7CgogIGRvbS5pbm5lckhUTUwgPSAnPHByZSBjbGFzcz0iYXNjaWktY2hhcnQiIHN0eWxlPSJtYXJnaW46MDtwYWRkaW5nOnZhcigtLXNwYWNlLW1kKTtjb2xvcjp2YXIoLS1wcmltYXJ5KTtmb250LWZhbWlseTpcJ0pldEJyYWlucyBNb25vXCcsbW9ub3NwYWNlO2ZvbnQtc2l6ZTowLjY1cmVtO2xpbmUtaGVpZ2h0OjEuNjt0ZXh0LXNoYWRvdzowIDAgNHB4IHJnYmEoMjAsMjU1LDIzLDAuMyk7b3ZlcmZsb3cteDphdXRvIj4nICsgZXNjYXBlSHRtbChsaW5lcy5qb2luKCdcbicpKSArICc8L3ByZT4nOwp9CgovLyA9PT09PSBQSVAtQk9ZOiBURVhUIE1PREVMIExJU1QgKHJlcGxhY2VkIGJ5IHRhYmxlKSA9PT09PQoKLy8gPT09PT0gUkVOREVSOiBTRVNTSU9OUyA9PT09PQpmdW5jdGlvbiByZW5kZXJTZXNzaW9ucyhzZXNzaW9uc0RhdGEpIHsKICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzZXNzaW9ucy1saXN0Jyk7CiAgY29uc3QgY291bnRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzZXNzaW9uLWNvdW50Jyk7CgogIGlmICghc2Vzc2lvbnNEYXRhIHx8IHNlc3Npb25zRGF0YS5fZXJyb3IpIHsKICAgIGVsLmlubmVySFRNTCA9ICc8ZGl2IGNsYXNzPSJzdGF0ZS1tc2ciIHN0eWxlPSJtaW4taGVpZ2h0OjE1MHB4Ij48ZGl2IGNsYXNzPSJkZXNjIGJvZHktc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpIj5OaWUgbW96bmEgemFsYWRvd2FjIHNlc2ppPC9kaXY+PC9kaXY+JzsKICAgIGNvdW50RWwudGV4dENvbnRlbnQgPSAnLS0nOwogICAgcmV0dXJuOwogIH0KCiAgY29uc3Qgc2Vzc2lvbnMgPSBzZXNzaW9uc0RhdGEuc2Vzc2lvbnMgfHwgW107CiAgY291bnRFbC50ZXh0Q29udGVudCA9IHNlc3Npb25zLnNsaWNlKDAsIDEwKS5sZW5ndGggKyAnIHNlc2ppJzsKCiAgaWYgKHNlc3Npb25zLmxlbmd0aCA9PT0gMCkgewogICAgZWwuaW5uZXJIVE1MID0gJzxkaXYgY2xhc3M9InN0YXRlLW1zZyIgc3R5bGU9Im1pbi1oZWlnaHQ6MTUwcHgiPjxkaXYgY2xhc3M9ImRlc2MgYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRNdXRlZCkiPkJyYWsgc2Vzamk8L2Rpdj48L2Rpdj4nOwogICAgcmV0dXJuOwogIH0KCiAgZWwuaW5uZXJIVE1MID0gc2Vzc2lvbnMuc2xpY2UoMCwgMTApLm1hcChzID0+IHsKICAgIHZhciBpc1BpcEJveSA9IGRvY3VtZW50LmJvZHkuZ2V0QXR0cmlidXRlKCdkYXRhLWxheW91dCcpID09PSAncGlwYm95JzsKICAgIHZhciBzb3VyY2VJY29uOwogICAgaWYgKGlzUGlwQm95KSB7CiAgICAgIHNvdXJjZUljb24gPSBzLnNvdXJjZSA9PT0gJ3RlbGVncmFtJyA/ICdbVF0nIDogcy5zb3VyY2UgPT09ICdrYW5iYW4nID8gJ1tLXScgOiAnW0NdJzsKICAgIH0gZWxzZSB7CiAgICAgIHNvdXJjZUljb24gPSBzLnNvdXJjZSA9PT0gJ3RlbGVncmFtJyA/ICdUJyA6IHMuc291cmNlID09PSAna2FuYmFuJyA/ICdLJyA6ICdDJzsKICAgIH0KICAgIGNvbnN0IG5hbWUgPSBzLmRpc3BsYXlfbmFtZSB8fCBzLmlkPy5zbGljZSgwLCAxNikgfHwgJy0tJzsKICAgIHJldHVybiAnPGRpdiBjbGFzcz0ic2Vzc2lvbi1yb3ciPicgKwogICAgICAnPGRpdiB0aXRsZT0iJyArIGVzY2FwZUh0bWwocy5zb3VyY2UpICsgJyIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRNdXRlZCk7Zm9udC1zaXplOjAuN3JlbTtmb250LXdlaWdodDo2MDAiPicgKyBzb3VyY2VJY29uICsgJzwvZGl2PicgKwogICAgICAnPHNwYW4gY2xhc3M9InByb2ZpbGUtY2hpcC1taW5pIj4nICsgZXNjYXBlSHRtbChzLl9wcm9maWxlIHx8ICc/JykgKyAnPC9zcGFuPicgKwogICAgICAnPGRpdj4nICsKICAgICAgICAnPGRpdiBjbGFzcz0iYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRQcmltYXJ5KSI+JyArIGVzY2FwZUh0bWwobmFtZSkgKyAnPC9kaXY+JyArCiAgICAgICAgJzxkaXYgY2xhc3M9ImJvZHktc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpIj4nICsgZXNjYXBlSHRtbChzLm1vZGVsfHwnLS0nKSArICcgLyAnICsgKHMubWVzc2FnZV9jb3VudHx8MCkgKyAnIG1zZyAvICcgKyAocy5hcGlfY2FsbF9jb3VudHx8MCkgKyAnIGNhbGw8L2Rpdj4nICsKICAgICAgJzwvZGl2PicgKwogICAgICAnPGRpdiBjbGFzcz0iaGlkZS1tb2JpbGUgbW9uby1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRTZWNvbmRhcnkpIj4nICsgZm9ybWF0TnVtYmVyKHMudG9rZW5zPy50b3RhbHx8MCkgKyAnIHRvay48L2Rpdj4nICsKICAgICAgJzxkaXYgY2xhc3M9ImhpZGUtbW9iaWxlIG1vbm8tc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KSI+JyArIGZvcm1hdENvc3Qocy5jb3N0Py5lc3RpbWF0ZWRfdXNkKSArICc8L2Rpdj4nICsKICAgICAgJzxkaXYgY2xhc3M9ImhpZGUtbW9iaWxlIGJvZHktc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpIj4nICsgdGltZUFnbyhzLmxhc3RfYWN0aXZpdHlfYXQpICsgJzwvZGl2PicgKwogICAgJzwvZGl2Pic7CiAgfSkuam9pbignJyk7Cn0KCi8vID09PT09IFJFTkRFUjogR0FURVdBWSA9PT09PQovLyBGb3JtYXRvd2FuaWUgY3phc3UgcHJhY3kgLyB3aWVrdQpmdW5jdGlvbiBmbXREdXIocykgewogIGlmIChzID09IG51bGwgfHwgaXNOYU4ocykpIHJldHVybiAnLS0nOwogIGlmIChzIDwgNjApIHJldHVybiBNYXRoLnJvdW5kKHMpICsgJ3MnOwogIGlmIChzIDwgMzYwMCkgcmV0dXJuIE1hdGgucm91bmQocyAvIDYwKSArICdtJzsKICBpZiAocyA8IDg2NDAwKSByZXR1cm4gKHMgLyAzNjAwKS50b0ZpeGVkKDEpICsgJ2gnOwogIHJldHVybiAocyAvIDg2NDAwKS50b0ZpeGVkKDEpICsgJ2QnOwp9Ci8vIEthdGVnb3JpYSBrcm9wa2kgc3RhdHVzdSBwcm9maWx1OiBvayAvIHdhcm4gLyBlcnIgLyBub25lCmZ1bmN0aW9uIGd3U3RhdHVzKGd3KSB7CiAgaWYgKCFndyB8fCAhZ3cuaGFzT3duUHJvcGVydHkoJ3N0YXRlJykpIHJldHVybiAnbm9uZSc7CiAgaWYgKGd3LnN0YXRlICE9PSAncnVubmluZycpIHJldHVybiAnZXJyJzsKICAvLyBydW5uaW5nOiBtYXJ0d3kgY3JvbiB0aWNrZXIgLyBixYLEmWR5IC8gY3rEmcWbxIcgcGxhdGZvcm0gZGlzY29ubmVjdGVkID0+IHdhcm4KICBpZiAoZ3cuY3Jvbl9hbGl2ZSA9PT0gZmFsc2UpIHJldHVybiAnd2Fybic7CiAgaWYgKChndy5lcnJvcnNfMWggfHwgMCkgPiAwKSByZXR1cm4gJ3dhcm4nOwogIHZhciBwbGF0cyA9IGd3LnBsYXRmb3JtcyB8fCBbXTsKICBpZiAocGxhdHMubGVuZ3RoID4gMCkgewogICAgdmFyIGNvbm5lY3RlZCA9IHBsYXRzLmZpbHRlcihmdW5jdGlvbih4KSB7IHJldHVybiB4LnN0YXRlID09PSAnY29ubmVjdGVkJzsgfSkubGVuZ3RoOwogICAgaWYgKGNvbm5lY3RlZCA8IHBsYXRzLmxlbmd0aCkgcmV0dXJuICd3YXJuJzsKICB9CiAgcmV0dXJuICdvayc7Cn0KLy8gU3RhbiBzemN6ZWfDs8WCb3d5ICsgZGVzaXJlZF9zdGF0ZQpmdW5jdGlvbiBnd1N0YXRlTWV0YShndykgewogIHZhciBzdCA9IGd3LnN0YXRlIHx8ICd1bmtub3duJzsKICB2YXIgZHMgPSBndy5kZXNpcmVkX3N0YXRlOwogIGlmIChzdCA9PT0gJ3J1bm5pbmcnKSB7CiAgICBpZiAoZHMgJiYgZHMgIT09ICdydW5uaW5nJyAmJiBkcyAhPT0gJ3VwJykgcmV0dXJuIHsgbGFiZWw6ICdydW5uaW5nJywgY2xpZW50OiAndXAgKGNoY2UgJyArIGRzICsgJyknIH07CiAgICByZXR1cm4geyBsYWJlbDogJ3J1bm5pbmcnLCBjbGllbnQ6IG51bGwgfTsKICB9CiAgaWYgKGRzICYmIGRzICE9PSBzdCkgcmV0dXJuIHsgbGFiZWw6IHN0LCBjbGllbnQ6ICdjaGNlICcgKyBkcyB9OwogIHJldHVybiB7IGxhYmVsOiBzdCwgY2xpZW50OiBudWxsIH07Cn0KZnVuY3Rpb24gcmVuZGVyR2F0ZXdheShzdGF0dXNEYXRhKSB7CiAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZ2F0ZXdheS1saXN0Jyk7CiAgY29uc3QgY291bnRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdnYXRld2F5LWNvdW50Jyk7CgogIGlmICghc3RhdHVzRGF0YSB8fCBzdGF0dXNEYXRhLl9lcnJvciB8fCAhc3RhdHVzRGF0YS5wcm9maWxlcykgewogICAgZWwuaW5uZXJIVE1MID0gJzxkaXYgY2xhc3M9InN0YXRlLW1zZyIgc3R5bGU9Im1pbi1oZWlnaHQ6MTUwcHgiPjxkaXYgY2xhc3M9ImRlc2MgYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRNdXRlZCkiPkJyYWsgZGFueWNoIG8gZ2F0ZXdheTwvZGl2PjwvZGl2Pic7CiAgICBjb3VudEVsLnRleHRDb250ZW50ID0gJy0tJzsKICAgIHJldHVybjsKICB9CgogIHZhciBwcm9maWxlcyA9IHN0YXR1c0RhdGEucHJvZmlsZXMgfHwgW107CiAgdmFyIGFnZ3JlZ2F0b3JzID0geyB1cDogMCwgd2FybjogMCwgZG93bjogMCwgbm9uZTogMCwgb25saW5lOiAwLCB0b3RhbDogMCB9OwogIHByb2ZpbGVzLmZvckVhY2goZnVuY3Rpb24ocCkgewogICAgdmFyIGcgPSBwLmdhdGV3YXkgfHwge307CiAgICB2YXIgY2F0ID0gZ3dTdGF0dXMoZyk7CiAgICBpZiAoY2F0ID09PSAnb2snKSBhZ2dyZWdhdG9ycy51cCsrOwogICAgZWxzZSBpZiAoY2F0ID09PSAnd2FybicpIGFnZ3JlZ2F0b3JzLndhcm4rKzsKICAgIGVsc2UgaWYgKGNhdCA9PT0gJ2VycicpIGFnZ3JlZ2F0b3JzLmRvd24rKzsKICAgIGVsc2UgYWdncmVnYXRvcnMubm9uZSsrOwogICAgKGcucGxhdGZvcm1zIHx8IFtdKS5mb3JFYWNoKGZ1bmN0aW9uKHBsKSB7IGFnZ3JlZ2F0b3JzLnRvdGFsKys7IGlmIChwbC5zdGF0ZSA9PT0gJ2Nvbm5lY3RlZCcpIGFnZ3JlZ2F0b3JzLm9ubGluZSsrOyB9KTsKICB9KTsKCiAgdmFyIGh0bWwgPSBwcm9maWxlcy5tYXAoZnVuY3Rpb24ocCkgewogICAgdmFyIGcgPSBwLmdhdGV3YXkgfHwge307CiAgICB2YXIgY2F0ID0gZ3dTdGF0dXMoZyk7CiAgICB2YXIgbWV0YSA9IGd3U3RhdGVNZXRhKGcpOwogICAgdmFyIHBpZCA9IGcucGlkOwogICAgdmFyIHVwVHh0ID0gZm10RHVyKGcudXB0aW1lKTsKICAgIHZhciBhZ2VUeHQgPSAoZy5hZ2Vfc2Vjb25kcyAhPSBudWxsICYmIGcuYWdlX3NlY29uZHMgPCA4NjQwMCkKICAgICAgPyBmbXREdXIoZy5hZ2Vfc2Vjb25kcykgKyAnIHRlbXUnIDogZm10RHVyKGcuYWdlX3NlY29uZHMpOwogICAgLy8gem5hY3playBvZMWbd2llxbxlbmlhIHR5bGtvIGdkeSBkYW5lIGlzdG5pZWrEhQogICAgdmFyIGFnZUh0bWwgPSAoZy51cGRhdGVkX2F0KSA/ICc8c3Bhbj51cGRhdGUgPHNwYW4gY2xhc3M9Im9rdiI+JyArIGVzY2FwZUh0bWwoYWdlVHh0KSArICc8L3NwYW4+PC9zcGFuPicgOiAnJzsKICAgIC8vIGV4aXRfcmVhc29uIHR5bGtvIGdkeSBuaWUgbnVsbAogICAgdmFyIGV4aXRIdG1sID0gKGcuZXhpdF9yZWFzb24gIT0gbnVsbCAmJiBnLmV4aXRfcmVhc29uICE9PSAnJykgPyAnPHNwYW4gY2xhc3M9ImZsYWctZXhpdCIgdGl0bGU9IicgKyBlc2NhcGVIdG1sKGcuZXhpdF9yZWFzb24pICsgJyI+ZXhpdDogJyArIGVzY2FwZUh0bWwoU3RyaW5nKGcuZXhpdF9yZWFzb24pKSArICc8L3NwYW4+JyA6ICcnOwogICAgLy8gcmVzdGFydF9yZXF1ZXN0ZWQKICAgIHZhciByZXN0YXJ0SHRtbCA9IGcucmVzdGFydF9yZXF1ZXN0ZWQgPyAnPHNwYW4gY2xhc3M9ImZsYWctcmVzdGFydCIgdGl0bGU9IlJlc3RhcnQgxbzEhWRhbnkiPlJFU1RBUlQ8L3NwYW4+JyA6ICcnOwogICAgLy8gYsWCxJlkeSAxaAogICAgdmFyIGVyckh0bWwgPSAoZy5lcnJvcnNfMWggfHwgMCkgPiAwID8gJzxzcGFuIGNsYXNzPSJiYWQiPicgKyAoZy5lcnJvcnNfMWgpICsgJyBixYIuPC9zcGFuPicgOiAnJzsKICAgIC8vIGNyb24gdGlja2VyCiAgICB2YXIgY3Jvbkh0bWwgPSAoZy5jcm9uX2FsaXZlID09PSBmYWxzZSkgPyAnPHNwYW4gY2xhc3M9ImJhZCI+Y3JvbiAnICsgZm10RHVyKGcuY3Jvbl9oZWFydGJlYXRfYWdlX3NlY29uZHMpICsgJytzPC9zcGFuPicgOiAnJzsKICAgIC8vIG9waXMgc3RhbnUgY3rEmcWbY2lvd2VnbyBwb2Qga3JvcGvEhQogICAgdmFyIHBhcnRpYWxOb3RlID0gbnVsbDsKICAgIGlmIChjYXQgPT09ICd3YXJuJykgewogICAgICB2YXIgYml0cyA9IFtdOwogICAgICBpZiAoZy5jcm9uX2FsaXZlID09PSBmYWxzZSkgYml0cy5wdXNoKCdjcm9uICsnICsgZm10RHVyKGcuY3Jvbl9oZWFydGJlYXRfYWdlX3NlY29uZHMgfHwgMCkpOwogICAgICBpZiAoKGcuZXJyb3JzXzFoIHx8IDApID4gMCkgYml0cy5wdXNoKChnLmVycm9yc18xaCkgKyAnIGLFgsSZZMOzdycpOwogICAgICB2YXIgcGxhdHMgPSBnLnBsYXRmb3JtcyB8fCBbXTsKICAgICAgcGxhdHMuZm9yRWFjaChmdW5jdGlvbihwbCkgeyBpZiAocGwuc3RhdGUgIT09ICdjb25uZWN0ZWQnKSBiaXRzLnB1c2gocGwubmFtZSArICcgJyArIHBsLnN0YXRlKTsgfSk7CiAgICAgIHBhcnRpYWxOb3RlID0gYml0cy5qb2luKCcsICcpOwogICAgfQoKICAgIC8vIHBvZC1za2xlcCBwbGF0Zm9ybSAoZXhwYW5kZXIpCiAgICB2YXIgcGxhdHMgPSBnLnBsYXRmb3JtcyB8fCBbXTsKICAgIHZhciBwbGF0SHRtbCA9ICcnOwogICAgaWYgKHBsYXRzLmxlbmd0aCA+IDApIHsKICAgICAgdmFyIHBsUm93cyA9IHBsYXRzLm1hcChmdW5jdGlvbihwbCkgewogICAgICAgIHZhciBzID0gcGwuc3RhdGUgfHwgJ3Vua25vd24nOwogICAgICAgIHZhciBkb3RDbHMgPSBzID09PSAnY29ubmVjdGVkJyA/ICdjb25uZWN0ZWQnIDogKHMgPT09ICdkaXNjb25uZWN0ZWQnID8gJ2Rpc2Nvbm5lY3RlZCcgOiAocyA9PT0gJ3N0YXJ0aW5nJyB8fCBzID09PSAnY29ubmVjdGluZycgPyAnc3RhcnRpbmcnIDogJ3Vua25vd24nKSk7CiAgICAgICAgdmFyIGVyclR4dCA9IHBsLmVycm9yX2NvZGUgIT0gbnVsbCA/ICgnIMK3ICcgKyBlc2NhcGVIdG1sKFN0cmluZyhwbC5lcnJvcl9jb2RlKSkpIDogJyc7CiAgICAgICAgaWYgKHBsLmVycm9yX21lc3NhZ2UpIGVyclR4dCArPSAnIMK3ICcgKyBlc2NhcGVIdG1sKFN0cmluZyhwbC5lcnJvcl9tZXNzYWdlKSk7CiAgICAgICAgcmV0dXJuICc8ZGl2IGNsYXNzPSJndy1wbGF0Zm9ybS1yb3ciPjxkaXYgY2xhc3M9InBsLXN0YXRlIj48c3BhbiBjbGFzcz0iZ3ctcGwtZG90ICcgKyBkb3RDbHMgKyAnIj48L3NwYW4+PHNwYW4+JyArIGVzY2FwZUh0bWwocGwubmFtZSkgKyAnPC9zcGFuPjxzcGFuIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpIj4nICsgZXNjYXBlSHRtbChzKSArICc8L3NwYW4+PC9kaXY+JyArIChlcnJUeHQgPyAnPHNwYW4gY2xhc3M9InBsLWVyciIgdGl0bGU9IicgKyBlcnJUeHQgKyAnIj4nICsgZXJyVHh0ICsgJzwvc3Bhbj4nIDogJycpICsgJzwvZGl2Pic7CiAgICAgIH0pLmpvaW4oJycpOwogICAgICBwbGF0SHRtbCA9ICc8ZGl2IGNsYXNzPSJndy1wbGF0Zm9ybXMiPjxkaXYgY2xhc3M9Imd3LXBsYXRmb3JtLXJvdyIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRTZWNvbmRhcnkpO2ZvbnQtd2VpZ2h0OjYwMCI+PHNwYW4+UGxhdGZvcm15PC9zcGFuPjxzcGFuPicgKyBwbGF0cy5maWx0ZXIoZnVuY3Rpb24oeCl7cmV0dXJuIHguc3RhdGU9PT0nY29ubmVjdGVkJzt9KS5sZW5ndGggKyAnLycgKyBwbGF0cy5sZW5ndGggKyAnIG9ubGluZTwvc3Bhbj48L2Rpdj4nICsgcGxSb3dzICsgJzwvZGl2Pic7CiAgICB9CgogICAgdmFyIG1ldGFQYXJ0cyA9IFtdOwogICAgbWV0YVBhcnRzLnB1c2gocGlkICE9IG51bGwgJiYgcGlkICE9PSAnJyA/ICdwaWQgJyArIHBpZCA6ICdwaWQg4oiSJyk7CiAgICBtZXRhUGFydHMucHVzaCgndXAgJyArIHVwVHh0KTsKICAgIG1ldGFQYXJ0cy5wdXNoKGFnZUh0bWwpOwogICAgaWYgKHJlc3RhcnRIdG1sKSBtZXRhUGFydHMucHVzaChyZXN0YXJ0SHRtbCk7CiAgICBpZiAoZXhpdEh0bWwpIG1ldGFQYXJ0cy5wdXNoKGV4aXRIdG1sKTsKICAgIGlmIChlcnJIdG1sKSBtZXRhUGFydHMucHVzaChlcnJIdG1sKTsKICAgIGlmIChjcm9uSHRtbCkgbWV0YVBhcnRzLnB1c2goY3Jvbkh0bWwpOwogICAgdmFyIG1ldGFIdG1sID0gbWV0YVBhcnRzLmpvaW4oJzxzcGFuIHN0eWxlPSJvcGFjaXR5OjAuMyI+fDwvc3Bhbj4nKTsKCiAgICB2YXIgc3RhdHVzTGFiZWwgPSAoY2F0ID09PSAnb2snKSA/ICdVUCcgOiAoY2F0ID09PSAnZXJyJyA/ICdET1dOJyA6IChjYXQgPT09ICd3YXJuJyA/ICdDWsSYxZpDSU9XTycgOiAnQlJBSycpKTsKICAgIHZhciBzdGF0dXNDb2xvciA9IGNhdCA9PT0gJ29rJyA/ICd2YXIoLS1zdWNjZXNzKScgOiAoY2F0ID09PSAnZXJyJyA/ICd2YXIoLS1jcml0aWNhbCknIDogKGNhdCA9PT0gJ3dhcm4nID8gJyNlYWIzMDgnIDogJ3ZhcigtLXRleHRNdXRlZCknKSk7CgogICAgdmFyIGxpbmUgPSAnPGRpdiBjbGFzcz0iZ2F0ZXdheS1yb3ciPicKICAgICAgKyAnPGRpdiBjbGFzcz0iZ3ctbGVmdCI+JwogICAgICAgICsgJzxkaXYgY2xhc3M9Imd3LWluZm8iPicKICAgICAgICAgICsgJzxkaXY+PHNwYW4gY2xhc3M9Imd3LW5hbWUiPicgKyBlc2NhcGVIdG1sKHAucHJvZmlsZSkgKyAnPC9zcGFuPicKICAgICAgICAgICAgKyAoZy5hY3RpdmVfYWdlbnRzID8gJzxzcGFuIGNsYXNzPSJndy1hZ2VudHMiPicgKyBnLmFjdGl2ZV9hZ2VudHMgKyAnIGFnLjwvc3Bhbj4nIDogJycpCiAgICAgICAgICAgICsgJzxzcGFuIGNsYXNzPSJndy1zdWIiPicgKyBlc2NhcGVIdG1sKG1ldGEubGFiZWwpICsgKG1ldGEuY2xpZW50ID8gJyAoJyArIGVzY2FwZUh0bWwobWV0YS5jbGllbnQpICsgJyknIDogJycpICsgJzwvc3Bhbj48L2Rpdj4nCiAgICAgICAgICArICc8ZGl2IGNsYXNzPSJndy1tZXRhIj4nICsgbWV0YUh0bWwgKyAnPC9kaXY+JwogICAgICAgICAgKyAocGFydGlhbE5vdGUgPyAnPGRpdiBzdHlsZT0iZm9udC1zaXplOjAuNnJlbTtjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpIj4nICsgZXNjYXBlSHRtbChwYXJ0aWFsTm90ZSkgKyAnPC9kaXY+JyA6ICcnKQogICAgICAgICsgJzwvZGl2PicKICAgICAgKyAnPC9kaXY+JwogICAgICArICc8ZGl2IGNsYXNzPSJndy1zdGF0dXMiPicKICAgICAgICArICc8ZGl2IGNsYXNzPSJndy1kb3QgJyArIGNhdCArICciPjwvZGl2PicKICAgICAgICArICc8c3BhbiBzdHlsZT0iY29sb3I6JyArIHN0YXR1c0NvbG9yICsgJyI+JyArIHN0YXR1c0xhYmVsICsgJzwvc3Bhbj4nCiAgICAgICAgKyAocGxhdHMubGVuZ3RoID8gJzxidXR0b24gY2xhc3M9Imd3LWV4cGFuZCIgZGF0YS1wcm9maWxlPSInICsgZXNjYXBlSHRtbChwLnByb2ZpbGUpICsgJyI+cGxhdGZvcm15ICcgKyBwbGF0cy5maWx0ZXIoZnVuY3Rpb24oeCl7cmV0dXJuIHguc3RhdGU9PT0nY29ubmVjdGVkJzt9KS5sZW5ndGggKyAnLycgKyBwbGF0cy5sZW5ndGggKyAnPC9idXR0b24+JyA6ICcnKQogICAgICArICc8L2Rpdj4nCiAgICArICc8L2Rpdj4nCiAgICArIHBsYXRIdG1sOwoKICAgIHJldHVybiBsaW5lOwogIH0pLmpvaW4oJycpOwoKICBjb3VudEVsLnRleHRDb250ZW50ID0gcHJvZmlsZXMubGVuZ3RoICsgJyBndywgJyArIGFnZ3JlZ2F0b3JzLnVwICsgJyBVUCwgJyArIGFnZ3JlZ2F0b3JzLndhcm4gKyAnIGN6xIVzdC4sICcgKyBhZ2dyZWdhdG9ycy5kb3duICsgJyBET1dOIMK3ICcgKyBhZ2dyZWdhdG9ycy5vbmxpbmUgKyAnLycgKyBhZ2dyZWdhdG9ycy50b3RhbCArICcgcGxhdGZvcm0gb25saW5lJzsKICBlbC5pbm5lckhUTUwgPSBodG1sOwoKICAvLyBEZWxlZ2F0ZSBjbGljayBuYSBleHBhbmRlcnkgcGxhdGZvcm0gKG5hanBpZXJ3IHVzdXdhbXkgc3RhcnkgaGFuZGxlcikKICBpZiAoZWwuX2d3RXhwYW5kSGFuZGxlcikgZWwucmVtb3ZlRXZlbnRMaXN0ZW5lcignY2xpY2snLCBlbC5fZ3dFeHBhbmRIYW5kbGVyKTsKICBlbC5fZ3dFeHBhbmRIYW5kbGVyID0gZnVuY3Rpb24oZXYpIHsKICAgIGlmIChldi50YXJnZXQuY2xhc3NMaXN0LmNvbnRhaW5zKCdndy1leHBhbmQnKSkgewogICAgICB2YXIgcm93ID0gZXYudGFyZ2V0LmNsb3Nlc3QoJy5nYXRld2F5LXJvdycpOwogICAgICB2YXIgcGxFbCA9IHJvdyA/IHJvdy5uZXh0RWxlbWVudFNpYmxpbmcgOiBudWxsOwogICAgICBpZiAocGxFbCAmJiBwbEVsLmNsYXNzTGlzdC5jb250YWlucygnZ3ctcGxhdGZvcm1zJykpIHsKICAgICAgICBwbEVsLmNsYXNzTGlzdC50b2dnbGUoJ29wZW4nKTsKICAgICAgICB2YXIgYWN0aXZlID0gcGxFbC5jbGFzc0xpc3QuY29udGFpbnMoJ29wZW4nKTsKICAgICAgICB2YXIgY29ubmVjdGVkID0gcGxFbC5xdWVyeVNlbGVjdG9yQWxsKCcuZ3ctcGwtZG90LmNvbm5lY3RlZCcpLmxlbmd0aDsKICAgICAgICB2YXIgdG90YWwgPSBwbEVsLnF1ZXJ5U2VsZWN0b3JBbGwoJy5ndy1wbGF0Zm9ybS1yb3cnKS5sZW5ndGggLSAxOwogICAgICAgIGV2LnRhcmdldC50ZXh0Q29udGVudCA9IGFjdGl2ZSA/ICdwbGF0Zm9ybXkg4pa8JyA6ICgncGxhdGZvcm15ICcgKyBjb25uZWN0ZWQgKyAnLycgKyB0b3RhbCk7CiAgICAgIH0KICAgIH0KICB9OwogIGVsLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgZWwuX2d3RXhwYW5kSGFuZGxlcik7Cn0KCi8vID09PT09IFJFTkRFUjogRk9PVEVSID09PT09CmZ1bmN0aW9uIHJlbmRlckZvb3RlcihrZXlzRGF0YSwga2FuYmFuRGF0YSwgc3RhdHVzRGF0YSkgewogIC8vIEtleXMgKGFnZ3JlZ2F0ZWQgZnJvbSBhbGwgcHJvZmlsZXMpCiAgY29uc3Qga2V5c0VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2Zvb3Rlci1rZXlzJyk7CiAgaWYgKGtleXNEYXRhICYmICFrZXlzRGF0YS5fZXJyb3IgJiYga2V5c0RhdGEuYXBpX2tleXNfc2V0Py5sZW5ndGgpIHsKICAgIGtleXNFbC5pbm5lckhUTUwgPSBrZXlzRGF0YS5hcGlfa2V5c19zZXQubWFwKGsgPT4gJzxzcGFuIGNsYXNzPSJrZXktY2hpcCI+JyArIGVzY2FwZUh0bWwoaykgKyAnPC9zcGFuPicpLmpvaW4oJycpOwogIH0gZWxzZSB7CiAgICBrZXlzRWwuaW5uZXJIVE1MID0gJzxkaXYgY2xhc3M9ImJvZHktc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpIj5CcmFrIGRhbnljaDwvZGl2Pic7CiAgfQoKICAvLyBLYW5iYW4KICBjb25zdCBrYW5iYW5FbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdmb290ZXIta2FuYmFuJyk7CiAgaWYgKGthbmJhbkRhdGEgJiYgIWthbmJhbkRhdGEuX2Vycm9yICYmIGthbmJhbkRhdGEudGFza3NfYnlfc3RhdHVzKSB7CiAgICBjb25zdCBzID0ga2FuYmFuRGF0YS50YXNrc19ieV9zdGF0dXM7CiAgICBrYW5iYW5FbC5pbm5lckhUTUwgPSAnJwogICAgICArICc8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOnZhcigtLXNwYWNlLW1kKTtmbGV4LXdyYXA6d3JhcCI+JwogICAgICArICc8ZGl2PjxzcGFuIGNsYXNzPSJiYWRnZSBvayI+ZG9uZTwvc3Bhbj4gPHNwYW4gY2xhc3M9Im1ldHJpYy1tZCI+JyArIChzLmRvbmV8fDApICsgJzwvc3Bhbj48L2Rpdj4nCiAgICAgICsgJzxkaXY+PHNwYW4gY2xhc3M9ImJhZGdlIiBzdHlsZT0iYmFja2dyb3VuZDojMUUzQTVGO2NvbG9yOnZhcigtLXByaW1hcnkpIj5ydW5uaW5nPC9zcGFuPiA8c3BhbiBjbGFzcz0ibWV0cmljLW1kIj4nICsgKHMucnVubmluZ3x8MCkgKyAnPC9zcGFuPjwvZGl2PicKICAgICAgKyAnPGRpdj48c3BhbiBjbGFzcz0iYmFkZ2UiIHN0eWxlPSJiYWNrZ3JvdW5kOnZhcigtLWJnSG92ZXIpO2NvbG9yOnZhcigtLXRleHRTZWNvbmRhcnkpIj50b2RvPC9zcGFuPiA8c3BhbiBjbGFzcz0ibWV0cmljLW1kIj4nICsgKHMudG9kb3x8MCkgKyAnPC9zcGFuPjwvZGl2PicKICAgICAgKyAnPGRpdj48c3BhbiBjbGFzcz0iYmFkZ2Ugd2FybiI+YmxvY2tlZDwvc3Bhbj4gPHNwYW4gY2xhc3M9Im1ldHJpYy1tZCI+JyArIChzLmJsb2NrZWR8fDApICsgJzwvc3Bhbj48L2Rpdj4nCiAgICAgICsgJzwvZGl2Pic7CiAgfSBlbHNlIHsKICAgIGthbmJhbkVsLmlubmVySFRNTCA9ICc8ZGl2IGNsYXNzPSJib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSI+QnJhayBkYW55Y2g8L2Rpdj4nOwogIH0KCiAgLy8gU3lzdGVtIGluZm8KICBjb25zdCBzeXNFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdmb290ZXItc3lzdGVtJyk7CiAgY29uc3Qgc3VtbWFyeSA9IHN0YXR1c0RhdGE/LnN1bW1hcnkgfHwge307CiAgc3lzRWwuaW5uZXJIVE1MID0gJycKICAgICsgJzxkaXYgY2xhc3M9ImJvZHktc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KSI+UHJvZmlsaTogPHNwYW4gY2xhc3M9Im1vbm8tc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0UHJpbWFyeSkiPicgKyAoc3VtbWFyeS5wcm9maWxlc190b3RhbHx8Jy0tJykgKyAnPC9zcGFuPjwvZGl2PicKICAgICsgJzxkaXYgY2xhc3M9ImJvZHktc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KSI+QWt0eXduZSBhZ2VudHk6IDxzcGFuIGNsYXNzPSJtb25vLXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dFByaW1hcnkpIj4nICsgKHN1bW1hcnkuYWN0aXZlX2FnZW50c3x8MCkgKyAnPC9zcGFuPjwvZGl2PicKICAgICsgJzxkaXYgY2xhc3M9ImJvZHktc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KSI+QmFja2VuZDogPHNwYW4gY2xhc3M9Im1vbm8tc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0UHJpbWFyeSkiPjEyNy4wLjAuMTo5MTE4PC9zcGFuPjwvZGl2PicKICAgICsgJzxkaXYgY2xhc3M9ImJvZHktc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KSI+T2Rzd2llemFuaWU6IDxzcGFuIGNsYXNzPSJtb25vLXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dFByaW1hcnkpIj4nICsgKFJFRlJFU0hfT1BUSU9OU1tSRUZSRVNIX0lOVEVSVkFMXSB8fCAoUkVGUkVTSF9JTlRFUlZBTC8xMDAwKSsncycpICsgJzwvc3Bhbj48L2Rpdj4nCiAgICArICc8ZGl2IGNsYXNzPSJib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSkiPkxheW91dDogPHNwYW4gY2xhc3M9Im1vbm8tc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0UHJpbWFyeSkiIGlkPSJzeXMtbGF5b3V0Ij4nICsgKGRvY3VtZW50LmJvZHkuZ2V0QXR0cmlidXRlKCdkYXRhLWxheW91dCcpID09PSAncGlwYm95JyA/ICdQaXAtQm95JyA6ICdIZXJtZXMnKSArICc8L3NwYW4+PC9kaXY+JzsKfQoKLy8gPT09PT0gTUFJTiBSRUZSRVNIID09PT09CmFzeW5jIGZ1bmN0aW9uIHJlZnJlc2hBbGwoKSB7CiAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTsKICBjb25zdCBjZXQgPSBuZXcgRGF0ZShub3cudG9Mb2NhbGVTdHJpbmcoJ2VuLVVTJywge3RpbWVab25lOidFdXJvcGUvV2Fyc2F3J30pKTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbGFzdC1yZWZyZXNoJykudGV4dENvbnRlbnQgPQogICAgY2V0LnRvTG9jYWxlRGF0ZVN0cmluZygncGwtUEwnLCB7ZGF5OicyLWRpZ2l0Jyxtb250aDonMi1kaWdpdCd9KSArICcgJyArCiAgICBjZXQudG9Mb2NhbGVUaW1lU3RyaW5nKCdwbC1QTCcsIHtob3VyOicyLWRpZ2l0JyxtaW51dGU6JzItZGlnaXQnfSkgKyAnIENFVCc7CgogIC8vIFJlc2V0IGxpY3puaWsgb2TFm3dpZcW8YW5pYSDigJQgcGFzZWsgemFjenluYSBvZG1pZXJ6YcSHIG9kIG5vd2EKICBsYXN0UmVmcmVzaEF0ID0gRGF0ZS5ub3coKTsKICB1cGRhdGVQcm9ncmVzc0JhcigpOwoKICB0cnkgewogICAgLy8gRmV0Y2ggc25hcHNob3QgKGFsbCBwcm9maWxlcywga2V5cywga2FuYmFuLCBhbGVydHMgaW4gb25lIGNhbGwpCiAgICBjb25zdCBzbmFwc2hvdCA9IGF3YWl0IGFwaUZldGNoKCcvYXBpL3NuYXBzaG90Jyk7CiAgICAKICAgIGlmIChzbmFwc2hvdC5fZXJyb3IpIHsKICAgICAgc2hvd1RvYXN0KCdCYWNrZW5kIG5pZSBvZHBvd2lhZGE6ICcgKyBzbmFwc2hvdC5fZXJyb3IsICdjcml0aWNhbCcpOwogICAgICByZXR1cm47CiAgICB9CgogICAgLy8gUG9rYcW8IGRhdMSZIGkgZ29kemluxJkgeiBrdMOzcmVqIHBvY2hvZHrEhSBkYW5lCiAgICBtYXJrRGF0YVRzKHNuYXBzaG90LnRzX2lzbyB8fCBudWxsKTsKICAgIAogICAgLy8gRXh0cmFjdCBkYXRhIGZyb20gc25hcHNob3QKICAgIGNvbnN0IHN0YXR1c0RhdGEgPSB7CiAgICAgIHRzOiBzbmFwc2hvdC50cywKICAgICAgc2lnbmFsX2JyaWRnZTogc25hcHNob3Quc2lnbmFsX2JyaWRnZSwKICAgICAgc3VtbWFyeTogc25hcHNob3Quc3VtbWFyeSwKICAgICAgcHJvZmlsZXM6IChzbmFwc2hvdC5wcm9maWxlcyB8fCBbXSkubWFwKGZ1bmN0aW9uKHApIHsKICAgICAgICByZXR1cm4gewogICAgICAgICAgcHJvZmlsZTogcC5wcm9maWxlLAogICAgICAgICAgaG9tZTogcC5ob21lLAogICAgICAgICAgZ2F0ZXdheTogcC5nYXRld2F5LAogICAgICAgICAgY3Jvbl90aWNrZXI6IHAuY3Jvbl90aWNrZXIsCiAgICAgICAgICB1c2FnZTogcC51c2FnZSwKICAgICAgICAgIGFwaV9rZXlzX3NldDogcC5hcGlfa2V5c19zZXQKICAgICAgICB9OwogICAgICB9KQogICAgfTsKICAgIGNvbnN0IGthbmJhbkRhdGEgPSBzbmFwc2hvdC5rYW5iYW47CiAgICBjb25zdCBhbGVydHNEYXRhID0gc25hcHNob3QuYWxlcnRzID8ge2FsZXJ0czogc25hcHNob3QuYWxlcnRzfSA6IG51bGw7CiAgICAKICAgIC8vIEFnZ3JlZ2F0ZSBrZXlzIGFjcm9zcyBhbGwgcHJvZmlsZXMgKGRlZHVwbGljYXRlZCkKICAgIHZhciBhbGxLZXlzID0ge307CiAgICAoc25hcHNob3QucHJvZmlsZXMgfHwgW10pLmZvckVhY2goZnVuY3Rpb24ocCkgewogICAgICAocC5hcGlfa2V5c19zZXQgfHwgW10pLmZvckVhY2goZnVuY3Rpb24oaykgeyBhbGxLZXlzW2tdID0gdHJ1ZTsgfSk7CiAgICB9KTsKICAgIGNvbnN0IGtleXNEYXRhID0ge2FwaV9rZXlzX3NldDogT2JqZWN0LmtleXMoYWxsS2V5cykuc29ydCgpfTsKCiAgICAvLyBGZXRjaCBwZXItcHJvZmlsZSBzZXNzaW9ucyBhbmQgdXNhZ2U7IHdoZW4gYSBwcm9maWxlIGlzIHNlbGVjdGVkLCBvbmx5IHRoYXQgb25lCiAgICBsZXQgcHJvZmlsZXMgPSAoc25hcHNob3QucHJvZmlsZXMgfHwgW10pCiAgICAgIC5tYXAoZnVuY3Rpb24ocCkgeyByZXR1cm4gcC5wcm9maWxlOyB9KQogICAgICAuZmlsdGVyKGZ1bmN0aW9uKHApIHsgcmV0dXJuICFhY3RpdmVQcm9maWxlIHx8IHAgPT09IGFjdGl2ZVByb2ZpbGU7IH0pOwogICAgaWYgKHByb2ZpbGVzLmxlbmd0aCA9PT0gMCAmJiBhY3RpdmVQcm9maWxlKSB7CiAgICAgIC8vIHJlcXVlc3QgcHJvZmlsZSBub3QgaW4gc25hcHNob3Qg4oCUIGZhbGwgYmFjayB0byBhbGwKICAgICAgcHJvZmlsZXMgPSAoc25hcHNob3QucHJvZmlsZXMgfHwgW10pLm1hcChmdW5jdGlvbihwKSB7IHJldHVybiBwLnByb2ZpbGU7IH0pOwogICAgfQogICAgLy8gVXBkYXRlIHNlc3Npb24gcGFuZWwgaGVhZGVyIHRvIHJlZmxlY3QgdGhlIGZpbHRlcgogICAgY29uc3Qgc2Vzc2lvbkhlYWRlciA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJy5zZXNzaW9ucy1jYXJkIC5oZWFkaW5nLW1kJyk7CiAgICBpZiAoc2Vzc2lvbkhlYWRlcikgewogICAgICBzZXNzaW9uSGVhZGVyLnRleHRDb250ZW50ID0gYWN0aXZlUHJvZmlsZQogICAgICAgID8gJ09zdGF0bmllIHNlc2plIChwcm9maWw6ICcgKyBhY3RpdmVQcm9maWxlICsgJyknCiAgICAgICAgOiAnT3N0YXRuaWUgc2VzamUgKHdzenlzdGtpZSBwcm9maWxlKSc7CiAgICB9CiAgICAvLyBVcGRhdGUgIktleXMiIGZvb3RlciBoZWFkZXIgdG8gcmVmbGVjdCB0aGUgZmlsdGVyCiAgICBjb25zdCBrZXlzSGVhZGVyID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvcignI2Zvb3Rlci1zZWN0aW9uIC5mb290ZXItY2FyZCAuZmMtaGVhZGVyJyk7CiAgICBpZiAoa2V5c0hlYWRlcikgewogICAgICBrZXlzSGVhZGVyLnRleHRDb250ZW50ID0gYWN0aXZlUHJvZmlsZQogICAgICAgID8gJ0tsdWN6ZSBBUEkgKHByb2ZpbDogJyArIGFjdGl2ZVByb2ZpbGUgKyAnKScKICAgICAgICA6ICdLbHVjemUgQVBJICh3c3p5c3RraWUgcHJvZmlsZSknOwogICAgfQogICAgCiAgICAvLyBGZXRjaCBzZXNzaW9ucyBmcm9tIGFsbCBwcm9maWxlcyAodXAgdG8gMTUgcGVyIHByb2ZpbGUpCiAgICBjb25zdCBzZXNzaW9uc1Jlc3VsdHMgPSBhd2FpdCBQcm9taXNlLmFsbCgKICAgICAgcHJvZmlsZXMubWFwKGZ1bmN0aW9uKHApIHsKICAgICAgICByZXR1cm4gYXBpRmV0Y2goJy9hcGkvc2Vzc2lvbnM/cHJvZmlsZT0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHApICsgJyZsaW1pdD0xNScpOwogICAgICB9KQogICAgKTsKICAgIC8vIE1lcmdlIGFsbCBzZXNzaW9ucywgc29ydCBieSBsYXN0X2FjdGl2aXR5IGRlc2MKICAgIHZhciBhbGxTZXNzaW9ucyA9IFtdOwogICAgc2Vzc2lvbnNSZXN1bHRzLmZvckVhY2goZnVuY3Rpb24ocmVzdWx0LCBpZHgpIHsKICAgICAgaWYgKHJlc3VsdCAmJiAhcmVzdWx0Ll9lcnJvciAmJiByZXN1bHQuc2Vzc2lvbnMpIHsKICAgICAgICByZXN1bHQuc2Vzc2lvbnMuZm9yRWFjaChmdW5jdGlvbihzKSB7CiAgICAgICAgICBzLl9wcm9maWxlID0gcHJvZmlsZXNbaWR4XTsKICAgICAgICAgIGFsbFNlc3Npb25zLnB1c2gocyk7CiAgICAgICAgfSk7CiAgICAgIH0KICAgIH0pOwogICAgYWxsU2Vzc2lvbnMuc29ydChmdW5jdGlvbihhLCBiKSB7CiAgICAgIHZhciBkYSA9IGEubGFzdF9hY3Rpdml0eV9hdCA/IG5ldyBEYXRlKGEubGFzdF9hY3Rpdml0eV9hdCkuZ2V0VGltZSgpIDogMDsKICAgICAgdmFyIGRiID0gYi5sYXN0X2FjdGl2aXR5X2F0ID8gbmV3IERhdGUoYi5sYXN0X2FjdGl2aXR5X2F0KS5nZXRUaW1lKCkgOiAwOwogICAgICByZXR1cm4gZGIgLSBkYTsKICAgIH0pOwogICAgY29uc3Qgc2Vzc2lvbnNEYXRhID0ge3Nlc3Npb25zOiBhbGxTZXNzaW9ucy5zbGljZSgwLCAxMCl9OwoKICAgIC8vIEZldGNoIHVzYWdlIGZyb20gYWxsIHByb2ZpbGVzIGZvciBjaGFydHMgKDE0IGRheXMpCiAgICBjb25zdCB1c2FnZVJlc3VsdHMgPSBhd2FpdCBQcm9taXNlLmFsbCgKICAgICAgcHJvZmlsZXMubWFwKGZ1bmN0aW9uKHApIHsKICAgICAgICByZXR1cm4gYXBpRmV0Y2goJy9hcGkvdXNhZ2U/cHJvZmlsZT0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHApICsgJyZkYXlzPTE0Jyk7CiAgICAgIH0pCiAgICApOwogICAgLy8gQWdncmVnYXRlIGRhaWx5IHVzYWdlIGFjcm9zcyBhbGwgcHJvZmlsZXMKICAgIHZhciBkYWlseU1hcCA9IHt9OwogICAgdmFyIG1vZGVsTWFwID0ge307CiAgICB2YXIgcHJvZmlsZVVzYWdlTWFwID0ge307ICAvLyBwZXItcHJvZmlsZToge3Rva2VucywgY29zdH0KICAgIHVzYWdlUmVzdWx0cy5mb3JFYWNoKGZ1bmN0aW9uKHJlc3VsdCkgewogICAgICBpZiAoIXJlc3VsdCB8fCByZXN1bHQuX2Vycm9yKSByZXR1cm47CiAgICAgIChyZXN1bHQuZGFpbHkgfHwgW10pLmZvckVhY2goZnVuY3Rpb24oZGF5KSB7CiAgICAgICAgaWYgKCFkYWlseU1hcFtkYXkuZGF5XSkgewogICAgICAgICAgZGFpbHlNYXBbZGF5LmRheV0gPSB7ZGF5OiBkYXkuZGF5LCBzZXNzaW9uX2NvdW50OiAwLCB0b2tlbnM6IHtpbnB1dDowLCBvdXRwdXQ6MCwgcmVhc29uaW5nOjB9LCBjb3N0OiB7ZXN0aW1hdGVkX3VzZDowLCBhY3R1YWxfdXNkOjB9fTsKICAgICAgICB9CiAgICAgICAgZGFpbHlNYXBbZGF5LmRheV0uc2Vzc2lvbl9jb3VudCArPSBkYXkuc2Vzc2lvbl9jb3VudCB8fCAwOwogICAgICAgIGRhaWx5TWFwW2RheS5kYXldLnRva2Vucy5pbnB1dCArPSBkYXkudG9rZW5zID8gKGRheS50b2tlbnMuaW5wdXQgfHwgMCkgOiAwOwogICAgICAgIGRhaWx5TWFwW2RheS5kYXldLnRva2Vucy5vdXRwdXQgKz0gZGF5LnRva2VucyA/IChkYXkudG9rZW5zLm91dHB1dCB8fCAwKSA6IDA7CiAgICAgICAgZGFpbHlNYXBbZGF5LmRheV0udG9rZW5zLnJlYXNvbmluZyArPSBkYXkudG9rZW5zID8gKGRheS50b2tlbnMucmVhc29uaW5nIHx8IDApIDogMDsKICAgICAgICBkYWlseU1hcFtkYXkuZGF5XS5jb3N0LmVzdGltYXRlZF91c2QgKz0gZGF5LmNvc3QgPyAoZGF5LmNvc3QuZXN0aW1hdGVkX3VzZCB8fCAwKSA6IDA7CiAgICAgIH0pOwogICAgICAocmVzdWx0LmJ5X21vZGVsIHx8IFtdKS5mb3JFYWNoKGZ1bmN0aW9uKG0pIHsKICAgICAgICB2YXIga2V5ID0gbS5tb2RlbDsKICAgICAgICBpZiAoIW1vZGVsTWFwW2tleV0pIHsKICAgICAgICAgIG1vZGVsTWFwW2tleV0gPSB7bW9kZWw6IG0ubW9kZWwsIHByb3ZpZGVyOiBtLnByb3ZpZGVyLCBhcGlfY2FsbHM6MCwgdG9rZW5zOntpbnB1dDowLCBvdXRwdXQ6MCwgcmVhc29uaW5nOjB9LCBlc3RpbWF0ZWRfY29zdF91c2Q6MH07CiAgICAgICAgfQogICAgICAgIG1vZGVsTWFwW2tleV0uYXBpX2NhbGxzICs9IG0uYXBpX2NhbGxzIHx8IDA7CiAgICAgICAgbW9kZWxNYXBba2V5XS50b2tlbnMuaW5wdXQgKz0gbS50b2tlbnMgPyAobS50b2tlbnMuaW5wdXQgfHwgMCkgOiAwOwogICAgICAgIG1vZGVsTWFwW2tleV0udG9rZW5zLm91dHB1dCArPSBtLnRva2VucyA/IChtLnRva2Vucy5vdXRwdXQgfHwgMCkgOiAwOwogICAgICAgIG1vZGVsTWFwW2tleV0udG9rZW5zLnJlYXNvbmluZyArPSBtLnRva2VucyA/IChtLnRva2Vucy5yZWFzb25pbmcgfHwgMCkgOiAwOwogICAgICAgIG1vZGVsTWFwW2tleV0uZXN0aW1hdGVkX2Nvc3RfdXNkICs9IG0uZXN0aW1hdGVkX2Nvc3RfdXNkIHx8IDA7CiAgICAgIH0pOwogICAgfSk7CiAgICAvLyBCdWlsZCBwZXItcHJvZmlsZSB1c2FnZSBmcm9tIGxhdGVzdCBkYWlseSBkYXRhCiAgICB1c2FnZVJlc3VsdHMuZm9yRWFjaChmdW5jdGlvbihyZXN1bHQsIGlkeCkgewogICAgICB2YXIgcHJvZiA9IHByb2ZpbGVzW2lkeF07CiAgICAgIGlmICghcHJvZiB8fCAhcmVzdWx0IHx8IHJlc3VsdC5fZXJyb3IpIHJldHVybjsKICAgICAgdmFyIHRvdGFsVG9rZW5zID0gMCwgdG90YWxDb3N0ID0gMDsKICAgICAgKHJlc3VsdC5kYWlseSB8fCBbXSkuZm9yRWFjaChmdW5jdGlvbihkKSB7CiAgICAgICAgdG90YWxUb2tlbnMgKz0gKGQudG9rZW5zPy5pbnB1dHx8MCkgKyAoZC50b2tlbnM/Lm91dHB1dHx8MCk7CiAgICAgICAgdG90YWxDb3N0ICs9IGQuY29zdD8uZXN0aW1hdGVkX3VzZHx8MDsKICAgICAgfSk7CiAgICAgIHByb2ZpbGVVc2FnZU1hcFtwcm9mXSA9IHt0b2tlbnM6IHRvdGFsVG9rZW5zLCBjb3N0OiB0b3RhbENvc3R9OwogICAgfSk7CiAgICB2YXIgZGFpbHlBcnIgPSBbXTsKICAgIGZvciAodmFyIGQgaW4gZGFpbHlNYXApIGRhaWx5QXJyLnB1c2goZGFpbHlNYXBbZF0pOwogICAgZGFpbHlBcnIuc29ydChmdW5jdGlvbihhLCBiKSB7IHJldHVybiBhLmRheS5sb2NhbGVDb21wYXJlKGIuZGF5KTsgfSk7CiAgICB2YXIgbW9kZWxBcnIgPSBbXTsKICAgIGZvciAodmFyIG1rIGluIG1vZGVsTWFwKSBtb2RlbEFyci5wdXNoKG1vZGVsTWFwW21rXSk7CiAgICBtb2RlbEFyci5zb3J0KGZ1bmN0aW9uKGEsIGIpIHsgcmV0dXJuIGIuZXN0aW1hdGVkX2Nvc3RfdXNkIC0gYS5lc3RpbWF0ZWRfY29zdF91c2Q7IH0pOwogICAgY29uc3QgdXNhZ2VEYXRhID0ge2RhaWx5OiBkYWlseUFyciwgYnlfbW9kZWw6IG1vZGVsQXJyLCBfcHJvZmlsZVVzYWdlOiBwcm9maWxlVXNhZ2VNYXB9OwoKICAgIHJlbmRlclN0YXR1c1N0cmlwKHN0YXR1c0RhdGEpOwogICAgcmVuZGVyUHJvZmlsZUNhcmRzKHN0YXR1c0RhdGEsIHNlc3Npb25zRGF0YSwgdXNhZ2VEYXRhKTsKICAgIHJlbmRlcktwaUdyaWQoc3RhdHVzRGF0YSwgdXNhZ2VEYXRhLCBzZXNzaW9uc0RhdGEsIGthbmJhbkRhdGEsIGFsZXJ0c0RhdGEsIGtleXNEYXRhKTsKICAgIHJlbmRlclNlc3Npb25zKHNlc3Npb25zRGF0YSk7CiAgICByZW5kZXJHYXRld2F5KHN0YXR1c0RhdGEpOwogICAgcmVuZGVyRm9vdGVyKGtleXNEYXRhLCBrYW5iYW5EYXRhLCBzdGF0dXNEYXRhKTsKCiAgICAvLyBDaGFydHMKICAgIHJlbmRlclVzYWdlQ2hhcnQodXNhZ2VEYXRhKTsKICAgIHJlbmRlck1vZGVsc0NoYXJ0KHVzYWdlRGF0YSk7CiAgfSBjYXRjaChlKSB7CiAgICBzaG93VG9hc3QoJ0JsYWQgb2Rzd2llemFuaWE6ICcgKyBlLm1lc3NhZ2UsICdjcml0aWNhbCcpOwogIH0KfQoKLy8gPT09PT0gSU5JVCA9PT09PQpmdW5jdGlvbiBpbml0KCkgewogIC8vIEluaXQgbGF5b3V0IHN3aXRjaGVyCiAgaW5pdExheW91dFN3aXRjaGVyKCk7CgogIC8vIFJlZnJlc2ggY29udHJvbHM6IG1hbnVhbCByZWZyZXNoIGJ1dHRvbiArIGludGVydmFsIHNlbGVjdG9yCiAgY29uc3QgcmVmcmVzaFNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyZWZyZXNoLWludGVydmFsJyk7CiAgcmVmcmVzaFNlbGVjdC52YWx1ZSA9IFN0cmluZyhSRUZSRVNIX0lOVEVSVkFMKTsKICByZWZyZXNoU2VsZWN0LmFkZEV2ZW50TGlzdGVuZXIoJ2NoYW5nZScsIGZ1bmN0aW9uKCkgewogICAgUkVGUkVTSF9JTlRFUlZBTCA9IHBhcnNlSW50KHJlZnJlc2hTZWxlY3QudmFsdWUsIDEwKSB8fCA5MDA7CiAgICBpZiAocmVmcmVzaFRpbWVyKSBjbGVhckludGVydmFsKHJlZnJlc2hUaW1lcik7CiAgICByZWZyZXNoVGltZXIgPSBzZXRJbnRlcnZhbChyZWZyZXNoQWxsLCBSRUZSRVNIX0lOVEVSVkFMICogMTAwMCk7CiAgICAvLyBabWlhbmEgaW50ZXJ3YcWCdSByZXNldHVqZSBsaWN6bmlrIOKAlCBwYXNlayBvZG1pZXJ6YSBvZCBub3dhIHd6Z2zEmWRlbSBub3dlZ28gaW50ZXJ3YcWCdQogICAgbGFzdFJlZnJlc2hBdCA9IERhdGUubm93KCk7CiAgICB1cGRhdGVQcm9ncmVzc0JhcigpOwogICAgc2hvd1RvYXN0KCdPZHN3aWV6YW5pZSBjbyAnICsgKFJFRlJFU0hfT1BUSU9OU1tSRUZSRVNIX0lOVEVSVkFMXSB8fCAoUkVGUkVTSF9JTlRFUlZBTC8xMDAwKSsncycpLCAnJyk7CiAgfSk7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21hbnVhbC1yZWZyZXNoJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCBmdW5jdGlvbigpIHsKICAgIC8vIFJlc2V0IGRvIGRvbXnFm2xuZWdvIGludGVyd2HFgnUgMTUgbWluCiAgICBSRUZSRVNIX0lOVEVSVkFMID0gOTAwOwogICAgY29uc3QgcmVmcmVzaFNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyZWZyZXNoLWludGVydmFsJyk7CiAgICByZWZyZXNoU2VsZWN0LnZhbHVlID0gJzkwMCc7CiAgICBpZiAocmVmcmVzaFRpbWVyKSBjbGVhckludGVydmFsKHJlZnJlc2hUaW1lcik7CiAgICByZWZyZXNoVGltZXIgPSBzZXRJbnRlcnZhbChyZWZyZXNoQWxsLCBSRUZSRVNIX0lOVEVSVkFMICogMTAwMCk7CiAgICBsYXN0UmVmcmVzaEF0ID0gRGF0ZS5ub3coKTsKICAgIHVwZGF0ZVByb2dyZXNzQmFyKCk7CiAgICAvLyBQb2JpZXJ6IGFrdHVhbG5lIGRhbmUKICAgIHJlZnJlc2hBbGwoKTsKICAgIHNob3dUb2FzdCgnT2Rzd2llemFuaWUgY28gMTUgbWluIChkb215c2xuZSknLCAnJyk7CiAgfSk7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2FsbC1wcm9maWxlcy1idG4nKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGZ1bmN0aW9uKCkgewogICAgYWN0aXZlUHJvZmlsZSA9IG51bGw7CiAgICB0aGlzLnN0eWxlLmRpc3BsYXkgPSAnbm9uZSc7CiAgICByZWZyZXNoQWxsKCk7CiAgfSk7CgogIC8vIFNob3cgbG9hZGluZyBza2VsZXRvbnMKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgna3BpLWdyaWQnKS5pbm5lckhUTUwgPSBBcnJheSg4KS5maWxsKCc8ZGl2IGNsYXNzPSJtZXRyaWMtdGlsZSI+PGRpdiBjbGFzcz0ic2tlbGV0b24gc2tlbGV0b24tdGV4dCI+PC9kaXY+PGRpdiBjbGFzcz0ic2tlbGV0b24gc2tlbGV0b24tdmFsdWUiPjwvZGl2PjxkaXYgY2xhc3M9InNrZWxldG9uIHNrZWxldG9uLXRleHQiIHN0eWxlPSJ3aWR0aDo0MCUiPjwvZGl2PjwvZGl2PicpLmpvaW4oJycpOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzZXNzaW9ucy1saXN0JykuaW5uZXJIVE1MID0gJzxkaXYgY2xhc3M9InN0YXRlLW1zZyIgc3R5bGU9Im1pbi1oZWlnaHQ6MTUwcHgiPjxkaXYgY2xhc3M9ImRlc2MgYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRNdXRlZCkiPkxhZG93YW5pZS4uLjwvZGl2PjwvZGl2Pic7CgogIC8vIFNrZWxldG9uIGNoaXBzIGZvciBzdGF0dXMgc3RyaXAKICBjb25zdCBza2VsZXRvbkNoaXBzID0gQXJyYXkoNikuZmlsbCgnPGRpdiBjbGFzcz0ic3RhdHVzLWNoaXAgc2tlbGV0b24tY2hpcCI+PGRpdiBjbGFzcz0ic2tlbGV0b24iIHN0eWxlPSJ3aWR0aDo4cHg7aGVpZ2h0OjhweDtib3JkZXItcmFkaXVzOjUwJTtmbGV4LXNocmluazowIj48L2Rpdj48ZGl2IGNsYXNzPSJza2VsZXRvbiBza2VsZXRvbi10ZXh0IiBzdHlsZT0id2lkdGg6NjBweDtoZWlnaHQ6MC43NXJlbTttYXJnaW46MCI+PC9kaXY+PC9kaXY+Jykuam9pbignJyk7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3N0YXR1cy1zdHJpcC1pbm5lcicpLmlubmVySFRNTCA9IHNrZWxldG9uQ2hpcHM7CgogIC8vIFNrZWxldG9uIGNhcmRzIGZvciBwcm9maWxlIGNhcmRzIHNlY3Rpb24KICBjb25zdCBza2VsZXRvbkNhcmRzID0gQXJyYXkoNykuZmlsbCgnPGRpdiBjbGFzcz0icHJvZmlsZS1jYXJkIHNrZWxldG9uLWNhcmQiPjxkaXYgY2xhc3M9InBjLWhlYWRlciI+PGRpdiBjbGFzcz0ic2tlbGV0b24iIHN0eWxlPSJ3aWR0aDoxMHB4O2hlaWdodDoxMHB4O2JvcmRlci1yYWRpdXM6NTAlO2ZsZXgtc2hyaW5rOjAiPjwvZGl2PjxkaXYgY2xhc3M9InNrZWxldG9uIHNrZWxldG9uLXRleHQiIHN0eWxlPSJ3aWR0aDo3MHB4O2hlaWdodDowLjlyZW07bWFyZ2luOjAiPjwvZGl2PjwvZGl2PjxkaXYgY2xhc3M9InBjLW1ldGEiPjxkaXYgY2xhc3M9InNrZWxldG9uIHNrZWxldG9uLXRleHQiIHN0eWxlPSJ3aWR0aDo5MHB4O2hlaWdodDowLjdyZW07bWFyZ2luOjAiPjwvZGl2PjxkaXYgY2xhc3M9InNrZWxldG9uIHNrZWxldG9uLXRleHQiIHN0eWxlPSJ3aWR0aDo2MHB4O2hlaWdodDowLjdyZW07bWFyZ2luOjAiPjwvZGl2PjxkaXYgY2xhc3M9InNrZWxldG9uIHNrZWxldG9uLXRleHQiIHN0eWxlPSJ3aWR0aDo4MHB4O2hlaWdodDowLjdyZW07bWFyZ2luOjAiPjwvZGl2PjwvZGl2PjwvZGl2PicpLmpvaW4oJycpOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwcm9maWxlLWNhcmRzLWdyaWQnKS5pbm5lckhUTUwgPSBza2VsZXRvbkNhcmRzOwoKICAvLyBJbml0aWFsIGxvYWQKICByZWZyZXNoQWxsKCk7CgogIC8vIEF1dG8tcmVmcmVzaCAoUkVGUkVTSF9JTlRFUlZBTCBqZXN0IHcgU0VLVU5EQUNIOyBzZXRJbnRlcnZhbCBwb3RyemVidWplIG1zKQogIHJlZnJlc2hUaW1lciA9IHNldEludGVydmFsKHJlZnJlc2hBbGwsIFJFRlJFU0hfSU5URVJWQUwgKiAxMDAwKTsKCiAgLy8gQ291bnRkb3duIHByb2dyZXNzIGJhcgogIHN0YXJ0UHJvZ3Jlc3NUaW1lcigpOwoKICAvLyBSZXNpemUgY2hhcnRzIG9uIHdpbmRvdyByZXNpemUKICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcigncmVzaXplJywgZnVuY3Rpb24oKSB7CiAgICBpZiAodXNhZ2VDaGFydCkgdXNhZ2VDaGFydC5yZXNpemUoKTsKICAgIGlmIChtb2RlbHNDaGFydCkgbW9kZWxzQ2hhcnQucmVzaXplKCk7CiAgfSk7Cn0KCmRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ0RPTUNvbnRlbnRMb2FkZWQnLCBpbml0KTsKPC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPg=="

def get_html():
    """Dekoduje HTML z base64 z podmianą API_BASE."""
    if HTML_B64 == "REPLACE_WITH_B64_HTML":
        return "<h1>Hermes Monitor</h1><p>Frontend nie został jeszcze osadzony.</p>"
    html = base64.b64decode(HTML_B64).decode("utf-8").replace("__VER__", APP_VERSION)
    # Podmień API_BASE na względną ścieżkę
    html = re.sub(
        r"const API_BASE\s*=\s*['\"][^'\"]+['\"]",
        "const API_BASE = ''",
        html,
    )
    return html

# --- HTTP Server -------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, body, code=200):
        body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _svg(self, body, code=200):
        body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "image/svg+xml")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _parse_path(self):
        parsed = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        return parsed.path, qs

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path, qs = self._parse_path()

        if path == "/":
            self._html(get_html())

        elif path == "/api/health":
            self._json({"status": "ok", "version": APP_VERSION, "backend": "bob-hermes-monitor"})

        elif path == "/api/status":
            snap = get_snapshot()
            if not snap:
                collect_all()
                snap = get_snapshot()
            self._json({
                "ts": snap.get("ts_iso") if snap else None,
                "summary": snap.get("summary") if snap else {},
                "profiles": [
                    {"profile": p["profile"], "home": p["home"],
                     "gateway": p["gateway"], "cron_ticker": p["cron_ticker"]}
                    for p in (snap.get("profiles", []) if snap else [])
                ],
            })

        elif path == "/api/sessions":
            profile = qs.get("profile", ["programista"])[0]
            limit = min(int(qs.get("limit", [20])[0]), 100)
            self._json({"sessions": _get_sessions(profile, limit), "profile": profile})

        elif path == "/api/usage":
            profile = qs.get("profile", ["programista"])[0]
            days = min(int(qs.get("days", [7])[0]), 90)
            self._json(_get_usage_stats(profile, days))

        elif path == "/api/cron/jobs":
            profile = qs.get("profile", ["programista"])[0]
            self._json({"profile": profile, "jobs": _get_cron_jobs(profile)})

        elif path == "/api/kanban":
            self._json(_get_kanban_summary())

        elif path == "/api/keys":
            profile = qs.get("profile", ["programista"])[0]
            env_names = _read_env_names(profile)
            auth_status = _parse_auth_status(profile)
            self._json({"profile": profile, "api_keys_set": env_names, "auth_providers": auth_status})

        elif path == "/api/logs/errors":
            profile = qs.get("profile", ["programista"])[0]
            since_h = min(int(qs.get("since_hours", [1])[0]), 168)
            self._json({
                "profile": profile,
                "errors": _read_log_summary(profile, "errors.log", since_h),
                "agent": _read_log_summary(profile, "agent.log", since_h),
            })

        elif path == "/api/alerts":
            self._json({"alerts": _get_active_alerts()})

        elif path == "/api/snapshot":
            snap = get_snapshot() or collect_all()
            self._json(snap)

        elif path == "/widgets/hermes":
            self._json(widget_data())

        # /api/metrics/{metric_name}
        elif path.startswith("/api/metrics/"):
            metric_name = path[len("/api/metrics/"):]
            hours = min(int(qs.get("hours", [24])[0]), 720)
            self._json({"metric": metric_name, "hours": hours, "data": _get_metric_history(metric_name, hours)})

        # /api/alerts/{id}/acknowledge — tylko POST, GET zwraca 405
        elif re.match(r"^/api/alerts/\d+/acknowledge$", path):
            self.send_response(405)
            self.send_header("Content-Length", "0")
            self.end_headers()

        # icon.svg (dla app_proxy UmbrelOS)
        elif path == "/icon.svg":
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.svg")
            if os.path.exists(icon_path):
                self._svg(open(icon_path).read())
            else:
                self.send_response(404)
                self.end_headers()

        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self):
        path, qs = self._parse_path()

        # /api/alerts/{id}/acknowledge
        m = re.match(r"^/api/alerts/(\d+)/acknowledge$", path)
        if m:
            alert_id = int(m.group(1))
            _acknowledge_alert(alert_id)
            self._json({"status": "ok", "alert_id": alert_id})
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass  # cicho


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    init_dashboard_db()
    print(f"[hermes-monitor] Starting server on 0.0.0.0:{PORT}")
    threading.Thread(target=collector_loop, daemon=True).start()
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()