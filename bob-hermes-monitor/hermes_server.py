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

APP_VERSION = "1.11.0"

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
HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9InBsIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+SGVybWVzIE1vbml0b3I8L3RpdGxlPgo8bGluayByZWw9InByZWNvbm5lY3QiIGhyZWY9Imh0dHBzOi8vZm9udHMuZ29vZ2xlYXBpcy5jb20iPgo8bGluayByZWw9InByZWNvbm5lY3QiIGhyZWY9Imh0dHBzOi8vZm9udHMuZ3N0YXRpYy5jb20iIGNyb3Nzb3JpZ2luPgo8bGluayBocmVmPSJodHRwczovL2ZvbnRzLmdvb2dsZWFwaXMuY29tL2NzczI/ZmFtaWx5PUludGVyOndnaHRANDAwOzUwMDs2MDA7NzAwJmZhbWlseT1KZXRCcmFpbnMrTW9ubzp3Z2h0QDQwMDs1MDA7NjAwOzcwMCZkaXNwbGF5PXN3YXAiIHJlbD0ic3R5bGVzaGVldCI+CjxsaW5rIGhyZWY9Imh0dHBzOi8vZm9udHMuZ29vZ2xlYXBpcy5jb20vY3NzMj9mYW1pbHk9U2hhcmUrVGVjaCtNb25vJmRpc3BsYXk9c3dhcCIgcmVsPSJzdHlsZXNoZWV0Ij4KPHNjcmlwdCBzcmM9Imh0dHBzOi8vY2RuLmpzZGVsaXZyLm5ldC9ucG0vZWNoYXJ0c0A1LjUuMS9kaXN0L2VjaGFydHMubWluLmpzIj48L3NjcmlwdD4KPHN0eWxlPgovKiA9PT09PSBERVNJR04gVE9LRU5TID09PT09ICovCjpyb290IHsKICAvKiBDb2xvcnMgKi8KICAtLXByaW1hcnk6ICM5ZWE4YTA7CiAgLS1zZWNvbmRhcnk6ICM4Yjk2OGU7CiAgLS1zdWNjZXNzOiAjOWZkMGEwOwogIC0td2FybmluZzogI2Q5Yjg0YTsKICAtLWNyaXRpY2FsOiAjZTA3YTVmOwogIC0taW5mbzogIzllYThhMDsKICAtLW5ldXRyYWw6ICM2MTZiNjQ7CiAgLS1iZ1Jvb3Q6ICMwNDFjMWM7CiAgLS1iZ1N1cmZhY2U6ICMwNjFmMWY7CiAgLS1iZ0NhcmQ6ICMwODIzMjI7CiAgLS1iZ0hvdmVyOiAjMGMyYTI5OwogIC0tYm9yZGVyOiAjMGUzMDJlOwogIC0tYm9yZGVyTGlnaHQ6ICMxNjNhMzc7CiAgLS10ZXh0UHJpbWFyeTogI2VmZTlkOTsKICAtLXRleHRTZWNvbmRhcnk6ICNiOGIyYTI7CiAgLS10ZXh0TXV0ZWQ6ICM3YTgxNzg7CiAgLS10ZXh0T25QcmltYXJ5OiAjMDQxYzFjOwoKICAvKiBTcGFjaW5nICovCiAgLS1zcGFjZS14czogNHB4OwogIC0tc3BhY2Utc206IDhweDsKICAtLXNwYWNlLW1kOiAxMnB4OwogIC0tc3BhY2UtbGc6IDE2cHg7CiAgLS1zcGFjZS14bDogMjRweDsKICAtLXNwYWNlLTJ4bDogMzJweDsKICAtLXNwYWNlLTN4bDogNDhweDsKCiAgLyogUmFkaXVzICovCiAgLS1yYWRpdXMtc206IDRweDsKICAtLXJhZGl1cy1tZDogOHB4OwogIC0tcmFkaXVzLWxnOiAxMnB4OwogIC0tcmFkaXVzLXhsOiAxNnB4OwogIC0tcmFkaXVzLWZ1bGw6IDk5OTlweDsKfQoKLyogPT09PT0gUkVTRVQgPT09PT0gKi8KKiwqOjpiZWZvcmUsKjo6YWZ0ZXJ7Ym94LXNpemluZzpib3JkZXItYm94O21hcmdpbjowO3BhZGRpbmc6MH0KaHRtbHtmb250LXNpemU6MTZweDstd2Via2l0LWZvbnQtc21vb3RoaW5nOmFudGlhbGlhc2VkfQpib2R5ewogIGZvbnQtZmFtaWx5OidJbnRlcicsc2Fucy1zZXJpZjsKICBiYWNrZ3JvdW5kOnZhcigtLWJnUm9vdCk7CiAgY29sb3I6dmFyKC0tdGV4dFByaW1hcnkpOwogIGxpbmUtaGVpZ2h0OjEuNTsKICBtaW4taGVpZ2h0OjEwMHZoOwp9CgovKiA9PT09PSBUWVBPR1JBUEhZID09PT09ICovCi5oZWFkaW5nLXhse2ZvbnQtZmFtaWx5OidJbnRlcicsc2Fucy1zZXJpZjtmb250LXNpemU6MS43NXJlbTtmb250LXdlaWdodDo3MDA7bGluZS1oZWlnaHQ6MS4yO2xldHRlci1zcGFjaW5nOi0wLjAyZW19Ci5oZWFkaW5nLWxne2ZvbnQtZmFtaWx5OidJbnRlcicsc2Fucy1zZXJpZjtmb250LXNpemU6MS4yNXJlbTtmb250LXdlaWdodDo2MDA7bGluZS1oZWlnaHQ6MS4zO2xldHRlci1zcGFjaW5nOi0wLjAxZW19Ci5oZWFkaW5nLW1ke2ZvbnQtZmFtaWx5OidJbnRlcicsc2Fucy1zZXJpZjtmb250LXNpemU6MXJlbTtmb250LXdlaWdodDo2MDA7bGluZS1oZWlnaHQ6MS40fQouYm9keS1tZHtmb250LWZhbWlseTonSW50ZXInLHNhbnMtc2VyaWY7Zm9udC1zaXplOjAuODc1cmVtO2ZvbnQtd2VpZ2h0OjQwMDtsaW5lLWhlaWdodDoxLjV9Ci5ib2R5LXNte2ZvbnQtZmFtaWx5OidJbnRlcicsc2Fucy1zZXJpZjtmb250LXNpemU6MC43NXJlbTtmb250LXdlaWdodDo0MDA7bGluZS1oZWlnaHQ6MS41fQoubGFiZWwtbWR7Zm9udC1mYW1pbHk6J0ludGVyJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZTowLjc1cmVtO2ZvbnQtd2VpZ2h0OjUwMDtsaW5lLWhlaWdodDoxLjQ7bGV0dGVyLXNwYWNpbmc6MC4wNWVtO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZX0KLmxhYmVsLWxne2ZvbnQtZmFtaWx5OidJbnRlcicsc2Fucy1zZXJpZjtmb250LXNpemU6MC44NzVyZW07Zm9udC13ZWlnaHQ6NjAwO2xpbmUtaGVpZ2h0OjEuNDtsZXR0ZXItc3BhY2luZzowLjAyZW19Ci5tZXRyaWMteGx7Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjIuMjVyZW07Zm9udC13ZWlnaHQ6NzAwO2xpbmUtaGVpZ2h0OjEuMTtsZXR0ZXItc3BhY2luZzotMC4wM2VtfQoubWV0cmljLWxne2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxLjVyZW07Zm9udC13ZWlnaHQ6NjAwO2xpbmUtaGVpZ2h0OjEuMjtsZXR0ZXItc3BhY2luZzotMC4wMmVtfQoubWV0cmljLW1ke2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxcmVtO2ZvbnQtd2VpZ2h0OjUwMDtsaW5lLWhlaWdodDoxLjN9Ci5tb25vLXNte2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZTowLjc1cmVtO2ZvbnQtd2VpZ2h0OjQwMDtsaW5lLWhlaWdodDoxLjZ9CgovKiA9PT09PSBMQVlPVVQgPT09PT0gKi8KLmNvbnRhaW5lcnttYXgtd2lkdGg6MTQwMHB4O21hcmdpbjowIGF1dG87cGFkZGluZzowIHZhcigtLXNwYWNlLXhsKX0KQG1lZGlhKG1heC13aWR0aDo3NjhweCl7LmNvbnRhaW5lcntwYWRkaW5nOjAgdmFyKC0tc3BhY2UtbWQpfX0KCi8qID09PT09IFRPUCBCQVIgPT09PT0gKi8KI3RvcGJhcnsKICBwb3NpdGlvbjpzdGlja3k7dG9wOjA7ei1pbmRleDoxMDA7CiAgYmFja2dyb3VuZDp2YXIoLS1iZ1N1cmZhY2UpOwogIGJvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgaGVpZ2h0OjU2cHg7Cn0KI3RvcGJhciAuY29udGFpbmVyewogIGRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47CiAgaGVpZ2h0OjEwMCU7Cn0KLnRvcGJhci1sZWZ0e2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOnZhcigtLXNwYWNlLW1kKX0KLnRvcGJhci1sb2dvewogIHdpZHRoOjEwcHg7aGVpZ2h0OjEwcHg7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtZnVsbCk7CiAgYmFja2dyb3VuZDp2YXIoLS1zdWNjZXNzKTsKICBhbmltYXRpb246cHVsc2UgMnMgaW5maW5pdGU7Cn0KLnRvcGJhci1yaWdodHtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDp2YXIoLS1zcGFjZS1sZyl9CiNjbG9ja3tmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MC44NzVyZW07Y29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSl9Ci5yZWZyZXNoLWluZGljYXRvcntkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDp2YXIoLS1zcGFjZS14cyk7Y29sb3I6dmFyKC0tdGV4dE11dGVkKX0KLnJlZnJlc2gtaW5kaWNhdG9yIC5kb3R7d2lkdGg6NnB4O2hlaWdodDo2cHg7Ym9yZGVyLXJhZGl1czo1MCU7YmFja2dyb3VuZDp2YXIoLS1wcmltYXJ5KX0KCi8qID09PT09IFJFRlJFU0ggUFJPR1JFU1MgQkFSICsgREFUQSBUSU1FU1RBTVAgPT09PT0gKi8KI3JlZnJlc2gtYmFyewogIGJhY2tncm91bmQ6dmFyKC0tYmdTdXJmYWNlKTsKICBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIHBhZGRpbmc6N3B4IDAgOXB4Owp9CiNyZWZyZXNoLWJhciAuY29udGFpbmVye2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjVweH0KLnJlZnJlc2gtcHJvZ3Jlc3N7CiAgcG9zaXRpb246cmVsYXRpdmU7aGVpZ2h0OjVweDtib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cy1mdWxsKTsKICBiYWNrZ3JvdW5kOnZhcigtLWJnQ2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO292ZXJmbG93OmhpZGRlbjsKfQoucmVmcmVzaC1wcm9ncmVzcyAuZmlsbHsKICBwb3NpdGlvbjphYnNvbHV0ZTt0b3A6MDtsZWZ0OjA7Ym90dG9tOjA7d2lkdGg6MCU7CiAgYmFja2dyb3VuZDp2YXIoLS1wcmltYXJ5KTt0cmFuc2l0aW9uOndpZHRoIDAuNHMgbGluZWFyOwp9Ci5yZWZyZXNoLXByb2dyZXNzIC5maWxsLndhcm57YmFja2dyb3VuZDp2YXIoLS13YXJuaW5nKX0KLnJlZnJlc2gtcHJvZ3Jlc3MgLmZpbGwuY3JpdHtiYWNrZ3JvdW5kOnZhcigtLWNyaXRpY2FsKX0KLnJlZnJlc2gtcHJvZ3Jlc3MtbGFiZWx7CiAgZGlzcGxheTpmbGV4O2p1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuO2dhcDp2YXIoLS1zcGFjZS1tZCk7CiAgZm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjAuNjVyZW07Y29sb3I6dmFyKC0tdGV4dE11dGVkKTsKfQoucmVmcmVzaC1wcm9ncmVzcy1sYWJlbCAucGN0e2NvbG9yOnZhcigtLXRleHRTZWNvbmRhcnkpfQoKLyogPT09PT0gTEFZT1VUIFNXSVRDSEVSID09PT09ICovCi5sYXlvdXQtc3dpdGNoZXJ7CiAgZGlzcGxheTpmbGV4O2dhcDoycHg7YmFja2dyb3VuZDp2YXIoLS1iZ0NhcmQpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTtib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cy1mdWxsKTsKICBwYWRkaW5nOjJweDsKfQoubGF5b3V0LXN3aXRjaGVyIGJ1dHRvbnsKICBiYWNrZ3JvdW5kOnRyYW5zcGFyZW50O2JvcmRlcjpub25lO2JvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLWZ1bGwpOwogIHBhZGRpbmc6NHB4IDEycHg7Y3Vyc29yOnBvaW50ZXI7CiAgZm9udC1mYW1pbHk6J0ludGVyJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZTowLjc1cmVtO2ZvbnQtd2VpZ2h0OjUwMDsKICBjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO3RyYW5zaXRpb246YWxsIDAuMnM7CiAgd2hpdGUtc3BhY2U6bm93cmFwOwp9Ci5sYXlvdXQtc3dpdGNoZXIgYnV0dG9uLmFjdGl2ZXsKICBiYWNrZ3JvdW5kOnZhcigtLXByaW1hcnkpO2NvbG9yOnZhcigtLXRleHRPblByaW1hcnkpOwp9Ci5sYXlvdXQtc3dpdGNoZXIgYnV0dG9uOmhvdmVyOm5vdCguYWN0aXZlKXtjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KX0KCi8qID09PT09IFNUQVRVUyBTVFJJUCA9PT09PSAqLwojc3RhdHVzLXN0cmlwewogIGJhY2tncm91bmQ6dmFyKC0tYmdTdXJmYWNlKTsKICBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwp9CiNzdGF0dXMtc3RyaXAgLmNvbnRhaW5lcnsKICBkaXNwbGF5OmZsZXg7Z2FwOnZhcigtLXNwYWNlLXNtKTtwYWRkaW5nOnZhcigtLXNwYWNlLXNtKSAwOwogIG92ZXJmbG93LXg6YXV0bzsKfQouc3RhdHVzLWNoaXB7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6dmFyKC0tc3BhY2UteHMpOwogIHBhZGRpbmc6NHB4IDEwcHg7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtZnVsbCk7CiAgYmFja2dyb3VuZDp2YXIoLS1iZ0NhcmQpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICB3aGl0ZS1zcGFjZTpub3dyYXA7Cn0KLnN0YXR1cy1jaGlwIC5kb3R7d2lkdGg6OHB4O2hlaWdodDo4cHg7Ym9yZGVyLXJhZGl1czo1MCU7ZmxleC1zaHJpbms6MH0KLnN0YXR1cy1jaGlwIC5kb3Qub25saW5le2JhY2tncm91bmQ6dmFyKC0tc3VjY2Vzcyl9Ci5zdGF0dXMtY2hpcCAuZG90Lm9mZmxpbmV7YmFja2dyb3VuZDp2YXIoLS1jcml0aWNhbCl9Ci5zdGF0dXMtY2hpcCAubmFtZXtmb250LXNpemU6MC43NXJlbTtmb250LXdlaWdodDo1MDA7Y29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSl9Ci5zdGF0dXMtY2hpcHtjdXJzb3I6cG9pbnRlcn0KLnN0YXR1cy1jaGlwLmFjdGl2ZXtib3JkZXItY29sb3I6dmFyKC0tcHJpbWFyeSk7YmFja2dyb3VuZDp2YXIoLS1iZ0hvdmVyKTtib3gtc2hhZG93OjAgMCAwIDFweCB2YXIoLS1wcmltYXJ5KX0KLnN0YXR1cy1jaGlwLmFjdGl2ZSAubmFtZXtjb2xvcjp2YXIoLS1wcmltYXJ5KX0KLnN0YXR1cy1jaGlwIC5wbGF0Zm9ybXtmb250LXNpemU6MC42NXJlbTtjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO21hcmdpbi1sZWZ0OjJweH0KCi8qIFNrZWxldG9uIGNoaXAgZm9yIGxvYWRpbmcgc3RhdGUgKi8KLnN0YXR1cy1jaGlwLnNrZWxldG9uLWNoaXB7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO29wYWNpdHk6MC42fQouc3RhdHVzLWNoaXAuc2tlbGV0b24tY2hpcCAuc2tlbGV0b257YmFja2dyb3VuZDp2YXIoLS1iZ0hvdmVyKX0KCi8qID09PT09IFBST0ZJTEUgQ0FSRFMgPT09PT0gKi8KLnByb2ZpbGUtY2FyZHMtc2VjdGlvbntwYWRkaW5nOnZhcigtLXNwYWNlLWxnKSAwfQoucHJvZmlsZS1jYXJkcy1ncmlkewogIGRpc3BsYXk6Z3JpZDsKICBncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KGF1dG8tZmlsbCxtaW5tYXgoMTcwcHgsMWZyKSk7CiAgZ2FwOnZhcigtLXNwYWNlLW1kKTsKfQpAbWVkaWEobWF4LXdpZHRoOjc2OHB4KXsucHJvZmlsZS1jYXJkcy1ncmlke2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoMiwxZnIpfX0KQG1lZGlhKG1heC13aWR0aDo0ODBweCl7LnByb2ZpbGUtY2FyZHMtZ3JpZHtncmlkLXRlbXBsYXRlLWNvbHVtbnM6MWZyfX0KCi5wcm9maWxlLWNhcmR7CiAgYmFja2dyb3VuZDp2YXIoLS1iZ0NhcmQpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cy1sZyk7CiAgcGFkZGluZzp2YXIoLS1zcGFjZS1sZyk7CiAgZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6dmFyKC0tc3BhY2UteHMpOwogIHRyYW5zaXRpb246Ym9yZGVyLWNvbG9yIDAuM3M7CiAgY3Vyc29yOmRlZmF1bHQ7Cn0KLnByb2ZpbGUtY2FyZDpob3Zlcntib3JkZXItY29sb3I6dmFyKC0tYm9yZGVyTGlnaHQpfQoucHJvZmlsZS1jYXJke2N1cnNvcjpwb2ludGVyfQoucHJvZmlsZS1jYXJkLmFjdGl2ZXtib3JkZXItY29sb3I6dmFyKC0tcHJpbWFyeSk7Ym94LXNoYWRvdzowIDAgMCAxcHggdmFyKC0tcHJpbWFyeSl9Ci5wcm9maWxlLWNhcmQuYWN0aXZlIC5wYy1uYW1le2NvbG9yOnZhcigtLXByaW1hcnkpfQoucHJvZmlsZS1jYXJkIC5wYy1oZWFkZXJ7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6dmFyKC0tc3BhY2Utc20pO21hcmdpbi1ib3R0b206dmFyKC0tc3BhY2Utc20pfQoucHJvZmlsZS1jYXJkIC5wYy1kb3R7d2lkdGg6MTBweDtoZWlnaHQ6MTBweDtib3JkZXItcmFkaXVzOjUwJTtmbGV4LXNocmluazowfQoucHJvZmlsZS1jYXJkIC5wYy1kb3Qub25saW5le2JhY2tncm91bmQ6dmFyKC0tc3VjY2Vzcyk7YW5pbWF0aW9uOnB1bHNlIDJzIGluZmluaXRlfQoucHJvZmlsZS1jYXJkIC5wYy1kb3Qub2ZmbGluZXtiYWNrZ3JvdW5kOnZhcigtLWNyaXRpY2FsKX0KLnByb2ZpbGUtY2FyZCAucGMtZG90LnN0YWxle2JhY2tncm91bmQ6dmFyKC0td2FybmluZyk7YW5pbWF0aW9uOnB1bHNlIDFzIGluZmluaXRlfQoucHJvZmlsZS1jYXJkIC5wYy1uYW1le2ZvbnQtd2VpZ2h0OjYwMDtmb250LXNpemU6MC45cmVtO2NvbG9yOnZhcigtLXRleHRQcmltYXJ5KTtvdmVyZmxvdzpoaWRkZW47dGV4dC1vdmVyZmxvdzplbGxpcHNpczt3aGl0ZS1zcGFjZTpub3dyYXB9Ci5wcm9maWxlLWNhcmQgLnBjLW1ldGF7ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6MnB4fQoucHJvZmlsZS1jYXJkIC5wYy1tZXRhLWl0ZW17Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjAuN3JlbTtjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KTt3aGl0ZS1zcGFjZTpub3dyYXB9Ci5wcm9maWxlLWNhcmQgLnBjLW1ldGEtaXRlbTo6YmVmb3Jle2NvbnRlbnQ6J+KWuCAnO2NvbG9yOnZhcigtLXByaW1hcnkpO21hcmdpbi1yaWdodDoycHh9Ci5wcm9maWxlLWNhcmQgLnBjLXBsYXRmb3Jtc3tkaXNwbGF5OmZsZXg7ZmxleC13cmFwOndyYXA7Z2FwOjNweDttYXJnaW4tdG9wOmF1dG87cGFkZGluZy10b3A6dmFyKC0tc3BhY2Utc20pO2JvcmRlci10b3A6MXB4IHNvbGlkIHZhcigtLWJvcmRlcil9Ci5wcm9maWxlLWNhcmQgLnBjLXBsYXQtY2hpcHtmb250LXNpemU6MC42cmVtO3BhZGRpbmc6MXB4IDVweDtiYWNrZ3JvdW5kOnZhcigtLWJnSG92ZXIpO2JvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLXNtKTtjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZX0KLnByb2ZpbGUtY2FyZCAucGMtcGxhdC1jaGlwLmNvbm5lY3RlZHtjb2xvcjp2YXIoLS1zdWNjZXNzKTtiYWNrZ3JvdW5kOnJnYmEoMzQsMTk3LDk0LDAuMDgpfQoucHJvZmlsZS1jYXJkIC5wYy1mb290ZXJ7Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjAuNnJlbTtjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO3BhZGRpbmctdG9wOnZhcigtLXNwYWNlLXhzKTtib3JkZXItdG9wOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpfQoucHJvZmlsZS1jYXJkLnNrZWxldG9uLWNhcmR7b3BhY2l0eTowLjY7cG9pbnRlci1ldmVudHM6bm9uZX0KLnByb2ZpbGUtY2FyZC5za2VsZXRvbi1jYXJkIC5za2VsZXRvbntiYWNrZ3JvdW5kOnZhcigtLWJnSG92ZXIpfQoKLyogPT09PT0gTUFJTiBDT05URU5UID09PT09ICovCiNtYWlue3BhZGRpbmc6dmFyKC0tc3BhY2UteGwpIDB9CgovKiBLUEkgR3JpZCAqLwoua3BpLWdyaWR7CiAgZGlzcGxheTpncmlkOwogIGdyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoNCwxZnIpOwogIGdhcDp2YXIoLS1zcGFjZS1sZyk7CiAgbWFyZ2luLWJvdHRvbTp2YXIoLS1zcGFjZS14bCk7Cn0KQG1lZGlhKG1heC13aWR0aDoxMjgwcHgpey5rcGktZ3JpZHtncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KDIsMWZyKX19CkBtZWRpYShtYXgtd2lkdGg6NzY4cHgpey5rcGktZ3JpZHtncmlkLXRlbXBsYXRlLWNvbHVtbnM6MWZyfX0KCi5tZXRyaWMtdGlsZXsKICBiYWNrZ3JvdW5kOnZhcigtLWJnQ2FyZCk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLWxnKTsKICBwYWRkaW5nOnZhcigtLXNwYWNlLWxnKTsKICBkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2dhcDp2YXIoLS1zcGFjZS1zbSk7CiAgdHJhbnNpdGlvbjpib3JkZXItY29sb3IgMC4zczsKfQoubWV0cmljLXRpbGU6aG92ZXJ7Ym9yZGVyLWNvbG9yOnZhcigtLWJvcmRlckxpZ2h0KX0KLm1ldHJpYy10aWxlLmNyaXRpY2Fse2JvcmRlci1sZWZ0OjNweCBzb2xpZCB2YXIoLS1jcml0aWNhbCl9Ci5tZXRyaWMtdGlsZS53YXJuaW5ne2JvcmRlci1sZWZ0OjNweCBzb2xpZCB2YXIoLS13YXJuaW5nKX0KLm1ldHJpYy10aWxlIC50aWxlLWxhYmVse2NvbG9yOnZhcigtLXRleHRTZWNvbmRhcnkpfQoubWV0cmljLXRpbGUgLnRpbGUtdmFsdWV7Y29sb3I6dmFyKC0tdGV4dFByaW1hcnkpfQoubWV0cmljLXRpbGUgLnRpbGUtc3Vie2NvbG9yOnZhcigtLXRleHRNdXRlZCl9CgovKiBDaGFydHMgUm93ICovCi5jaGFydHMtcm93ewogIGRpc3BsYXk6Z3JpZDsKICBncmlkLXRlbXBsYXRlLWNvbHVtbnM6MmZyIDFmcjsKICBnYXA6dmFyKC0tc3BhY2UtbGcpOwogIG1hcmdpbi1ib3R0b206dmFyKC0tc3BhY2UteGwpOwp9CkBtZWRpYShtYXgtd2lkdGg6NzY4cHgpey5jaGFydHMtcm93e2dyaWQtdGVtcGxhdGUtY29sdW1uczoxZnJ9fQoKLmNoYXJ0LWNhcmR7CiAgYmFja2dyb3VuZDp2YXIoLS1iZ0NhcmQpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cy1sZyk7CiAgcGFkZGluZzp2YXIoLS1zcGFjZS1sZyk7Cn0KLmNoYXJ0LWNhcmQgLmNoYXJ0LWhlYWRlcnttYXJnaW4tYm90dG9tOnZhcigtLXNwYWNlLW1kKX0KLmNoYXJ0LWNhcmQgLmNoYXJ0LWJvZHl7aGVpZ2h0OjMwMHB4fQoKLyogVG9wIG1vZGVsZSDigJQgdGFiZWxhICovCi5tb2RlbHMtdGFibGV7d2lkdGg6MTAwJTtib3JkZXItY29sbGFwc2U6Y29sbGFwc2U7Zm9udC1zaXplOjAuNzhyZW19Ci5tb2RlbHMtdGFibGUgdGh7CiAgdGV4dC1hbGlnbjpsZWZ0O3BhZGRpbmc6OHB4IDEycHg7Zm9udC1zaXplOjAuNjVyZW07dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlOwogIGxldHRlci1zcGFjaW5nOjAuMDVlbTtjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlckxpZ2h0KTsKICBmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTt3aGl0ZS1zcGFjZTpub3dyYXA7Cn0KLm1vZGVscy10YWJsZSB0ZHtwYWRkaW5nOjhweCAxMnB4O2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7dmVydGljYWwtYWxpZ246bWlkZGxlfQoubW9kZWxzLXRhYmxlIHRyOmxhc3QtY2hpbGQgdGR7Ym9yZGVyLWJvdHRvbTpub25lfQoubW9kZWxzLXRhYmxlIHRyOmhvdmVyIHRke2JhY2tncm91bmQ6dmFyKC0tYmdIb3Zlcil9Ci5tb2RlbHMtdGFibGUgLm0tcmFua3tjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlO3dpZHRoOjMwcHh9Ci5tb2RlbHMtdGFibGUgLm0tbmFtZXtjb2xvcjp2YXIoLS10ZXh0UHJpbWFyeSk7Zm9udC13ZWlnaHQ6NTAwfQoubW9kZWxzLXRhYmxlIC5tLXRva2VucywubW9kZWxzLXRhYmxlIC5tLWNvc3QsLm1vZGVscy10YWJsZSAubS1jYWxsc3tmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTtjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KTt3aGl0ZS1zcGFjZTpub3dyYXA7dGV4dC1hbGlnbjpyaWdodH0KLm1vZGVscy10YWJsZSAubS1jb3N0e2NvbG9yOnZhcigtLXRleHRQcmltYXJ5KTtmb250LXdlaWdodDo2MDB9Ci5tb2RlbHMtdGFibGUgLm0tY2FsbHN7Y29sb3I6dmFyKC0tdGV4dE11dGVkKX0KCi8qIERldGFpbCBSb3cgKi8KLmRldGFpbC1yb3d7CiAgZGlzcGxheTpncmlkOwogIGdyaWQtdGVtcGxhdGUtY29sdW1uczozZnIgMmZyOwogIGdhcDp2YXIoLS1zcGFjZS1sZyk7CiAgbWFyZ2luLWJvdHRvbTp2YXIoLS1zcGFjZS14bCk7Cn0KQG1lZGlhKG1heC13aWR0aDo3NjhweCl7LmRldGFpbC1yb3d7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOjFmcn19CgovKiBTZXNzaW9ucyAqLwouc2Vzc2lvbnMtY2FyZHsKICBiYWNrZ3JvdW5kOnZhcigtLWJnQ2FyZCk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLWxnKTsKfQouc2Vzc2lvbnMtY2FyZCAuY2FyZC1oZWFkZXJ7CiAgcGFkZGluZzp2YXIoLS1zcGFjZS1sZyk7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47YWxpZ24taXRlbXM6Y2VudGVyOwp9Ci5zZXNzaW9uLXJvd3sKICBkaXNwbGF5OmdyaWQ7CiAgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOmF1dG8gYXV0byAxZnIgYXV0byBhdXRvIGF1dG8gYXV0byBhdXRvOwogIGdhcDp2YXIoLS1zcGFjZS1tZCk7YWxpZ24taXRlbXM6Y2VudGVyOwogIHBhZGRpbmc6dmFyKC0tc3BhY2UtbWQpIHZhcigtLXNwYWNlLWxnKTsKICBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIHRyYW5zaXRpb246YmFja2dyb3VuZCAwLjE1czsKfQouc2Vzc2lvbi1yb3c6aG92ZXJ7YmFja2dyb3VuZDp2YXIoLS1iZ0hvdmVyKX0KLnNlc3Npb24tcm93Omxhc3QtY2hpbGR7Ym9yZGVyLWJvdHRvbTpub25lfQpAbWVkaWEobWF4LXdpZHRoOjc2OHB4KXsKICAuc2Vzc2lvbi1yb3d7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOmF1dG8gMWZyIGF1dG87Z2FwOnZhcigtLXNwYWNlLXNtKX0KICAuc2Vzc2lvbi1yb3cgLmhpZGUtbW9iaWxle2Rpc3BsYXk6bm9uZX0KfQoucHJvZmlsZS1jaGlwLW1pbml7CiAgZGlzcGxheTppbmxpbmUtYmxvY2s7cGFkZGluZzoxcHggNnB4OwogIGJhY2tncm91bmQ6dmFyKC0tYmdIb3Zlcik7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtZnVsbCk7CiAgZm9udC1zaXplOjAuNnJlbTtmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTsKICBjb2xvcjp2YXIoLS1wcmltYXJ5KTt3aGl0ZS1zcGFjZTpub3dyYXA7Cn0KCi8qIEdhdGV3YXkgKi8KLmdhdGV3YXktY2FyZHsKICBiYWNrZ3JvdW5kOnZhcigtLWJnQ2FyZCk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLWxnKTsKfQouZ2F0ZXdheS1jYXJkIC5jYXJkLWhlYWRlcnsKICBwYWRkaW5nOnZhcigtLXNwYWNlLWxnKTtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGRpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjthbGlnbi1pdGVtczpjZW50ZXI7Cn0KLmdhdGV3YXktcm93ewogIGRpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjthbGlnbi1pdGVtczpjZW50ZXI7CiAgcGFkZGluZzp2YXIoLS1zcGFjZS1tZCkgdmFyKC0tc3BhY2UtbGcpOwogIGJvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgdHJhbnNpdGlvbjpiYWNrZ3JvdW5kIDAuMTVzOwp9Ci5nYXRld2F5LXJvdzpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLWJnSG92ZXIpfQouZ2F0ZXdheS1yb3c6bGFzdC1jaGlsZHtib3JkZXItYm90dG9tOm5vbmV9Ci5nYXRld2F5LXJvdyAuZ3ctbGVmdHtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDp2YXIoLS1zcGFjZS1zbSk7bWluLXdpZHRoOjB9Ci5nYXRld2F5LXJvdyAuZ3ctbmFtZXtmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MC43NXJlbTtmb250LXdlaWdodDo1MDA7Y29sb3I6dmFyKC0tdGV4dFByaW1hcnkpO292ZXJmbG93OmhpZGRlbjt0ZXh0LW92ZXJmbG93OmVsbGlwc2lzO3doaXRlLXNwYWNlOm5vd3JhcH0KLmdhdGV3YXktcm93IC5ndy1zdWJ7Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjAuNjVyZW07Y29sb3I6dmFyKC0tdGV4dE11dGVkKTttYXJnaW4tbGVmdDoycHh9Ci5nYXRld2F5LXJvdyAuZ3ctc3RhdHVze2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOnZhcigtLXNwYWNlLXhzKTtmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MC43cmVtO2ZvbnQtd2VpZ2h0OjYwMH0KCi8qIFN0YXR1cyBrcm9wa2kgZ2F0ZXdheSDigJQgNCBzdGFueTogb2sgLyB3YXJuIC8gZXJyIC8gbm9uZSAqLwpAa2V5ZnJhbWVzIGd3UHVsc2V7MCUsMTAwJXtvcGFjaXR5OjE7Ym94LXNoYWRvdzowIDAgOHB4IGN1cnJlbnRDb2xvcn01MCV7b3BhY2l0eTowLjU1O2JveC1zaGFkb3c6MCAwIDNweCBjdXJyZW50Q29sb3J9fQpAa2V5ZnJhbWVzIGd3QmxpbmtTb2Z0ezAlLDEwMCV7b3BhY2l0eToxO2JveC1zaGFkb3c6MCAwIDZweCBjdXJyZW50Q29sb3J9NTAle29wYWNpdHk6MC42Mjtib3gtc2hhZG93OjAgMCAycHggY3VycmVudENvbG9yfX0KQGtleWZyYW1lcyBnd0JsaW5rRmFzdHswJSwxMDAle29wYWNpdHk6MTtib3gtc2hhZG93OjAgMCAxMHB4IGN1cnJlbnRDb2xvcn01MCV7b3BhY2l0eTowLjEyO2JveC1zaGFkb3c6bm9uZX19Ci5ndy1kb3R7d2lkdGg6OXB4O2hlaWdodDo5cHg7Ym9yZGVyLXJhZGl1czo1MCU7ZmxleC1zaHJpbms6MDttYXJnaW4tdG9wOjFweH0KLmd3LWRvdC5va3tiYWNrZ3JvdW5kOnZhcigtLXN1Y2Nlc3MpO2NvbG9yOnZhcigtLXN1Y2Nlc3MpO2FuaW1hdGlvbjpnd1B1bHNlIDJzIGVhc2UtaW4tb3V0IGluZmluaXRlfQouZ3ctZG90Lndhcm57YmFja2dyb3VuZDojZWFiMzA4O2NvbG9yOiNlYWIzMDg7YW5pbWF0aW9uOmd3QmxpbmtTb2Z0IDJzIGVhc2UtaW4tb3V0IGluZmluaXRlfQouZ3ctZG90LmVycntiYWNrZ3JvdW5kOnZhcigtLWNyaXRpY2FsKTtjb2xvcjp2YXIoLS1jcml0aWNhbCk7YW5pbWF0aW9uOmd3QmxpbmtGYXN0IDAuNXMgc3RlcHMoMSkgaW5maW5pdGV9Ci5ndy1kb3Qubm9uZXtiYWNrZ3JvdW5kOnZhcigtLXRleHRNdXRlZCk7b3BhY2l0eTowLjQ1O2FuaW1hdGlvbjpub25lfQouZ2F0ZXdheS1yb3cgLmd3LWluZm97ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6MnB4O21pbi13aWR0aDowfQouZ2F0ZXdheS1yb3cgLmd3LWFnZW50c3tmb250LXNpemU6MC42MnJlbTtjb2xvcjp2YXIoLS1wcmltYXJ5KTttYXJnaW4tbGVmdDo2cHg7Zm9udC13ZWlnaHQ6NTAwfQouZ2F0ZXdheS1yb3cgLmd3LW1ldGF7Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjAuNjJyZW07Y29sb3I6dmFyKC0tdGV4dE11dGVkKTtkaXNwbGF5OmZsZXg7ZmxleC13cmFwOndyYXA7Z2FwOjhweDttYXJnaW4tdG9wOjJweH0KLmdhdGV3YXktcm93IC5ndy1tZXRhIC5mbGFne2NvbG9yOiNlYWIzMDg7Zm9udC13ZWlnaHQ6NjAwfQouZ2F0ZXdheS1yb3cgLmd3LW1ldGEgLmZsYWctcmVzdGFydHtjb2xvcjojZjU5ZTBiO2ZvbnQtd2VpZ2h0OjcwMH0KLmdhdGV3YXktcm93IC5ndy1tZXRhIC5mbGFnLWV4aXR7Y29sb3I6dmFyKC0tY3JpdGljYWwpfQouZ2F0ZXdheS1yb3cgLmd3LW1ldGEgLmJhZHtjb2xvcjp2YXIoLS1jcml0aWNhbCl9Ci5nYXRld2F5LXJvdyAuZ3ctbWV0YSAub2t2e2NvbG9yOnZhcigtLXN1Y2Nlc3MpfQouZ3ctZXhwYW5ke2JhY2tncm91bmQ6dmFyKC0tYmdIb3Zlcik7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXJMaWdodCk7Y29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSk7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtZnVsbCk7Zm9udC1zaXplOjAuNjJyZW07Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7cGFkZGluZzoycHggOHB4O2N1cnNvcjpwb2ludGVyO3doaXRlLXNwYWNlOm5vd3JhcH0KLmd3LWV4cGFuZDpob3Zlcntjb2xvcjp2YXIoLS10ZXh0UHJpbWFyeSk7Ym9yZGVyLWNvbG9yOnZhcigtLXByaW1hcnkpfQouZ3ctcGxhdGZvcm1ze2Rpc3BsYXk6bm9uZTtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC4xNSk7cGFkZGluZzo0cHggdmFyKC0tc3BhY2UtbGcpIDhweDtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpfQouZ2F0ZXdheS1yb3cgfiAuZ3ctcGxhdGZvcm1zLm9wZW57ZGlzcGxheTpibG9ja30KLmd3LXBsYXRmb3JtLXJvd3tkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47YWxpZ24taXRlbXM6Y2VudGVyO3BhZGRpbmc6M3B4IDA7Ym9yZGVyLWJvdHRvbToxcHggZGFzaGVkIHZhcigtLWJvcmRlcik7Zm9udC1zaXplOjAuNjJyZW07Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2V9Ci5ndy1wbGF0Zm9ybS1yb3c6bGFzdC1jaGlsZHtib3JkZXItYm90dG9tOm5vbmV9Ci5ndy1wbGF0Zm9ybS1yb3cgLnBsLXN0YXRle2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjZweH0KLmd3LXBsLWRvdHt3aWR0aDo2cHg7aGVpZ2h0OjZweDtib3JkZXItcmFkaXVzOjUwJTtmbGV4LXNocmluazowfQouZ3ctcGwtZG90LmNvbm5lY3RlZHtiYWNrZ3JvdW5kOnZhcigtLXN1Y2Nlc3MpfQouZ3ctcGwtZG90LmRpc2Nvbm5lY3RlZHtiYWNrZ3JvdW5kOnZhcigtLWNyaXRpY2FsKX0KLmd3LXBsLWRvdC5zdGFydGluZ3tiYWNrZ3JvdW5kOiNlYWIzMDh9Ci5ndy1wbC1kb3QudW5rbm93bntiYWNrZ3JvdW5kOnZhcigtLXRleHRNdXRlZCl9Ci5ndy1wbGF0Zm9ybS1yb3cgLnBsLWVycntjb2xvcjp2YXIoLS1jcml0aWNhbCk7Zm9udC1zaXplOjAuNThyZW07bWF4LXdpZHRoOjE4MHB4O292ZXJmbG93OmhpZGRlbjt0ZXh0LW92ZXJmbG93OmVsbGlwc2lzO3doaXRlLXNwYWNlOm5vd3JhcH0KCi8qIEZvb3RlciAqLwojZm9vdGVyewogIGJhY2tncm91bmQ6dmFyKC0tYmdTdXJmYWNlKTsKICBib3JkZXItdG9wOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIHBhZGRpbmc6dmFyKC0tc3BhY2UtbGcpIDA7Cn0KLmZvb3Rlci1jYXJkc3tkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCgzLDFmcik7Z2FwOnZhcigtLXNwYWNlLWxnKX0KQG1lZGlhKG1heC13aWR0aDo3NjhweCl7LmZvb3Rlci1jYXJkc3tncmlkLXRlbXBsYXRlLWNvbHVtbnM6MWZyfX0KLmZvb3Rlci1jYXJke2JhY2tncm91bmQ6dmFyKC0tYmdDYXJkKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtbGcpO3BhZGRpbmc6dmFyKC0tc3BhY2UtbGcpfQouZm9vdGVyLWNhcmQgLmZjLWhlYWRlcnttYXJnaW4tYm90dG9tOnZhcigtLXNwYWNlLXNtKX0KLmtleS1jaGlwewogIGRpc3BsYXk6aW5saW5lLWJsb2NrO3BhZGRpbmc6MnB4IDhweDttYXJnaW46MnB4OwogIGJhY2tncm91bmQ6dmFyKC0tYmdIb3Zlcik7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtc20pOwogIGZvbnQtc2l6ZTowLjdyZW07Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7CiAgY29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSk7Cn0KLmJhZGdlewogIGRpc3BsYXk6aW5saW5lLWJsb2NrO3BhZGRpbmc6MnB4IDhweDtib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cy1mdWxsKTsKICBmb250LXNpemU6MC43cmVtO2ZvbnQtd2VpZ2h0OjUwMDsKfQouYmFkZ2Uub2t7YmFja2dyb3VuZDojMDUyRTE2O2NvbG9yOnZhcigtLXN1Y2Nlc3MpfQouYmFkZ2Uud2FybntiYWNrZ3JvdW5kOiM0MjIwMDY7Y29sb3I6dmFyKC0td2FybmluZyl9Ci5iYWRnZS5lcnJ7YmFja2dyb3VuZDojMkUwODE1O2NvbG9yOnZhcigtLWNyaXRpY2FsKX0KCi8qID09PT09IFNUQVRFUyA9PT09PSAqLwouc3RhdGUtbXNnewogIGRpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7CiAgcGFkZGluZzp2YXIoLS1zcGFjZS0zeGwpO3RleHQtYWxpZ246Y2VudGVyO2dhcDp2YXIoLS1zcGFjZS1tZCk7CiAgbWluLWhlaWdodDoyMDBweDsKfQouc3RhdGUtbXNnIC5pY29ue2ZvbnQtc2l6ZToyLjVyZW19Ci5zdGF0ZS1tc2cgLnRpdGxle2NvbG9yOnZhcigtLXRleHRQcmltYXJ5KX0KLnN0YXRlLW1zZyAuZGVzY3tjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KX0KCi8qIFNrZWxldG9uIGxvYWRpbmcgKi8KQGtleWZyYW1lcyBzaGltbWVyezAle29wYWNpdHk6MC4zfTUwJXtvcGFjaXR5OjAuNn0xMDAle29wYWNpdHk6MC4zfX0KLnNrZWxldG9uewogIGJhY2tncm91bmQ6dmFyKC0tYmdIb3Zlcik7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtbWQpOwogIGFuaW1hdGlvbjpzaGltbWVyIDEuNXMgaW5maW5pdGU7Cn0KLnNrZWxldG9uLXRleHR7aGVpZ2h0OjFyZW07d2lkdGg6NjAlO21hcmdpbi1ib3R0b206dmFyKC0tc3BhY2Utc20pfQouc2tlbGV0b24tdmFsdWV7aGVpZ2h0OjIuMjVyZW07d2lkdGg6NDAlfQoKLyogUHVsc2UgYW5pbWF0aW9uIGZvciBzdGF0dXMgZG90cyAqLwpAa2V5ZnJhbWVzIHB1bHNlewogIDAlLDEwMCV7b3BhY2l0eToxfQogIDUwJXtvcGFjaXR5OjAuNH0KfQoKLyogPT09PT0gUElQLUJPWSBUSEVNRSAoVkFVTFQtVEVDIGluc3BpcmVkKSA9PT09PSAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXXsKICAtLXByaW1hcnk6ICMxNEZGMTc7CiAgLS1zZWNvbmRhcnk6ICMwRUJEMEY7CiAgLS1zdWNjZXNzOiAjMTRGRjE3OwogIC0td2FybmluZzogI0M4RkYwMDsKICAtLWNyaXRpY2FsOiAjRkYzQjNCOwogIC0taW5mbzogIzE0RkYxNzsKICAtLW5ldXRyYWw6ICMyQTRBMjA7CiAgLS1iZ1Jvb3Q6ICMwNTA4MDM7CiAgLS1iZ1N1cmZhY2U6ICMwODBDMDU7CiAgLS1iZ0NhcmQ6ICMwQTEyMDc7CiAgLS1iZ0hvdmVyOiAjMEYxRDBBOwogIC0tYm9yZGVyOiAjMUE1QTEyOwogIC0tYm9yZGVyTGlnaHQ6ICMyMjhBMTg7CiAgLS10ZXh0UHJpbWFyeTogIzE0RkYxNzsKICAtLXRleHRTZWNvbmRhcnk6ICMwRUJEMEY7CiAgLS10ZXh0TXV0ZWQ6ICMyQTdBMjA7CiAgLS10ZXh0T25QcmltYXJ5OiAjMDUwODAzOwogIGZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsJ0NvdXJpZXIgTmV3Jyxtb25vc3BhY2U7Cn0KCi8qID09PT09IFBJUC1CT1k6IEdsb2JhbCB0ZXh0IGdsb3cgPT09PT0gKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmhlYWRpbmcteGwsCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5oZWFkaW5nLWxnLApib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuaGVhZGluZy1tZCwKYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmJvZHktbWQsCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5ib2R5LXNtLApib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAubGFiZWwtbWQsCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5sYWJlbC1sZywKYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLm1vbm8tc217CiAgZm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJywnQ291cmllciBOZXcnLG1vbm9zcGFjZTsKICB0ZXh0LXNoYWRvdzowIDAgNHB4IHJnYmEoMjAsMjU1LDIzLDAuNCksIDAgMCAxMnB4IHJnYmEoMjAsMjU1LDIzLDAuMTUpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tZXRyaWMteGwsCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tZXRyaWMtbGcsCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tZXRyaWMtbWR7CiAgdGV4dC1zaGFkb3c6MCAwIDhweCByZ2JhKDIwLDI1NSwyMywwLjUpLCAwIDAgMjBweCByZ2JhKDIwLDI1NSwyMywwLjIpOwp9CgovKiA9PT09PSBQSVAtQk9ZOiBUaGljayBDUlQgYmV6ZWwgZnJhbWUgPT09PT0gKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il17CiAgYm9yZGVyOjEwcHggc29saWQgIzFBM0ExMjsKICBib3JkZXItaW1hZ2U6bGluZWFyLWdyYWRpZW50KDEzNWRlZywjMEQyMDA4LCMxQTNBMTIgMzAlLCMyQTVBMjAgNTAlLCMxQTNBMTIgNzAlLCMwRDIwMDgpIDE7CiAgYm94LXNoYWRvdzppbnNldCAwIDAgODBweCByZ2JhKDAsMCwwLDAuNyk7CiAgbWluLWhlaWdodDoxMDB2aDsKfQpAbWVkaWEobWF4LXdpZHRoOjc2OHB4KXsKICBib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXXtib3JkZXItd2lkdGg6NnB4fQp9CgovKiA9PT09PSBQSVAtQk9ZOiBDUlQgdmlnbmV0dGUgb3ZlcmxheSA9PT09PSAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXTo6YmVmb3JlewogIGNvbnRlbnQ6Jyc7cG9zaXRpb246Zml4ZWQ7aW5zZXQ6MDtwb2ludGVyLWV2ZW50czpub25lO3otaW5kZXg6OTk5NzsKICBiYWNrZ3JvdW5kOnJhZGlhbC1ncmFkaWVudChlbGxpcHNlIGF0IDUwJSA1MCUsdHJhbnNwYXJlbnQgNTAlLHJnYmEoMCwwLDAsMC41KSAxMDAlKTsKfQoKLyogPT09PT0gUElQLUJPWTogQ1JUIHNjYW5saW5lcyA9PT09PSAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXTo6YWZ0ZXJ7CiAgY29udGVudDonJztwb3NpdGlvbjpmaXhlZDt0b3A6MDtsZWZ0OjA7cmlnaHQ6MDtib3R0b206MDsKICBiYWNrZ3JvdW5kOnJlcGVhdGluZy1saW5lYXItZ3JhZGllbnQoMGRlZywKICAgIHJnYmEoMjAsMjU1LDIzLDAuMDE1KSAwcHgsCiAgICByZ2JhKDIwLDI1NSwyMywwLjAxNSkgMXB4LAogICAgdHJhbnNwYXJlbnQgMXB4LAogICAgdHJhbnNwYXJlbnQgM3B4KTsKICBwb2ludGVyLWV2ZW50czpub25lO3otaW5kZXg6OTk5ODsKICBhbmltYXRpb246Y3JmRmxpY2tlciA2cyBpbmZpbml0ZTsKfQpAa2V5ZnJhbWVzIGNyZkZsaWNrZXJ7CiAgMCUsMTAwJXtvcGFjaXR5OjF9CiAgOTEle29wYWNpdHk6MX0KICA5MiV7b3BhY2l0eTowLjkyfQogIDkzJXtvcGFjaXR5OjAuNzV9CiAgOTQle29wYWNpdHk6MC45OH0KICA5NiV7b3BhY2l0eTowLjg4fQogIDk3JXtvcGFjaXR5OjF9Cn0KCi8qID09PT09IFBJUC1CT1k6IENvbXBvbmVudCBvdmVycmlkZXMgPT09PT0gKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gI3RvcGJhcnsKICBiYWNrZ3JvdW5kOnJnYmEoMTAsMTgsNywwLjk1KTsKICBib3JkZXItYm90dG9tOjJweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJveC1zaGFkb3c6MCAycHggMTJweCByZ2JhKDIwLDI1NSwyMywwLjA4KTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAjc3RhdHVzLXN0cmlwewogIGJhY2tncm91bmQ6cmdiYSg4LDEyLDUsMC45NSk7CiAgYm9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAubGF5b3V0LXN3aXRjaGVyewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4wNik7CiAgYm9yZGVyLWNvbG9yOnZhcigtLWJvcmRlcik7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmxheW91dC1zd2l0Y2hlciBidXR0b24uYWN0aXZlewogIGJhY2tncm91bmQ6dmFyKC0tcHJpbWFyeSk7CiAgY29sb3I6IzA1MDgwMzsKICB0ZXh0LXNoYWRvdzpub25lOwogIGJveC1zaGFkb3c6MCAwIDEycHggcmdiYSgyMCwyNTUsMjMsMC41KTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAubGF5b3V0LXN3aXRjaGVyIGJ1dHRvbjpob3Zlcjpub3QoLmFjdGl2ZSl7CiAgY29sb3I6dmFyKC0tcHJpbWFyeSk7CiAgdGV4dC1zaGFkb3c6MCAwIDZweCB2YXIoLS1wcmltYXJ5KTsKfQoKLyogS1BJIGNhcmRzICovCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tZXRyaWMtdGlsZXsKICBiYWNrZ3JvdW5kOnJnYmEoMTAsMTgsNywwLjg1KTsKICBib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgYm94LXNoYWRvdzppbnNldCAwIDAgMTVweCByZ2JhKDIwLDI1NSwyMywwLjAzKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAubWV0cmljLXRpbGU6aG92ZXJ7CiAgYm9yZGVyLWNvbG9yOnZhcigtLXByaW1hcnkpOwogIGJveC1zaGFkb3c6aW5zZXQgMCAwIDIwcHggcmdiYSgyMCwyNTUsMjMsMC4wNiksIDAgMCAxMnB4IHJnYmEoMjAsMjU1LDIzLDAuMSk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLm1ldHJpYy10aWxlLmNyaXRpY2Fse2JvcmRlci1sZWZ0OjNweCBzb2xpZCB2YXIoLS1jcml0aWNhbCl9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tZXRyaWMtdGlsZS53YXJuaW5ne2JvcmRlci1sZWZ0OjNweCBzb2xpZCAjQzhGRjAwfQoKLyogQ2hhcnQgY2FyZHMgKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmNoYXJ0LWNhcmR7CiAgYmFja2dyb3VuZDpyZ2JhKDEwLDE4LDcsMC44NSk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5zZXNzaW9ucy1jYXJkLApib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuZ2F0ZXdheS1jYXJkewogIGJhY2tncm91bmQ6cmdiYSgxMCwxOCw3LDAuODUpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuc2Vzc2lvbi1yb3c6aG92ZXJ7YmFja2dyb3VuZDp2YXIoLS1iZ0hvdmVyKX0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnNlc3Npb24tcm93e2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHJnYmEoMjYsOTAsMTgsMC40KX0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmdhdGV3YXktcm93e2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHJnYmEoMjYsOTAsMTgsMC40KX0KCi8qIEZvb3RlciAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAjZm9vdGVyewogIGJhY2tncm91bmQ6cmdiYSg4LDEyLDUsMC45NSk7CiAgYm9yZGVyLXRvcDoycHggc29saWQgdmFyKC0tYm9yZGVyKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuZm9vdGVyLWNhcmR7CiAgYmFja2dyb3VuZDpyZ2JhKDEwLDE4LDcsMC44NSk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwp9CgovKiBCYWRnZXMgKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmJhZGdlLm9re2JhY2tncm91bmQ6IzBBMkUwNjtjb2xvcjp2YXIoLS1zdWNjZXNzKTt0ZXh0LXNoYWRvdzowIDAgNnB4IHJnYmEoMjAsMjU1LDIzLDAuNSl9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5iYWRnZS53YXJue2JhY2tncm91bmQ6IzJFMjAwMDtjb2xvcjojQzhGRjAwO3RleHQtc2hhZG93OjAgMCA2cHggcmdiYSgyMDAsMjU1LDAsMC41KX0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmJhZGdlLmVycntiYWNrZ3JvdW5kOiMyRTA4MTU7Y29sb3I6dmFyKC0tY3JpdGljYWwpO3RleHQtc2hhZG93OjAgMCA2cHggcmdiYSgyNTUsNTksNTksMC41KX0KCi8qIFN0YXR1cyBjaGlwcyAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuc3RhdHVzLWNoaXB7CiAgYmFja2dyb3VuZDpyZ2JhKDEwLDE4LDcsMC44NSk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5zdGF0dXMtY2hpcCAuZG90Lm9ubGluZXsKICBiYWNrZ3JvdW5kOnZhcigtLXN1Y2Nlc3MpOwogIGJveC1zaGFkb3c6MCAwIDEwcHggdmFyKC0tc3VjY2VzcyksIDAgMCAyMHB4IHJnYmEoMjAsMjU1LDIzLDAuNCk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnN0YXR1cy1jaGlwIC5kb3Qub2ZmbGluZXsKICBiYWNrZ3JvdW5kOnZhcigtLWNyaXRpY2FsKTsKICBib3gtc2hhZG93OjAgMCA2cHggdmFyKC0tY3JpdGljYWwpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5zdGF0dXMtY2hpcC5za2VsZXRvbi1jaGlwe29wYWNpdHk6MC41fQoKLyogPT09PT0gUElQLUJPWTogUHJvZmlsZSBDYXJkcyA9PT09PSAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAucHJvZmlsZS1jYXJkewogIGJhY2tncm91bmQ6cmdiYSgxMCwxOCw3LDAuODUpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBib3JkZXItcmFkaXVzOjJweDsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAucHJvZmlsZS1jYXJkOmhvdmVyewogIGJvcmRlci1jb2xvcjp2YXIoLS1wcmltYXJ5KTsKICBib3gtc2hhZG93Omluc2V0IDAgMCAyMHB4IHJnYmEoMjAsMjU1LDIzLDAuMDYpLDAgMCAxMnB4IHJnYmEoMjAsMjU1LDIzLDAuMSk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2FyZCAucGMtaGVhZGVyewogIGJvcmRlci1ib3R0b206MXB4IHNvbGlkIHJnYmEoMjAsMjU1LDIzLDAuMTUpOwogIHBhZGRpbmctYm90dG9tOnZhcigtLXNwYWNlLXNtKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAucHJvZmlsZS1jYXJkIC5wYy1kb3Qub25saW5lewogIGJveC1zaGFkb3c6MCAwIDEwcHggdmFyKC0tc3VjY2VzcyksMCAwIDIwcHggcmdiYSgyMCwyNTUsMjMsMC40KTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAucHJvZmlsZS1jYXJkIC5wYy1kb3Qub2ZmbGluZXsKICBib3gtc2hhZG93OjAgMCA2cHggdmFyKC0tY3JpdGljYWwpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5wcm9maWxlLWNhcmQgLnBjLWRvdC5zdGFsZXsKICBib3gtc2hhZG93OjAgMCA2cHggdmFyKC0td2FybmluZyk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2FyZCAucGMtbmFtZXsKICB0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7CiAgZm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7CiAgdGV4dC1zaGFkb3c6MCAwIDRweCByZ2JhKDIwLDI1NSwyMywwLjQpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5wcm9maWxlLWNhcmQgLnBjLW1ldGEtaXRlbXsKICBmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTsKICB0ZXh0LXNoYWRvdzowIDAgNHB4IHJnYmEoMjAsMjU1LDIzLDAuMTUpOwogIHRleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAucHJvZmlsZS1jYXJkIC5wYy1tZXRhLWl0ZW06OmJlZm9yZXtjb250ZW50Oic+ICd9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5wcm9maWxlLWNhcmQgLnBjLXBsYXRmb3Jtc3tib3JkZXItdG9wOjFweCBzb2xpZCByZ2JhKDIwLDI1NSwyMywwLjEyKX0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2FyZCAucGMtcGxhdC1jaGlwewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4wNik7CiAgYm9yZGVyOjFweCBzb2xpZCByZ2JhKDIwLDI1NSwyMywwLjE1KTsKICBjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KTsKICB0ZXh0LXNoYWRvdzowIDAgM3B4IHJnYmEoMjAsMjU1LDIzLDAuMik7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2FyZCAucGMtcGxhdC1jaGlwLmNvbm5lY3RlZHsKICBjb2xvcjp2YXIoLS1zdWNjZXNzKTsKICB0ZXh0LXNoYWRvdzowIDAgNnB4IHJnYmEoMjAsMjU1LDIzLDAuNCk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2FyZCAucGMtZm9vdGVyewogIGJvcmRlci10b3A6MXB4IHNvbGlkIHJnYmEoMjAsMjU1LDIzLDAuMTIpOwogIHRleHQtc2hhZG93OjAgMCAzcHggcmdiYSgyMCwyNTUsMjMsMC4xNSk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2FyZCAucGMtc3RhdHVzLXByZWZpeHsKICBmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTsKICBmb250LXNpemU6MC42NXJlbTsKICBmb250LXdlaWdodDo3MDA7CiAgbWFyZ2luLXJpZ2h0OnZhcigtLXNwYWNlLXhzKTsKfQoKLyogVG9wYmFyIGVsZW1lbnRzICovCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC50b3BiYXItbG9nb3sKICBib3gtc2hhZG93OjAgMCAxMnB4IHZhcigtLXN1Y2Nlc3MpLCAwIDAgMjRweCByZ2JhKDIwLDI1NSwyMywwLjQpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5yZWZyZXNoLWluZGljYXRvciAuZG90ewogIGJveC1zaGFkb3c6MCAwIDhweCB2YXIoLS1wcmltYXJ5KTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAjY2xvY2t7CiAgdGV4dC1zaGFkb3c6MCAwIDZweCByZ2JhKDIwLDI1NSwyMywwLjQpOwp9CgovKiBCdXR0b25zICovCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5jdHJsLWJ0bnsKICBiYWNrZ3JvdW5kOnJnYmEoMjAsMjU1LDIzLDAuMTUpOwogIGNvbG9yOnZhcigtLXByaW1hcnkpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICB0ZXh0LXNoYWRvdzowIDAgNnB4IHJnYmEoMjAsMjU1LDIzLDAuMyk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmN0cmwtYnRuOmhvdmVyewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4yNSk7CiAgYm94LXNoYWRvdzowIDAgMTVweCByZ2JhKDIwLDI1NSwyMywwLjMpOwogIGNvbG9yOiMyMEZGMjQ7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmN0cmwtc2VsZWN0ewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4wOCk7CiAgY29sb3I6dmFyKC0tcHJpbWFyeSk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIHRleHQtc2hhZG93OjAgMCA2cHggcmdiYSgyMCwyNTUsMjMsMC4zKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuY3RybC1idG4uYWN0aXZle2JhY2tncm91bmQ6dmFyKC0tcHJpbWFyeSk7Y29sb3I6IzAzMTQwMztib3JkZXItY29sb3I6dmFyKC0tcHJpbWFyeSl9CgovKiBHYXRld2F5IHJvd3MgKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmdhdGV3YXktcm93e2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHJnYmEoMjYsOTAsMTgsMC4zKX0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmdhdGV3YXktcm93IC5ndy1uYW1le3RleHQtc2hhZG93OjAgMCA0cHggcmdiYSgyMCwyNTUsMjMsMC4zKX0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmd3LWRvdC51cHtib3gtc2hhZG93OjAgMCAwIHJnYmEoMjAsMjU1LDIzLDApfQoKLyogTW9kZWxzIHRhYmxlICovCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tb2RlbHMtdGFibGUgdGh7Y29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSl9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tb2RlbHMtdGFibGUgdGR7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgcmdiYSgyNiw5MCwxOCwwLjMpfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAubW9kZWxzLXRhYmxlIHRyOmhvdmVyIHRke2JhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4wNil9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tb2RlbHMtdGFibGUgLm0tbmFtZXt0ZXh0LXNoYWRvdzowIDAgNHB4IHJnYmEoMjAsMjU1LDIzLDAuMyl9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tLWNvc3R7dGV4dC1zaGFkb3c6MCAwIDRweCByZ2JhKDIwLDI1NSwyMywwLjMpfQoKLyogUHJvZmlsZSBjaGlwIG1pbmkgKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2hpcC1taW5pewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4wOCk7CiAgYm9yZGVyOjFweCBzb2xpZCByZ2JhKDIwLDI1NSwyMywwLjIpOwogIGNvbG9yOnZhcigtLXByaW1hcnkpOwogIHRleHQtc2hhZG93OjAgMCA0cHggcmdiYSgyMCwyNTUsMjMsMC4zKTsKfQoKLyogS2V5IGNoaXAgKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmtleS1jaGlwewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4wNSk7CiAgYm9yZGVyOjFweCBzb2xpZCByZ2JhKDIwLDI1NSwyMywwLjE1KTsKICBjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KTsKfQoKLyogVG9hc3QgKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnRvYXN0ewogIGJhY2tncm91bmQ6cmdiYSgxMCwxOCw3LDAuOTUpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBib3gtc2hhZG93OjAgMCAyMHB4IHJnYmEoMjAsMjU1LDIzLDAuMSk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnRvYXN0LmNyaXRpY2FsewogIGJhY2tncm91bmQ6cmdiYSgzMCw1LDUsMC45NSk7CiAgYm9yZGVyLWxlZnQ6M3B4IHNvbGlkIHZhcigtLWNyaXRpY2FsKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAudG9hc3Qud2FybmluZ3sKICBib3JkZXItbGVmdDozcHggc29saWQgI0M4RkYwMDsKfQoKLyogSGVhZGVyIGJsaW5raW5nIGN1cnNvciAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAjdG9wYmFyIC5oZWFkaW5nLW1kOjphZnRlcnsKICBjb250ZW50OidcMjU4Qyc7CiAgZGlzcGxheTppbmxpbmUtYmxvY2s7CiAgbWFyZ2luLWxlZnQ6NnB4OwogIGNvbG9yOnZhcigtLXByaW1hcnkpOwogIHRleHQtc2hhZG93OjAgMCA4cHggdmFyKC0tcHJpbWFyeSk7CiAgYW5pbWF0aW9uOnBpcEJsaW5rIDEuMXMgc3RlcHMoMSkgaW5maW5pdGU7CiAgdmVydGljYWwtYWxpZ246LTFweDsKfQpAa2V5ZnJhbWVzIHBpcEJsaW5rezUwJXtvcGFjaXR5OjB9fQoKLyogU2tlbGV0b24gKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnNrZWxldG9uewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4xKTsKfQoKLyogQ29udHJvbCBidXR0b25zIChyZWZyZXNoICsgYWxsLXByb2ZpbGVzKSAqLwouY3RybC1idG57CiAgYmFja2dyb3VuZDp2YXIoLS1iZ0NhcmQpO2NvbG9yOnZhcigtLXRleHRQcmltYXJ5KTsKICBib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtbWQpOwogIHBhZGRpbmc6NnB4IDE0cHg7Y3Vyc29yOnBvaW50ZXI7CiAgZm9udC1mYW1pbHk6J0ludGVyJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZTowLjhyZW07Zm9udC13ZWlnaHQ6NjAwOwogIHRyYW5zaXRpb246YmFja2dyb3VuZCAwLjJzLGJvcmRlci1jb2xvciAwLjJzOwp9Ci5jdHJsLWJ0bjpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLWJnSG92ZXIpO2JvcmRlci1jb2xvcjp2YXIoLS1ib3JkZXJMaWdodCl9Ci5jdHJsLWJ0bi5hY3RpdmV7YmFja2dyb3VuZDp2YXIoLS1wcmltYXJ5KTtjb2xvcjp2YXIoLS10ZXh0T25QcmltYXJ5KTtib3JkZXItY29sb3I6dmFyKC0tcHJpbWFyeSl9CgouY3RybC1zZWxlY3R7CiAgYmFja2dyb3VuZDp2YXIoLS1iZ0NhcmQpO2NvbG9yOnZhcigtLXRleHRQcmltYXJ5KTsKICBib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtbWQpOwogIHBhZGRpbmc6NnB4IDhweDtjdXJzb3I6cG9pbnRlcjsKICBmb250LWZhbWlseTonSW50ZXInLHNhbnMtc2VyaWY7Zm9udC1zaXplOjAuOHJlbTtmb250LXdlaWdodDo2MDA7Cn0KLmN0cmwtc2VsZWN0OmhvdmVye2JvcmRlci1jb2xvcjp2YXIoLS1ib3JkZXJMaWdodCl9CgovKiBUb2FzdCBub3RpZmljYXRpb24gKi8KLnRvYXN0LWNvbnRhaW5lcntwb3NpdGlvbjpmaXhlZDt0b3A6dmFyKC0tc3BhY2UtbGcpO3JpZ2h0OnZhcigtLXNwYWNlLWxnKTt6LWluZGV4OjIwMDtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2dhcDp2YXIoLS1zcGFjZS1zbSl9Ci50b2FzdHsKICBiYWNrZ3JvdW5kOnZhcigtLWJnQ2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLW1kKTtwYWRkaW5nOnZhcigtLXNwYWNlLW1kKSB2YXIoLS1zcGFjZS1sZyk7CiAgbWF4LXdpZHRoOjM2MHB4O2FuaW1hdGlvbjpzbGlkZUluIDAuM3MgZWFzZTsKfQoudG9hc3QuY3JpdGljYWx7Ym9yZGVyLWxlZnQ6M3B4IHNvbGlkIHZhcigtLWNyaXRpY2FsKX0KLnRvYXN0Lndhcm5pbmd7Ym9yZGVyLWxlZnQ6M3B4IHNvbGlkIHZhcigtLXdhcm5pbmcpfQpAa2V5ZnJhbWVzIHNsaWRlSW57ZnJvbXt0cmFuc2Zvcm06dHJhbnNsYXRlWCgxMDAlKTtvcGFjaXR5OjB9dG97dHJhbnNmb3JtOnRyYW5zbGF0ZVgoMCk7b3BhY2l0eToxfX0KCi8qID09PT09IEFDQ0VTU0lCSUxJVFkgPT09PT0gKi8KQG1lZGlhKHByZWZlcnMtcmVkdWNlZC1tb3Rpb246cmVkdWNlKXsKICAudG9wYmFyLWxvZ28sLnN0YXR1cy1jaGlwIC5kb3QsLnByb2ZpbGUtY2FyZCAucGMtZG90e2FuaW1hdGlvbjpub25lfQogIGJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdOjphZnRlcnthbmltYXRpb246bm9uZX0KICBib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAudG9wYmFyLWxvZ297YW5pbWF0aW9uOm5vbmV9Cn0KLnZlci1iYWRnZXtkaXNwbGF5OmlubGluZS1ibG9jazttYXJnaW4tbGVmdDo4cHg7cGFkZGluZzoycHggOXB4O2JvcmRlci1yYWRpdXM6OTk5cHg7CiAgYmFja2dyb3VuZDpyZ2JhKDU2LDE4OSwyNDgsLjEyKTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoNTYsMTg5LDI0OCwuMzUpOwogIGNvbG9yOnZhcigtLXByaW1hcnksIzM4YmRmOCk7Zm9udC1zaXplOjExcHg7Zm9udC13ZWlnaHQ6NjAwO2xldHRlci1zcGFjaW5nOi40cHg7CiAgZm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7dmVydGljYWwtYWxpZ246MnB4fQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAudmVyLWJhZGdle2JhY2tncm91bmQ6cmdiYSgzNCwxOTcsOTQsLjEwKTtib3JkZXItY29sb3I6cmdiYSgzNCwxOTcsOTQsLjQpO2NvbG9yOiM0YWRlODB9CgovKiA9PT09PSBQSVAtQk9ZOiBDUlQgRlJBTUUgKHd6b3J6ZWMgTmV0d29yayBNb25pdG9yKSA9PT09PSAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXXtmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJywnSmV0QnJhaW5zIE1vbm8nLCdDb3VyaWVyIE5ldycsbW9ub3NwYWNlfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuaGVhZGluZy1tZCxib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuaGVhZGluZy1sZywKYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmhlYWRpbmcteGwsYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmJvZHktbWQsCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5ib2R5LXNtLGJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5sYWJlbC1tZCwKYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmxhYmVsLWxnLGJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tb25vLXNtLApib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAubWV0cmljLXhsLGJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5rcGktdmFsdWV7CiAgZm9udC1mYW1pbHk6aW5oZXJpdH0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gI21haW57CiAgcG9zaXRpb246cmVsYXRpdmU7CiAgYm9yZGVyOjhweCBzb2xpZCAjMjIzMjFjO2JvcmRlci1yYWRpdXM6MThweDsKICBiYWNrZ3JvdW5kOnJnYmEoNSw4LDMsLjkyKTsKICBib3gtc2hhZG93OjAgMCAzMHB4IHJnYmEoMjAsMjU1LDIzLC4xMCksaW5zZXQgMCAwIDUwcHggcmdiYSgwLDAsMCwuOSk7CiAgcGFkZGluZzoxNnB4IDE4cHh9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdICNtYWluOjpiZWZvcmV7Y29udGVudDonJztwb3NpdGlvbjphYnNvbHV0ZTtpbnNldDowO3BvaW50ZXItZXZlbnRzOm5vbmU7CiAgYmFja2dyb3VuZDpyZXBlYXRpbmctbGluZWFyLWdyYWRpZW50KDBkZWcscmdiYSgwLDAsMCwuMzApIDAgMXB4LHRyYW5zcGFyZW50IDFweCAzcHgpOwogIHotaW5kZXg6NTtib3JkZXItcmFkaXVzOmluaGVyaXR9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdICNtYWluOjphZnRlcntjb250ZW50OicnO3Bvc2l0aW9uOmFic29sdXRlO2luc2V0OjA7cG9pbnRlci1ldmVudHM6bm9uZTsKICBiYWNrZ3JvdW5kOnJhZGlhbC1ncmFkaWVudChlbGxpcHNlIGF0IDUwJSA1MCUsdHJhbnNwYXJlbnQgNTUlLHJnYmEoMCwwLDAsLjUpIDEwMCUpOwogIGFuaW1hdGlvbjpmbGlja2VyIDhzIGluZmluaXRlO3otaW5kZXg6Njtib3JkZXItcmFkaXVzOmluaGVyaXR9CkBrZXlmcmFtZXMgZmxpY2tlcnswJSwxMDAle29wYWNpdHk6Ljk3fTkyJXtvcGFjaXR5Oi45N305MyV7b3BhY2l0eTouODB9OTQle29wYWNpdHk6Ljk3fTk3JXtvcGFjaXR5Oi45fTk4JXtvcGFjaXR5Oi45N319CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdICNtYWluPiosYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gI21haW4gLmNvbnRhaW5lcntwb3NpdGlvbjpyZWxhdGl2ZTt6LWluZGV4OjJ9Cgo8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5PgoKPCEtLSA9PT09PSBUT1AgQkFSID09PT09IC0tPgo8ZGl2IGlkPSJ0b3BiYXIiPgogIDxkaXYgY2xhc3M9ImNvbnRhaW5lciI+CiAgICA8ZGl2IGNsYXNzPSJ0b3BiYXItbGVmdCI+CiAgICAgIDxkaXYgY2xhc3M9InRvcGJhci1sb2dvIiBpZD0idG9wYmFyLWRvdCI+PC9kaXY+CiAgICAgIDxzcGFuIGNsYXNzPSJoZWFkaW5nLW1kIj5IZXJtZXMgTW9uaXRvciA8c3BhbiBjbGFzcz0idmVyLWJhZGdlIiBpZD0idmVyLWJhZGdlIj52X19WRVJfXzwvc3Bhbj48L3NwYW4+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InRvcGJhci1yaWdodCI+CiAgICAgIDxidXR0b24gY2xhc3M9ImN0cmwtYnRuIiBpZD0iYWxsLXByb2ZpbGVzLWJ0biIgc3R5bGU9ImRpc3BsYXk6bm9uZSIgdGl0bGU9IlByenl3csOzxIcgZGFuZSB6YmlvcmN6ZSBkbGEgd3N6eXN0a2ljaCBwcm9maWxpIj5BbGw8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iY3RybC1idG4iIGlkPSJtYW51YWwtcmVmcmVzaCIgdGl0bGU9Ik9kxZt3aWXFvCBkYW5lIG5hIMW8xIVkYW5pZSI+T2TFm3dpZcW8PC9idXR0b24+CiAgICAgIDxzZWxlY3QgY2xhc3M9ImN0cmwtc2VsZWN0IiBpZD0icmVmcmVzaC1pbnRlcnZhbCIgdGl0bGU9IkludGVyd2HFgiBhdXRvbWF0eWN6bmVnbyBvZMWbd2llxbxhbmlhIj4KICAgICAgICA8b3B0aW9uIHZhbHVlPSI5MDAiPjE1IG1pbjwvb3B0aW9uPgogICAgICAgIDxvcHRpb24gdmFsdWU9IjE4MDAiPjMwIG1pbjwvb3B0aW9uPgogICAgICAgIDxvcHRpb24gdmFsdWU9IjM2MDAiPjYwIG1pbjwvb3B0aW9uPgogICAgICA8L3NlbGVjdD4KICAgICAgPGRpdiBjbGFzcz0ibGF5b3V0LXN3aXRjaGVyIiBpZD0ibGF5b3V0LXN3aXRjaGVyIj4KICAgICAgICA8YnV0dG9uIGRhdGEtbGF5b3V0PSJkZWZhdWx0IiBjbGFzcz0iYWN0aXZlIj5IZXJtZXM8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGRhdGEtbGF5b3V0PSJwaXBib3kiPlBpcC1Cb3k8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InJlZnJlc2gtaW5kaWNhdG9yIj48ZGl2IGNsYXNzPSJkb3QiPjwvZGl2PjxzcGFuIGNsYXNzPSJtb25vLXNtIiBpZD0ibGFzdC1yZWZyZXNoIj4tLTwvc3Bhbj48L2Rpdj4KICAgICAgPHNwYW4gaWQ9ImNsb2NrIiBjbGFzcz0ibW9uby1zbSI+LS06LS06LS08L3NwYW4+CiAgICA8L2Rpdj4KICA8L2Rpdj4KPC9kaXY+Cgo8IS0tID09PT09IFJFRlJFU0ggUFJPR1JFU1MgQkFSICsgREFUQSBUSU1FU1RBTVAgPT09PT0gLS0+CjxkaXYgaWQ9InJlZnJlc2gtYmFyIj4KICA8ZGl2IGNsYXNzPSJjb250YWluZXIiPgogICAgPGRpdiBjbGFzcz0icmVmcmVzaC1wcm9ncmVzcyI+PGRpdiBjbGFzcz0iZmlsbCIgaWQ9InJlZnJlc2gtYmFyLWZpbGwiPjwvZGl2PjwvZGl2PgogICAgPGRpdiBjbGFzcz0icmVmcmVzaC1wcm9ncmVzcy1sYWJlbCI+CiAgICAgIDxzcGFuIGlkPSJyZWZyZXNoLWJhci1wY3QiPjAlPC9zcGFuPgogICAgICA8c3Bhbj5EbyBuYXN0xJlwbmVnbzogPHNwYW4gaWQ9InJlZnJlc2gtYmFyLW5leHQiIGNsYXNzPSJwY3QiPi0tPC9zcGFuPjwvc3Bhbj4KICAgICAgPHNwYW4+RGFuZSB6OiA8c3BhbiBpZD0icmVmcmVzaC1iYXItZGF0YSIgY2xhc3M9InBjdCI+LS08L3NwYW4+PC9zcGFuPgogICAgPC9kaXY+CiAgPC9kaXY+CjwvZGl2PgoKPCEtLSA9PT09PSBTVEFUVVMgU1RSSVAgPT09PT0gLS0+CjxkaXYgaWQ9InN0YXR1cy1zdHJpcCI+PGRpdiBjbGFzcz0iY29udGFpbmVyIiBpZD0ic3RhdHVzLXN0cmlwLWlubmVyIj48L2Rpdj48L2Rpdj4KCjwhLS0gPT09PT0gUFJPRklMRSBDQVJEUyA9PT09PSAtLT4KPGRpdiBjbGFzcz0icHJvZmlsZS1jYXJkcy1zZWN0aW9uIj48ZGl2IGNsYXNzPSJjb250YWluZXIiPjxkaXYgY2xhc3M9InByb2ZpbGUtY2FyZHMtZ3JpZCIgaWQ9InByb2ZpbGUtY2FyZHMtZ3JpZCI+PC9kaXY+PC9kaXY+PC9kaXY+Cgo8IS0tID09PT09IE1BSU4gQ09OVEVOVCA9PT09PSAtLT4KPGRpdiBjbGFzcz0iY29udGFpbmVyIiBpZD0ibWFpbiI+CgogIDwhLS0gS1BJIEdyaWQgLS0+CiAgPGRpdiBjbGFzcz0ia3BpLWdyaWQiIGlkPSJrcGktZ3JpZCI+PC9kaXY+CgogIDwhLS0gQ2hhcnRzIFJvdyAtLT4KICA8ZGl2IGNsYXNzPSJjaGFydHMtcm93Ij4KICAgIDxkaXYgY2xhc3M9ImNoYXJ0LWNhcmQiPgogICAgICA8ZGl2IGNsYXNzPSJjaGFydC1oZWFkZXIgaGVhZGluZy1tZCI+V3lrb3J6eXN0YW5pZSB0b2tlbsOzdyAvIGtvc3p0w7N3PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LWJvZHkiIGlkPSJjaGFydC11c2FnZSI+PC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNoYXJ0LWNhcmQiPgogICAgICA8ZGl2IGNsYXNzPSJjaGFydC1oZWFkZXIgaGVhZGluZy1tZCI+VG9wIG1vZGVsZSA8c3BhbiBjbGFzcz0iYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRNdXRlZCkiPihvZCBuYWpiYXJkemllaiBkbyBuYWptbmllaiB1xbx5d2FuZWdvKTwvc3Bhbj48L2Rpdj4KICAgICAgPGRpdiBpZD0iY2hhcnQtbW9kZWxzIj48L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8IS0tIERldGFpbCBSb3cgLS0+CiAgPGRpdiBjbGFzcz0iZGV0YWlsLXJvdyI+CiAgICA8ZGl2IGNsYXNzPSJzZXNzaW9ucy1jYXJkIj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZC1oZWFkZXIiPjxzcGFuIGNsYXNzPSJoZWFkaW5nLW1kIj5Pc3RhdG5pZSBzZXNqZSAod3N6eXN0a2llIHByb2ZpbGUpPC9zcGFuPjxzcGFuIGNsYXNzPSJib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSIgaWQ9InNlc3Npb24tY291bnQiPi0tPC9zcGFuPjwvZGl2PgogICAgICA8ZGl2IGlkPSJzZXNzaW9ucy1saXN0Ij48L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iZ2F0ZXdheS1jYXJkIj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZC1oZWFkZXIiPjxzcGFuIGNsYXNzPSJoZWFkaW5nLW1kIj5HYXRld2F5PC9zcGFuPjxzcGFuIGNsYXNzPSJib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSIgaWQ9ImdhdGV3YXktY291bnQiPi0tPC9zcGFuPjwvZGl2PgogICAgICA8ZGl2IGlkPSJnYXRld2F5LWxpc3QiPjwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDwhLS0gRm9vdGVyIC0tPgogIDxkaXYgaWQ9ImZvb3Rlci1zZWN0aW9uIj4KICAgIDxkaXYgY2xhc3M9ImZvb3Rlci1jYXJkcyI+CiAgICAgIDxkaXYgY2xhc3M9ImZvb3Rlci1jYXJkIj4KICAgICAgICA8ZGl2IGNsYXNzPSJmYy1oZWFkZXIgbGFiZWwtbWQiIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KSI+S2x1Y3plIEFQSSAod3N6eXN0a2llIHByb2ZpbGUpPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZm9vdGVyLWtleXMiPjwvZGl2PgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iZm9vdGVyLWNhcmQiPgogICAgICAgIDxkaXYgY2xhc3M9ImZjLWhlYWRlciBsYWJlbC1tZCIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRTZWNvbmRhcnkpIj5LYW5iYW48L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJmb290ZXIta2FuYmFuIj48L2Rpdj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImZvb3Rlci1jYXJkIj4KICAgICAgICA8ZGl2IGNsYXNzPSJmYy1oZWFkZXIgbGFiZWwtbWQiIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KSI+U3lzdGVtPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZm9vdGVyLXN5c3RlbSI+PC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+Cgo8L2Rpdj4KCjwhLS0gVG9hc3QgY29udGFpbmVyIC0tPgo8ZGl2IGNsYXNzPSJ0b2FzdC1jb250YWluZXIiIGlkPSJ0b2FzdHMiPjwvZGl2PgoKPHNjcmlwdD4KLy8gPT09PT0gQ09ORklHID09PT09CmNvbnN0IEFQSV9CQVNFID0gJ2h0dHA6Ly8xMjcuMC4wLjE6OTExOCc7CmNvbnN0IEFQSV9WRVJTSU9OID0gJzEuMTEuMCc7CmNvbnN0IFJFRlJFU0hfT1BUSU9OUyA9IHs5MDA6JzE1IG1pbicsMTgwMDonMzAgbWluJywzNjAwOic2MCBtaW4nfTsKbGV0IFJFRlJFU0hfSU5URVJWQUwgPSA5MDA7IC8vIGRvbXlzbG5pZSAxNSBtaW4KY29uc3QgTEFZT1VUX0tFWSA9ICdoZXJtZXMtbW9uaXRvci1sYXlvdXQnOwoKbGV0IHVzYWdlQ2hhcnQgPSBudWxsOwpsZXQgbW9kZWxzQ2hhcnQgPSBudWxsOwpsZXQgcmVmcmVzaFRpbWVyID0gbnVsbDsKbGV0IGxhc3RSZWZyZXNoQXQgPSAwOyAgICAgICAgICAgLy8gdGltZXN0YW1wIChtcykgd2hlbiBkYXRhIHdhcyBsYXN0IGZldGNoZWQKbGV0IHByb2dyZXNzVGltZXIgPSBudWxsOyAgICAgICAgLy8gY291bnRkb3duIHByb2dyZXNzIGJhciB0aW1lcgovLyBGaWx0ciBwcm9maWx1OiBudWxsID0gd3N6eXN0a2llIHByb2ZpbGUsIGluYWN6ZWogbmF6d2EgcHJvZmlsdQpsZXQgYWN0aXZlUHJvZmlsZSA9IG51bGw7CgovLyA9PT09PSBIRUxQRVJTID09PT09CmZ1bmN0aW9uIGZvcm1hdE51bWJlcihuKSB7CiAgaWYgKG4gPT0gbnVsbCkgcmV0dXJuICctLSc7CiAgaWYgKG4gPj0gMV8wMDBfMDAwKSByZXR1cm4gKG4gLyAxXzAwMF8wMDApLnRvRml4ZWQoMSkgKyAnTSc7CiAgaWYgKG4gPj0gMV8wMDApIHJldHVybiAobiAvIDFfMDAwKS50b0ZpeGVkKDEpICsgJ2snOwogIHJldHVybiBuLnRvTG9jYWxlU3RyaW5nKCdwbC1QTCcpOwp9CgpmdW5jdGlvbiBmb3JtYXRDb3N0KHVzZCkgewogIGlmICh1c2QgPT0gbnVsbCkgcmV0dXJuICctLSc7CiAgcmV0dXJuICckJyArIHVzZC50b0ZpeGVkKDIpOwp9CgpmdW5jdGlvbiBmb3JtYXREdXJhdGlvbihzZWNvbmRzKSB7CiAgaWYgKHNlY29uZHMgPT0gbnVsbCkgcmV0dXJuICctLSc7CiAgaWYgKHNlY29uZHMgPCA2MCkgcmV0dXJuIE1hdGgucm91bmQoc2Vjb25kcykgKyAncyc7CiAgaWYgKHNlY29uZHMgPCAzNjAwKSByZXR1cm4gTWF0aC5yb3VuZChzZWNvbmRzIC8gNjApICsgJ20nOwogIHJldHVybiAoc2Vjb25kcyAvIDM2MDApLnRvRml4ZWQoMSkgKyAnaCc7Cn0KCmZ1bmN0aW9uIHRpbWVBZ28oaXNvU3RyKSB7CiAgaWYgKCFpc29TdHIpIHJldHVybiAnLS0nOwogIGNvbnN0IG1zID0gRGF0ZS5ub3coKSAtIG5ldyBEYXRlKGlzb1N0cikuZ2V0VGltZSgpOwogIHJldHVybiBmb3JtYXREdXJhdGlvbihtcyAvIDEwMDApICsgJyB0ZW11JzsKfQoKZnVuY3Rpb24gZXNjYXBlSHRtbChzKSB7CiAgaWYgKCFzKSByZXR1cm4gJyc7CiAgY29uc3QgZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogIGQudGV4dENvbnRlbnQgPSBzOwogIHJldHVybiBkLmlubmVySFRNTDsKfQoKLy8gPT09PT0gQ0xPQ0sgPT09PT0KZnVuY3Rpb24gdXBkYXRlQ2xvY2soKSB7CiAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTsKICBjb25zdCBjZXQgPSBuZXcgRGF0ZShub3cudG9Mb2NhbGVTdHJpbmcoJ2VuLVVTJywge3RpbWVab25lOidFdXJvcGUvV2Fyc2F3J30pKTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY2xvY2snKS50ZXh0Q29udGVudCA9CiAgICBjZXQudG9Mb2NhbGVUaW1lU3RyaW5nKCdwbC1QTCcsIHtob3VyOicyLWRpZ2l0JyxtaW51dGU6JzItZGlnaXQnfSkgKyAnIENFVCc7Cn0Kc2V0SW50ZXJ2YWwodXBkYXRlQ2xvY2ssIDEwMDApOwp1cGRhdGVDbG9jaygpOwoKLy8gPT09PT0gVE9BU1RTID09PT09CmZ1bmN0aW9uIHNob3dUb2FzdChtc2csIGxldmVsKSB7CiAgY29uc3QgY29udGFpbmVyID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RvYXN0cycpOwogIGNvbnN0IGVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgZWwuY2xhc3NOYW1lID0gJ3RvYXN0ICcgKyAobGV2ZWx8fCcnKTsKICBlbC50ZXh0Q29udGVudCA9IG1zZzsKICBjb250YWluZXIuYXBwZW5kQ2hpbGQoZWwpOwogIHNldFRpbWVvdXQoKCkgPT4gZWwucmVtb3ZlKCksIDUwMDApOwp9CgovLyA9PT09PSBMQVlPVVQgU1dJVENIRVIgPT09PT0KZnVuY3Rpb24gc3dpdGNoTGF5b3V0KGxheW91dCkgewogIGRvY3VtZW50LmJvZHkuc2V0QXR0cmlidXRlKCdkYXRhLWxheW91dCcsIGxheW91dCk7CiAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oTEFZT1VUX0tFWSwgbGF5b3V0KTsKCiAgLy8gVXBkYXRlIGJ1dHRvbnMKICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcjbGF5b3V0LXN3aXRjaGVyIGJ1dHRvbicpLmZvckVhY2goYnRuID0+IHsKICAgIGJ0bi5jbGFzc0xpc3QudG9nZ2xlKCdhY3RpdmUnLCBidG4uZGF0YXNldC5sYXlvdXQgPT09IGxheW91dCk7CiAgfSk7CgogIC8vIFBpcC1Cb3k6IGRpc3Bvc2UgRUNoYXJ0cywgSGVybWVzOiByZWluaXRpYWxpemUKICBpZiAobGF5b3V0ID09PSAncGlwYm95JykgewogICAgaWYgKHVzYWdlQ2hhcnQpIHsgdXNhZ2VDaGFydC5kaXNwb3NlKCk7IHVzYWdlQ2hhcnQgPSBudWxsOyB9CiAgICBpZiAobW9kZWxzQ2hhcnQpIHsgbW9kZWxzQ2hhcnQuZGlzcG9zZSgpOyBtb2RlbHNDaGFydCA9IG51bGw7IH0KICB9CgogIC8vIFJlZnJlc2ggYWxsIGRhdGEgKHJlLXJlbmRlcnMgZXZlcnl0aGluZyBmb3IgbmV3IGxheW91dCkKICAvLyBaYWNob3dhaiB0aW1lciBvZMWbd2llxbxhbmlhIOKAlCB6bWlhbmEgbGF5b3V0dSBuaWUgcG93aW5uYSBnbyByZXNldG93YcSHCiAgdmFyIHNhdmVkUmVmcmVzaEF0ID0gbGFzdFJlZnJlc2hBdDsKICByZWZyZXNoQWxsKCk7CiAgbGFzdFJlZnJlc2hBdCA9IHNhdmVkUmVmcmVzaEF0OwogIHVwZGF0ZVByb2dyZXNzQmFyKCk7Cn0KCmZ1bmN0aW9uIGluaXRMYXlvdXRTd2l0Y2hlcigpIHsKICBjb25zdCBzYXZlZCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKExBWU9VVF9LRVkpIHx8ICdkZWZhdWx0JzsKICBjb25zdCBidXR0b25zID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnI2xheW91dC1zd2l0Y2hlciBidXR0b24nKTsKICAKICAvLyBBcHBseSBzYXZlZCBsYXlvdXQKICBzd2l0Y2hMYXlvdXQoc2F2ZWQpOwogIAogIC8vIENsaWNrIGhhbmRsZXJzCiAgYnV0dG9ucy5mb3JFYWNoKGJ0biA9PiB7CiAgICBidG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiBzd2l0Y2hMYXlvdXQoYnRuLmRhdGFzZXQubGF5b3V0KSk7CiAgfSk7Cn0KCi8vID09PT09IEZFVENIIFdJVEggRVJST1IgSEFORExJTkcgPT09PT0KYXN5bmMgZnVuY3Rpb24gYXBpRmV0Y2gocGF0aCkgewogIHRyeSB7CiAgICBjb25zdCBzZXAgPSBwYXRoLmluY2x1ZGVzKCc/JykgPyAnJicgOiAnPyc7CiAgICBjb25zdCB1cmwgPSBBUElfQkFTRSArIHBhdGggKyBzZXAgKyAndj0nICsgQVBJX1ZFUlNJT047CiAgICBjb25zdCByZXNwID0gYXdhaXQgZmV0Y2godXJsKTsKICAgIGlmICghcmVzcC5vaykgdGhyb3cgbmV3IEVycm9yKCdIVFRQICcgKyByZXNwLnN0YXR1cyk7CiAgICByZXR1cm4gYXdhaXQgcmVzcC5qc29uKCk7CiAgfSBjYXRjaChlKSB7CiAgICByZXR1cm4ge19lcnJvcjogZS5tZXNzYWdlfTsKICB9Cn0KCi8vID09PT09IFJFRlJFU0ggUFJPR1JFU1MgQkFSID09PT09Ci8vIFBhc2VrIG9kbWllcnphIG9kc2V0ZWsgY3phc3UsIGt0w7NyeSBtaW7EhcWCIG9kIG9zdGF0bmllZ28gb2TFm3dpZcW8ZW5pYQovLyB3emdsxJlkZW0gYmllxbzEhWNlZ28gaW50ZXJ3YcWCdSBSRUZSRVNIX0lOVEVSVkFMLiBSZXNldHVqZSBzacSZIHBvIGthxbxkeW0KLy8gb2TFm3dpZcW8ZW5pdSAoYXV0b21hdHljem55bSwgcsSZY3pueW0gbHViIHptaWFuaWUgaW50ZXJ3YcWCdSkuCmZ1bmN0aW9uIHVwZGF0ZVByb2dyZXNzQmFyKCkgewogIGNvbnN0IGJhciA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyZWZyZXNoLWJhci1maWxsJyk7CiAgY29uc3QgcGN0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncmVmcmVzaC1iYXItcGN0Jyk7CiAgY29uc3QgbmV4dEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3JlZnJlc2gtYmFyLW5leHQnKTsKICBpZiAoIWJhcikgcmV0dXJuOwogIGlmIChsYXN0UmVmcmVzaEF0ID09PSAwKSB7CiAgICBiYXIuc3R5bGUud2lkdGggPSAnMCUnOyBiYXIuY2xhc3NOYW1lID0gJ2ZpbGwnOwogICAgaWYgKHBjdEVsKSBwY3RFbC50ZXh0Q29udGVudCA9ICcwJSc7CiAgICBpZiAobmV4dEVsKSBuZXh0RWwudGV4dENvbnRlbnQgPSAnLS0nOwogICAgcmV0dXJuOwogIH0KICBjb25zdCB0b3RhbCA9IFJFRlJFU0hfSU5URVJWQUw7CiAgY29uc3QgZWxhcHNlZCA9IERhdGUubm93KCkgLSBsYXN0UmVmcmVzaEF0OwogIGNvbnN0IHJlbWFpbmluZyA9IE1hdGgubWF4KDAsIE1hdGgucm91bmQoKHRvdGFsICogMTAwMCAtIGVsYXBzZWQpIC8gMTAwMCkpOwogIGNvbnN0IHBjdCA9IE1hdGgubWluKDEwMCwgTWF0aC5tYXgoMCwgTWF0aC5yb3VuZChlbGFwc2VkIC8gdG90YWwgLyAxMCkpKTsKICBiYXIuc3R5bGUud2lkdGggPSBwY3QgKyAnJSc7CiAgYmFyLmNsYXNzTmFtZSA9ICdmaWxsJyArIChwY3QgPj0gMTAwID8gJyBjcml0JyA6IChwY3QgPj0gODUgPyAnIHdhcm4nIDogJycpKTsKICBpZiAocGN0RWwpIHBjdEVsLnRleHRDb250ZW50ID0gcGN0ICsgJyUnOwogIC8vIFBva2F6dWogY3phcyBkbyBuYXN0xJlwbmVnbyBvZHN3aWV6ZW5pYQogIGlmIChuZXh0RWwpIHsKICAgIGlmIChyZW1haW5pbmcgPD0gMCkgewogICAgICBuZXh0RWwudGV4dENvbnRlbnQgPSAnb2TFm3dpZcW8YW5pZS4uLic7CiAgICAgIG5leHRFbC5zdHlsZS5jb2xvciA9ICd2YXIoLS13YXJuaW5nKSc7CiAgICB9IGVsc2UgewogICAgICBjb25zdCBybSA9IE1hdGguZmxvb3IocmVtYWluaW5nIC8gNjApOwogICAgICBjb25zdCBycyA9IHJlbWFpbmluZyAlIDYwOwogICAgICBuZXh0RWwudGV4dENvbnRlbnQgPSBybSArICc6JyArIFN0cmluZyhycykucGFkU3RhcnQoMiwgJzAnKTsKICAgICAgbmV4dEVsLnN0eWxlLmNvbG9yID0gJyc7CiAgICB9CiAgfQogIC8vIHBvIHByemVrcm9jemVuaXUgMTAwJSAoc3DDs8W6bmlvbmUgb2Rzd2llemVuaWUpIOKAlCB3c2theiAidGVyYXogb2TFm3dpZcW8YW0iCiAgaWYgKHBjdCA+PSAxMDAgJiYgcGN0RWwpIHBjdEVsLnRleHRDb250ZW50ID0gJzEwMCUnOwp9CgpmdW5jdGlvbiBzdGFydFByb2dyZXNzVGltZXIoKSB7CiAgaWYgKHByb2dyZXNzVGltZXIpIGNsZWFySW50ZXJ2YWwocHJvZ3Jlc3NUaW1lcik7CiAgdXBkYXRlUHJvZ3Jlc3NCYXIoKTsKICBwcm9ncmVzc1RpbWVyID0gc2V0SW50ZXJ2YWwodXBkYXRlUHJvZ3Jlc3NCYXIsIDI1MCk7Cn0KCmZ1bmN0aW9uIG1hcmtEYXRhVHMoaXNvU3RyKSB7CiAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncmVmcmVzaC1iYXItZGF0YScpOwogIGlmICghZWwpIHJldHVybjsKICBpZiAoaXNvU3RyKSB7CiAgICBjb25zdCBkID0gbmV3IERhdGUoaXNvU3RyKTsKICAgIGlmICghaXNOYU4oZC5nZXRUaW1lKCkpKSB7CiAgICAgIGVsLnRleHRDb250ZW50ID0gZC50b0xvY2FsZURhdGVTdHJpbmcoJ3BsLVBMJywge2RheTonMi1kaWdpdCcsbW9udGg6JzItZGlnaXQnLHllYXI6J251bWVyaWMnfSkgKwogICAgICAgICcgJyArIGQudG9Mb2NhbGVUaW1lU3RyaW5nKCdwbC1QTCcsIHtob3VyOicyLWRpZ2l0JyxtaW51dGU6JzItZGlnaXQnLHNlY29uZDonMi1kaWdpdCd9KTsKICAgICAgcmV0dXJuOwogICAgfQogIH0KICBlbC50ZXh0Q29udGVudCA9ICctLSc7Cn0KCi8vID09PT09IFJFTkRFUjogU1RBVFVTIFNUUklQID09PT09CmZ1bmN0aW9uIHJlbmRlclN0YXR1c1N0cmlwKHN0YXR1c0RhdGEpIHsKICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzdGF0dXMtc3RyaXAtaW5uZXInKTsKICBpZiAoIXN0YXR1c0RhdGEgfHwgc3RhdHVzRGF0YS5fZXJyb3IgfHwgIXN0YXR1c0RhdGEucHJvZmlsZXMpIHsKICAgIGVsLmlubmVySFRNTCA9ICc8ZGl2IGNsYXNzPSJzdGF0ZS1tc2ciPjxkaXYgY2xhc3M9ImJvZHktc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpIj5CcmFrIGRhbnljaCBvIHN0YXR1c2llPC9kaXY+PC9kaXY+JzsKICAgIHJldHVybjsKICB9CgogIC8vIFVwZGF0ZSB0b3BiYXIgZG90CiAgY29uc3QgYWxsUnVubmluZyA9IHN0YXR1c0RhdGEuc3VtbWFyeT8ucHJvZmlsZXNfdG90YWwgPT09IHN0YXR1c0RhdGEuc3VtbWFyeT8ucHJvZmlsZXNfcnVubmluZzsKICBjb25zdCBkb3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndG9wYmFyLWRvdCcpOwogIGRvdC5zdHlsZS5iYWNrZ3JvdW5kID0gYWxsUnVubmluZyA/ICd2YXIoLS1zdWNjZXNzKScgOiAndmFyKC0td2FybmluZyknOwoKICBlbC5pbm5lckhUTUwgPSBzdGF0dXNEYXRhLnByb2ZpbGVzLm1hcChwID0+IHsKICAgIGNvbnN0IGd3UnVubmluZyA9IHAuZ2F0ZXdheT8ucnVubmluZzsKICAgIGNvbnN0IHN0YXRlID0gZ3dSdW5uaW5nID8gJ29ubGluZScgOiAnb2ZmbGluZSc7CiAgICBjb25zdCBuYW1lID0gcC5wcm9maWxlOwogICAgY29uc3QgYWN0aXZlQ2xzID0gKGFjdGl2ZVByb2ZpbGUgPT09IG5hbWUpID8gJyBhY3RpdmUnIDogJyc7CiAgICAKICAgIC8vIENvdW50IGNvbm5lY3RlZCBwbGF0Zm9ybXMKICAgIGNvbnN0IHBsYXRmb3JtcyA9IChwLmdhdGV3YXkgJiYgcC5nYXRld2F5LnBsYXRmb3JtcykgPyBwLmdhdGV3YXkucGxhdGZvcm1zIDogW107CiAgICBjb25zdCBjb25uZWN0ZWRDb3VudCA9IHBsYXRmb3Jtcy5maWx0ZXIocGwgPT4gcGwuc3RhdGUgPT09ICdjb25uZWN0ZWQnKS5sZW5ndGg7CiAgICBjb25zdCB0b3RhbFBsYXRzID0gcGxhdGZvcm1zLmxlbmd0aDsKICAgIGNvbnN0IHBsYXRmb3JtSW5mbyA9IHRvdGFsUGxhdHMgPiAwID8gY29ubmVjdGVkQ291bnQgKyAnLycgKyB0b3RhbFBsYXRzICsgJyBwbGF0Zi4nIDogJyc7CiAgICAKICAgIHJldHVybiAnPGRpdiBjbGFzcz0ic3RhdHVzLWNoaXAnICsgYWN0aXZlQ2xzICsgJyIgb25jbGljaz0ic2V0UHJvZmlsZUZpbHRlcihcJycgKyBlbmNvZGVVUklDb21wb25lbnQobmFtZSkgKyAnXCcpIiB0aXRsZT0iUG9rYcW8IGRhbmUgdHlsa28gZGxhIHRlZ28gcHJvZmlsdSI+JyArCiAgICAgICc8ZGl2IGNsYXNzPSJkb3QgJyArIHN0YXRlICsgJyInICsgKGd3UnVubmluZyA/ICcgc3R5bGU9ImFuaW1hdGlvbjpwdWxzZSAycyBpbmZpbml0ZSInIDogJycpICsgJz48L2Rpdj4nICsKICAgICAgJzxzcGFuIGNsYXNzPSJuYW1lIj4nICsgZXNjYXBlSHRtbChuYW1lKSArICc8L3NwYW4+JyArCiAgICAgIChwLmdhdGV3YXk/LmFjdGl2ZV9hZ2VudHMgPiAwID8gJzxzcGFuIGNsYXNzPSJtb25vLXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tcHJpbWFyeSkiPicgKyBwLmdhdGV3YXkuYWN0aXZlX2FnZW50cyArICcgYWcuPC9zcGFuPicgOiAnJykgKwogICAgICAocGxhdGZvcm1JbmZvID8gJzxzcGFuIGNsYXNzPSJwbGF0Zm9ybSI+JyArIHBsYXRmb3JtSW5mbyArICc8L3NwYW4+JyA6ICcnKSArCiAgICAnPC9kaXY+JzsKICB9KS5qb2luKCcnKSB8fCAnPHNwYW4gY2xhc3M9ImJvZHktc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO3BhZGRpbmc6MCB2YXIoLS1zcGFjZS1zbSkiPkJyYWsgcHJvZmlsaTwvc3Bhbj4nOwp9CgovLyA9PT09PSBSRU5ERVI6IFBST0ZJTEUgQ0FSRFMgPT09PT0KZnVuY3Rpb24gcmVuZGVyUHJvZmlsZUNhcmRzKHN0YXR1c0RhdGEsIHNlc3Npb25zRGF0YSwgdXNhZ2VEYXRhKSB7CiAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncHJvZmlsZS1jYXJkcy1ncmlkJyk7CiAgaWYgKCFzdGF0dXNEYXRhIHx8IHN0YXR1c0RhdGEuX2Vycm9yIHx8ICFzdGF0dXNEYXRhLnByb2ZpbGVzKSB7CiAgICBlbC5pbm5lckhUTUwgPSAnJzsKICAgIHJldHVybjsKICB9CgogIHZhciBpc1BpcEJveSA9IGRvY3VtZW50LmJvZHkuZ2V0QXR0cmlidXRlKCdkYXRhLWxheW91dCcpID09PSAncGlwYm95JzsKCiAgLy8gQnVpbGQgcGVyLXByb2ZpbGUgbG9va3VwIG1hcHMgZnJvbSBzZXNzaW9ucy91c2FnZSBkYXRhCiAgdmFyIHByb2ZpbGVTZXNzaW9ucyA9IHt9OwogIHZhciBwcm9maWxlVXNhZ2UgPSB7fTsKCiAgLy8gTWFwIHNlc3Npb25zIHRvIHByb2ZpbGVzCiAgKHN0YXR1c0RhdGEucHJvZmlsZXMgfHwgW10pLmZvckVhY2goZnVuY3Rpb24ocCkgewogICAgcHJvZmlsZVNlc3Npb25zW3AucHJvZmlsZV0gPSAwOwogICAgcHJvZmlsZVVzYWdlW3AucHJvZmlsZV0gPSB7dG9rZW5zOiAwLCBjb3N0OiAwfTsKICB9KTsKCiAgaWYgKHNlc3Npb25zRGF0YSAmJiBzZXNzaW9uc0RhdGEuc2Vzc2lvbnMpIHsKICAgIHNlc3Npb25zRGF0YS5zZXNzaW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHMpIHsKICAgICAgaWYgKHMuX3Byb2ZpbGUgJiYgcHJvZmlsZVNlc3Npb25zLmhhc093blByb3BlcnR5KHMuX3Byb2ZpbGUpKSB7CiAgICAgICAgcHJvZmlsZVNlc3Npb25zW3MuX3Byb2ZpbGVdKys7CiAgICAgIH0KICAgIH0pOwogIH0KCiAgaWYgKHVzYWdlRGF0YSAmJiB1c2FnZURhdGEuX3Byb2ZpbGVVc2FnZSkgewogICAgT2JqZWN0LmtleXModXNhZ2VEYXRhLl9wcm9maWxlVXNhZ2UpLmZvckVhY2goZnVuY3Rpb24ocCkgewogICAgICBwcm9maWxlVXNhZ2VbcF0gPSB1c2FnZURhdGEuX3Byb2ZpbGVVc2FnZVtwXTsKICAgIH0pOwogIH0KCiAgZWwuaW5uZXJIVE1MID0gKHN0YXR1c0RhdGEucHJvZmlsZXMgfHwgW10pLm1hcChmdW5jdGlvbihwKSB7CiAgICB2YXIgZ3cgPSBwLmdhdGV3YXkgfHwge307CiAgICB2YXIgcnVubmluZyA9IGd3LnJ1bm5pbmc7CiAgICB2YXIgc3RhdGVDbHMgPSBydW5uaW5nID8gJ29ubGluZScgOiAoZ3cuc3RhdGUgPT09ICdzdGFsZScgPyAnc3RhbGUnIDogJ29mZmxpbmUnKTsKICAgIHZhciBwbGF0SW5mbyA9IChndy5wbGF0Zm9ybXMgJiYgQXJyYXkuaXNBcnJheShndy5wbGF0Zm9ybXMpKSA/IGd3LnBsYXRmb3JtcyA6IFtdOwogICAgdmFyIGNvbm5lY3RlZFBsYXRzID0gcGxhdEluZm8uZmlsdGVyKGZ1bmN0aW9uKGspIHsgcmV0dXJuIGsuc3RhdGUgPT09ICdjb25uZWN0ZWQnOyB9KTsKICAgIHZhciBhZ2VudHMgPSBndy5hY3RpdmVfYWdlbnRzIHx8IDA7CgogICAgdmFyIHByZWZpeEh0bWwgPSAnJzsKICAgIHZhciBjYXJkQWN0aXZlQ2xzID0gKGFjdGl2ZVByb2ZpbGUgPT09IHAucHJvZmlsZSkgPyAnIGFjdGl2ZScgOiAnJzsKICAgIGlmIChpc1BpcEJveSkgewogICAgICB2YXIgcHJlZml4Q29sb3IgPSBydW5uaW5nID8gJ3ZhcigtLXN1Y2Nlc3MpJyA6IChzdGF0ZUNscyA9PT0gJ3N0YWxlJyA/ICd2YXIoLS13YXJuaW5nKScgOiAndmFyKC0tY3JpdGljYWwpJyk7CiAgICAgIHZhciBwcmVmaXggPSBydW5uaW5nID8gJ1tPTkxdJyA6IChzdGF0ZUNscyA9PT0gJ3N0YWxlJyA/ICdbU1RMXScgOiAnW09GRl0nKTsKICAgICAgcHJlZml4SHRtbCA9ICc8c3BhbiBjbGFzcz0icGMtc3RhdHVzLXByZWZpeCIgc3R5bGU9ImNvbG9yOicgKyBwcmVmaXhDb2xvciArICciPicgKyBwcmVmaXggKyAnPC9zcGFuPic7CiAgICB9CgogICAgdmFyIHNlc2hDb3VudCA9IHByb2ZpbGVTZXNzaW9uc1twLnByb2ZpbGVdIHx8IDA7CiAgICB2YXIgdG9rQ291bnQgPSBwcm9maWxlVXNhZ2VbcC5wcm9maWxlXSA/IHByb2ZpbGVVc2FnZVtwLnByb2ZpbGVdLnRva2VucyA6IDA7CiAgICB2YXIgY29zdFZhbCA9IHByb2ZpbGVVc2FnZVtwLnByb2ZpbGVdID8gcHJvZmlsZVVzYWdlW3AucHJvZmlsZV0uY29zdCA6IDA7CgogICAgcmV0dXJuICc8ZGl2IGNsYXNzPSJwcm9maWxlLWNhcmQnICsgY2FyZEFjdGl2ZUNscyArICciIG9uY2xpY2s9InNldFByb2ZpbGVGaWx0ZXIoXCcnICsgZW5jb2RlVVJJQ29tcG9uZW50KHAucHJvZmlsZSkgKyAnXCcpIiB0aXRsZT0iUG9rYcW8IGRhbmUgdHlsa28gZGxhIHRlZ28gcHJvZmlsdSI+JyArCiAgICAgICc8ZGl2IGNsYXNzPSJwYy1oZWFkZXIiPicgKwogICAgICAgIChpc1BpcEJveSA/IHByZWZpeEh0bWwgOiAnPGRpdiBjbGFzcz0icGMtZG90ICcgKyBzdGF0ZUNscyArICciPjwvZGl2PicpICsKICAgICAgICAnPHNwYW4gY2xhc3M9InBjLW5hbWUiPicgKyBlc2NhcGVIdG1sKHAucHJvZmlsZSkgKyAnPC9zcGFuPicgKwogICAgICAnPC9kaXY+JyArCiAgICAgICc8ZGl2IGNsYXNzPSJwYy1tZXRhIj4nICsKICAgICAgICAnPHNwYW4gY2xhc3M9InBjLW1ldGEtaXRlbSI+QUdFTlRTOicgKyBhZ2VudHMgKyAnPC9zcGFuPicgKwogICAgICAgICc8c3BhbiBjbGFzcz0icGMtbWV0YS1pdGVtIj5TRVNTSU9OUzonICsgc2VzaENvdW50ICsgJzwvc3Bhbj4nICsKICAgICAgICAnPHNwYW4gY2xhc3M9InBjLW1ldGEtaXRlbSI+VE9LRU5TOicgKyBmb3JtYXROdW1iZXIodG9rQ291bnQpICsgJzwvc3Bhbj4nICsKICAgICAgICAnPHNwYW4gY2xhc3M9InBjLW1ldGEtaXRlbSI+Q09TVDonICsgZm9ybWF0Q29zdChjb3N0VmFsKSArICc8L3NwYW4+JyArCiAgICAgICc8L2Rpdj4nICsKICAgICAgKGNvbm5lY3RlZFBsYXRzLmxlbmd0aCA+IDAgPwogICAgICAgICc8ZGl2IGNsYXNzPSJwYy1wbGF0Zm9ybXMiPicgKwogICAgICAgICAgcGxhdEluZm8ubWFwKGZ1bmN0aW9uKHBsKSB7CiAgICAgICAgICAgIHZhciBjbHMgPSBwbC5zdGF0ZSA9PT0gJ2Nvbm5lY3RlZCcgPyAnY29ubmVjdGVkJyA6ICcnOwogICAgICAgICAgICByZXR1cm4gJzxzcGFuIGNsYXNzPSJwYy1wbGF0LWNoaXAgJyArIGNscyArICciPicgKyBlc2NhcGVIdG1sKChwbC5uYW1lfHwnJykuc3Vic3RyaW5nKDAsNikpICsgJzwvc3Bhbj4nOwogICAgICAgICAgfSkuam9pbignJykgKwogICAgICAgICc8L2Rpdj4nIDogJycpICsKICAgICAgJzxkaXYgY2xhc3M9InBjLWZvb3RlciI+JyArCiAgICAgICAgKGd3LnVwZGF0ZWRfYXQgPyAnVVBEOicgKyB0aW1lQWdvKGd3LnVwZGF0ZWRfYXQpIDogJycpICsKICAgICAgICAoZ3cucHJvY2Vzc19jbWRsaW5lID8gJyB8ICcgKyAoZ3cucHJvY2Vzc19jbWRsaW5lIHx8ICcnKS5zcGxpdCgnLycpLnBvcCgpLnN1YnN0cmluZygwLDIwKSA6ICcnKSArCiAgICAgICc8L2Rpdj4nICsKICAgICc8L2Rpdj4nOwogIH0pLmpvaW4oJycpOwp9CgovLyA9PT09PSBQUk9GSUxFIEZJTFRFUiA9PT09PQpmdW5jdGlvbiBzZXRQcm9maWxlRmlsdGVyKGVuY29kZWROYW1lKSB7CiAgY29uc3QgbmFtZSA9IGFjdGl2ZVByb2ZpbGUgJiYgYWN0aXZlUHJvZmlsZSA9PT0gZGVjb2RlVVJJQ29tcG9uZW50KGVuY29kZWROYW1lKSA/IG51bGwgOiBkZWNvZGVVUklDb21wb25lbnQoZW5jb2RlZE5hbWUpOwogIGFjdGl2ZVByb2ZpbGUgPSBuYW1lOwogIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2FsbC1wcm9maWxlcy1idG4nKTsKICBpZiAoZWwpIGVsLnN0eWxlLmRpc3BsYXkgPSBhY3RpdmVQcm9maWxlID8gJ2lubGluZS1ibG9jaycgOiAnbm9uZSc7CiAgcmVmcmVzaEFsbCgpOwp9CgovLyA9PT09PSBSRU5ERVI6IEtQSSBHUklEID09PT09CmZ1bmN0aW9uIHJlbmRlcktwaUdyaWQoc3RhdHVzRGF0YSwgdXNhZ2VEYXRhLCBzZXNzaW9uc0RhdGEsIGthbmJhbkRhdGEsIGFsZXJ0c0RhdGEsIGtleXNEYXRhKSB7CiAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgna3BpLWdyaWQnKTsKICBpZiAoc3RhdHVzRGF0YT8uX2Vycm9yICYmIHVzYWdlRGF0YT8uX2Vycm9yKSB7CiAgICBlbC5pbm5lckhUTUwgPSAnPGRpdiBjbGFzcz0ic3RhdGUtbXNnIj48ZGl2IGNsYXNzPSJpY29uIj4mI3gyNkEwOyYjeEZFMEY7PC9kaXY+PGRpdiBjbGFzcz0idGl0bGUgaGVhZGluZy1tZCI+TmllIG1vJiN4MTdDO25hIHphJiN4MTQyO2Fkb3dhJiN4MTA3OyBtZXRyeWs8L2Rpdj48ZGl2IGNsYXNzPSJkZXNjIGJvZHktc20iPkJhY2tlbmQgbmllIG9kcG93aWFkYTwvZGl2PjwvZGl2Pic7CiAgICByZXR1cm47CiAgfQoKICBjb25zdCBzdW1tYXJ5ID0gc3RhdHVzRGF0YT8uc3VtbWFyeSB8fCB7fTsKICBjb25zdCBzZXNzaW9ucyA9IHNlc3Npb25zRGF0YT8uc2Vzc2lvbnMgfHwgW107CiAgY29uc3QgdXNhZ2UgPSB1c2FnZURhdGE/LmRhaWx5IHx8IFtdOwogIGNvbnN0IHRvZGF5VXNhZ2UgPSB1c2FnZS5sZW5ndGggPiAwID8gdXNhZ2VbdXNhZ2UubGVuZ3RoIC0gMV0gOiBudWxsOwoKICAvLyBBY3RpdmUgcHJvZmlsZSBmaWx0ZXI6IGlmIGEgcHJvZmlsZSBpcyBzZWxlY3RlZCwgc2hvdyBvbmx5IGl0cyBkYXRhCiAgY29uc3QgcHJvZmlsZUxpc3QgPSAoc3RhdHVzRGF0YT8ucHJvZmlsZXMgfHwgW10pLmZpbHRlcihwID0+ICFhY3RpdmVQcm9maWxlIHx8IHAucHJvZmlsZSA9PT0gYWN0aXZlUHJvZmlsZSk7CgogIC8vIFRvZGF5OiB1c2FnZURhdGEuZGFpbHkgaXMgYWxyZWFkeSBhZ2dyZWdhdGVkIGFjcm9zcyB0aGUgc2NvcGUgKGFsbCBwcm9maWxlcywgb3IgdGhlIHNpbmdsZQogIC8vIHNlbGVjdGVkIHByb2ZpbGUgd2hlbiBmaWx0ZXJlZCDigJQgcmVmcmVzaEFsbCBvbmx5IGZldGNoZXMgdGhhdCBwcm9maWxlKS4gTGFzdCBlbnRyeSA9IHRvZGF5LgogIGNvbnN0IHRvZGF5RGF0YSA9IHRvZGF5VXNhZ2UgfHwge3Rva2Vuczp7aW5wdXQ6MCxvdXRwdXQ6MH0sIGNvc3Q6e2VzdGltYXRlZF91c2Q6MH0sIHNlc3Npb25fY291bnQ6MCwgZGF5OiBudWxsfTsKICBjb25zdCBkYXlMYWJlbCA9IHRvZGF5RGF0YS5kYXkgPyB0b2RheURhdGEuZGF5IDogJy0tJzsKCiAgLy8gQWN0aXZlIGFnZW50cyBhY3Jvc3MgKGZpbHRlcmVkIG9yIGFsbCkgcHJvZmlsZXMKICBsZXQgYWN0aXZlQWdlbnRzID0gMDsKICBwcm9maWxlTGlzdC5mb3JFYWNoKHAgPT4geyBhY3RpdmVBZ2VudHMgKz0gcC5nYXRld2F5Py5hY3RpdmVfYWdlbnRzIHx8IDA7IH0pOwoKICAvLyBBZ2dyZWdhdGVkIHRvdGFscyBvdmVyIHRoZSBkYWlseSB3aW5kb3cgKGFsbCBkYXlzKSBmb3IgdGhlICJyYXplbSIgdGlsZXMKICBsZXQgdG90YWxUb2tlbnNJbiA9IDAsIHRvdGFsVG9rZW5zT3V0ID0gMCwgdG90YWxDb3N0RXN0ID0gMDsKICAodXNhZ2UgfHwgW10pLmZvckVhY2goZGF5ID0+IHsKICAgIHRvdGFsVG9rZW5zSW4gKz0gZGF5LnRva2Vucz8uaW5wdXQgfHwgMDsKICAgIHRvdGFsVG9rZW5zT3V0ICs9IGRheS50b2tlbnM/Lm91dHB1dCB8fCAwOwogICAgdG90YWxDb3N0RXN0ICs9IGRheS5jb3N0Py5lc3RpbWF0ZWRfdXNkIHx8IDA7CiAgfSk7CgogIC8vIFNlc3Npb24gY291bnQgZm9yIHRoZSBkYXRhIHNjb3BlIChhbGwgcHJvZmlsZXMgdnMgc2luZ2xlIHByb2ZpbGUpCiAgY29uc3Qgc2Vzc2lvbnNTY29wZSA9IGFjdGl2ZVByb2ZpbGUKICAgID8gKHRvZGF5VXNhZ2UgPyB0b2RheVVzYWdlLnNlc3Npb25fY291bnQgfHwgMCA6IDApCiAgICA6IChzZXNzaW9ucy5sZW5ndGgpOwoKICBjb25zdCB0aWxlcyA9IFsKICAgIHsKICAgICAgbGFiZWw6ICdQcm9maWxlIG9ubGluZScsCiAgICAgIHZhbHVlOiAoc3VtbWFyeS5wcm9maWxlc19ydW5uaW5nIHx8IDApICsgJy8nICsgKHN1bW1hcnkucHJvZmlsZXNfdG90YWwgfHwgMCksCiAgICAgIHN1Yjogc3VtbWFyeS5wcm9maWxlc19ydW5uaW5nID09PSBzdW1tYXJ5LnByb2ZpbGVzX3RvdGFsID8gJ1dzenlzdGtpZSBPSycgOiAnTmlla3RvcmUgb2ZmbGluZScsCiAgICAgIGNsczogJycKICAgIH0sCiAgICB7CiAgICAgIGxhYmVsOiAnQWt0eXduZSBhZ2VudHknLAogICAgICB2YWx1ZTogYWN0aXZlQWdlbnRzLAogICAgICBzdWI6IGFjdGl2ZVByb2ZpbGUgPyAoJ3Byb2ZpbDogJyArIGFjdGl2ZVByb2ZpbGUpIDogJ3N1YnByb2Nlc3N5IGdhdGV3YXknLAogICAgICBjbHM6ICcnCiAgICB9LAogICAgewogICAgICBsYWJlbDogJ1Rva2VueSDFgsSFY3puaWUnLAogICAgICB2YWx1ZTogZm9ybWF0TnVtYmVyKHRvdGFsVG9rZW5zSW4gKyB0b3RhbFRva2Vuc091dCksCiAgICAgIHN1YjogZm9ybWF0TnVtYmVyKHRvdGFsVG9rZW5zSW4pICsgJyBpbiAvICcgKyBmb3JtYXROdW1iZXIodG90YWxUb2tlbnNPdXQpICsgJyBvdXQnLAogICAgICBjbHM6ICcnCiAgICB9LAogICAgewogICAgICBsYWJlbDogJ1Rva2VueSAob3V0cHV0LHN1bWEpJywKICAgICAgdmFsdWU6IGZvcm1hdE51bWJlcih0b2RheVVzYWdlPy50b2tlbnM/Lm91dHB1dCB8fCAwKSwKICAgICAgc3ViOiAnc2VzamE6ICcgKyBzZXNzaW9uc1Njb3BlICsgJyDCtyBkemllxYQ6ICcgKyBkYXlMYWJlbCwKICAgICAgY2xzOiAnJwogICAgfSwKICAgIHsKICAgICAgbGFiZWw6ICdUb2tlbnkgKGlucHV0LHN1bWEpJywKICAgICAgdmFsdWU6IGZvcm1hdE51bWJlcih0b2RheVVzYWdlPy50b2tlbnM/LmlucHV0IHx8IDApLAogICAgICBzdWI6ICdzZXNqYTogJyArIHNlc3Npb25zU2NvcGUgKyAoYWN0aXZlUHJvZmlsZSA/ICcgwrcgJyArIGFjdGl2ZVByb2ZpbGUgOiAnJykgKyAnIMK3IGR6aWXFhDogJyArIGRheUxhYmVsLAogICAgICBjbHM6ICcnCiAgICB9LAogICAgewogICAgICBsYWJlbDogJ0tvc3p0IMWCxIVjem5pZSAoZXN0LiknLAogICAgICB2YWx1ZTogZm9ybWF0Q29zdCh0b3RhbENvc3RFc3QpLAogICAgICBzdWI6IGFjdGl2ZVByb2ZpbGUgPyAncHJvZmlsOiAnICsgYWN0aXZlUHJvZmlsZSA6ICdXc3p5c3RraWUgcHJvZmlsZScsCiAgICAgIGNsczogJycKICAgIH0sCiAgICB7CiAgICAgIGxhYmVsOiAnS29zenQgZHppxZsgKGVzdC4pJywKICAgICAgdmFsdWU6IGZvcm1hdENvc3QodG9kYXlVc2FnZT8uY29zdD8uZXN0aW1hdGVkX3VzZCB8fCAwKSwKICAgICAgc3ViOiAodXNhZ2VEYXRhPy5ieV9tb2RlbD8ubGVuZ3RoIHx8IDApICsgJyBtb2RlbGUnLAogICAgICBjbHM6ICcnCiAgICB9LAogICAgewogICAgICBsYWJlbDogJ0LFgsSZZHkgKDFoKScsCiAgICAgIHZhbHVlOiBzdW1tYXJ5LmVycm9yc18xaCB8fCAwLAogICAgICBzdWI6IHN1bW1hcnkuZXJyb3JzXzFoID4gMCA/ICdXeW1hZ2EgdXdhZ2knIDogJ0N6eXN0bycsCiAgICAgIGNsczogc3VtbWFyeS5lcnJvcnNfMWggPiAwID8gJ2NyaXRpY2FsJyA6ICcnCiAgICB9CiAgXTsKCiAgZWwuaW5uZXJIVE1MID0gdGlsZXMubWFwKHQgPT4gJycKICAgICsgJzxkaXYgY2xhc3M9Im1ldHJpYy10aWxlICcgKyB0LmNscyArICciPicKICAgICsgJzxkaXYgY2xhc3M9InRpbGUtbGFiZWwgYm9keS1zbSI+JyArIHQubGFiZWwgKyAnPC9kaXY+JwogICAgKyAnPGRpdiBjbGFzcz0idGlsZS12YWx1ZSBtZXRyaWMteGwiPicgKyB0LnZhbHVlICsgJzwvZGl2PicKICAgICsgJzxkaXYgY2xhc3M9InRpbGUtc3ViIGJvZHktc20iPicgKyB0LnN1YiArICc8L2Rpdj4nCiAgICArICc8L2Rpdj4nCiAgKS5qb2luKCcnKTsKfQoKLy8gPT09PT0gUkVOREVSOiBVU0FHRSBDSEFSVCAoRUNoYXJ0cyBvciBBU0NJSSBmb3IgUGlwLUJveSkgPT09PT0KZnVuY3Rpb24gcmVuZGVyVXNhZ2VDaGFydCh1c2FnZURhdGEpIHsKICBjb25zdCBkb20gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY2hhcnQtdXNhZ2UnKTsKICB2YXIgaXNQaXBCb3kgPSBkb2N1bWVudC5ib2R5LmdldEF0dHJpYnV0ZSgnZGF0YS1sYXlvdXQnKSA9PT0gJ3BpcGJveSc7CgogIGlmIChpc1BpcEJveSkgewogICAgcmVuZGVyVXNhZ2VBc2NpaSh1c2FnZURhdGEsIGRvbSk7CiAgICByZXR1cm47CiAgfQogIGlmICghdXNhZ2VEYXRhIHx8IHVzYWdlRGF0YS5fZXJyb3IgfHwgIXVzYWdlRGF0YS5kYWlseT8ubGVuZ3RoKSB7CiAgICBpZiAodXNhZ2VDaGFydCkgeyB1c2FnZUNoYXJ0LmRpc3Bvc2UoKTsgdXNhZ2VDaGFydCA9IG51bGw7IH0KICAgIGRvbS5pbm5lckhUTUwgPSAnPGRpdiBjbGFzcz0ic3RhdGUtbXNnIiBzdHlsZT0ibWluLWhlaWdodDoyMDBweCI+PGRpdiBjbGFzcz0iZGVzYyBib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSI+QnJhayBkYW55Y2ggbyB6dXp5Y2l1PC9kaXY+PC9kaXY+JzsKICAgIHJldHVybjsKICB9CgogIGlmICghdXNhZ2VDaGFydCkgewogICAgZG9tLmlubmVySFRNTCA9ICcnOwogICAgdXNhZ2VDaGFydCA9IGVjaGFydHMuaW5pdChkb20sIG51bGwsIHtyZW5kZXJlcjonY2FudmFzJ30pOwogIH0gZWxzZSB7CiAgICB1c2FnZUNoYXJ0LnJlc2l6ZSgpOwogIH0KCiAgY29uc3QgZGF5cyA9IHVzYWdlRGF0YS5kYWlseS5zbGljZSgpLnJldmVyc2UoKTsKICBjb25zdCBkYXRlcyA9IGRheXMubWFwKGQgPT4gZC5kYXkuc2xpY2UoNSkpOwogIGNvbnN0IGlucHV0cyA9IGRheXMubWFwKGQgPT4gZC50b2tlbnM/LmlucHV0IHx8IDApOwogIGNvbnN0IG91dHB1dHMgPSBkYXlzLm1hcChkID0+IGQudG9rZW5zPy5vdXRwdXQgfHwgMCk7CiAgY29uc3QgY29zdHMgPSBkYXlzLm1hcChkID0+IGQuY29zdD8uZXN0aW1hdGVkX3VzZCB8fCAwKTsKCiAgdXNhZ2VDaGFydC5zZXRPcHRpb24oewogICAgZGFya01vZGU6IHRydWUsCiAgICBiYWNrZ3JvdW5kQ29sb3I6ICd0cmFuc3BhcmVudCcsCiAgICB0b29sdGlwOiB7CiAgICAgIHRyaWdnZXI6J2F4aXMnLAogICAgICBmb3JtYXR0ZXI6IGZ1bmN0aW9uKHBhcmFtcykgewogICAgICAgIHZhciBhcnIgPSBBcnJheS5pc0FycmF5KHBhcmFtcykgPyBwYXJhbXMgOiBbcGFyYW1zXTsKICAgICAgICByZXR1cm4gYXJyLm1hcChmdW5jdGlvbihwKSB7CiAgICAgICAgICB2YXIgbWFya2VyID0gcC5tYXJrZXIgfHwgJyc7CiAgICAgICAgICBpZiAocC5zZXJpZXNOYW1lID09PSAnS29zenQgKCQpJykgewogICAgICAgICAgICByZXR1cm4gbWFya2VyICsgcC5zZXJpZXNOYW1lICsgJzogPGI+JCcgKyAoTnVtYmVyKHAudmFsdWUpfHwwKS50b0ZpeGVkKDIpICsgJzwvYj4nOwogICAgICAgICAgfQogICAgICAgICAgcmV0dXJuIG1hcmtlciArIHAuc2VyaWVzTmFtZSArICc6IDxiPicgKyBmb3JtYXROdW1iZXIocC52YWx1ZSkgKyAnPC9iPic7CiAgICAgICAgfSkuam9pbignPGJyLz4nKTsKICAgICAgfQogICAgfSwKICAgIGxlZ2VuZDoge2RhdGE6WydJbnB1dCB0b2tlbnMnLCdPdXRwdXQgdG9rZW5zJywnS29zenQgKCQpJ10sdGV4dFN0eWxlOntjb2xvcjonIzk0QTNCOCd9LGJvdHRvbTowfSwKICAgIGdyaWQ6IHtsZWZ0OjEyLCByaWdodDoxMiwgdG9wOjEyLCBib3R0b206MzJ9LAogICAgeEF4aXM6IHt0eXBlOidjYXRlZ29yeScsZGF0YTpkYXRlcyxheGlzTGluZTp7bGluZVN0eWxlOntjb2xvcjonIzFFMzM0Rid9fSxheGlzTGFiZWw6e2NvbG9yOicjNjQ3NDhCJyxmb250U2l6ZToxMH19LAogICAgeUF4aXM6IFsKICAgICAge3R5cGU6J3ZhbHVlJyxheGlzTGFiZWw6e2NvbG9yOicjNjQ3NDhCJyxmb250U2l6ZToxMCxmb3JtYXR0ZXI6dj0+Zm9ybWF0TnVtYmVyKHYpfSxzcGxpdExpbmU6e2xpbmVTdHlsZTp7Y29sb3I6JyMxRTMzNEYnfX19LAogICAgICB7dHlwZTondmFsdWUnLGF4aXNMYWJlbDp7Y29sb3I6JyM2NDc0OEInLGZvbnRTaXplOjEwLGZvcm1hdHRlcjp2PT4nJCcrdi50b0ZpeGVkKDIpfSxzcGxpdExpbmU6e3Nob3c6ZmFsc2V9fQogICAgXSwKICAgIHNlcmllczogWwogICAgICB7bmFtZTonSW5wdXQgdG9rZW5zJyx0eXBlOidiYXInLGRhdGE6aW5wdXRzLGl0ZW1TdHlsZTp7Y29sb3I6JyMzOEJERjgnfSxiYXJNYXhXaWR0aDoyMH0sCiAgICAgIHtuYW1lOidPdXRwdXQgdG9rZW5zJyx0eXBlOidiYXInLGRhdGE6b3V0cHV0cyxpdGVtU3R5bGU6e2NvbG9yOicjODE4Q0Y4J30sYmFyTWF4V2lkdGg6MjB9LAogICAgICB7bmFtZTonS29zenQgKCQpJyx0eXBlOidsaW5lJyx5QXhpc0luZGV4OjEsZGF0YTpjb3N0cyxsaW5lU3R5bGU6e2NvbG9yOicjRjU5RTBCJyx3aWR0aDoyfSxzeW1ib2w6J2NpcmNsZScsc3ltYm9sU2l6ZTo2LGl0ZW1TdHlsZTp7Y29sb3I6JyNGNTlFMEInfX0KICAgIF0KICB9KTsKfQoKLy8gPT09PT0gUkVOREVSOiBNT0RFTFMgVEFCTEUgKGJvdGggbGF5b3V0cyDigJQgdGFibGUgc29ydGVkIGJ5IGNvc3QgZGVzYykgPT09PT0KZnVuY3Rpb24gcmVuZGVyTW9kZWxzQ2hhcnQodXNhZ2VEYXRhKSB7CiAgY29uc3QgZG9tID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2NoYXJ0LW1vZGVscycpOwogIGlmIChtb2RlbHNDaGFydCkgeyBtb2RlbHNDaGFydC5kaXNwb3NlKCk7IG1vZGVsc0NoYXJ0ID0gbnVsbDsgfQoKICBpZiAoIXVzYWdlRGF0YSB8fCB1c2FnZURhdGEuX2Vycm9yIHx8ICF1c2FnZURhdGEuYnlfbW9kZWw/Lmxlbmd0aCkgewogICAgZG9tLmlubmVySFRNTCA9ICc8ZGl2IGNsYXNzPSJzdGF0ZS1tc2ciIHN0eWxlPSJtaW4taGVpZ2h0OjE1MHB4Ij48ZGl2IGNsYXNzPSJkZXNjIGJvZHktc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpIj5CcmFrIGRhbnljaCBvIG1vZGVsYWNoPC9kaXY+PC9kaXY+JzsKICAgIHJldHVybjsKICB9CgogIC8vIFNvcnR1aiBvZCBuYWpiYXJkemllaiBkbyBuYWptbmllaiB1xbx5d2FuZWdvIHBvZCBXWkdMxJhERU0gS09TWlTDk1cgKGRlc2MpCiAgY29uc3QgbW9kZWxzID0gKHVzYWdlRGF0YS5ieV9tb2RlbCB8fCBbXSkuc2xpY2UoKS5zb3J0KGZ1bmN0aW9uKGEsYikgewogICAgcmV0dXJuIChOdW1iZXIoYi5lc3RpbWF0ZWRfY29zdF91c2QpfHwwKSAtIChOdW1iZXIoYS5lc3RpbWF0ZWRfY29zdF91c2QpfHwwKTsKICB9KTsKCiAgZnVuY3Rpb24gbm0obSkgewogICAgcmV0dXJuICgobS5tb2RlbHx8Jz8nKS5yZXBsYWNlKC9eZGVlcHNlZWstLywnJykucmVwbGFjZSgvXm9wZW5haVwvLywnJykuc3Vic3RyaW5nKDAsMzIpKTsKICB9CgogIGRvbS5pbm5lckhUTUwgPQogICAgJzx0YWJsZSBjbGFzcz0ibW9kZWxzLXRhYmxlIj4nICsKICAgICc8dGhlYWQ+PHRyPicgKwogICAgICAnPHRoIGNsYXNzPSJtLXJhbmsiPiM8L3RoPjx0aD5Nb2RlbDwvdGg+JyArCiAgICAgICc8dGggY2xhc3M9Im0tdG9rZW5zIj5Ub2tlbnk8L3RoPjx0aCBjbGFzcz0ibS1jb3N0Ij5Lb3N6dCAoZXN0Lik8L3RoPjx0aCBjbGFzcz0ibS1jYWxscyI+V3l3b8WCYW5pYTwvdGg+JyArCiAgICAnPC90cj48L3RoZWFkPjx0Ym9keT4nICsKICAgIG1vZGVscy5zbGljZSgwLCAxNSkubWFwKGZ1bmN0aW9uKG0sIGkpIHsKICAgICAgdmFyIHQgPSAobS50b2tlbnM/LmlucHV0fHwwKSArIChtLnRva2Vucz8ub3V0cHV0fHwwKTsKICAgICAgcmV0dXJuICc8dHI+JyArCiAgICAgICAgJzx0ZCBjbGFzcz0ibS1yYW5rIj4nICsgKGkrMSkgKyAnPC90ZD4nICsKICAgICAgICAnPHRkIGNsYXNzPSJtLW5hbWUiPicgKyBlc2NhcGVIdG1sKG5tKG0pKSArICc8L3RkPicgKwogICAgICAgICc8dGQgY2xhc3M9Im0tdG9rZW5zIj4nICsgZm9ybWF0TnVtYmVyKHQpICsgJzwvdGQ+JyArCiAgICAgICAgJzx0ZCBjbGFzcz0ibS1jb3N0Ij4nICsgZm9ybWF0Q29zdChtLmVzdGltYXRlZF9jb3N0X3VzZCkgKyAnPC90ZD4nICsKICAgICAgICAnPHRkIGNsYXNzPSJtLWNhbGxzIj4nICsgZm9ybWF0TnVtYmVyKG0uYXBpX2NhbGxzKSArICc8L3RkPicgKwogICAgICAnPC90cj4nOwogICAgfSkuam9pbignJykgKwogICAgJzwvdGJvZHk+PC90YWJsZT4nOwp9CgovLyA9PT09PSBQSVAtQk9ZOiBBU0NJSSBVU0FHRSBDSEFSVCA9PT09PQpmdW5jdGlvbiByZW5kZXJVc2FnZUFzY2lpKHVzYWdlRGF0YSwgZG9tKSB7CiAgaWYgKHVzYWdlQ2hhcnQpIHsgdXNhZ2VDaGFydC5kaXNwb3NlKCk7IHVzYWdlQ2hhcnQgPSBudWxsOyB9CiAgZG9tLmlubmVySFRNTCA9ICcnOwoKICBpZiAoIXVzYWdlRGF0YSB8fCB1c2FnZURhdGEuX2Vycm9yIHx8ICF1c2FnZURhdGEuZGFpbHk/Lmxlbmd0aCkgewogICAgZG9tLmlubmVySFRNTCA9ICc8cHJlIGNsYXNzPSJhc2NpaS1jaGFydCIgc3R5bGU9Im1pbi1oZWlnaHQ6MjAwcHg7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyO2NvbG9yOnZhcigtLXRleHRNdXRlZCk7Zm9udC1mYW1pbHk6XCdKZXRCcmFpbnMgTW9ub1wnLG1vbm9zcGFjZTtmb250LXNpemU6MC43cmVtO3BhZGRpbmc6dmFyKC0tc3BhY2UtbGcpIj5CUkFLIERBTllDSCBPIFpVWllDSVU8L3ByZT4nOwogICAgcmV0dXJuOwogIH0KCiAgY29uc3QgZGF5cyA9IHVzYWdlRGF0YS5kYWlseS5zbGljZSgpLnJldmVyc2UoKS5zbGljZSgtMTQpOwogIGNvbnN0IG1heFRva2VucyA9IE1hdGgubWF4LmFwcGx5KG51bGwsIGRheXMubWFwKGZ1bmN0aW9uKGQpIHsgcmV0dXJuIChkLnRva2Vucz8uaW5wdXR8fDApICsgKGQudG9rZW5zPy5vdXRwdXR8fDApOyB9KSkgfHwgMTsKICBjb25zdCBtYXhDb3N0ID0gTWF0aC5tYXguYXBwbHkobnVsbCwgZGF5cy5tYXAoZnVuY3Rpb24oZCkgeyByZXR1cm4gZC5jb3N0Py5lc3RpbWF0ZWRfdXNkfHwwOyB9KSkgfHwgMTsKICBjb25zdCBiYXJDaGFycyA9IFsn4paBJywn4paCJywn4paDJywn4paEJywn4paFJywn4paGJywn4paHJywn4paIJ107CgogIHZhciBsaW5lcyA9IFtdOwogIGxpbmVzLnB1c2goJyAgVE9LRU4gVVNBR0UgKG9zdC4gJyArIGRheXMubGVuZ3RoICsgJyBkbmkpJyk7CiAgbGluZXMucHVzaCgnICAnICsgJ+KUgCcucmVwZWF0KDUwKSk7CiAgZGF5cy5mb3JFYWNoKGZ1bmN0aW9uKGQpIHsKICAgIHZhciB0b3RhbCA9IChkLnRva2Vucz8uaW5wdXR8fDApICsgKGQudG9rZW5zPy5vdXRwdXR8fDApOwogICAgdmFyIGlkeCA9IE1hdGgubWluKE1hdGguZmxvb3IodG90YWwgLyBtYXhUb2tlbnMgKiA3KSwgNyk7CiAgICB2YXIgYmFyID0gYmFyQ2hhcnNbaWR4XS5yZXBlYXQoTWF0aC5tYXgoMSwgTWF0aC5mbG9vcih0b3RhbCAvIG1heFRva2VucyAqIDMwKSkpOwogICAgdmFyIGxhYmVsID0gKGQuZGF5fHwnJykuc2xpY2UoNSk7CiAgICBsaW5lcy5wdXNoKCcgICcgKyBsYWJlbCArICcg4pSCJyArIGJhciArICcgJyArIGZvcm1hdE51bWJlcih0b3RhbCkpOwogIH0pOwogIGxpbmVzLnB1c2goJyAgJyArICfilIAnLnJlcGVhdCg1MCkpOwoKICBkb20uaW5uZXJIVE1MID0gJzxwcmUgY2xhc3M9ImFzY2lpLWNoYXJ0IiBzdHlsZT0ibWFyZ2luOjA7cGFkZGluZzp2YXIoLS1zcGFjZS1tZCk7Y29sb3I6dmFyKC0tcHJpbWFyeSk7Zm9udC1mYW1pbHk6XCdKZXRCcmFpbnMgTW9ub1wnLG1vbm9zcGFjZTtmb250LXNpemU6MC42NXJlbTtsaW5lLWhlaWdodDoxLjY7dGV4dC1zaGFkb3c6MCAwIDRweCByZ2JhKDIwLDI1NSwyMywwLjMpO292ZXJmbG93LXg6YXV0byI+JyArIGVzY2FwZUh0bWwobGluZXMuam9pbignXG4nKSkgKyAnPC9wcmU+JzsKfQoKLy8gPT09PT0gUElQLUJPWTogVEVYVCBNT0RFTCBMSVNUIChyZXBsYWNlZCBieSB0YWJsZSkgPT09PT0KCi8vID09PT09IFJFTkRFUjogU0VTU0lPTlMgPT09PT0KZnVuY3Rpb24gcmVuZGVyU2Vzc2lvbnMoc2Vzc2lvbnNEYXRhKSB7CiAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc2Vzc2lvbnMtbGlzdCcpOwogIGNvbnN0IGNvdW50RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc2Vzc2lvbi1jb3VudCcpOwoKICBpZiAoIXNlc3Npb25zRGF0YSB8fCBzZXNzaW9uc0RhdGEuX2Vycm9yKSB7CiAgICBlbC5pbm5lckhUTUwgPSAnPGRpdiBjbGFzcz0ic3RhdGUtbXNnIiBzdHlsZT0ibWluLWhlaWdodDoxNTBweCI+PGRpdiBjbGFzcz0iZGVzYyBib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSI+TmllIG1vem5hIHphbGFkb3dhYyBzZXNqaTwvZGl2PjwvZGl2Pic7CiAgICBjb3VudEVsLnRleHRDb250ZW50ID0gJy0tJzsKICAgIHJldHVybjsKICB9CgogIGNvbnN0IHNlc3Npb25zID0gc2Vzc2lvbnNEYXRhLnNlc3Npb25zIHx8IFtdOwogIGNvdW50RWwudGV4dENvbnRlbnQgPSBzZXNzaW9ucy5zbGljZSgwLCAxMCkubGVuZ3RoICsgJyBzZXNqaSc7CgogIGlmIChzZXNzaW9ucy5sZW5ndGggPT09IDApIHsKICAgIGVsLmlubmVySFRNTCA9ICc8ZGl2IGNsYXNzPSJzdGF0ZS1tc2ciIHN0eWxlPSJtaW4taGVpZ2h0OjE1MHB4Ij48ZGl2IGNsYXNzPSJkZXNjIGJvZHktc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpIj5CcmFrIHNlc2ppPC9kaXY+PC9kaXY+JzsKICAgIHJldHVybjsKICB9CgogIGVsLmlubmVySFRNTCA9IHNlc3Npb25zLnNsaWNlKDAsIDEwKS5tYXAocyA9PiB7CiAgICB2YXIgaXNQaXBCb3kgPSBkb2N1bWVudC5ib2R5LmdldEF0dHJpYnV0ZSgnZGF0YS1sYXlvdXQnKSA9PT0gJ3BpcGJveSc7CiAgICB2YXIgc291cmNlSWNvbjsKICAgIGlmIChpc1BpcEJveSkgewogICAgICBzb3VyY2VJY29uID0gcy5zb3VyY2UgPT09ICd0ZWxlZ3JhbScgPyAnW1RdJyA6IHMuc291cmNlID09PSAna2FuYmFuJyA/ICdbS10nIDogJ1tDXSc7CiAgICB9IGVsc2UgewogICAgICBzb3VyY2VJY29uID0gcy5zb3VyY2UgPT09ICd0ZWxlZ3JhbScgPyAnVCcgOiBzLnNvdXJjZSA9PT0gJ2thbmJhbicgPyAnSycgOiAnQyc7CiAgICB9CiAgICBjb25zdCBuYW1lID0gcy5kaXNwbGF5X25hbWUgfHwgcy5pZD8uc2xpY2UoMCwgMTYpIHx8ICctLSc7CiAgICByZXR1cm4gJzxkaXYgY2xhc3M9InNlc3Npb24tcm93Ij4nICsKICAgICAgJzxkaXYgdGl0bGU9IicgKyBlc2NhcGVIdG1sKHMuc291cmNlKSArICciIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO2ZvbnQtc2l6ZTowLjdyZW07Zm9udC13ZWlnaHQ6NjAwIj4nICsgc291cmNlSWNvbiArICc8L2Rpdj4nICsKICAgICAgJzxzcGFuIGNsYXNzPSJwcm9maWxlLWNoaXAtbWluaSI+JyArIGVzY2FwZUh0bWwocy5fcHJvZmlsZSB8fCAnPycpICsgJzwvc3Bhbj4nICsKICAgICAgJzxkaXY+JyArCiAgICAgICAgJzxkaXYgY2xhc3M9ImJvZHktc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0UHJpbWFyeSkiPicgKyBlc2NhcGVIdG1sKG5hbWUpICsgJzwvZGl2PicgKwogICAgICAgICc8ZGl2IGNsYXNzPSJib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSI+JyArIGVzY2FwZUh0bWwocy5tb2RlbHx8Jy0tJykgKyAnIC8gJyArIChzLm1lc3NhZ2VfY291bnR8fDApICsgJyBtc2cgLyAnICsgKHMuYXBpX2NhbGxfY291bnR8fDApICsgJyBjYWxsPC9kaXY+JyArCiAgICAgICc8L2Rpdj4nICsKICAgICAgJzxkaXYgY2xhc3M9ImhpZGUtbW9iaWxlIG1vbm8tc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KSI+JyArIGZvcm1hdE51bWJlcihzLnRva2Vucz8udG90YWx8fDApICsgJyB0b2suPC9kaXY+JyArCiAgICAgICc8ZGl2IGNsYXNzPSJoaWRlLW1vYmlsZSBtb25vLXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSkiPicgKyBmb3JtYXRDb3N0KHMuY29zdD8uZXN0aW1hdGVkX3VzZCkgKyAnPC9kaXY+JyArCiAgICAgICc8ZGl2IGNsYXNzPSJoaWRlLW1vYmlsZSBib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSI+JyArIHRpbWVBZ28ocy5sYXN0X2FjdGl2aXR5X2F0KSArICc8L2Rpdj4nICsKICAgICc8L2Rpdj4nOwogIH0pLmpvaW4oJycpOwp9CgovLyA9PT09PSBSRU5ERVI6IEdBVEVXQVkgPT09PT0KLy8gRm9ybWF0b3dhbmllIGN6YXN1IHByYWN5IC8gd2lla3UKZnVuY3Rpb24gZm10RHVyKHMpIHsKICBpZiAocyA9PSBudWxsIHx8IGlzTmFOKHMpKSByZXR1cm4gJy0tJzsKICBpZiAocyA8IDYwKSByZXR1cm4gTWF0aC5yb3VuZChzKSArICdzJzsKICBpZiAocyA8IDM2MDApIHJldHVybiBNYXRoLnJvdW5kKHMgLyA2MCkgKyAnbSc7CiAgaWYgKHMgPCA4NjQwMCkgcmV0dXJuIChzIC8gMzYwMCkudG9GaXhlZCgxKSArICdoJzsKICByZXR1cm4gKHMgLyA4NjQwMCkudG9GaXhlZCgxKSArICdkJzsKfQovLyBLYXRlZ29yaWEga3JvcGtpIHN0YXR1c3UgcHJvZmlsdTogb2sgLyB3YXJuIC8gZXJyIC8gbm9uZQpmdW5jdGlvbiBnd1N0YXR1cyhndykgewogIGlmICghZ3cgfHwgIWd3Lmhhc093blByb3BlcnR5KCdzdGF0ZScpKSByZXR1cm4gJ25vbmUnOwogIGlmIChndy5zdGF0ZSAhPT0gJ3J1bm5pbmcnKSByZXR1cm4gJ2Vycic7CiAgLy8gcnVubmluZzogbWFydHd5IGNyb24gdGlja2VyIC8gYsWCxJlkeSAvIGN6xJnFm8SHIHBsYXRmb3JtIGRpc2Nvbm5lY3RlZCA9PiB3YXJuCiAgaWYgKGd3LmNyb25fYWxpdmUgPT09IGZhbHNlKSByZXR1cm4gJ3dhcm4nOwogIGlmICgoZ3cuZXJyb3JzXzFoIHx8IDApID4gMCkgcmV0dXJuICd3YXJuJzsKICB2YXIgcGxhdHMgPSBndy5wbGF0Zm9ybXMgfHwgW107CiAgaWYgKHBsYXRzLmxlbmd0aCA+IDApIHsKICAgIHZhciBjb25uZWN0ZWQgPSBwbGF0cy5maWx0ZXIoZnVuY3Rpb24oeCkgeyByZXR1cm4geC5zdGF0ZSA9PT0gJ2Nvbm5lY3RlZCc7IH0pLmxlbmd0aDsKICAgIGlmIChjb25uZWN0ZWQgPCBwbGF0cy5sZW5ndGgpIHJldHVybiAnd2Fybic7CiAgfQogIHJldHVybiAnb2snOwp9Ci8vIFN0YW4gc3pjemVnw7PFgm93eSArIGRlc2lyZWRfc3RhdGUKZnVuY3Rpb24gZ3dTdGF0ZU1ldGEoZ3cpIHsKICB2YXIgc3QgPSBndy5zdGF0ZSB8fCAndW5rbm93bic7CiAgdmFyIGRzID0gZ3cuZGVzaXJlZF9zdGF0ZTsKICBpZiAoc3QgPT09ICdydW5uaW5nJykgewogICAgaWYgKGRzICYmIGRzICE9PSAncnVubmluZycgJiYgZHMgIT09ICd1cCcpIHJldHVybiB7IGxhYmVsOiAncnVubmluZycsIGNsaWVudDogJ3VwIChjaGNlICcgKyBkcyArICcpJyB9OwogICAgcmV0dXJuIHsgbGFiZWw6ICdydW5uaW5nJywgY2xpZW50OiBudWxsIH07CiAgfQogIGlmIChkcyAmJiBkcyAhPT0gc3QpIHJldHVybiB7IGxhYmVsOiBzdCwgY2xpZW50OiAnY2hjZSAnICsgZHMgfTsKICByZXR1cm4geyBsYWJlbDogc3QsIGNsaWVudDogbnVsbCB9Owp9CmZ1bmN0aW9uIHJlbmRlckdhdGV3YXkoc3RhdHVzRGF0YSkgewogIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2dhdGV3YXktbGlzdCcpOwogIGNvbnN0IGNvdW50RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZ2F0ZXdheS1jb3VudCcpOwoKICBpZiAoIXN0YXR1c0RhdGEgfHwgc3RhdHVzRGF0YS5fZXJyb3IgfHwgIXN0YXR1c0RhdGEucHJvZmlsZXMpIHsKICAgIGVsLmlubmVySFRNTCA9ICc8ZGl2IGNsYXNzPSJzdGF0ZS1tc2ciIHN0eWxlPSJtaW4taGVpZ2h0OjE1MHB4Ij48ZGl2IGNsYXNzPSJkZXNjIGJvZHktc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpIj5CcmFrIGRhbnljaCBvIGdhdGV3YXk8L2Rpdj48L2Rpdj4nOwogICAgY291bnRFbC50ZXh0Q29udGVudCA9ICctLSc7CiAgICByZXR1cm47CiAgfQoKICB2YXIgcHJvZmlsZXMgPSBzdGF0dXNEYXRhLnByb2ZpbGVzIHx8IFtdOwogIHZhciBhZ2dyZWdhdG9ycyA9IHsgdXA6IDAsIHdhcm46IDAsIGRvd246IDAsIG5vbmU6IDAsIG9ubGluZTogMCwgdG90YWw6IDAgfTsKICBwcm9maWxlcy5mb3JFYWNoKGZ1bmN0aW9uKHApIHsKICAgIHZhciBnID0gcC5nYXRld2F5IHx8IHt9OwogICAgdmFyIGNhdCA9IGd3U3RhdHVzKGcpOwogICAgaWYgKGNhdCA9PT0gJ29rJykgYWdncmVnYXRvcnMudXArKzsKICAgIGVsc2UgaWYgKGNhdCA9PT0gJ3dhcm4nKSBhZ2dyZWdhdG9ycy53YXJuKys7CiAgICBlbHNlIGlmIChjYXQgPT09ICdlcnInKSBhZ2dyZWdhdG9ycy5kb3duKys7CiAgICBlbHNlIGFnZ3JlZ2F0b3JzLm5vbmUrKzsKICAgIChnLnBsYXRmb3JtcyB8fCBbXSkuZm9yRWFjaChmdW5jdGlvbihwbCkgeyBhZ2dyZWdhdG9ycy50b3RhbCsrOyBpZiAocGwuc3RhdGUgPT09ICdjb25uZWN0ZWQnKSBhZ2dyZWdhdG9ycy5vbmxpbmUrKzsgfSk7CiAgfSk7CgogIHZhciBodG1sID0gcHJvZmlsZXMubWFwKGZ1bmN0aW9uKHApIHsKICAgIHZhciBnID0gcC5nYXRld2F5IHx8IHt9OwogICAgdmFyIGNhdCA9IGd3U3RhdHVzKGcpOwogICAgdmFyIG1ldGEgPSBnd1N0YXRlTWV0YShnKTsKICAgIHZhciBwaWQgPSBnLnBpZDsKICAgIHZhciB1cFR4dCA9IGZtdER1cihnLnVwdGltZSk7CiAgICB2YXIgYWdlVHh0ID0gKGcuYWdlX3NlY29uZHMgIT0gbnVsbCAmJiBnLmFnZV9zZWNvbmRzIDwgODY0MDApCiAgICAgID8gZm10RHVyKGcuYWdlX3NlY29uZHMpICsgJyB0ZW11JyA6IGZtdER1cihnLmFnZV9zZWNvbmRzKTsKICAgIC8vIHpuYWN6ZWsgb2TFm3dpZcW8ZW5pYSB0eWxrbyBnZHkgZGFuZSBpc3RuaWVqxIUKICAgIHZhciBhZ2VIdG1sID0gKGcudXBkYXRlZF9hdCkgPyAnPHNwYW4+dXBkYXRlIDxzcGFuIGNsYXNzPSJva3YiPicgKyBlc2NhcGVIdG1sKGFnZVR4dCkgKyAnPC9zcGFuPjwvc3Bhbj4nIDogJyc7CiAgICAvLyBleGl0X3JlYXNvbiB0eWxrbyBnZHkgbmllIG51bGwKICAgIHZhciBleGl0SHRtbCA9IChnLmV4aXRfcmVhc29uICE9IG51bGwgJiYgZy5leGl0X3JlYXNvbiAhPT0gJycpID8gJzxzcGFuIGNsYXNzPSJmbGFnLWV4aXQiIHRpdGxlPSInICsgZXNjYXBlSHRtbChnLmV4aXRfcmVhc29uKSArICciPmV4aXQ6ICcgKyBlc2NhcGVIdG1sKFN0cmluZyhnLmV4aXRfcmVhc29uKSkgKyAnPC9zcGFuPicgOiAnJzsKICAgIC8vIHJlc3RhcnRfcmVxdWVzdGVkCiAgICB2YXIgcmVzdGFydEh0bWwgPSBnLnJlc3RhcnRfcmVxdWVzdGVkID8gJzxzcGFuIGNsYXNzPSJmbGFnLXJlc3RhcnQiIHRpdGxlPSJSZXN0YXJ0IMW8xIVkYW55Ij5SRVNUQVJUPC9zcGFuPicgOiAnJzsKICAgIC8vIGLFgsSZZHkgMWgKICAgIHZhciBlcnJIdG1sID0gKGcuZXJyb3JzXzFoIHx8IDApID4gMCA/ICc8c3BhbiBjbGFzcz0iYmFkIj4nICsgKGcuZXJyb3JzXzFoKSArICcgYsWCLjwvc3Bhbj4nIDogJyc7CiAgICAvLyBjcm9uIHRpY2tlcgogICAgdmFyIGNyb25IdG1sID0gKGcuY3Jvbl9hbGl2ZSA9PT0gZmFsc2UpID8gJzxzcGFuIGNsYXNzPSJiYWQiPmNyb24gJyArIGZtdER1cihnLmNyb25faGVhcnRiZWF0X2FnZV9zZWNvbmRzKSArICcrczwvc3Bhbj4nIDogJyc7CiAgICAvLyBvcGlzIHN0YW51IGN6xJnFm2Npb3dlZ28gcG9kIGtyb3BrxIUKICAgIHZhciBwYXJ0aWFsTm90ZSA9IG51bGw7CiAgICBpZiAoY2F0ID09PSAnd2FybicpIHsKICAgICAgdmFyIGJpdHMgPSBbXTsKICAgICAgaWYgKGcuY3Jvbl9hbGl2ZSA9PT0gZmFsc2UpIGJpdHMucHVzaCgnY3JvbiArJyArIGZtdER1cihnLmNyb25faGVhcnRiZWF0X2FnZV9zZWNvbmRzIHx8IDApKTsKICAgICAgaWYgKChnLmVycm9yc18xaCB8fCAwKSA+IDApIGJpdHMucHVzaCgoZy5lcnJvcnNfMWgpICsgJyBixYLEmWTDs3cnKTsKICAgICAgdmFyIHBsYXRzID0gZy5wbGF0Zm9ybXMgfHwgW107CiAgICAgIHBsYXRzLmZvckVhY2goZnVuY3Rpb24ocGwpIHsgaWYgKHBsLnN0YXRlICE9PSAnY29ubmVjdGVkJykgYml0cy5wdXNoKHBsLm5hbWUgKyAnICcgKyBwbC5zdGF0ZSk7IH0pOwogICAgICBwYXJ0aWFsTm90ZSA9IGJpdHMuam9pbignLCAnKTsKICAgIH0KCiAgICAvLyBwb2Qtc2tsZXAgcGxhdGZvcm0gKGV4cGFuZGVyKQogICAgdmFyIHBsYXRzID0gZy5wbGF0Zm9ybXMgfHwgW107CiAgICB2YXIgcGxhdEh0bWwgPSAnJzsKICAgIGlmIChwbGF0cy5sZW5ndGggPiAwKSB7CiAgICAgIHZhciBwbFJvd3MgPSBwbGF0cy5tYXAoZnVuY3Rpb24ocGwpIHsKICAgICAgICB2YXIgcyA9IHBsLnN0YXRlIHx8ICd1bmtub3duJzsKICAgICAgICB2YXIgZG90Q2xzID0gcyA9PT0gJ2Nvbm5lY3RlZCcgPyAnY29ubmVjdGVkJyA6IChzID09PSAnZGlzY29ubmVjdGVkJyA/ICdkaXNjb25uZWN0ZWQnIDogKHMgPT09ICdzdGFydGluZycgfHwgcyA9PT0gJ2Nvbm5lY3RpbmcnID8gJ3N0YXJ0aW5nJyA6ICd1bmtub3duJykpOwogICAgICAgIHZhciBlcnJUeHQgPSBwbC5lcnJvcl9jb2RlICE9IG51bGwgPyAoJyDCtyAnICsgZXNjYXBlSHRtbChTdHJpbmcocGwuZXJyb3JfY29kZSkpKSA6ICcnOwogICAgICAgIGlmIChwbC5lcnJvcl9tZXNzYWdlKSBlcnJUeHQgKz0gJyDCtyAnICsgZXNjYXBlSHRtbChTdHJpbmcocGwuZXJyb3JfbWVzc2FnZSkpOwogICAgICAgIHJldHVybiAnPGRpdiBjbGFzcz0iZ3ctcGxhdGZvcm0tcm93Ij48ZGl2IGNsYXNzPSJwbC1zdGF0ZSI+PHNwYW4gY2xhc3M9Imd3LXBsLWRvdCAnICsgZG90Q2xzICsgJyI+PC9zcGFuPjxzcGFuPicgKyBlc2NhcGVIdG1sKHBsLm5hbWUpICsgJzwvc3Bhbj48c3BhbiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSI+JyArIGVzY2FwZUh0bWwocykgKyAnPC9zcGFuPjwvZGl2PicgKyAoZXJyVHh0ID8gJzxzcGFuIGNsYXNzPSJwbC1lcnIiIHRpdGxlPSInICsgZXJyVHh0ICsgJyI+JyArIGVyclR4dCArICc8L3NwYW4+JyA6ICcnKSArICc8L2Rpdj4nOwogICAgICB9KS5qb2luKCcnKTsKICAgICAgcGxhdEh0bWwgPSAnPGRpdiBjbGFzcz0iZ3ctcGxhdGZvcm1zIj48ZGl2IGNsYXNzPSJndy1wbGF0Zm9ybS1yb3ciIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KTtmb250LXdlaWdodDo2MDAiPjxzcGFuPlBsYXRmb3JteTwvc3Bhbj48c3Bhbj4nICsgcGxhdHMuZmlsdGVyKGZ1bmN0aW9uKHgpe3JldHVybiB4LnN0YXRlPT09J2Nvbm5lY3RlZCc7fSkubGVuZ3RoICsgJy8nICsgcGxhdHMubGVuZ3RoICsgJyBvbmxpbmU8L3NwYW4+PC9kaXY+JyArIHBsUm93cyArICc8L2Rpdj4nOwogICAgfQoKICAgIHZhciBtZXRhUGFydHMgPSBbXTsKICAgIG1ldGFQYXJ0cy5wdXNoKHBpZCAhPSBudWxsICYmIHBpZCAhPT0gJycgPyAncGlkICcgKyBwaWQgOiAncGlkIOKIkicpOwogICAgbWV0YVBhcnRzLnB1c2goJ3VwICcgKyB1cFR4dCk7CiAgICBtZXRhUGFydHMucHVzaChhZ2VIdG1sKTsKICAgIGlmIChyZXN0YXJ0SHRtbCkgbWV0YVBhcnRzLnB1c2gocmVzdGFydEh0bWwpOwogICAgaWYgKGV4aXRIdG1sKSBtZXRhUGFydHMucHVzaChleGl0SHRtbCk7CiAgICBpZiAoZXJySHRtbCkgbWV0YVBhcnRzLnB1c2goZXJySHRtbCk7CiAgICBpZiAoY3Jvbkh0bWwpIG1ldGFQYXJ0cy5wdXNoKGNyb25IdG1sKTsKICAgIHZhciBtZXRhSHRtbCA9IG1ldGFQYXJ0cy5qb2luKCc8c3BhbiBzdHlsZT0ib3BhY2l0eTowLjMiPnw8L3NwYW4+Jyk7CgogICAgdmFyIHN0YXR1c0xhYmVsID0gKGNhdCA9PT0gJ29rJykgPyAnVVAnIDogKGNhdCA9PT0gJ2VycicgPyAnRE9XTicgOiAoY2F0ID09PSAnd2FybicgPyAnQ1rEmMWaQ0lPV08nIDogJ0JSQUsnKSk7CiAgICB2YXIgc3RhdHVzQ29sb3IgPSBjYXQgPT09ICdvaycgPyAndmFyKC0tc3VjY2VzcyknIDogKGNhdCA9PT0gJ2VycicgPyAndmFyKC0tY3JpdGljYWwpJyA6IChjYXQgPT09ICd3YXJuJyA/ICcjZWFiMzA4JyA6ICd2YXIoLS10ZXh0TXV0ZWQpJykpOwoKICAgIHZhciBsaW5lID0gJzxkaXYgY2xhc3M9ImdhdGV3YXktcm93Ij4nCiAgICAgICsgJzxkaXYgY2xhc3M9Imd3LWxlZnQiPicKICAgICAgICArICc8ZGl2IGNsYXNzPSJndy1pbmZvIj4nCiAgICAgICAgICArICc8ZGl2PjxzcGFuIGNsYXNzPSJndy1uYW1lIj4nICsgZXNjYXBlSHRtbChwLnByb2ZpbGUpICsgJzwvc3Bhbj4gJwogICAgICAgICAgICArIChnLmFjdGl2ZV9hZ2VudHMgPyAnPHNwYW4gY2xhc3M9Imd3LWFnZW50cyI+JyArIGcuYWN0aXZlX2FnZW50cyArICcgYWcuPC9zcGFuPicgOiAnJykKICAgICAgICAgICAgKyAnPHNwYW4gY2xhc3M9Imd3LXN1YiI+JyArIGVzY2FwZUh0bWwobWV0YS5sYWJlbCkgKyAobWV0YS5jbGllbnQgPyAnICgnICsgZXNjYXBlSHRtbChtZXRhLmNsaWVudCkgKyAnKScgOiAnJykgKyAnPC9zcGFuPjwvZGl2PicKICAgICAgICAgICsgJzxkaXYgY2xhc3M9Imd3LW1ldGEiPicgKyBtZXRhSHRtbCArICc8L2Rpdj4nCiAgICAgICAgICArIChwYXJ0aWFsTm90ZSA/ICc8ZGl2IHN0eWxlPSJmb250LXNpemU6MC42cmVtO2NvbG9yOnZhcigtLXRleHRNdXRlZCkiPicgKyBlc2NhcGVIdG1sKHBhcnRpYWxOb3RlKSArICc8L2Rpdj4nIDogJycpCiAgICAgICAgKyAnPC9kaXY+JwogICAgICArICc8L2Rpdj4nCiAgICAgICsgJzxkaXYgY2xhc3M9Imd3LXN0YXR1cyI+JwogICAgICAgICsgJzxkaXYgY2xhc3M9Imd3LWRvdCAnICsgY2F0ICsgJyI+PC9kaXY+JwogICAgICAgICsgJzxzcGFuIHN0eWxlPSJjb2xvcjonICsgc3RhdHVzQ29sb3IgKyAnIj4nICsgc3RhdHVzTGFiZWwgKyAnPC9zcGFuPicKICAgICAgICArIChwbGF0cy5sZW5ndGggPyAnPGJ1dHRvbiBjbGFzcz0iZ3ctZXhwYW5kIiBkYXRhLXByb2ZpbGU9IicgKyBlc2NhcGVIdG1sKHAucHJvZmlsZSkgKyAnIj5wbGF0Zm9ybXkgJyArIHBsYXRzLmZpbHRlcihmdW5jdGlvbih4KXtyZXR1cm4geC5zdGF0ZT09PSdjb25uZWN0ZWQnO30pLmxlbmd0aCArICcvJyArIHBsYXRzLmxlbmd0aCArICc8L2J1dHRvbj4nIDogJycpCiAgICAgICsgJzwvZGl2PicKICAgICsgJzwvZGl2PicKICAgICsgcGxhdEh0bWw7CgogICAgcmV0dXJuIGxpbmU7CiAgfSkuam9pbignJyk7CgogIGNvdW50RWwudGV4dENvbnRlbnQgPSBwcm9maWxlcy5sZW5ndGggKyAnIGd3LCAnICsgYWdncmVnYXRvcnMudXAgKyAnIFVQLCAnICsgYWdncmVnYXRvcnMud2FybiArICcgY3rEhXN0LiwgJyArIGFnZ3JlZ2F0b3JzLmRvd24gKyAnIERPV04gwrcgJyArIGFnZ3JlZ2F0b3JzLm9ubGluZSArICcvJyArIGFnZ3JlZ2F0b3JzLnRvdGFsICsgJyBwbGF0Zm9ybSBvbmxpbmUnOwogIGVsLmlubmVySFRNTCA9IGh0bWw7CgogIC8vIERlbGVnYXRlIGNsaWNrIG5hIGV4cGFuZGVyeSBwbGF0Zm9ybSAobmFqcGllcncgdXN1d2FteSBzdGFyeSBoYW5kbGVyKQogIGlmIChlbC5fZ3dFeHBhbmRIYW5kbGVyKSBlbC5yZW1vdmVFdmVudExpc3RlbmVyKCdjbGljaycsIGVsLl9nd0V4cGFuZEhhbmRsZXIpOwogIGVsLl9nd0V4cGFuZEhhbmRsZXIgPSBmdW5jdGlvbihldikgewogICAgaWYgKGV2LnRhcmdldC5jbG9zZXN0KCcuZ3ctZXhwYW5kJykpIHsKICAgICAgdmFyIHJvdyA9IGV2LnRhcmdldC5jbG9zZXN0KCcuZ2F0ZXdheS1yb3cnKTsKICAgICAgdmFyIHBsRWwgPSByb3cgPyByb3cubmV4dEVsZW1lbnRTaWJsaW5nIDogbnVsbDsKICAgICAgaWYgKHBsRWwgJiYgcGxFbC5jbGFzc0xpc3QuY29udGFpbnMoJ2d3LXBsYXRmb3JtcycpKSB7CiAgICAgICAgcGxFbC5jbGFzc0xpc3QudG9nZ2xlKCdvcGVuJyk7CiAgICAgICAgdmFyIGFjdGl2ZSA9IHBsRWwuY2xhc3NMaXN0LmNvbnRhaW5zKCdvcGVuJyk7CiAgICAgICAgdmFyIGNvbm5lY3RlZCA9IHBsRWwucXVlcnlTZWxlY3RvckFsbCgnLmd3LXBsLWRvdC5jb25uZWN0ZWQnKS5sZW5ndGg7CiAgICAgICAgdmFyIHRvdGFsID0gcGxFbC5xdWVyeVNlbGVjdG9yQWxsKCcuZ3ctcGxhdGZvcm0tcm93JykubGVuZ3RoIC0gMTsKICAgICAgICBldi50YXJnZXQudGV4dENvbnRlbnQgPSBhY3RpdmUgPyAncGxhdGZvcm15IOKWvCcgOiAoJ3BsYXRmb3JteSAnICsgY29ubmVjdGVkICsgJy8nICsgdG90YWwpOwogICAgICB9CiAgICB9CiAgfTsKICBlbC5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGVsLl9nd0V4cGFuZEhhbmRsZXIpOwp9CgovLyA9PT09PSBSRU5ERVI6IEZPT1RFUiA9PT09PQpmdW5jdGlvbiByZW5kZXJGb290ZXIoa2V5c0RhdGEsIGthbmJhbkRhdGEsIHN0YXR1c0RhdGEpIHsKICAvLyBLZXlzIChhZ2dyZWdhdGVkIGZyb20gYWxsIHByb2ZpbGVzKQogIGNvbnN0IGtleXNFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdmb290ZXIta2V5cycpOwogIGlmIChrZXlzRGF0YSAmJiAha2V5c0RhdGEuX2Vycm9yICYmIGtleXNEYXRhLmFwaV9rZXlzX3NldD8ubGVuZ3RoKSB7CiAgICBrZXlzRWwuaW5uZXJIVE1MID0ga2V5c0RhdGEuYXBpX2tleXNfc2V0Lm1hcChrID0+ICc8c3BhbiBjbGFzcz0ia2V5LWNoaXAiPicgKyBlc2NhcGVIdG1sKGspICsgJzwvc3Bhbj4nKS5qb2luKCcnKTsKICB9IGVsc2UgewogICAga2V5c0VsLmlubmVySFRNTCA9ICc8ZGl2IGNsYXNzPSJib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSI+QnJhayBkYW55Y2g8L2Rpdj4nOwogIH0KCiAgLy8gS2FuYmFuCiAgY29uc3Qga2FuYmFuRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZm9vdGVyLWthbmJhbicpOwogIGlmIChrYW5iYW5EYXRhICYmICFrYW5iYW5EYXRhLl9lcnJvciAmJiBrYW5iYW5EYXRhLnRhc2tzX2J5X3N0YXR1cykgewogICAgY29uc3QgcyA9IGthbmJhbkRhdGEudGFza3NfYnlfc3RhdHVzOwogICAga2FuYmFuRWwuaW5uZXJIVE1MID0gJycKICAgICAgKyAnPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2dhcDp2YXIoLS1zcGFjZS1tZCk7ZmxleC13cmFwOndyYXAiPicKICAgICAgKyAnPGRpdj48c3BhbiBjbGFzcz0iYmFkZ2Ugb2siPmRvbmU8L3NwYW4+IDxzcGFuIGNsYXNzPSJtZXRyaWMtbWQiPicgKyAocy5kb25lfHwwKSArICc8L3NwYW4+PC9kaXY+JwogICAgICArICc8ZGl2PjxzcGFuIGNsYXNzPSJiYWRnZSIgc3R5bGU9ImJhY2tncm91bmQ6IzFFM0E1Rjtjb2xvcjp2YXIoLS1wcmltYXJ5KSI+cnVubmluZzwvc3Bhbj4gPHNwYW4gY2xhc3M9Im1ldHJpYy1tZCI+JyArIChzLnJ1bm5pbmd8fDApICsgJzwvc3Bhbj48L2Rpdj4nCiAgICAgICsgJzxkaXY+PHNwYW4gY2xhc3M9ImJhZGdlIiBzdHlsZT0iYmFja2dyb3VuZDp2YXIoLS1iZ0hvdmVyKTtjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KSI+dG9kbzwvc3Bhbj4gPHNwYW4gY2xhc3M9Im1ldHJpYy1tZCI+JyArIChzLnRvZG98fDApICsgJzwvc3Bhbj48L2Rpdj4nCiAgICAgICsgJzxkaXY+PHNwYW4gY2xhc3M9ImJhZGdlIHdhcm4iPmJsb2NrZWQ8L3NwYW4+IDxzcGFuIGNsYXNzPSJtZXRyaWMtbWQiPicgKyAocy5ibG9ja2VkfHwwKSArICc8L3NwYW4+PC9kaXY+JwogICAgICArICc8L2Rpdj4nOwogIH0gZWxzZSB7CiAgICBrYW5iYW5FbC5pbm5lckhUTUwgPSAnPGRpdiBjbGFzcz0iYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRNdXRlZCkiPkJyYWsgZGFueWNoPC9kaXY+JzsKICB9CgogIC8vIFN5c3RlbSBpbmZvCiAgY29uc3Qgc3lzRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZm9vdGVyLXN5c3RlbScpOwogIGNvbnN0IHN1bW1hcnkgPSBzdGF0dXNEYXRhPy5zdW1tYXJ5IHx8IHt9OwogIHN5c0VsLmlubmVySFRNTCA9ICcnCiAgICArICc8ZGl2IGNsYXNzPSJib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSkiPlByb2ZpbGk6IDxzcGFuIGNsYXNzPSJtb25vLXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dFByaW1hcnkpIj4nICsgKHN1bW1hcnkucHJvZmlsZXNfdG90YWx8fCctLScpICsgJzwvc3Bhbj48L2Rpdj4nCiAgICArICc8ZGl2IGNsYXNzPSJib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSkiPkFrdHl3bmUgYWdlbnR5OiA8c3BhbiBjbGFzcz0ibW9uby1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRQcmltYXJ5KSI+JyArIChzdW1tYXJ5LmFjdGl2ZV9hZ2VudHN8fDApICsgJzwvc3Bhbj48L2Rpdj4nCiAgICArICc8ZGl2IGNsYXNzPSJib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSkiPkJhY2tlbmQ6IDxzcGFuIGNsYXNzPSJtb25vLXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dFByaW1hcnkpIj4xMjcuMC4wLjE6OTExODwvc3Bhbj48L2Rpdj4nCiAgICArICc8ZGl2IGNsYXNzPSJib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSkiPk9kxZt3aWXFvGFuaWU6IDxzcGFuIGNsYXNzPSJtb25vLXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dFByaW1hcnkpIj4nICsgKFJFRlJFU0hfT1BUSU9OU1tSRUZSRVNIX0lOVEVSVkFMXSB8fCAoUkVGUkVTSF9JTlRFUlZBTC8xMDAwKSsncycpICsgJzwvc3Bhbj48L2Rpdj4nCiAgICArICc8ZGl2IGNsYXNzPSJib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSkiPkxheW91dDogPHNwYW4gY2xhc3M9Im1vbm8tc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0UHJpbWFyeSkiIGlkPSJzeXMtbGF5b3V0Ij4nICsgKGRvY3VtZW50LmJvZHkuZ2V0QXR0cmlidXRlKCdkYXRhLWxheW91dCcpID09PSAncGlwYm95JyA/ICdQaXAtQm95JyA6ICdIZXJtZXMnKSArICc8L3NwYW4+PC9kaXY+JzsKfQoKLy8gPT09PT0gTUFJTiBSRUZSRVNIID09PT09CmFzeW5jIGZ1bmN0aW9uIHJlZnJlc2hBbGwoKSB7CiAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTsKICBjb25zdCBjZXQgPSBuZXcgRGF0ZShub3cudG9Mb2NhbGVTdHJpbmcoJ2VuLVVTJywge3RpbWVab25lOidFdXJvcGUvV2Fyc2F3J30pKTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbGFzdC1yZWZyZXNoJykudGV4dENvbnRlbnQgPQogICAgY2V0LnRvTG9jYWxlRGF0ZVN0cmluZygncGwtUEwnLCB7ZGF5OicyLWRpZ2l0Jyxtb250aDonMi1kaWdpdCd9KSArICcgJyArCiAgICBjZXQudG9Mb2NhbGVUaW1lU3RyaW5nKCdwbC1QTCcsIHtob3VyOicyLWRpZ2l0JyxtaW51dGU6JzItZGlnaXQnfSkgKyAnIENFVCc7CgogIC8vIFJlc2V0IGxpY3puaWsgb2TFm3dpZcW8YW5pYSDigJQgcGFzZWsgemFjenluYSBvZG1pZXJ6YcSHIG9kIG5vd2EKICBsYXN0UmVmcmVzaEF0ID0gRGF0ZS5ub3coKTsKICB1cGRhdGVQcm9ncmVzc0JhcigpOwoKICB0cnkgewogICAgLy8gRmV0Y2ggc25hcHNob3QgKGFsbCBwcm9maWxlcywga2V5cywga2FuYmFuLCBhbGVydHMgaW4gb25lIGNhbGwpCiAgICBjb25zdCBzbmFwc2hvdCA9IGF3YWl0IGFwaUZldGNoKCcvYXBpL3NuYXBzaG90Jyk7CiAgICAKICAgIGlmIChzbmFwc2hvdC5fZXJyb3IpIHsKICAgICAgc2hvd1RvYXN0KCdCYWNrZW5kIG5pZSBvZHBvd2lhZGE6ICcgKyBzbmFwc2hvdC5fZXJyb3IsICdjcml0aWNhbCcpOwogICAgICByZXR1cm47CiAgICB9CgogICAgLy8gUG9rYcW8IGRhdMSZIGkgZ29kemluxJkgeiBrdMOzcmVqIHBvY2hvZHrEhSBkYW5lCiAgICBtYXJrRGF0YVRzKHNuYXBzaG90LnRzX2lzbyB8fCBudWxsKTsKICAgIAogICAgLy8gRXh0cmFjdCBkYXRhIGZyb20gc25hcHNob3QKICAgIGNvbnN0IHN0YXR1c0RhdGEgPSB7CiAgICAgIHRzOiBzbmFwc2hvdC50cywKICAgICAgc2lnbmFsX2JyaWRnZTogc25hcHNob3Quc2lnbmFsX2JyaWRnZSwKICAgICAgc3VtbWFyeTogc25hcHNob3Quc3VtbWFyeSwKICAgICAgcHJvZmlsZXM6IChzbmFwc2hvdC5wcm9maWxlcyB8fCBbXSkubWFwKGZ1bmN0aW9uKHApIHsKICAgICAgICByZXR1cm4gewogICAgICAgICAgcHJvZmlsZTogcC5wcm9maWxlLAogICAgICAgICAgaG9tZTogcC5ob21lLAogICAgICAgICAgZ2F0ZXdheTogcC5nYXRld2F5LAogICAgICAgICAgY3Jvbl90aWNrZXI6IHAuY3Jvbl90aWNrZXIsCiAgICAgICAgICB1c2FnZTogcC51c2FnZSwKICAgICAgICAgIGFwaV9rZXlzX3NldDogcC5hcGlfa2V5c19zZXQKICAgICAgICB9OwogICAgICB9KQogICAgfTsKICAgIGNvbnN0IGthbmJhbkRhdGEgPSBzbmFwc2hvdC5rYW5iYW47CiAgICBjb25zdCBhbGVydHNEYXRhID0gc25hcHNob3QuYWxlcnRzID8ge2FsZXJ0czogc25hcHNob3QuYWxlcnRzfSA6IG51bGw7CiAgICAKICAgIC8vIEFnZ3JlZ2F0ZSBrZXlzIGFjcm9zcyBhbGwgcHJvZmlsZXMgKGRlZHVwbGljYXRlZCkKICAgIHZhciBhbGxLZXlzID0ge307CiAgICAoc25hcHNob3QucHJvZmlsZXMgfHwgW10pLmZvckVhY2goZnVuY3Rpb24ocCkgewogICAgICAocC5hcGlfa2V5c19zZXQgfHwgW10pLmZvckVhY2goZnVuY3Rpb24oaykgeyBhbGxLZXlzW2tdID0gdHJ1ZTsgfSk7CiAgICB9KTsKICAgIGNvbnN0IGtleXNEYXRhID0ge2FwaV9rZXlzX3NldDogT2JqZWN0LmtleXMoYWxsS2V5cykuc29ydCgpfTsKCiAgICAvLyBGZXRjaCBwZXItcHJvZmlsZSBzZXNzaW9ucyBhbmQgdXNhZ2U7IHdoZW4gYSBwcm9maWxlIGlzIHNlbGVjdGVkLCBvbmx5IHRoYXQgb25lCiAgICBsZXQgcHJvZmlsZXMgPSAoc25hcHNob3QucHJvZmlsZXMgfHwgW10pCiAgICAgIC5tYXAoZnVuY3Rpb24ocCkgeyByZXR1cm4gcC5wcm9maWxlOyB9KQogICAgICAuZmlsdGVyKGZ1bmN0aW9uKHApIHsgcmV0dXJuICFhY3RpdmVQcm9maWxlIHx8IHAgPT09IGFjdGl2ZVByb2ZpbGU7IH0pOwogICAgaWYgKHByb2ZpbGVzLmxlbmd0aCA9PT0gMCAmJiBhY3RpdmVQcm9maWxlKSB7CiAgICAgIC8vIHJlcXVlc3QgcHJvZmlsZSBub3QgaW4gc25hcHNob3Qg4oCUIGZhbGwgYmFjayB0byBhbGwKICAgICAgcHJvZmlsZXMgPSAoc25hcHNob3QucHJvZmlsZXMgfHwgW10pLm1hcChmdW5jdGlvbihwKSB7IHJldHVybiBwLnByb2ZpbGU7IH0pOwogICAgfQogICAgLy8gVXBkYXRlIHNlc3Npb24gcGFuZWwgaGVhZGVyIHRvIHJlZmxlY3QgdGhlIGZpbHRlcgogICAgY29uc3Qgc2Vzc2lvbkhlYWRlciA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJy5zZXNzaW9ucy1jYXJkIC5oZWFkaW5nLW1kJyk7CiAgICBpZiAoc2Vzc2lvbkhlYWRlcikgewogICAgICBzZXNzaW9uSGVhZGVyLnRleHRDb250ZW50ID0gYWN0aXZlUHJvZmlsZQogICAgICAgID8gJ09zdGF0bmllIHNlc2plIChwcm9maWw6ICcgKyBhY3RpdmVQcm9maWxlICsgJyknCiAgICAgICAgOiAnT3N0YXRuaWUgc2VzamUgKHdzenlzdGtpZSBwcm9maWxlKSc7CiAgICB9CiAgICAvLyBVcGRhdGUgIktleXMiIGZvb3RlciBoZWFkZXIgdG8gcmVmbGVjdCB0aGUgZmlsdGVyCiAgICBjb25zdCBrZXlzSGVhZGVyID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvcignI2Zvb3Rlci1zZWN0aW9uIC5mb290ZXItY2FyZCAuZmMtaGVhZGVyJyk7CiAgICBpZiAoa2V5c0hlYWRlcikgewogICAgICBrZXlzSGVhZGVyLnRleHRDb250ZW50ID0gYWN0aXZlUHJvZmlsZQogICAgICAgID8gJ0tsdWN6ZSBBUEkgKHByb2ZpbDogJyArIGFjdGl2ZVByb2ZpbGUgKyAnKScKICAgICAgICA6ICdLbHVjemUgQVBJICh3c3p5c3RraWUgcHJvZmlsZSknOwogICAgfQogICAgCiAgICAvLyBGZXRjaCBzZXNzaW9ucyBmcm9tIGFsbCBwcm9maWxlcyAodXAgdG8gMTUgcGVyIHByb2ZpbGUpCiAgICBjb25zdCBzZXNzaW9uc1Jlc3VsdHMgPSBhd2FpdCBQcm9taXNlLmFsbCgKICAgICAgcHJvZmlsZXMubWFwKGZ1bmN0aW9uKHApIHsKICAgICAgICByZXR1cm4gYXBpRmV0Y2goJy9hcGkvc2Vzc2lvbnM/cHJvZmlsZT0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHApICsgJyZsaW1pdD0xNScpOwogICAgICB9KQogICAgKTsKICAgIC8vIE1lcmdlIGFsbCBzZXNzaW9ucywgc29ydCBieSBsYXN0X2FjdGl2aXR5IGRlc2MKICAgIHZhciBhbGxTZXNzaW9ucyA9IFtdOwogICAgc2Vzc2lvbnNSZXN1bHRzLmZvckVhY2goZnVuY3Rpb24ocmVzdWx0LCBpZHgpIHsKICAgICAgaWYgKHJlc3VsdCAmJiAhcmVzdWx0Ll9lcnJvciAmJiByZXN1bHQuc2Vzc2lvbnMpIHsKICAgICAgICByZXN1bHQuc2Vzc2lvbnMuZm9yRWFjaChmdW5jdGlvbihzKSB7CiAgICAgICAgICBzLl9wcm9maWxlID0gcHJvZmlsZXNbaWR4XTsKICAgICAgICAgIGFsbFNlc3Npb25zLnB1c2gocyk7CiAgICAgICAgfSk7CiAgICAgIH0KICAgIH0pOwogICAgYWxsU2Vzc2lvbnMuc29ydChmdW5jdGlvbihhLCBiKSB7CiAgICAgIHZhciBkYSA9IGEubGFzdF9hY3Rpdml0eV9hdCA/IG5ldyBEYXRlKGEubGFzdF9hY3Rpdml0eV9hdCkuZ2V0VGltZSgpIDogMDsKICAgICAgdmFyIGRiID0gYi5sYXN0X2FjdGl2aXR5X2F0ID8gbmV3IERhdGUoYi5sYXN0X2FjdGl2aXR5X2F0KS5nZXRUaW1lKCkgOiAwOwogICAgICByZXR1cm4gZGIgLSBkYTsKICAgIH0pOwogICAgY29uc3Qgc2Vzc2lvbnNEYXRhID0ge3Nlc3Npb25zOiBhbGxTZXNzaW9ucy5zbGljZSgwLCAxMCl9OwoKICAgIC8vIEZldGNoIHVzYWdlIGZyb20gYWxsIHByb2ZpbGVzIGZvciBjaGFydHMgKDE0IGRheXMpCiAgICBjb25zdCB1c2FnZVJlc3VsdHMgPSBhd2FpdCBQcm9taXNlLmFsbCgKICAgICAgcHJvZmlsZXMubWFwKGZ1bmN0aW9uKHApIHsKICAgICAgICByZXR1cm4gYXBpRmV0Y2goJy9hcGkvdXNhZ2U/cHJvZmlsZT0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHApICsgJyZkYXlzPTE0Jyk7CiAgICAgIH0pCiAgICApOwogICAgLy8gQWdncmVnYXRlIGRhaWx5IHVzYWdlIGFjcm9zcyBhbGwgcHJvZmlsZXMKICAgIHZhciBkYWlseU1hcCA9IHt9OwogICAgdmFyIG1vZGVsTWFwID0ge307CiAgICB2YXIgcHJvZmlsZVVzYWdlTWFwID0ge307ICAvLyBwZXItcHJvZmlsZToge3Rva2VucywgY29zdH0KICAgIHVzYWdlUmVzdWx0cy5mb3JFYWNoKGZ1bmN0aW9uKHJlc3VsdCkgewogICAgICBpZiAoIXJlc3VsdCB8fCByZXN1bHQuX2Vycm9yKSByZXR1cm47CiAgICAgIChyZXN1bHQuZGFpbHkgfHwgW10pLmZvckVhY2goZnVuY3Rpb24oZGF5KSB7CiAgICAgICAgaWYgKCFkYWlseU1hcFtkYXkuZGF5XSkgewogICAgICAgICAgZGFpbHlNYXBbZGF5LmRheV0gPSB7ZGF5OiBkYXkuZGF5LCBzZXNzaW9uX2NvdW50OiAwLCB0b2tlbnM6IHtpbnB1dDowLCBvdXRwdXQ6MCwgcmVhc29uaW5nOjB9LCBjb3N0OiB7ZXN0aW1hdGVkX3VzZDowLCBhY3R1YWxfdXNkOjB9fTsKICAgICAgICB9CiAgICAgICAgZGFpbHlNYXBbZGF5LmRheV0uc2Vzc2lvbl9jb3VudCArPSBkYXkuc2Vzc2lvbl9jb3VudCB8fCAwOwogICAgICAgIGRhaWx5TWFwW2RheS5kYXldLnRva2Vucy5pbnB1dCArPSBkYXkudG9rZW5zID8gKGRheS50b2tlbnMuaW5wdXQgfHwgMCkgOiAwOwogICAgICAgIGRhaWx5TWFwW2RheS5kYXldLnRva2Vucy5vdXRwdXQgKz0gZGF5LnRva2VucyA/IChkYXkudG9rZW5zLm91dHB1dCB8fCAwKSA6IDA7CiAgICAgICAgZGFpbHlNYXBbZGF5LmRheV0udG9rZW5zLnJlYXNvbmluZyArPSBkYXkudG9rZW5zID8gKGRheS50b2tlbnMucmVhc29uaW5nIHx8IDApIDogMDsKICAgICAgICBkYWlseU1hcFtkYXkuZGF5XS5jb3N0LmVzdGltYXRlZF91c2QgKz0gZGF5LmNvc3QgPyAoZGF5LmNvc3QuZXN0aW1hdGVkX3VzZCB8fCAwKSA6IDA7CiAgICAgIH0pOwogICAgICAocmVzdWx0LmJ5X21vZGVsIHx8IFtdKS5mb3JFYWNoKGZ1bmN0aW9uKG0pIHsKICAgICAgICB2YXIga2V5ID0gbS5tb2RlbDsKICAgICAgICBpZiAoIW1vZGVsTWFwW2tleV0pIHsKICAgICAgICAgIG1vZGVsTWFwW2tleV0gPSB7bW9kZWw6IG0ubW9kZWwsIHByb3ZpZGVyOiBtLnByb3ZpZGVyLCBhcGlfY2FsbHM6MCwgdG9rZW5zOntpbnB1dDowLCBvdXRwdXQ6MCwgcmVhc29uaW5nOjB9LCBlc3RpbWF0ZWRfY29zdF91c2Q6MH07CiAgICAgICAgfQogICAgICAgIG1vZGVsTWFwW2tleV0uYXBpX2NhbGxzICs9IG0uYXBpX2NhbGxzIHx8IDA7CiAgICAgICAgbW9kZWxNYXBba2V5XS50b2tlbnMuaW5wdXQgKz0gbS50b2tlbnMgPyAobS50b2tlbnMuaW5wdXQgfHwgMCkgOiAwOwogICAgICAgIG1vZGVsTWFwW2tleV0udG9rZW5zLm91dHB1dCArPSBtLnRva2VucyA/IChtLnRva2Vucy5vdXRwdXQgfHwgMCkgOiAwOwogICAgICAgIG1vZGVsTWFwW2tleV0udG9rZW5zLnJlYXNvbmluZyArPSBtLnRva2VucyA/IChtLnRva2Vucy5yZWFzb25pbmcgfHwgMCkgOiAwOwogICAgICAgIG1vZGVsTWFwW2tleV0uZXN0aW1hdGVkX2Nvc3RfdXNkICs9IG0uZXN0aW1hdGVkX2Nvc3RfdXNkIHx8IDA7CiAgICAgIH0pOwogICAgfSk7CiAgICAvLyBCdWlsZCBwZXItcHJvZmlsZSB1c2FnZSBmcm9tIGxhdGVzdCBkYWlseSBkYXRhCiAgICB1c2FnZVJlc3VsdHMuZm9yRWFjaChmdW5jdGlvbihyZXN1bHQsIGlkeCkgewogICAgICB2YXIgcHJvZiA9IHByb2ZpbGVzW2lkeF07CiAgICAgIGlmICghcHJvZiB8fCAhcmVzdWx0IHx8IHJlc3VsdC5fZXJyb3IpIHJldHVybjsKICAgICAgdmFyIHRvdGFsVG9rZW5zID0gMCwgdG90YWxDb3N0ID0gMDsKICAgICAgKHJlc3VsdC5kYWlseSB8fCBbXSkuZm9yRWFjaChmdW5jdGlvbihkKSB7CiAgICAgICAgdG90YWxUb2tlbnMgKz0gKGQudG9rZW5zPy5pbnB1dHx8MCkgKyAoZC50b2tlbnM/Lm91dHB1dHx8MCk7CiAgICAgICAgdG90YWxDb3N0ICs9IGQuY29zdD8uZXN0aW1hdGVkX3VzZHx8MDsKICAgICAgfSk7CiAgICAgIHByb2ZpbGVVc2FnZU1hcFtwcm9mXSA9IHt0b2tlbnM6IHRvdGFsVG9rZW5zLCBjb3N0OiB0b3RhbENvc3R9OwogICAgfSk7CiAgICB2YXIgZGFpbHlBcnIgPSBbXTsKICAgIGZvciAodmFyIGQgaW4gZGFpbHlNYXApIGRhaWx5QXJyLnB1c2goZGFpbHlNYXBbZF0pOwogICAgZGFpbHlBcnIuc29ydChmdW5jdGlvbihhLCBiKSB7IHJldHVybiBhLmRheS5sb2NhbGVDb21wYXJlKGIuZGF5KTsgfSk7CiAgICB2YXIgbW9kZWxBcnIgPSBbXTsKICAgIGZvciAodmFyIG1rIGluIG1vZGVsTWFwKSBtb2RlbEFyci5wdXNoKG1vZGVsTWFwW21rXSk7CiAgICBtb2RlbEFyci5zb3J0KGZ1bmN0aW9uKGEsIGIpIHsgcmV0dXJuIGIuZXN0aW1hdGVkX2Nvc3RfdXNkIC0gYS5lc3RpbWF0ZWRfY29zdF91c2Q7IH0pOwogICAgY29uc3QgdXNhZ2VEYXRhID0ge2RhaWx5OiBkYWlseUFyciwgYnlfbW9kZWw6IG1vZGVsQXJyLCBfcHJvZmlsZVVzYWdlOiBwcm9maWxlVXNhZ2VNYXB9OwoKICAgIHJlbmRlclN0YXR1c1N0cmlwKHN0YXR1c0RhdGEpOwogICAgcmVuZGVyUHJvZmlsZUNhcmRzKHN0YXR1c0RhdGEsIHNlc3Npb25zRGF0YSwgdXNhZ2VEYXRhKTsKICAgIHJlbmRlcktwaUdyaWQoc3RhdHVzRGF0YSwgdXNhZ2VEYXRhLCBzZXNzaW9uc0RhdGEsIGthbmJhbkRhdGEsIGFsZXJ0c0RhdGEsIGtleXNEYXRhKTsKICAgIHJlbmRlclNlc3Npb25zKHNlc3Npb25zRGF0YSk7CiAgICByZW5kZXJHYXRld2F5KHN0YXR1c0RhdGEpOwogICAgcmVuZGVyRm9vdGVyKGtleXNEYXRhLCBrYW5iYW5EYXRhLCBzdGF0dXNEYXRhKTsKCiAgICAvLyBDaGFydHMKICAgIHJlbmRlclVzYWdlQ2hhcnQodXNhZ2VEYXRhKTsKICAgIHJlbmRlck1vZGVsc0NoYXJ0KHVzYWdlRGF0YSk7CiAgfSBjYXRjaChlKSB7CiAgICBzaG93VG9hc3QoJ0JsYWQgb2Rzd2llemFuaWE6ICcgKyBlLm1lc3NhZ2UsICdjcml0aWNhbCcpOwogIH0KfQoKLy8gPT09PT0gSU5JVCA9PT09PQpmdW5jdGlvbiBpbml0KCkgewogIC8vIEluaXQgbGF5b3V0IHN3aXRjaGVyCiAgaW5pdExheW91dFN3aXRjaGVyKCk7CgogIC8vIFJlZnJlc2ggY29udHJvbHM6IG1hbnVhbCByZWZyZXNoIGJ1dHRvbiArIGludGVydmFsIHNlbGVjdG9yCiAgY29uc3QgcmVmcmVzaFNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyZWZyZXNoLWludGVydmFsJyk7CiAgcmVmcmVzaFNlbGVjdC52YWx1ZSA9IFN0cmluZyhSRUZSRVNIX0lOVEVSVkFMKTsKICByZWZyZXNoU2VsZWN0LmFkZEV2ZW50TGlzdGVuZXIoJ2NoYW5nZScsIGZ1bmN0aW9uKCkgewogICAgUkVGUkVTSF9JTlRFUlZBTCA9IHBhcnNlSW50KHJlZnJlc2hTZWxlY3QudmFsdWUsIDEwKSB8fCA5MDA7CiAgICBpZiAocmVmcmVzaFRpbWVyKSBjbGVhckludGVydmFsKHJlZnJlc2hUaW1lcik7CiAgICByZWZyZXNoVGltZXIgPSBzZXRJbnRlcnZhbChyZWZyZXNoQWxsLCBSRUZSRVNIX0lOVEVSVkFMICogMTAwMCk7CiAgICAvLyBabWlhbmEgaW50ZXJ3YcWCdSByZXNldHVqZSBsaWN6bmlrIOKAlCBwYXNlayBvZG1pZXJ6YSBvZCBub3dhIHd6Z2zEmWRlbSBub3dlZ28gaW50ZXJ3YcWCdQogICAgbGFzdFJlZnJlc2hBdCA9IERhdGUubm93KCk7CiAgICB1cGRhdGVQcm9ncmVzc0JhcigpOwogICAgc2hvd1RvYXN0KCdPZMWbd2llxbxhbmllIGNvICcgKyAoUkVGUkVTSF9PUFRJT05TW1JFRlJFU0hfSU5URVJWQUxdIHx8IChSRUZSRVNIX0lOVEVSVkFMLzEwMDApKydzJyksICcnKTsKICB9KTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbWFudWFsLXJlZnJlc2gnKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGZ1bmN0aW9uKCkgewogICAgLy8gUmVzZXQgZG8gZG9tecWbbG5lZ28gaW50ZXJ3YcWCdSAxNSBtaW4KICAgIFJFRlJFU0hfSU5URVJWQUwgPSA5MDA7CiAgICBjb25zdCByZWZyZXNoU2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3JlZnJlc2gtaW50ZXJ2YWwnKTsKICAgIHJlZnJlc2hTZWxlY3QudmFsdWUgPSAnOTAwJzsKICAgIGlmIChyZWZyZXNoVGltZXIpIGNsZWFySW50ZXJ2YWwocmVmcmVzaFRpbWVyKTsKICAgIHJlZnJlc2hUaW1lciA9IHNldEludGVydmFsKHJlZnJlc2hBbGwsIFJFRlJFU0hfSU5URVJWQUwgKiAxMDAwKTsKICAgIGxhc3RSZWZyZXNoQXQgPSBEYXRlLm5vdygpOwogICAgdXBkYXRlUHJvZ3Jlc3NCYXIoKTsKICAgIC8vIFBvYmllcnogYWt0dWFsbmUgZGFuZQogICAgcmVmcmVzaEFsbCgpOwogICAgc2hvd1RvYXN0KCdPZMWbd2llxbxhbmllIGNvIDE1IG1pbiAoZG9tecWbbG5lKScsICcnKTsKICB9KTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYWxsLXByb2ZpbGVzLWJ0bicpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgZnVuY3Rpb24oKSB7CiAgICBhY3RpdmVQcm9maWxlID0gbnVsbDsKICAgIHRoaXMuc3R5bGUuZGlzcGxheSA9ICdub25lJzsKICAgIHJlZnJlc2hBbGwoKTsKICB9KTsKCiAgLy8gU2hvdyBsb2FkaW5nIHNrZWxldG9ucwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdrcGktZ3JpZCcpLmlubmVySFRNTCA9IEFycmF5KDgpLmZpbGwoJzxkaXYgY2xhc3M9Im1ldHJpYy10aWxlIj48ZGl2IGNsYXNzPSJza2VsZXRvbiBza2VsZXRvbi10ZXh0Ij48L2Rpdj48ZGl2IGNsYXNzPSJza2VsZXRvbiBza2VsZXRvbi12YWx1ZSI+PC9kaXY+PGRpdiBjbGFzcz0ic2tlbGV0b24gc2tlbGV0b24tdGV4dCIgc3R5bGU9IndpZHRoOjQwJSI+PC9kaXY+PC9kaXY+Jykuam9pbignJyk7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3Nlc3Npb25zLWxpc3QnKS5pbm5lckhUTUwgPSAnPGRpdiBjbGFzcz0ic3RhdGUtbXNnIiBzdHlsZT0ibWluLWhlaWdodDoxNTBweCI+PGRpdiBjbGFzcz0iZGVzYyBib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSI+TGFkb3dhbmllLi4uPC9kaXY+PC9kaXY+JzsKCiAgLy8gU2tlbGV0b24gY2hpcHMgZm9yIHN0YXR1cyBzdHJpcAogIGNvbnN0IHNrZWxldG9uQ2hpcHMgPSBBcnJheSg2KS5maWxsKCc8ZGl2IGNsYXNzPSJzdGF0dXMtY2hpcCBza2VsZXRvbi1jaGlwIj48ZGl2IGNsYXNzPSJza2VsZXRvbiIgc3R5bGU9IndpZHRoOjhweDtoZWlnaHQ6OHB4O2JvcmRlci1yYWRpdXM6NTAlO2ZsZXgtc2hyaW5rOjAiPjwvZGl2PjxkaXYgY2xhc3M9InNrZWxldG9uIHNrZWxldG9uLXRleHQiIHN0eWxlPSJ3aWR0aDo2MHB4O2hlaWdodDowLjc1cmVtO21hcmdpbjowIj48L2Rpdj48L2Rpdj4nKS5qb2luKCcnKTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3RhdHVzLXN0cmlwLWlubmVyJykuaW5uZXJIVE1MID0gc2tlbGV0b25DaGlwczsKCiAgLy8gU2tlbGV0b24gY2FyZHMgZm9yIHByb2ZpbGUgY2FyZHMgc2VjdGlvbgogIGNvbnN0IHNrZWxldG9uQ2FyZHMgPSBBcnJheSg3KS5maWxsKCc8ZGl2IGNsYXNzPSJwcm9maWxlLWNhcmQgc2tlbGV0b24tY2FyZCI+PGRpdiBjbGFzcz0icGMtaGVhZGVyIj48ZGl2IGNsYXNzPSJza2VsZXRvbiIgc3R5bGU9IndpZHRoOjEwcHg7aGVpZ2h0OjEwcHg7Ym9yZGVyLXJhZGl1czo1MCU7ZmxleC1zaHJpbms6MCI+PC9kaXY+PGRpdiBjbGFzcz0ic2tlbGV0b24gc2tlbGV0b24tdGV4dCIgc3R5bGU9IndpZHRoOjcwcHg7aGVpZ2h0OjAuOXJlbTttYXJnaW46MCI+PC9kaXY+PC9kaXY+PGRpdiBjbGFzcz0icGMtbWV0YSI+PGRpdiBjbGFzcz0ic2tlbGV0b24gc2tlbGV0b24tdGV4dCIgc3R5bGU9IndpZHRoOjkwcHg7aGVpZ2h0OjAuN3JlbTttYXJnaW46MCI+PC9kaXY+PGRpdiBjbGFzcz0ic2tlbGV0b24gc2tlbGV0b24tdGV4dCIgc3R5bGU9IndpZHRoOjYwcHg7aGVpZ2h0OjAuN3JlbTttYXJnaW46MCI+PC9kaXY+PGRpdiBjbGFzcz0ic2tlbGV0b24gc2tlbGV0b24tdGV4dCIgc3R5bGU9IndpZHRoOjgwcHg7aGVpZ2h0OjAuN3JlbTttYXJnaW46MCI+PC9kaXY+PC9kaXY+PC9kaXY+Jykuam9pbignJyk7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3Byb2ZpbGUtY2FyZHMtZ3JpZCcpLmlubmVySFRNTCA9IHNrZWxldG9uQ2FyZHM7CgogIC8vIEluaXRpYWwgbG9hZAogIHJlZnJlc2hBbGwoKTsKCiAgLy8gQXV0by1yZWZyZXNoIChSRUZSRVNIX0lOVEVSVkFMIGplc3QgdyBTRUtVTkRBQ0g7IHNldEludGVydmFsIHBvdHJ6ZWJ1amUgbXMpCiAgcmVmcmVzaFRpbWVyID0gc2V0SW50ZXJ2YWwocmVmcmVzaEFsbCwgUkVGUkVTSF9JTlRFUlZBTCAqIDEwMDApOwoKICAvLyBDb3VudGRvd24gcHJvZ3Jlc3MgYmFyCiAgc3RhcnRQcm9ncmVzc1RpbWVyKCk7CgogIC8vIFJlc2l6ZSBjaGFydHMgb24gd2luZG93IHJlc2l6ZQogIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdyZXNpemUnLCBmdW5jdGlvbigpIHsKICAgIGlmICh1c2FnZUNoYXJ0KSB1c2FnZUNoYXJ0LnJlc2l6ZSgpOwogICAgaWYgKG1vZGVsc0NoYXJ0KSBtb2RlbHNDaGFydC5yZXNpemUoKTsKICB9KTsKfQoKZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignRE9NQ29udGVudExvYWRlZCcsIGluaXQpOwo8L3NjcmlwdD4KPC9ib2R5Pgo8L2h0bWw+"

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

        elif path == "/api/cron/jobs" or path == "/api/cron":
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