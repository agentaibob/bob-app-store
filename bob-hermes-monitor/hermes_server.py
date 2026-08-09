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

APP_VERSION = "1.9.0"

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
HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9InBsIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+SGVybWVzIE1vbml0b3I8L3RpdGxlPgo8bGluayByZWw9InByZWNvbm5lY3QiIGhyZWY9Imh0dHBzOi8vZm9udHMuZ29vZ2xlYXBpcy5jb20iPgo8bGluayByZWw9InByZWNvbm5lY3QiIGhyZWY9Imh0dHBzOi8vZm9udHMuZ3N0YXRpYy5jb20iIGNyb3Nzb3JpZ2luPgo8bGluayBocmVmPSJodHRwczovL2ZvbnRzLmdvb2dsZWFwaXMuY29tL2NzczI/ZmFtaWx5PUludGVyOndnaHRANDAwOzUwMDs2MDA7NzAwJmZhbWlseT1KZXRCcmFpbnMrTW9ubzp3Z2h0QDQwMDs1MDA7NjAwOzcwMCZkaXNwbGF5PXN3YXAiIHJlbD0ic3R5bGVzaGVldCI+CjxsaW5rIGhyZWY9Imh0dHBzOi8vZm9udHMuZ29vZ2xlYXBpcy5jb20vY3NzMj9mYW1pbHk9U2hhcmUrVGVjaCtNb25vJmRpc3BsYXk9c3dhcCIgcmVsPSJzdHlsZXNoZWV0Ij4KPHNjcmlwdCBzcmM9Imh0dHBzOi8vY2RuLmpzZGVsaXZyLm5ldC9ucG0vZWNoYXJ0c0A1LjUuMS9kaXN0L2VjaGFydHMubWluLmpzIj48L3NjcmlwdD4KPHN0eWxlPgovKiA9PT09PSBERVNJR04gVE9LRU5TID09PT09ICovCjpyb290IHsKICAvKiBDb2xvcnMgKi8KICAtLXByaW1hcnk6ICM5ZWE4YTA7CiAgLS1zZWNvbmRhcnk6ICM4Yjk2OGU7CiAgLS1zdWNjZXNzOiAjOWZkMGEwOwogIC0td2FybmluZzogI2Q5Yjg0YTsKICAtLWNyaXRpY2FsOiAjZTA3YTVmOwogIC0taW5mbzogIzllYThhMDsKICAtLW5ldXRyYWw6ICM2MTZiNjQ7CiAgLS1iZ1Jvb3Q6ICMwNDFjMWM7CiAgLS1iZ1N1cmZhY2U6ICMwNjFmMWY7CiAgLS1iZ0NhcmQ6ICMwODIzMjI7CiAgLS1iZ0hvdmVyOiAjMGMyYTI5OwogIC0tYm9yZGVyOiAjMGUzMDJlOwogIC0tYm9yZGVyTGlnaHQ6ICMxNjNhMzc7CiAgLS10ZXh0UHJpbWFyeTogI2VmZTlkOTsKICAtLXRleHRTZWNvbmRhcnk6ICNiOGIyYTI7CiAgLS10ZXh0TXV0ZWQ6ICM3YTgxNzg7CiAgLS10ZXh0T25QcmltYXJ5OiAjMDQxYzFjOwoKICAvKiBTcGFjaW5nICovCiAgLS1zcGFjZS14czogNHB4OwogIC0tc3BhY2Utc206IDhweDsKICAtLXNwYWNlLW1kOiAxMnB4OwogIC0tc3BhY2UtbGc6IDE2cHg7CiAgLS1zcGFjZS14bDogMjRweDsKICAtLXNwYWNlLTJ4bDogMzJweDsKICAtLXNwYWNlLTN4bDogNDhweDsKCiAgLyogUmFkaXVzICovCiAgLS1yYWRpdXMtc206IDRweDsKICAtLXJhZGl1cy1tZDogOHB4OwogIC0tcmFkaXVzLWxnOiAxMnB4OwogIC0tcmFkaXVzLXhsOiAxNnB4OwogIC0tcmFkaXVzLWZ1bGw6IDk5OTlweDsKfQoKLyogPT09PT0gUkVTRVQgPT09PT0gKi8KKiwqOjpiZWZvcmUsKjo6YWZ0ZXJ7Ym94LXNpemluZzpib3JkZXItYm94O21hcmdpbjowO3BhZGRpbmc6MH0KaHRtbHtmb250LXNpemU6MTZweDstd2Via2l0LWZvbnQtc21vb3RoaW5nOmFudGlhbGlhc2VkfQpib2R5ewogIGZvbnQtZmFtaWx5OidJbnRlcicsc2Fucy1zZXJpZjsKICBiYWNrZ3JvdW5kOnZhcigtLWJnUm9vdCk7CiAgY29sb3I6dmFyKC0tdGV4dFByaW1hcnkpOwogIGxpbmUtaGVpZ2h0OjEuNTsKICBtaW4taGVpZ2h0OjEwMHZoOwp9CgovKiA9PT09PSBUWVBPR1JBUEhZID09PT09ICovCi5oZWFkaW5nLXhse2ZvbnQtZmFtaWx5OidJbnRlcicsc2Fucy1zZXJpZjtmb250LXNpemU6MS43NXJlbTtmb250LXdlaWdodDo3MDA7bGluZS1oZWlnaHQ6MS4yO2xldHRlci1zcGFjaW5nOi0wLjAyZW19Ci5oZWFkaW5nLWxne2ZvbnQtZmFtaWx5OidJbnRlcicsc2Fucy1zZXJpZjtmb250LXNpemU6MS4yNXJlbTtmb250LXdlaWdodDo2MDA7bGluZS1oZWlnaHQ6MS4zO2xldHRlci1zcGFjaW5nOi0wLjAxZW19Ci5oZWFkaW5nLW1ke2ZvbnQtZmFtaWx5OidJbnRlcicsc2Fucy1zZXJpZjtmb250LXNpemU6MXJlbTtmb250LXdlaWdodDo2MDA7bGluZS1oZWlnaHQ6MS40fQouYm9keS1tZHtmb250LWZhbWlseTonSW50ZXInLHNhbnMtc2VyaWY7Zm9udC1zaXplOjAuODc1cmVtO2ZvbnQtd2VpZ2h0OjQwMDtsaW5lLWhlaWdodDoxLjV9Ci5ib2R5LXNte2ZvbnQtZmFtaWx5OidJbnRlcicsc2Fucy1zZXJpZjtmb250LXNpemU6MC43NXJlbTtmb250LXdlaWdodDo0MDA7bGluZS1oZWlnaHQ6MS41fQoubGFiZWwtbWR7Zm9udC1mYW1pbHk6J0ludGVyJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZTowLjc1cmVtO2ZvbnQtd2VpZ2h0OjUwMDtsaW5lLWhlaWdodDoxLjQ7bGV0dGVyLXNwYWNpbmc6MC4wNWVtO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZX0KLmxhYmVsLWxne2ZvbnQtZmFtaWx5OidJbnRlcicsc2Fucy1zZXJpZjtmb250LXNpemU6MC44NzVyZW07Zm9udC13ZWlnaHQ6NjAwO2xpbmUtaGVpZ2h0OjEuNDtsZXR0ZXItc3BhY2luZzowLjAyZW19Ci5tZXRyaWMteGx7Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjIuMjVyZW07Zm9udC13ZWlnaHQ6NzAwO2xpbmUtaGVpZ2h0OjEuMTtsZXR0ZXItc3BhY2luZzotMC4wM2VtfQoubWV0cmljLWxne2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxLjVyZW07Zm9udC13ZWlnaHQ6NjAwO2xpbmUtaGVpZ2h0OjEuMjtsZXR0ZXItc3BhY2luZzotMC4wMmVtfQoubWV0cmljLW1ke2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxcmVtO2ZvbnQtd2VpZ2h0OjUwMDtsaW5lLWhlaWdodDoxLjN9Ci5tb25vLXNte2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZTowLjc1cmVtO2ZvbnQtd2VpZ2h0OjQwMDtsaW5lLWhlaWdodDoxLjZ9CgovKiA9PT09PSBMQVlPVVQgPT09PT0gKi8KLmNvbnRhaW5lcnttYXgtd2lkdGg6MTQwMHB4O21hcmdpbjowIGF1dG87cGFkZGluZzowIHZhcigtLXNwYWNlLXhsKX0KQG1lZGlhKG1heC13aWR0aDo3NjhweCl7LmNvbnRhaW5lcntwYWRkaW5nOjAgdmFyKC0tc3BhY2UtbWQpfX0KCi8qID09PT09IFRPUCBCQVIgPT09PT0gKi8KI3RvcGJhcnsKICBwb3NpdGlvbjpzdGlja3k7dG9wOjA7ei1pbmRleDoxMDA7CiAgYmFja2dyb3VuZDp2YXIoLS1iZ1N1cmZhY2UpOwogIGJvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgaGVpZ2h0OjU2cHg7Cn0KI3RvcGJhciAuY29udGFpbmVyewogIGRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47CiAgaGVpZ2h0OjEwMCU7Cn0KLnRvcGJhci1sZWZ0e2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOnZhcigtLXNwYWNlLW1kKX0KLnRvcGJhci1sb2dvewogIHdpZHRoOjEwcHg7aGVpZ2h0OjEwcHg7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtZnVsbCk7CiAgYmFja2dyb3VuZDp2YXIoLS1zdWNjZXNzKTsKICBhbmltYXRpb246cHVsc2UgMnMgaW5maW5pdGU7Cn0KLnRvcGJhci1yaWdodHtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDp2YXIoLS1zcGFjZS1sZyl9CiNjbG9ja3tmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MC44NzVyZW07Y29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSl9Ci5yZWZyZXNoLWluZGljYXRvcntkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDp2YXIoLS1zcGFjZS14cyk7Y29sb3I6dmFyKC0tdGV4dE11dGVkKX0KLnJlZnJlc2gtaW5kaWNhdG9yIC5kb3R7d2lkdGg6NnB4O2hlaWdodDo2cHg7Ym9yZGVyLXJhZGl1czo1MCU7YmFja2dyb3VuZDp2YXIoLS1wcmltYXJ5KX0KCi8qID09PT09IFJFRlJFU0ggUFJPR1JFU1MgQkFSICsgREFUQSBUSU1FU1RBTVAgPT09PT0gKi8KI3JlZnJlc2gtYmFyewogIGJhY2tncm91bmQ6dmFyKC0tYmdTdXJmYWNlKTsKICBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIHBhZGRpbmc6N3B4IDAgOXB4Owp9CiNyZWZyZXNoLWJhciAuY29udGFpbmVye2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjVweH0KLnJlZnJlc2gtcHJvZ3Jlc3N7CiAgcG9zaXRpb246cmVsYXRpdmU7aGVpZ2h0OjVweDtib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cy1mdWxsKTsKICBiYWNrZ3JvdW5kOnZhcigtLWJnQ2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO292ZXJmbG93OmhpZGRlbjsKfQoucmVmcmVzaC1wcm9ncmVzcyAuZmlsbHsKICBwb3NpdGlvbjphYnNvbHV0ZTt0b3A6MDtsZWZ0OjA7Ym90dG9tOjA7d2lkdGg6MCU7CiAgYmFja2dyb3VuZDp2YXIoLS1wcmltYXJ5KTt0cmFuc2l0aW9uOndpZHRoIDAuNHMgbGluZWFyOwp9Ci5yZWZyZXNoLXByb2dyZXNzIC5maWxsLndhcm57YmFja2dyb3VuZDp2YXIoLS13YXJuaW5nKX0KLnJlZnJlc2gtcHJvZ3Jlc3MgLmZpbGwuY3JpdHtiYWNrZ3JvdW5kOnZhcigtLWNyaXRpY2FsKX0KLnJlZnJlc2gtcHJvZ3Jlc3MtbGFiZWx7CiAgZGlzcGxheTpmbGV4O2p1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuO2dhcDp2YXIoLS1zcGFjZS1tZCk7CiAgZm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjAuNjVyZW07Y29sb3I6dmFyKC0tdGV4dE11dGVkKTsKfQoucmVmcmVzaC1wcm9ncmVzcy1sYWJlbCAucGN0e2NvbG9yOnZhcigtLXRleHRTZWNvbmRhcnkpfQoKLyogPT09PT0gTEFZT1VUIFNXSVRDSEVSID09PT09ICovCi5sYXlvdXQtc3dpdGNoZXJ7CiAgZGlzcGxheTpmbGV4O2dhcDoycHg7YmFja2dyb3VuZDp2YXIoLS1iZ0NhcmQpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTtib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cy1mdWxsKTsKICBwYWRkaW5nOjJweDsKfQoubGF5b3V0LXN3aXRjaGVyIGJ1dHRvbnsKICBiYWNrZ3JvdW5kOnRyYW5zcGFyZW50O2JvcmRlcjpub25lO2JvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLWZ1bGwpOwogIHBhZGRpbmc6NHB4IDEycHg7Y3Vyc29yOnBvaW50ZXI7CiAgZm9udC1mYW1pbHk6J0ludGVyJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZTowLjc1cmVtO2ZvbnQtd2VpZ2h0OjUwMDsKICBjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO3RyYW5zaXRpb246YWxsIDAuMnM7CiAgd2hpdGUtc3BhY2U6bm93cmFwOwp9Ci5sYXlvdXQtc3dpdGNoZXIgYnV0dG9uLmFjdGl2ZXsKICBiYWNrZ3JvdW5kOnZhcigtLXByaW1hcnkpO2NvbG9yOnZhcigtLXRleHRPblByaW1hcnkpOwp9Ci5sYXlvdXQtc3dpdGNoZXIgYnV0dG9uOmhvdmVyOm5vdCguYWN0aXZlKXtjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KX0KCi8qID09PT09IFNUQVRVUyBTVFJJUCA9PT09PSAqLwojc3RhdHVzLXN0cmlwewogIGJhY2tncm91bmQ6dmFyKC0tYmdTdXJmYWNlKTsKICBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwp9CiNzdGF0dXMtc3RyaXAgLmNvbnRhaW5lcnsKICBkaXNwbGF5OmZsZXg7Z2FwOnZhcigtLXNwYWNlLXNtKTtwYWRkaW5nOnZhcigtLXNwYWNlLXNtKSAwOwogIG92ZXJmbG93LXg6YXV0bzsKfQouc3RhdHVzLWNoaXB7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6dmFyKC0tc3BhY2UteHMpOwogIHBhZGRpbmc6NHB4IDEwcHg7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtZnVsbCk7CiAgYmFja2dyb3VuZDp2YXIoLS1iZ0NhcmQpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICB3aGl0ZS1zcGFjZTpub3dyYXA7Cn0KLnN0YXR1cy1jaGlwIC5kb3R7d2lkdGg6OHB4O2hlaWdodDo4cHg7Ym9yZGVyLXJhZGl1czo1MCU7ZmxleC1zaHJpbms6MH0KLnN0YXR1cy1jaGlwIC5kb3Qub25saW5le2JhY2tncm91bmQ6dmFyKC0tc3VjY2Vzcyl9Ci5zdGF0dXMtY2hpcCAuZG90Lm9mZmxpbmV7YmFja2dyb3VuZDp2YXIoLS1jcml0aWNhbCl9Ci5zdGF0dXMtY2hpcCAubmFtZXtmb250LXNpemU6MC43NXJlbTtmb250LXdlaWdodDo1MDA7Y29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSl9Ci5zdGF0dXMtY2hpcHtjdXJzb3I6cG9pbnRlcn0KLnN0YXR1cy1jaGlwLmFjdGl2ZXtib3JkZXItY29sb3I6dmFyKC0tcHJpbWFyeSk7YmFja2dyb3VuZDp2YXIoLS1iZ0hvdmVyKTtib3gtc2hhZG93OjAgMCAwIDFweCB2YXIoLS1wcmltYXJ5KX0KLnN0YXR1cy1jaGlwLmFjdGl2ZSAubmFtZXtjb2xvcjp2YXIoLS1wcmltYXJ5KX0KLnN0YXR1cy1jaGlwIC5wbGF0Zm9ybXtmb250LXNpemU6MC42NXJlbTtjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO21hcmdpbi1sZWZ0OjJweH0KCi8qIFNrZWxldG9uIGNoaXAgZm9yIGxvYWRpbmcgc3RhdGUgKi8KLnN0YXR1cy1jaGlwLnNrZWxldG9uLWNoaXB7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO29wYWNpdHk6MC42fQouc3RhdHVzLWNoaXAuc2tlbGV0b24tY2hpcCAuc2tlbGV0b257YmFja2dyb3VuZDp2YXIoLS1iZ0hvdmVyKX0KCi8qID09PT09IFBST0ZJTEUgQ0FSRFMgPT09PT0gKi8KLnByb2ZpbGUtY2FyZHMtc2VjdGlvbntwYWRkaW5nOnZhcigtLXNwYWNlLWxnKSAwfQoucHJvZmlsZS1jYXJkcy1ncmlkewogIGRpc3BsYXk6Z3JpZDsKICBncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KGF1dG8tZmlsbCxtaW5tYXgoMTcwcHgsMWZyKSk7CiAgZ2FwOnZhcigtLXNwYWNlLW1kKTsKfQpAbWVkaWEobWF4LXdpZHRoOjc2OHB4KXsucHJvZmlsZS1jYXJkcy1ncmlke2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoMiwxZnIpfX0KQG1lZGlhKG1heC13aWR0aDo0ODBweCl7LnByb2ZpbGUtY2FyZHMtZ3JpZHtncmlkLXRlbXBsYXRlLWNvbHVtbnM6MWZyfX0KCi5wcm9maWxlLWNhcmR7CiAgYmFja2dyb3VuZDp2YXIoLS1iZ0NhcmQpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cy1sZyk7CiAgcGFkZGluZzp2YXIoLS1zcGFjZS1sZyk7CiAgZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6dmFyKC0tc3BhY2UteHMpOwogIHRyYW5zaXRpb246Ym9yZGVyLWNvbG9yIDAuM3M7CiAgY3Vyc29yOmRlZmF1bHQ7Cn0KLnByb2ZpbGUtY2FyZDpob3Zlcntib3JkZXItY29sb3I6dmFyKC0tYm9yZGVyTGlnaHQpfQoucHJvZmlsZS1jYXJke2N1cnNvcjpwb2ludGVyfQoucHJvZmlsZS1jYXJkLmFjdGl2ZXtib3JkZXItY29sb3I6dmFyKC0tcHJpbWFyeSk7Ym94LXNoYWRvdzowIDAgMCAxcHggdmFyKC0tcHJpbWFyeSl9Ci5wcm9maWxlLWNhcmQuYWN0aXZlIC5wYy1uYW1le2NvbG9yOnZhcigtLXByaW1hcnkpfQoucHJvZmlsZS1jYXJkIC5wYy1oZWFkZXJ7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6dmFyKC0tc3BhY2Utc20pO21hcmdpbi1ib3R0b206dmFyKC0tc3BhY2Utc20pfQoucHJvZmlsZS1jYXJkIC5wYy1kb3R7d2lkdGg6MTBweDtoZWlnaHQ6MTBweDtib3JkZXItcmFkaXVzOjUwJTtmbGV4LXNocmluazowfQoucHJvZmlsZS1jYXJkIC5wYy1kb3Qub25saW5le2JhY2tncm91bmQ6dmFyKC0tc3VjY2Vzcyk7YW5pbWF0aW9uOnB1bHNlIDJzIGluZmluaXRlfQoucHJvZmlsZS1jYXJkIC5wYy1kb3Qub2ZmbGluZXtiYWNrZ3JvdW5kOnZhcigtLWNyaXRpY2FsKX0KLnByb2ZpbGUtY2FyZCAucGMtZG90LnN0YWxle2JhY2tncm91bmQ6dmFyKC0td2FybmluZyk7YW5pbWF0aW9uOnB1bHNlIDFzIGluZmluaXRlfQoucHJvZmlsZS1jYXJkIC5wYy1uYW1le2ZvbnQtd2VpZ2h0OjYwMDtmb250LXNpemU6MC45cmVtO2NvbG9yOnZhcigtLXRleHRQcmltYXJ5KTtvdmVyZmxvdzpoaWRkZW47dGV4dC1vdmVyZmxvdzplbGxpcHNpczt3aGl0ZS1zcGFjZTpub3dyYXB9Ci5wcm9maWxlLWNhcmQgLnBjLW1ldGF7ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6MnB4fQoucHJvZmlsZS1jYXJkIC5wYy1tZXRhLWl0ZW17Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjAuN3JlbTtjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KTt3aGl0ZS1zcGFjZTpub3dyYXB9Ci5wcm9maWxlLWNhcmQgLnBjLW1ldGEtaXRlbTo6YmVmb3Jle2NvbnRlbnQ6J+KWuCAnO2NvbG9yOnZhcigtLXByaW1hcnkpO21hcmdpbi1yaWdodDoycHh9Ci5wcm9maWxlLWNhcmQgLnBjLXBsYXRmb3Jtc3tkaXNwbGF5OmZsZXg7ZmxleC13cmFwOndyYXA7Z2FwOjNweDttYXJnaW4tdG9wOmF1dG87cGFkZGluZy10b3A6dmFyKC0tc3BhY2Utc20pO2JvcmRlci10b3A6MXB4IHNvbGlkIHZhcigtLWJvcmRlcil9Ci5wcm9maWxlLWNhcmQgLnBjLXBsYXQtY2hpcHtmb250LXNpemU6MC42cmVtO3BhZGRpbmc6MXB4IDVweDtiYWNrZ3JvdW5kOnZhcigtLWJnSG92ZXIpO2JvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLXNtKTtjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZX0KLnByb2ZpbGUtY2FyZCAucGMtcGxhdC1jaGlwLmNvbm5lY3RlZHtjb2xvcjp2YXIoLS1zdWNjZXNzKTtiYWNrZ3JvdW5kOnJnYmEoMzQsMTk3LDk0LDAuMDgpfQoucHJvZmlsZS1jYXJkIC5wYy1mb290ZXJ7Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjAuNnJlbTtjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO3BhZGRpbmctdG9wOnZhcigtLXNwYWNlLXhzKTtib3JkZXItdG9wOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpfQoucHJvZmlsZS1jYXJkLnNrZWxldG9uLWNhcmR7b3BhY2l0eTowLjY7cG9pbnRlci1ldmVudHM6bm9uZX0KLnByb2ZpbGUtY2FyZC5za2VsZXRvbi1jYXJkIC5za2VsZXRvbntiYWNrZ3JvdW5kOnZhcigtLWJnSG92ZXIpfQoKLyogPT09PT0gTUFJTiBDT05URU5UID09PT09ICovCiNtYWlue3BhZGRpbmc6dmFyKC0tc3BhY2UteGwpIDB9CgovKiBLUEkgR3JpZCAqLwoua3BpLWdyaWR7CiAgZGlzcGxheTpncmlkOwogIGdyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoNCwxZnIpOwogIGdhcDp2YXIoLS1zcGFjZS1sZyk7CiAgbWFyZ2luLWJvdHRvbTp2YXIoLS1zcGFjZS14bCk7Cn0KQG1lZGlhKG1heC13aWR0aDoxMjgwcHgpey5rcGktZ3JpZHtncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KDIsMWZyKX19CkBtZWRpYShtYXgtd2lkdGg6NzY4cHgpey5rcGktZ3JpZHtncmlkLXRlbXBsYXRlLWNvbHVtbnM6MWZyfX0KCi5tZXRyaWMtdGlsZXsKICBiYWNrZ3JvdW5kOnZhcigtLWJnQ2FyZCk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLWxnKTsKICBwYWRkaW5nOnZhcigtLXNwYWNlLWxnKTsKICBkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2dhcDp2YXIoLS1zcGFjZS1zbSk7CiAgdHJhbnNpdGlvbjpib3JkZXItY29sb3IgMC4zczsKfQoubWV0cmljLXRpbGU6aG92ZXJ7Ym9yZGVyLWNvbG9yOnZhcigtLWJvcmRlckxpZ2h0KX0KLm1ldHJpYy10aWxlLmNyaXRpY2Fse2JvcmRlci1sZWZ0OjNweCBzb2xpZCB2YXIoLS1jcml0aWNhbCl9Ci5tZXRyaWMtdGlsZS53YXJuaW5ne2JvcmRlci1sZWZ0OjNweCBzb2xpZCB2YXIoLS13YXJuaW5nKX0KLm1ldHJpYy10aWxlIC50aWxlLWxhYmVse2NvbG9yOnZhcigtLXRleHRTZWNvbmRhcnkpfQoubWV0cmljLXRpbGUgLnRpbGUtdmFsdWV7Y29sb3I6dmFyKC0tdGV4dFByaW1hcnkpfQoubWV0cmljLXRpbGUgLnRpbGUtc3Vie2NvbG9yOnZhcigtLXRleHRNdXRlZCl9CgovKiBDaGFydHMgUm93ICovCi5jaGFydHMtcm93ewogIGRpc3BsYXk6Z3JpZDsKICBncmlkLXRlbXBsYXRlLWNvbHVtbnM6MmZyIDFmcjsKICBnYXA6dmFyKC0tc3BhY2UtbGcpOwogIG1hcmdpbi1ib3R0b206dmFyKC0tc3BhY2UteGwpOwp9CkBtZWRpYShtYXgtd2lkdGg6NzY4cHgpey5jaGFydHMtcm93e2dyaWQtdGVtcGxhdGUtY29sdW1uczoxZnJ9fQoKLmNoYXJ0LWNhcmR7CiAgYmFja2dyb3VuZDp2YXIoLS1iZ0NhcmQpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cy1sZyk7CiAgcGFkZGluZzp2YXIoLS1zcGFjZS1sZyk7Cn0KLmNoYXJ0LWNhcmQgLmNoYXJ0LWhlYWRlcnttYXJnaW4tYm90dG9tOnZhcigtLXNwYWNlLW1kKX0KLmNoYXJ0LWNhcmQgLmNoYXJ0LWJvZHl7aGVpZ2h0OjMwMHB4fQoKLyogVG9wIG1vZGVsZSDigJQgdGFiZWxhICovCi5tb2RlbHMtdGFibGV7d2lkdGg6MTAwJTtib3JkZXItY29sbGFwc2U6Y29sbGFwc2U7Zm9udC1zaXplOjAuNzhyZW19Ci5tb2RlbHMtdGFibGUgdGh7CiAgdGV4dC1hbGlnbjpsZWZ0O3BhZGRpbmc6OHB4IDEycHg7Zm9udC1zaXplOjAuNjVyZW07dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlOwogIGxldHRlci1zcGFjaW5nOjAuMDVlbTtjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlckxpZ2h0KTsKICBmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTt3aGl0ZS1zcGFjZTpub3dyYXA7Cn0KLm1vZGVscy10YWJsZSB0ZHtwYWRkaW5nOjhweCAxMnB4O2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7dmVydGljYWwtYWxpZ246bWlkZGxlfQoubW9kZWxzLXRhYmxlIHRyOmxhc3QtY2hpbGQgdGR7Ym9yZGVyLWJvdHRvbTpub25lfQoubW9kZWxzLXRhYmxlIHRyOmhvdmVyIHRke2JhY2tncm91bmQ6dmFyKC0tYmdIb3Zlcil9Ci5tb2RlbHMtdGFibGUgLm0tcmFua3tjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlO3dpZHRoOjMwcHh9Ci5tb2RlbHMtdGFibGUgLm0tbmFtZXtjb2xvcjp2YXIoLS10ZXh0UHJpbWFyeSk7Zm9udC13ZWlnaHQ6NTAwfQoubW9kZWxzLXRhYmxlIC5tLXRva2VucywubW9kZWxzLXRhYmxlIC5tLWNvc3QsLm1vZGVscy10YWJsZSAubS1jYWxsc3tmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTtjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KTt3aGl0ZS1zcGFjZTpub3dyYXA7dGV4dC1hbGlnbjpyaWdodH0KLm1vZGVscy10YWJsZSAubS1jb3N0e2NvbG9yOnZhcigtLXRleHRQcmltYXJ5KTtmb250LXdlaWdodDo2MDB9Ci5tb2RlbHMtdGFibGUgLm0tY2FsbHN7Y29sb3I6dmFyKC0tdGV4dE11dGVkKX0KCi8qIERldGFpbCBSb3cgKi8KLmRldGFpbC1yb3d7CiAgZGlzcGxheTpncmlkOwogIGdyaWQtdGVtcGxhdGUtY29sdW1uczozZnIgMmZyOwogIGdhcDp2YXIoLS1zcGFjZS1sZyk7CiAgbWFyZ2luLWJvdHRvbTp2YXIoLS1zcGFjZS14bCk7Cn0KQG1lZGlhKG1heC13aWR0aDo3NjhweCl7LmRldGFpbC1yb3d7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOjFmcn19CgovKiBTZXNzaW9ucyAqLwouc2Vzc2lvbnMtY2FyZHsKICBiYWNrZ3JvdW5kOnZhcigtLWJnQ2FyZCk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLWxnKTsKfQouc2Vzc2lvbnMtY2FyZCAuY2FyZC1oZWFkZXJ7CiAgcGFkZGluZzp2YXIoLS1zcGFjZS1sZyk7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47YWxpZ24taXRlbXM6Y2VudGVyOwp9Ci5zZXNzaW9uLXJvd3sKICBkaXNwbGF5OmdyaWQ7CiAgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOmF1dG8gYXV0byAxZnIgYXV0byBhdXRvIGF1dG8gYXV0byBhdXRvOwogIGdhcDp2YXIoLS1zcGFjZS1tZCk7YWxpZ24taXRlbXM6Y2VudGVyOwogIHBhZGRpbmc6dmFyKC0tc3BhY2UtbWQpIHZhcigtLXNwYWNlLWxnKTsKICBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIHRyYW5zaXRpb246YmFja2dyb3VuZCAwLjE1czsKfQouc2Vzc2lvbi1yb3c6aG92ZXJ7YmFja2dyb3VuZDp2YXIoLS1iZ0hvdmVyKX0KLnNlc3Npb24tcm93Omxhc3QtY2hpbGR7Ym9yZGVyLWJvdHRvbTpub25lfQpAbWVkaWEobWF4LXdpZHRoOjc2OHB4KXsKICAuc2Vzc2lvbi1yb3d7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOmF1dG8gMWZyIGF1dG87Z2FwOnZhcigtLXNwYWNlLXNtKX0KICAuc2Vzc2lvbi1yb3cgLmhpZGUtbW9iaWxle2Rpc3BsYXk6bm9uZX0KfQoucHJvZmlsZS1jaGlwLW1pbml7CiAgZGlzcGxheTppbmxpbmUtYmxvY2s7cGFkZGluZzoxcHggNnB4OwogIGJhY2tncm91bmQ6dmFyKC0tYmdIb3Zlcik7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtZnVsbCk7CiAgZm9udC1zaXplOjAuNnJlbTtmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTsKICBjb2xvcjp2YXIoLS1wcmltYXJ5KTt3aGl0ZS1zcGFjZTpub3dyYXA7Cn0KCi8qIEdhdGV3YXkgKi8KLmdhdGV3YXktY2FyZHsKICBiYWNrZ3JvdW5kOnZhcigtLWJnQ2FyZCk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLWxnKTsKfQouZ2F0ZXdheS1jYXJkIC5jYXJkLWhlYWRlcnsKICBwYWRkaW5nOnZhcigtLXNwYWNlLWxnKTtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGRpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjthbGlnbi1pdGVtczpjZW50ZXI7Cn0KLmdhdGV3YXktcm93ewogIGRpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjthbGlnbi1pdGVtczpjZW50ZXI7CiAgcGFkZGluZzp2YXIoLS1zcGFjZS1tZCkgdmFyKC0tc3BhY2UtbGcpOwogIGJvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgdHJhbnNpdGlvbjpiYWNrZ3JvdW5kIDAuMTVzOwp9Ci5nYXRld2F5LXJvdzpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLWJnSG92ZXIpfQouZ2F0ZXdheS1yb3c6bGFzdC1jaGlsZHtib3JkZXItYm90dG9tOm5vbmV9Ci5nYXRld2F5LXJvdyAuZ3ctbGVmdHtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDp2YXIoLS1zcGFjZS1zbSk7bWluLXdpZHRoOjB9Ci5nYXRld2F5LXJvdyAuZ3ctbmFtZXtmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MC43NXJlbTtmb250LXdlaWdodDo1MDA7Y29sb3I6dmFyKC0tdGV4dFByaW1hcnkpO292ZXJmbG93OmhpZGRlbjt0ZXh0LW92ZXJmbG93OmVsbGlwc2lzO3doaXRlLXNwYWNlOm5vd3JhcH0KLmdhdGV3YXktcm93IC5ndy1zdWJ7Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjAuNjVyZW07Y29sb3I6dmFyKC0tdGV4dE11dGVkKTttYXJnaW4tbGVmdDoycHh9Ci5nYXRld2F5LXJvdyAuZ3ctc3RhdHVze2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOnZhcigtLXNwYWNlLXhzKTtmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MC43cmVtO2ZvbnQtd2VpZ2h0OjYwMH0KCi8qIFN0YXR1cyBrcm9wa2kgZ2F0ZXdheSDigJQgNCBzdGFueTogb2sgLyB3YXJuIC8gZXJyIC8gbm9uZSAqLwpAa2V5ZnJhbWVzIGd3UHVsc2V7MCUsMTAwJXtvcGFjaXR5OjE7Ym94LXNoYWRvdzowIDAgOHB4IGN1cnJlbnRDb2xvcn01MCV7b3BhY2l0eTowLjU1O2JveC1zaGFkb3c6MCAwIDNweCBjdXJyZW50Q29sb3J9fQpAa2V5ZnJhbWVzIGd3QmxpbmtTb2Z0ezAlLDEwMCV7b3BhY2l0eToxO2JveC1zaGFkb3c6MCAwIDZweCBjdXJyZW50Q29sb3J9NTAle29wYWNpdHk6MC42Mjtib3gtc2hhZG93OjAgMCAycHggY3VycmVudENvbG9yfX0KQGtleWZyYW1lcyBnd0JsaW5rRmFzdHswJSwxMDAle29wYWNpdHk6MTtib3gtc2hhZG93OjAgMCAxMHB4IGN1cnJlbnRDb2xvcn01MCV7b3BhY2l0eTowLjEyO2JveC1zaGFkb3c6bm9uZX19Ci5ndy1kb3R7d2lkdGg6OXB4O2hlaWdodDo5cHg7Ym9yZGVyLXJhZGl1czo1MCU7ZmxleC1zaHJpbms6MDttYXJnaW4tdG9wOjFweH0KLmd3LWRvdC5va3tiYWNrZ3JvdW5kOnZhcigtLXN1Y2Nlc3MpO2NvbG9yOnZhcigtLXN1Y2Nlc3MpO2FuaW1hdGlvbjpnd1B1bHNlIDJzIGVhc2UtaW4tb3V0IGluZmluaXRlfQouZ3ctZG90Lndhcm57YmFja2dyb3VuZDojZWFiMzA4O2NvbG9yOiNlYWIzMDg7YW5pbWF0aW9uOmd3QmxpbmtTb2Z0IDJzIGVhc2UtaW4tb3V0IGluZmluaXRlfQouZ3ctZG90LmVycntiYWNrZ3JvdW5kOnZhcigtLWNyaXRpY2FsKTtjb2xvcjp2YXIoLS1jcml0aWNhbCk7YW5pbWF0aW9uOmd3QmxpbmtGYXN0IDAuNXMgc3RlcHMoMSkgaW5maW5pdGV9Ci5ndy1kb3Qubm9uZXtiYWNrZ3JvdW5kOnZhcigtLXRleHRNdXRlZCk7b3BhY2l0eTowLjQ1O2FuaW1hdGlvbjpub25lfQouZ2F0ZXdheS1yb3cgLmd3LWluZm97ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6MnB4O21pbi13aWR0aDowfQouZ2F0ZXdheS1yb3cgLmd3LWFnZW50c3tmb250LXNpemU6MC42MnJlbTtjb2xvcjp2YXIoLS1wcmltYXJ5KTttYXJnaW4tbGVmdDo2cHg7Zm9udC13ZWlnaHQ6NTAwfQouZ2F0ZXdheS1yb3cgLmd3LW1ldGF7Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjAuNjJyZW07Y29sb3I6dmFyKC0tdGV4dE11dGVkKTtkaXNwbGF5OmZsZXg7ZmxleC13cmFwOndyYXA7Z2FwOjhweDttYXJnaW4tdG9wOjJweH0KLmdhdGV3YXktcm93IC5ndy1tZXRhIC5mbGFne2NvbG9yOiNlYWIzMDg7Zm9udC13ZWlnaHQ6NjAwfQouZ2F0ZXdheS1yb3cgLmd3LW1ldGEgLmZsYWctcmVzdGFydHtjb2xvcjojZjU5ZTBiO2ZvbnQtd2VpZ2h0OjcwMH0KLmdhdGV3YXktcm93IC5ndy1tZXRhIC5mbGFnLWV4aXR7Y29sb3I6dmFyKC0tY3JpdGljYWwpfQouZ2F0ZXdheS1yb3cgLmd3LW1ldGEgLmJhZHtjb2xvcjp2YXIoLS1jcml0aWNhbCl9Ci5nYXRld2F5LXJvdyAuZ3ctbWV0YSAub2t2e2NvbG9yOnZhcigtLXN1Y2Nlc3MpfQouZ3ctZXhwYW5ke2JhY2tncm91bmQ6dmFyKC0tYmdIb3Zlcik7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXJMaWdodCk7Y29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSk7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtZnVsbCk7Zm9udC1zaXplOjAuNjJyZW07Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7cGFkZGluZzoycHggOHB4O2N1cnNvcjpwb2ludGVyO3doaXRlLXNwYWNlOm5vd3JhcH0KLmd3LWV4cGFuZDpob3Zlcntjb2xvcjp2YXIoLS10ZXh0UHJpbWFyeSk7Ym9yZGVyLWNvbG9yOnZhcigtLXByaW1hcnkpfQouZ3ctcGxhdGZvcm1ze2Rpc3BsYXk6bm9uZTtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsMC4xNSk7cGFkZGluZzo0cHggdmFyKC0tc3BhY2UtbGcpIDhweDtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpfQouZ2F0ZXdheS1yb3cgfiAuZ3ctcGxhdGZvcm1zLm9wZW57ZGlzcGxheTpibG9ja30KLmd3LXBsYXRmb3JtLXJvd3tkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47YWxpZ24taXRlbXM6Y2VudGVyO3BhZGRpbmc6M3B4IDA7Ym9yZGVyLWJvdHRvbToxcHggZGFzaGVkIHZhcigtLWJvcmRlcik7Zm9udC1zaXplOjAuNjJyZW07Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2V9Ci5ndy1wbGF0Zm9ybS1yb3c6bGFzdC1jaGlsZHtib3JkZXItYm90dG9tOm5vbmV9Ci5ndy1wbGF0Zm9ybS1yb3cgLnBsLXN0YXRle2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjZweH0KLmd3LXBsLWRvdHt3aWR0aDo2cHg7aGVpZ2h0OjZweDtib3JkZXItcmFkaXVzOjUwJTtmbGV4LXNocmluazowfQouZ3ctcGwtZG90LmNvbm5lY3RlZHtiYWNrZ3JvdW5kOnZhcigtLXN1Y2Nlc3MpfQouZ3ctcGwtZG90LmRpc2Nvbm5lY3RlZHtiYWNrZ3JvdW5kOnZhcigtLWNyaXRpY2FsKX0KLmd3LXBsLWRvdC5zdGFydGluZ3tiYWNrZ3JvdW5kOiNlYWIzMDh9Ci5ndy1wbC1kb3QudW5rbm93bntiYWNrZ3JvdW5kOnZhcigtLXRleHRNdXRlZCl9Ci5ndy1wbGF0Zm9ybS1yb3cgLnBsLWVycntjb2xvcjp2YXIoLS1jcml0aWNhbCk7Zm9udC1zaXplOjAuNThyZW07bWF4LXdpZHRoOjE4MHB4O292ZXJmbG93OmhpZGRlbjt0ZXh0LW92ZXJmbG93OmVsbGlwc2lzO3doaXRlLXNwYWNlOm5vd3JhcH0KCi8qIEZvb3RlciAqLwojZm9vdGVyewogIGJhY2tncm91bmQ6dmFyKC0tYmdTdXJmYWNlKTsKICBib3JkZXItdG9wOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIHBhZGRpbmc6dmFyKC0tc3BhY2UtbGcpIDA7Cn0KLmZvb3Rlci1jYXJkc3tkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCgzLDFmcik7Z2FwOnZhcigtLXNwYWNlLWxnKX0KQG1lZGlhKG1heC13aWR0aDo3NjhweCl7LmZvb3Rlci1jYXJkc3tncmlkLXRlbXBsYXRlLWNvbHVtbnM6MWZyfX0KLmZvb3Rlci1jYXJke2JhY2tncm91bmQ6dmFyKC0tYmdDYXJkKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtbGcpO3BhZGRpbmc6dmFyKC0tc3BhY2UtbGcpfQouZm9vdGVyLWNhcmQgLmZjLWhlYWRlcnttYXJnaW4tYm90dG9tOnZhcigtLXNwYWNlLXNtKX0KLmtleS1jaGlwewogIGRpc3BsYXk6aW5saW5lLWJsb2NrO3BhZGRpbmc6MnB4IDhweDttYXJnaW46MnB4OwogIGJhY2tncm91bmQ6dmFyKC0tYmdIb3Zlcik7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtc20pOwogIGZvbnQtc2l6ZTowLjdyZW07Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7CiAgY29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSk7Cn0KLmJhZGdlewogIGRpc3BsYXk6aW5saW5lLWJsb2NrO3BhZGRpbmc6MnB4IDhweDtib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cy1mdWxsKTsKICBmb250LXNpemU6MC43cmVtO2ZvbnQtd2VpZ2h0OjUwMDsKfQouYmFkZ2Uub2t7YmFja2dyb3VuZDojMDUyRTE2O2NvbG9yOnZhcigtLXN1Y2Nlc3MpfQouYmFkZ2Uud2FybntiYWNrZ3JvdW5kOiM0MjIwMDY7Y29sb3I6dmFyKC0td2FybmluZyl9Ci5iYWRnZS5lcnJ7YmFja2dyb3VuZDojMkUwODE1O2NvbG9yOnZhcigtLWNyaXRpY2FsKX0KCi8qID09PT09IFNUQVRFUyA9PT09PSAqLwouc3RhdGUtbXNnewogIGRpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7CiAgcGFkZGluZzp2YXIoLS1zcGFjZS0zeGwpO3RleHQtYWxpZ246Y2VudGVyO2dhcDp2YXIoLS1zcGFjZS1tZCk7CiAgbWluLWhlaWdodDoyMDBweDsKfQouc3RhdGUtbXNnIC5pY29ue2ZvbnQtc2l6ZToyLjVyZW19Ci5zdGF0ZS1tc2cgLnRpdGxle2NvbG9yOnZhcigtLXRleHRQcmltYXJ5KX0KLnN0YXRlLW1zZyAuZGVzY3tjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KX0KCi8qIFNrZWxldG9uIGxvYWRpbmcgKi8KQGtleWZyYW1lcyBzaGltbWVyezAle29wYWNpdHk6MC4zfTUwJXtvcGFjaXR5OjAuNn0xMDAle29wYWNpdHk6MC4zfX0KLnNrZWxldG9uewogIGJhY2tncm91bmQ6dmFyKC0tYmdIb3Zlcik7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtbWQpOwogIGFuaW1hdGlvbjpzaGltbWVyIDEuNXMgaW5maW5pdGU7Cn0KLnNrZWxldG9uLXRleHR7aGVpZ2h0OjFyZW07d2lkdGg6NjAlO21hcmdpbi1ib3R0b206dmFyKC0tc3BhY2Utc20pfQouc2tlbGV0b24tdmFsdWV7aGVpZ2h0OjIuMjVyZW07d2lkdGg6NDAlfQoKLyogUHVsc2UgYW5pbWF0aW9uIGZvciBzdGF0dXMgZG90cyAqLwpAa2V5ZnJhbWVzIHB1bHNlewogIDAlLDEwMCV7b3BhY2l0eToxfQogIDUwJXtvcGFjaXR5OjAuNH0KfQoKLyogPT09PT0gUElQLUJPWSBUSEVNRSAoVkFVTFQtVEVDIGluc3BpcmVkKSA9PT09PSAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXXsKICAtLXByaW1hcnk6ICMxNEZGMTc7CiAgLS1zZWNvbmRhcnk6ICMwRUJEMEY7CiAgLS1zdWNjZXNzOiAjMTRGRjE3OwogIC0td2FybmluZzogI0M4RkYwMDsKICAtLWNyaXRpY2FsOiAjRkYzQjNCOwogIC0taW5mbzogIzE0RkYxNzsKICAtLW5ldXRyYWw6ICMyQTRBMjA7CiAgLS1iZ1Jvb3Q6ICMwNTA4MDM7CiAgLS1iZ1N1cmZhY2U6ICMwODBDMDU7CiAgLS1iZ0NhcmQ6ICMwQTEyMDc7CiAgLS1iZ0hvdmVyOiAjMEYxRDBBOwogIC0tYm9yZGVyOiAjMUE1QTEyOwogIC0tYm9yZGVyTGlnaHQ6ICMyMjhBMTg7CiAgLS10ZXh0UHJpbWFyeTogIzE0RkYxNzsKICAtLXRleHRTZWNvbmRhcnk6ICMwRUJEMEY7CiAgLS10ZXh0TXV0ZWQ6ICMyQTdBMjA7CiAgLS10ZXh0T25QcmltYXJ5OiAjMDUwODAzOwogIGZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsJ0NvdXJpZXIgTmV3Jyxtb25vc3BhY2U7Cn0KCi8qID09PT09IFBJUC1CT1k6IEdsb2JhbCB0ZXh0IGdsb3cgPT09PT0gKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmhlYWRpbmcteGwsCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5oZWFkaW5nLWxnLApib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuaGVhZGluZy1tZCwKYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmJvZHktbWQsCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5ib2R5LXNtLApib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAubGFiZWwtbWQsCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5sYWJlbC1sZywKYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLm1vbm8tc217CiAgZm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJywnQ291cmllciBOZXcnLG1vbm9zcGFjZTsKICB0ZXh0LXNoYWRvdzowIDAgNHB4IHJnYmEoMjAsMjU1LDIzLDAuNCksIDAgMCAxMnB4IHJnYmEoMjAsMjU1LDIzLDAuMTUpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tZXRyaWMteGwsCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tZXRyaWMtbGcsCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tZXRyaWMtbWR7CiAgdGV4dC1zaGFkb3c6MCAwIDhweCByZ2JhKDIwLDI1NSwyMywwLjUpLCAwIDAgMjBweCByZ2JhKDIwLDI1NSwyMywwLjIpOwp9CgovKiA9PT09PSBQSVAtQk9ZOiBUaGljayBDUlQgYmV6ZWwgZnJhbWUgPT09PT0gKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il17CiAgYm9yZGVyOjEwcHggc29saWQgIzFBM0ExMjsKICBib3JkZXItaW1hZ2U6bGluZWFyLWdyYWRpZW50KDEzNWRlZywjMEQyMDA4LCMxQTNBMTIgMzAlLCMyQTVBMjAgNTAlLCMxQTNBMTIgNzAlLCMwRDIwMDgpIDE7CiAgYm94LXNoYWRvdzppbnNldCAwIDAgODBweCByZ2JhKDAsMCwwLDAuNyk7CiAgbWluLWhlaWdodDoxMDB2aDsKfQpAbWVkaWEobWF4LXdpZHRoOjc2OHB4KXsKICBib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXXtib3JkZXItd2lkdGg6NnB4fQp9CgovKiA9PT09PSBQSVAtQk9ZOiBDUlQgdmlnbmV0dGUgb3ZlcmxheSA9PT09PSAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXTo6YmVmb3JlewogIGNvbnRlbnQ6Jyc7cG9zaXRpb246Zml4ZWQ7aW5zZXQ6MDtwb2ludGVyLWV2ZW50czpub25lO3otaW5kZXg6OTk5NzsKICBiYWNrZ3JvdW5kOnJhZGlhbC1ncmFkaWVudChlbGxpcHNlIGF0IDUwJSA1MCUsdHJhbnNwYXJlbnQgNTAlLHJnYmEoMCwwLDAsMC41KSAxMDAlKTsKfQoKLyogPT09PT0gUElQLUJPWTogQ1JUIHNjYW5saW5lcyA9PT09PSAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXTo6YWZ0ZXJ7CiAgY29udGVudDonJztwb3NpdGlvbjpmaXhlZDt0b3A6MDtsZWZ0OjA7cmlnaHQ6MDtib3R0b206MDsKICBiYWNrZ3JvdW5kOnJlcGVhdGluZy1saW5lYXItZ3JhZGllbnQoMGRlZywKICAgIHJnYmEoMjAsMjU1LDIzLDAuMDE1KSAwcHgsCiAgICByZ2JhKDIwLDI1NSwyMywwLjAxNSkgMXB4LAogICAgdHJhbnNwYXJlbnQgMXB4LAogICAgdHJhbnNwYXJlbnQgM3B4KTsKICBwb2ludGVyLWV2ZW50czpub25lO3otaW5kZXg6OTk5ODsKICBhbmltYXRpb246Y3JmRmxpY2tlciA2cyBpbmZpbml0ZTsKfQpAa2V5ZnJhbWVzIGNyZkZsaWNrZXJ7CiAgMCUsMTAwJXtvcGFjaXR5OjF9CiAgOTEle29wYWNpdHk6MX0KICA5MiV7b3BhY2l0eTowLjkyfQogIDkzJXtvcGFjaXR5OjAuNzV9CiAgOTQle29wYWNpdHk6MC45OH0KICA5NiV7b3BhY2l0eTowLjg4fQogIDk3JXtvcGFjaXR5OjF9Cn0KCi8qID09PT09IFBJUC1CT1k6IENvbXBvbmVudCBvdmVycmlkZXMgPT09PT0gKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gI3RvcGJhcnsKICBiYWNrZ3JvdW5kOnJnYmEoMTAsMTgsNywwLjk1KTsKICBib3JkZXItYm90dG9tOjJweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJveC1zaGFkb3c6MCAycHggMTJweCByZ2JhKDIwLDI1NSwyMywwLjA4KTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAjc3RhdHVzLXN0cmlwewogIGJhY2tncm91bmQ6cmdiYSg4LDEyLDUsMC45NSk7CiAgYm9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAubGF5b3V0LXN3aXRjaGVyewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4wNik7CiAgYm9yZGVyLWNvbG9yOnZhcigtLWJvcmRlcik7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmxheW91dC1zd2l0Y2hlciBidXR0b24uYWN0aXZlewogIGJhY2tncm91bmQ6dmFyKC0tcHJpbWFyeSk7CiAgY29sb3I6IzA1MDgwMzsKICB0ZXh0LXNoYWRvdzpub25lOwogIGJveC1zaGFkb3c6MCAwIDEycHggcmdiYSgyMCwyNTUsMjMsMC41KTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAubGF5b3V0LXN3aXRjaGVyIGJ1dHRvbjpob3Zlcjpub3QoLmFjdGl2ZSl7CiAgY29sb3I6dmFyKC0tcHJpbWFyeSk7CiAgdGV4dC1zaGFkb3c6MCAwIDZweCB2YXIoLS1wcmltYXJ5KTsKfQoKLyogS1BJIGNhcmRzICovCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tZXRyaWMtdGlsZXsKICBiYWNrZ3JvdW5kOnJnYmEoMTAsMTgsNywwLjg1KTsKICBib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgYm94LXNoYWRvdzppbnNldCAwIDAgMTVweCByZ2JhKDIwLDI1NSwyMywwLjAzKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAubWV0cmljLXRpbGU6aG92ZXJ7CiAgYm9yZGVyLWNvbG9yOnZhcigtLXByaW1hcnkpOwogIGJveC1zaGFkb3c6aW5zZXQgMCAwIDIwcHggcmdiYSgyMCwyNTUsMjMsMC4wNiksIDAgMCAxMnB4IHJnYmEoMjAsMjU1LDIzLDAuMSk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLm1ldHJpYy10aWxlLmNyaXRpY2Fse2JvcmRlci1sZWZ0OjNweCBzb2xpZCB2YXIoLS1jcml0aWNhbCl9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tZXRyaWMtdGlsZS53YXJuaW5ne2JvcmRlci1sZWZ0OjNweCBzb2xpZCAjQzhGRjAwfQoKLyogQ2hhcnQgY2FyZHMgKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmNoYXJ0LWNhcmR7CiAgYmFja2dyb3VuZDpyZ2JhKDEwLDE4LDcsMC44NSk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5zZXNzaW9ucy1jYXJkLApib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuZ2F0ZXdheS1jYXJkewogIGJhY2tncm91bmQ6cmdiYSgxMCwxOCw3LDAuODUpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuc2Vzc2lvbi1yb3c6aG92ZXJ7YmFja2dyb3VuZDp2YXIoLS1iZ0hvdmVyKX0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnNlc3Npb24tcm93e2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHJnYmEoMjYsOTAsMTgsMC40KX0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmdhdGV3YXktcm93e2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHJnYmEoMjYsOTAsMTgsMC40KX0KCi8qIEZvb3RlciAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAjZm9vdGVyewogIGJhY2tncm91bmQ6cmdiYSg4LDEyLDUsMC45NSk7CiAgYm9yZGVyLXRvcDoycHggc29saWQgdmFyKC0tYm9yZGVyKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuZm9vdGVyLWNhcmR7CiAgYmFja2dyb3VuZDpyZ2JhKDEwLDE4LDcsMC44NSk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwp9CgovKiBCYWRnZXMgKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmJhZGdlLm9re2JhY2tncm91bmQ6IzBBMkUwNjtjb2xvcjp2YXIoLS1zdWNjZXNzKTt0ZXh0LXNoYWRvdzowIDAgNnB4IHJnYmEoMjAsMjU1LDIzLDAuNSl9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5iYWRnZS53YXJue2JhY2tncm91bmQ6IzJFMjAwMDtjb2xvcjojQzhGRjAwO3RleHQtc2hhZG93OjAgMCA2cHggcmdiYSgyMDAsMjU1LDAsMC41KX0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmJhZGdlLmVycntiYWNrZ3JvdW5kOiMyRTA4MTU7Y29sb3I6dmFyKC0tY3JpdGljYWwpO3RleHQtc2hhZG93OjAgMCA2cHggcmdiYSgyNTUsNTksNTksMC41KX0KCi8qIFN0YXR1cyBjaGlwcyAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuc3RhdHVzLWNoaXB7CiAgYmFja2dyb3VuZDpyZ2JhKDEwLDE4LDcsMC44NSk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5zdGF0dXMtY2hpcCAuZG90Lm9ubGluZXsKICBiYWNrZ3JvdW5kOnZhcigtLXN1Y2Nlc3MpOwogIGJveC1zaGFkb3c6MCAwIDEwcHggdmFyKC0tc3VjY2VzcyksIDAgMCAyMHB4IHJnYmEoMjAsMjU1LDIzLDAuNCk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnN0YXR1cy1jaGlwIC5kb3Qub2ZmbGluZXsKICBiYWNrZ3JvdW5kOnZhcigtLWNyaXRpY2FsKTsKICBib3gtc2hhZG93OjAgMCA2cHggdmFyKC0tY3JpdGljYWwpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5zdGF0dXMtY2hpcC5za2VsZXRvbi1jaGlwe29wYWNpdHk6MC41fQoKLyogPT09PT0gUElQLUJPWTogUHJvZmlsZSBDYXJkcyA9PT09PSAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAucHJvZmlsZS1jYXJkewogIGJhY2tncm91bmQ6cmdiYSgxMCwxOCw3LDAuODUpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBib3JkZXItcmFkaXVzOjJweDsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAucHJvZmlsZS1jYXJkOmhvdmVyewogIGJvcmRlci1jb2xvcjp2YXIoLS1wcmltYXJ5KTsKICBib3gtc2hhZG93Omluc2V0IDAgMCAyMHB4IHJnYmEoMjAsMjU1LDIzLDAuMDYpLDAgMCAxMnB4IHJnYmEoMjAsMjU1LDIzLDAuMSk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2FyZCAucGMtaGVhZGVyewogIGJvcmRlci1ib3R0b206MXB4IHNvbGlkIHJnYmEoMjAsMjU1LDIzLDAuMTUpOwogIHBhZGRpbmctYm90dG9tOnZhcigtLXNwYWNlLXNtKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAucHJvZmlsZS1jYXJkIC5wYy1kb3Qub25saW5lewogIGJveC1zaGFkb3c6MCAwIDEwcHggdmFyKC0tc3VjY2VzcyksMCAwIDIwcHggcmdiYSgyMCwyNTUsMjMsMC40KTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAucHJvZmlsZS1jYXJkIC5wYy1kb3Qub2ZmbGluZXsKICBib3gtc2hhZG93OjAgMCA2cHggdmFyKC0tY3JpdGljYWwpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5wcm9maWxlLWNhcmQgLnBjLWRvdC5zdGFsZXsKICBib3gtc2hhZG93OjAgMCA2cHggdmFyKC0td2FybmluZyk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2FyZCAucGMtbmFtZXsKICB0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7CiAgZm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7CiAgdGV4dC1zaGFkb3c6MCAwIDRweCByZ2JhKDIwLDI1NSwyMywwLjQpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5wcm9maWxlLWNhcmQgLnBjLW1ldGEtaXRlbXsKICBmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTsKICB0ZXh0LXNoYWRvdzowIDAgNHB4IHJnYmEoMjAsMjU1LDIzLDAuMTUpOwogIHRleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAucHJvZmlsZS1jYXJkIC5wYy1tZXRhLWl0ZW06OmJlZm9yZXtjb250ZW50Oic+ICd9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5wcm9maWxlLWNhcmQgLnBjLXBsYXRmb3Jtc3tib3JkZXItdG9wOjFweCBzb2xpZCByZ2JhKDIwLDI1NSwyMywwLjEyKX0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2FyZCAucGMtcGxhdC1jaGlwewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4wNik7CiAgYm9yZGVyOjFweCBzb2xpZCByZ2JhKDIwLDI1NSwyMywwLjE1KTsKICBjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KTsKICB0ZXh0LXNoYWRvdzowIDAgM3B4IHJnYmEoMjAsMjU1LDIzLDAuMik7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2FyZCAucGMtcGxhdC1jaGlwLmNvbm5lY3RlZHsKICBjb2xvcjp2YXIoLS1zdWNjZXNzKTsKICB0ZXh0LXNoYWRvdzowIDAgNnB4IHJnYmEoMjAsMjU1LDIzLDAuNCk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2FyZCAucGMtZm9vdGVyewogIGJvcmRlci10b3A6MXB4IHNvbGlkIHJnYmEoMjAsMjU1LDIzLDAuMTIpOwogIHRleHQtc2hhZG93OjAgMCAzcHggcmdiYSgyMCwyNTUsMjMsMC4xNSk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2FyZCAucGMtc3RhdHVzLXByZWZpeHsKICBmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTsKICBmb250LXNpemU6MC42NXJlbTsKICBmb250LXdlaWdodDo3MDA7CiAgbWFyZ2luLXJpZ2h0OnZhcigtLXNwYWNlLXhzKTsKfQoKLyogVG9wYmFyIGVsZW1lbnRzICovCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC50b3BiYXItbG9nb3sKICBib3gtc2hhZG93OjAgMCAxMnB4IHZhcigtLXN1Y2Nlc3MpLCAwIDAgMjRweCByZ2JhKDIwLDI1NSwyMywwLjQpOwp9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5yZWZyZXNoLWluZGljYXRvciAuZG90ewogIGJveC1zaGFkb3c6MCAwIDhweCB2YXIoLS1wcmltYXJ5KTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAjY2xvY2t7CiAgdGV4dC1zaGFkb3c6MCAwIDZweCByZ2JhKDIwLDI1NSwyMywwLjQpOwp9CgovKiBCdXR0b25zICovCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5jdHJsLWJ0bnsKICBiYWNrZ3JvdW5kOnJnYmEoMjAsMjU1LDIzLDAuMTUpOwogIGNvbG9yOnZhcigtLXByaW1hcnkpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICB0ZXh0LXNoYWRvdzowIDAgNnB4IHJnYmEoMjAsMjU1LDIzLDAuMyk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmN0cmwtYnRuOmhvdmVyewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4yNSk7CiAgYm94LXNoYWRvdzowIDAgMTVweCByZ2JhKDIwLDI1NSwyMywwLjMpOwogIGNvbG9yOiMyMEZGMjQ7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmN0cmwtc2VsZWN0ewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4wOCk7CiAgY29sb3I6dmFyKC0tcHJpbWFyeSk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIHRleHQtc2hhZG93OjAgMCA2cHggcmdiYSgyMCwyNTUsMjMsMC4zKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuY3RybC1idG4uYWN0aXZle2JhY2tncm91bmQ6dmFyKC0tcHJpbWFyeSk7Y29sb3I6IzAzMTQwMztib3JkZXItY29sb3I6dmFyKC0tcHJpbWFyeSl9CgovKiBHYXRld2F5IHJvd3MgKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmdhdGV3YXktcm93e2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHJnYmEoMjYsOTAsMTgsMC4zKX0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmdhdGV3YXktcm93IC5ndy1uYW1le3RleHQtc2hhZG93OjAgMCA0cHggcmdiYSgyMCwyNTUsMjMsMC4zKX0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmd3LWRvdC51cHtib3gtc2hhZG93OjAgMCAwIHJnYmEoMjAsMjU1LDIzLDApfQoKLyogTW9kZWxzIHRhYmxlICovCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tb2RlbHMtdGFibGUgdGh7Y29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSl9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tb2RlbHMtdGFibGUgdGR7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgcmdiYSgyNiw5MCwxOCwwLjMpfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAubW9kZWxzLXRhYmxlIHRyOmhvdmVyIHRke2JhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4wNil9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tb2RlbHMtdGFibGUgLm0tbmFtZXt0ZXh0LXNoYWRvdzowIDAgNHB4IHJnYmEoMjAsMjU1LDIzLDAuMyl9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tLWNvc3R7dGV4dC1zaGFkb3c6MCAwIDRweCByZ2JhKDIwLDI1NSwyMywwLjMpfQoKLyogUHJvZmlsZSBjaGlwIG1pbmkgKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnByb2ZpbGUtY2hpcC1taW5pewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4wOCk7CiAgYm9yZGVyOjFweCBzb2xpZCByZ2JhKDIwLDI1NSwyMywwLjIpOwogIGNvbG9yOnZhcigtLXByaW1hcnkpOwogIHRleHQtc2hhZG93OjAgMCA0cHggcmdiYSgyMCwyNTUsMjMsMC4zKTsKfQoKLyogS2V5IGNoaXAgKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmtleS1jaGlwewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4wNSk7CiAgYm9yZGVyOjFweCBzb2xpZCByZ2JhKDIwLDI1NSwyMywwLjE1KTsKICBjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KTsKfQoKLyogVG9hc3QgKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnRvYXN0ewogIGJhY2tncm91bmQ6cmdiYSgxMCwxOCw3LDAuOTUpOwogIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBib3gtc2hhZG93OjAgMCAyMHB4IHJnYmEoMjAsMjU1LDIzLDAuMSk7Cn0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnRvYXN0LmNyaXRpY2FsewogIGJhY2tncm91bmQ6cmdiYSgzMCw1LDUsMC45NSk7CiAgYm9yZGVyLWxlZnQ6M3B4IHNvbGlkIHZhcigtLWNyaXRpY2FsKTsKfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAudG9hc3Qud2FybmluZ3sKICBib3JkZXItbGVmdDozcHggc29saWQgI0M4RkYwMDsKfQoKLyogSGVhZGVyIGJsaW5raW5nIGN1cnNvciAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAjdG9wYmFyIC5oZWFkaW5nLW1kOjphZnRlcnsKICBjb250ZW50OidcMjU4Qyc7CiAgZGlzcGxheTppbmxpbmUtYmxvY2s7CiAgbWFyZ2luLWxlZnQ6NnB4OwogIGNvbG9yOnZhcigtLXByaW1hcnkpOwogIHRleHQtc2hhZG93OjAgMCA4cHggdmFyKC0tcHJpbWFyeSk7CiAgYW5pbWF0aW9uOnBpcEJsaW5rIDEuMXMgc3RlcHMoMSkgaW5maW5pdGU7CiAgdmVydGljYWwtYWxpZ246LTFweDsKfQpAa2V5ZnJhbWVzIHBpcEJsaW5rezUwJXtvcGFjaXR5OjB9fQoKLyogU2tlbGV0b24gKi8KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLnNrZWxldG9uewogIGJhY2tncm91bmQ6cmdiYSgyMCwyNTUsMjMsMC4xKTsKfQoKLyogQ29udHJvbCBidXR0b25zIChyZWZyZXNoICsgYWxsLXByb2ZpbGVzKSAqLwouY3RybC1idG57CiAgYmFja2dyb3VuZDp2YXIoLS1iZ0NhcmQpO2NvbG9yOnZhcigtLXRleHRQcmltYXJ5KTsKICBib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtbWQpOwogIHBhZGRpbmc6NnB4IDE0cHg7Y3Vyc29yOnBvaW50ZXI7CiAgZm9udC1mYW1pbHk6J0ludGVyJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZTowLjhyZW07Zm9udC13ZWlnaHQ6NjAwOwogIHRyYW5zaXRpb246YmFja2dyb3VuZCAwLjJzLGJvcmRlci1jb2xvciAwLjJzOwp9Ci5jdHJsLWJ0bjpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLWJnSG92ZXIpO2JvcmRlci1jb2xvcjp2YXIoLS1ib3JkZXJMaWdodCl9Ci5jdHJsLWJ0bi5hY3RpdmV7YmFja2dyb3VuZDp2YXIoLS1wcmltYXJ5KTtjb2xvcjp2YXIoLS10ZXh0T25QcmltYXJ5KTtib3JkZXItY29sb3I6dmFyKC0tcHJpbWFyeSl9CgouY3RybC1zZWxlY3R7CiAgYmFja2dyb3VuZDp2YXIoLS1iZ0NhcmQpO2NvbG9yOnZhcigtLXRleHRQcmltYXJ5KTsKICBib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMtbWQpOwogIHBhZGRpbmc6NnB4IDhweDtjdXJzb3I6cG9pbnRlcjsKICBmb250LWZhbWlseTonSW50ZXInLHNhbnMtc2VyaWY7Zm9udC1zaXplOjAuOHJlbTtmb250LXdlaWdodDo2MDA7Cn0KLmN0cmwtc2VsZWN0OmhvdmVye2JvcmRlci1jb2xvcjp2YXIoLS1ib3JkZXJMaWdodCl9CgovKiBUb2FzdCBub3RpZmljYXRpb24gKi8KLnRvYXN0LWNvbnRhaW5lcntwb3NpdGlvbjpmaXhlZDt0b3A6dmFyKC0tc3BhY2UtbGcpO3JpZ2h0OnZhcigtLXNwYWNlLWxnKTt6LWluZGV4OjIwMDtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2dhcDp2YXIoLS1zcGFjZS1zbSl9Ci50b2FzdHsKICBiYWNrZ3JvdW5kOnZhcigtLWJnQ2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLW1kKTtwYWRkaW5nOnZhcigtLXNwYWNlLW1kKSB2YXIoLS1zcGFjZS1sZyk7CiAgbWF4LXdpZHRoOjM2MHB4O2FuaW1hdGlvbjpzbGlkZUluIDAuM3MgZWFzZTsKfQoudG9hc3QuY3JpdGljYWx7Ym9yZGVyLWxlZnQ6M3B4IHNvbGlkIHZhcigtLWNyaXRpY2FsKX0KLnRvYXN0Lndhcm5pbmd7Ym9yZGVyLWxlZnQ6M3B4IHNvbGlkIHZhcigtLXdhcm5pbmcpfQpAa2V5ZnJhbWVzIHNsaWRlSW57ZnJvbXt0cmFuc2Zvcm06dHJhbnNsYXRlWCgxMDAlKTtvcGFjaXR5OjB9dG97dHJhbnNmb3JtOnRyYW5zbGF0ZVgoMCk7b3BhY2l0eToxfX0KCi8qID09PT09IEFDQ0VTU0lCSUxJVFkgPT09PT0gKi8KQG1lZGlhKHByZWZlcnMtcmVkdWNlZC1tb3Rpb246cmVkdWNlKXsKICAudG9wYmFyLWxvZ28sLnN0YXR1cy1jaGlwIC5kb3QsLnByb2ZpbGUtY2FyZCAucGMtZG90e2FuaW1hdGlvbjpub25lfQogIGJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdOjphZnRlcnthbmltYXRpb246bm9uZX0KICBib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAudG9wYmFyLWxvZ297YW5pbWF0aW9uOm5vbmV9Cn0KLnZlci1iYWRnZXtkaXNwbGF5OmlubGluZS1ibG9jazttYXJnaW4tbGVmdDo4cHg7cGFkZGluZzoycHggOXB4O2JvcmRlci1yYWRpdXM6OTk5cHg7CiAgYmFja2dyb3VuZDpyZ2JhKDU2LDE4OSwyNDgsLjEyKTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoNTYsMTg5LDI0OCwuMzUpOwogIGNvbG9yOnZhcigtLXByaW1hcnksIzM4YmRmOCk7Zm9udC1zaXplOjExcHg7Zm9udC13ZWlnaHQ6NjAwO2xldHRlci1zcGFjaW5nOi40cHg7CiAgZm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7dmVydGljYWwtYWxpZ246MnB4fQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAudmVyLWJhZGdle2JhY2tncm91bmQ6cmdiYSgzNCwxOTcsOTQsLjEwKTtib3JkZXItY29sb3I6cmdiYSgzNCwxOTcsOTQsLjQpO2NvbG9yOiM0YWRlODB9CgovKiA9PT09PSBQSVAtQk9ZOiBDUlQgRlJBTUUgKHd6b3J6ZWMgTmV0d29yayBNb25pdG9yKSA9PT09PSAqLwpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXXtmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJywnSmV0QnJhaW5zIE1vbm8nLCdDb3VyaWVyIE5ldycsbW9ub3NwYWNlfQpib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuaGVhZGluZy1tZCxib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAuaGVhZGluZy1sZywKYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmhlYWRpbmcteGwsYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmJvZHktbWQsCmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5ib2R5LXNtLGJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5sYWJlbC1tZCwKYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gLmxhYmVsLWxnLGJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5tb25vLXNtLApib2R5W2RhdGEtbGF5b3V0PSJwaXBib3kiXSAubWV0cmljLXhsLGJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdIC5rcGktdmFsdWV7CiAgZm9udC1mYW1pbHk6aW5oZXJpdH0KYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gI21haW57CiAgcG9zaXRpb246cmVsYXRpdmU7CiAgYm9yZGVyOjhweCBzb2xpZCAjMjIzMjFjO2JvcmRlci1yYWRpdXM6MThweDsKICBiYWNrZ3JvdW5kOnJnYmEoNSw4LDMsLjkyKTsKICBib3gtc2hhZG93OjAgMCAzMHB4IHJnYmEoMjAsMjU1LDIzLC4xMCksaW5zZXQgMCAwIDUwcHggcmdiYSgwLDAsMCwuOSk7CiAgcGFkZGluZzoxNnB4IDE4cHh9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdICNtYWluOjpiZWZvcmV7Y29udGVudDonJztwb3NpdGlvbjphYnNvbHV0ZTtpbnNldDowO3BvaW50ZXItZXZlbnRzOm5vbmU7CiAgYmFja2dyb3VuZDpyZXBlYXRpbmctbGluZWFyLWdyYWRpZW50KDBkZWcscmdiYSgwLDAsMCwuMzApIDAgMXB4LHRyYW5zcGFyZW50IDFweCAzcHgpOwogIHotaW5kZXg6NTtib3JkZXItcmFkaXVzOmluaGVyaXR9CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdICNtYWluOjphZnRlcntjb250ZW50OicnO3Bvc2l0aW9uOmFic29sdXRlO2luc2V0OjA7cG9pbnRlci1ldmVudHM6bm9uZTsKICBiYWNrZ3JvdW5kOnJhZGlhbC1ncmFkaWVudChlbGxpcHNlIGF0IDUwJSA1MCUsdHJhbnNwYXJlbnQgNTUlLHJnYmEoMCwwLDAsLjUpIDEwMCUpOwogIGFuaW1hdGlvbjpmbGlja2VyIDhzIGluZmluaXRlO3otaW5kZXg6Njtib3JkZXItcmFkaXVzOmluaGVyaXR9CkBrZXlmcmFtZXMgZmxpY2tlcnswJSwxMDAle29wYWNpdHk6Ljk3fTkyJXtvcGFjaXR5Oi45N305MyV7b3BhY2l0eTouODB9OTQle29wYWNpdHk6Ljk3fTk3JXtvcGFjaXR5Oi45fTk4JXtvcGFjaXR5Oi45N319CmJvZHlbZGF0YS1sYXlvdXQ9InBpcGJveSJdICNtYWluPiosYm9keVtkYXRhLWxheW91dD0icGlwYm95Il0gI21haW4gLmNvbnRhaW5lcntwb3NpdGlvbjpyZWxhdGl2ZTt6LWluZGV4OjJ9Cgo8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5PgoKPCEtLSA9PT09PSBUT1AgQkFSID09PT09IC0tPgo8ZGl2IGlkPSJ0b3BiYXIiPgogIDxkaXYgY2xhc3M9ImNvbnRhaW5lciI+CiAgICA8ZGl2IGNsYXNzPSJ0b3BiYXItbGVmdCI+CiAgICAgIDxkaXYgY2xhc3M9InRvcGJhci1sb2dvIiBpZD0idG9wYmFyLWRvdCI+PC9kaXY+CiAgICAgIDxzcGFuIGNsYXNzPSJoZWFkaW5nLW1kIj5IZXJtZXMgTW9uaXRvciA8c3BhbiBjbGFzcz0idmVyLWJhZGdlIiBpZD0idmVyLWJhZGdlIj52X19WRVJfXzwvc3Bhbj48L3NwYW4+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InRvcGJhci1yaWdodCI+CiAgICAgIDxidXR0b24gY2xhc3M9ImN0cmwtYnRuIiBpZD0iYWxsLXByb2ZpbGVzLWJ0biIgc3R5bGU9ImRpc3BsYXk6bm9uZSIgdGl0bGU9IlByenl3csOzxIcgZGFuZSB6YmlvcmN6ZSBkbGEgd3N6eXN0a2ljaCBwcm9maWxpIj5BbGw8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iY3RybC1idG4iIGlkPSJtYW51YWwtcmVmcmVzaCIgdGl0bGU9Ik9kxZt3aWXFvCBkYW5lIG5hIMW8xIVkYW5pZSI+T2TFm3dpZcW8PC9idXR0b24+CiAgICAgIDxzZWxlY3QgY2xhc3M9ImN0cmwtc2VsZWN0IiBpZD0icmVmcmVzaC1pbnRlcnZhbCIgdGl0bGU9IkludGVyd2HFgiBhdXRvbWF0eWN6bmVnbyBvZMWbd2llxbxhbmlhIj4KICAgICAgICA8b3B0aW9uIHZhbHVlPSI5MDAiPjE1IG1pbjwvb3B0aW9uPgogICAgICAgIDxvcHRpb24gdmFsdWU9IjE4MDAiPjMwIG1pbjwvb3B0aW9uPgogICAgICAgIDxvcHRpb24gdmFsdWU9IjM2MDAiPjYwIG1pbjwvb3B0aW9uPgogICAgICA8L3NlbGVjdD4KICAgICAgPGRpdiBjbGFzcz0ibGF5b3V0LXN3aXRjaGVyIiBpZD0ibGF5b3V0LXN3aXRjaGVyIj4KICAgICAgICA8YnV0dG9uIGRhdGEtbGF5b3V0PSJkZWZhdWx0IiBjbGFzcz0iYWN0aXZlIj5IZXJtZXM8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGRhdGEtbGF5b3V0PSJwaXBib3kiPlBpcC1Cb3k8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InJlZnJlc2gtaW5kaWNhdG9yIj48ZGl2IGNsYXNzPSJkb3QiPjwvZGl2PjxzcGFuIGNsYXNzPSJtb25vLXNtIiBpZD0ibGFzdC1yZWZyZXNoIj4tLTwvc3Bhbj48L2Rpdj4KICAgICAgPHNwYW4gaWQ9ImNsb2NrIiBjbGFzcz0ibW9uby1zbSI+LS06LS06LS08L3NwYW4+CiAgICA8L2Rpdj4KICA8L2Rpdj4KPC9kaXY+Cgo8IS0tID09PT09IFJFRlJFU0ggUFJPR1JFU1MgQkFSICsgREFUQSBUSU1FU1RBTVAgPT09PT0gLS0+CjxkaXYgaWQ9InJlZnJlc2gtYmFyIj4KICA8ZGl2IGNsYXNzPSJjb250YWluZXIiPgogICAgPGRpdiBjbGFzcz0icmVmcmVzaC1wcm9ncmVzcyI+PGRpdiBjbGFzcz0iZmlsbCIgaWQ9InJlZnJlc2gtYmFyLWZpbGwiPjwvZGl2PjwvZGl2PgogICAgPGRpdiBjbGFzcz0icmVmcmVzaC1wcm9ncmVzcy1sYWJlbCI+CiAgICAgIDxzcGFuIGlkPSJyZWZyZXNoLWJhci1wY3QiPjAlPC9zcGFuPgogICAgICA8c3Bhbj5EbyBuYXN0xJlwbmVnbzogPHNwYW4gaWQ9InJlZnJlc2gtYmFyLW5leHQiIGNsYXNzPSJwY3QiPi0tPC9zcGFuPjwvc3Bhbj4KICAgICAgPHNwYW4+RGFuZSB6OiA8c3BhbiBpZD0icmVmcmVzaC1iYXItZGF0YSIgY2xhc3M9InBjdCI+LS08L3NwYW4+PC9zcGFuPgogICAgPC9kaXY+CiAgPC9kaXY+CjwvZGl2PgoKPCEtLSA9PT09PSBTVEFUVVMgU1RSSVAgPT09PT0gLS0+CjxkaXYgaWQ9InN0YXR1cy1zdHJpcCI+PGRpdiBjbGFzcz0iY29udGFpbmVyIiBpZD0ic3RhdHVzLXN0cmlwLWlubmVyIj48L2Rpdj48L2Rpdj4KCjwhLS0gPT09PT0gUFJPRklMRSBDQVJEUyA9PT09PSAtLT4KPGRpdiBjbGFzcz0icHJvZmlsZS1jYXJkcy1zZWN0aW9uIj48ZGl2IGNsYXNzPSJjb250YWluZXIiPjxkaXYgY2xhc3M9InByb2ZpbGUtY2FyZHMtZ3JpZCIgaWQ9InByb2ZpbGUtY2FyZHMtZ3JpZCI+PC9kaXY+PC9kaXY+PC9kaXY+Cgo8IS0tID09PT09IE1BSU4gQ09OVEVOVCA9PT09PSAtLT4KPGRpdiBjbGFzcz0iY29udGFpbmVyIiBpZD0ibWFpbiI+CgogIDwhLS0gS1BJIEdyaWQgLS0+CiAgPGRpdiBjbGFzcz0ia3BpLWdyaWQiIGlkPSJrcGktZ3JpZCI+PC9kaXY+CgogIDwhLS0gQ2hhcnRzIFJvdyAtLT4KICA8ZGl2IGNsYXNzPSJjaGFydHMtcm93Ij4KICAgIDxkaXYgY2xhc3M9ImNoYXJ0LWNhcmQiPgogICAgICA8ZGl2IGNsYXNzPSJjaGFydC1oZWFkZXIgaGVhZGluZy1tZCI+V3lrb3J6eXN0YW5pZSB0b2tlbsOzdyAvIGtvc3p0w7N3PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LWJvZHkiIGlkPSJjaGFydC11c2FnZSI+PC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNoYXJ0LWNhcmQiPgogICAgICA8ZGl2IGNsYXNzPSJjaGFydC1oZWFkZXIgaGVhZGluZy1tZCI+VG9wIG1vZGVsZSA8c3BhbiBjbGFzcz0iYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRNdXRlZCkiPihvZCBuYWpiYXJkemllaiBkbyBuYWptbmllaiB1xbx5d2FuZWdvKTwvc3Bhbj48L2Rpdj4KICAgICAgPGRpdiBpZD0iY2hhcnQtbW9kZWxzIj48L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8IS0tIERldGFpbCBSb3cgLS0+CiAgPGRpdiBjbGFzcz0iZGV0YWlsLXJvdyI+CiAgICA8ZGl2IGNsYXNzPSJzZXNzaW9ucy1jYXJkIj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZC1oZWFkZXIiPjxzcGFuIGNsYXNzPSJoZWFkaW5nLW1kIj5Pc3RhdG5pZSBzZXNqZSAod3N6eXN0a2llIHByb2ZpbGUpPC9zcGFuPjxzcGFuIGNsYXNzPSJib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSIgaWQ9InNlc3Npb24tY291bnQiPi0tPC9zcGFuPjwvZGl2PgogICAgICA8ZGl2IGlkPSJzZXNzaW9ucy1saXN0Ij48L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iZ2F0ZXdheS1jYXJkIj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZC1oZWFkZXIiPjxzcGFuIGNsYXNzPSJoZWFkaW5nLW1kIj5HYXRld2F5PC9zcGFuPjxzcGFuIGNsYXNzPSJib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSIgaWQ9ImdhdGV3YXktY291bnQiPi0tPC9zcGFuPjwvZGl2PgogICAgICA8ZGl2IGlkPSJnYXRld2F5LWxpc3QiPjwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDwhLS0gRm9vdGVyIC0tPgogIDxkaXYgaWQ9ImZvb3Rlci1zZWN0aW9uIj4KICAgIDxkaXYgY2xhc3M9ImZvb3Rlci1jYXJkcyI+CiAgICAgIDxkaXYgY2xhc3M9ImZvb3Rlci1jYXJkIj4KICAgICAgICA8ZGl2IGNsYXNzPSJmYy1oZWFkZXIgbGFiZWwtbWQiIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KSI+S2x1Y3plIEFQSSAod3N6eXN0a2llIHByb2ZpbGUpPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZm9vdGVyLWtleXMiPjwvZGl2PgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iZm9vdGVyLWNhcmQiPgogICAgICAgIDxkaXYgY2xhc3M9ImZjLWhlYWRlciBsYWJlbC1tZCIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRTZWNvbmRhcnkpIj5LYW5iYW48L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJmb290ZXIta2FuYmFuIj48L2Rpdj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImZvb3Rlci1jYXJkIj4KICAgICAgICA8ZGl2IGNsYXNzPSJmYy1oZWFkZXIgbGFiZWwtbWQiIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KSI+U3lzdGVtPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZm9vdGVyLXN5c3RlbSI+PC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+Cgo8L2Rpdj4KCjwhLS0gVG9hc3QgY29udGFpbmVyIC0tPgo8ZGl2IGNsYXNzPSJ0b2FzdC1jb250YWluZXIiIGlkPSJ0b2FzdHMiPjwvZGl2PgoKPHNjcmlwdD4KLy8gPT09PT0gQ09ORklHID09PT09CmNvbnN0IEFQSV9CQVNFID0gJ2h0dHA6Ly8xMjcuMC4wLjE6OTExOCc7CmNvbnN0IEFQSV9WRVJTSU9OID0gJzEuOS4wJzsKY29uc3QgUkVGUkVTSF9PUFRJT05TID0gezkwMDonMTUgbWluJywxODAwOiczMCBtaW4nLDM2MDA6JzYwIG1pbid9OwpsZXQgUkVGUkVTSF9JTlRFUlZBTCA9IDkwMDsgLy8gZG9teXNsbmllIDE1IG1pbgpjb25zdCBMQVlPVVRfS0VZID0gJ2hlcm1lcy1tb25pdG9yLWxheW91dCc7CgpsZXQgdXNhZ2VDaGFydCA9IG51bGw7CmxldCBtb2RlbHNDaGFydCA9IG51bGw7CmxldCByZWZyZXNoVGltZXIgPSBudWxsOwpsZXQgbGFzdFJlZnJlc2hBdCA9IDA7ICAgICAgICAgICAvLyB0aW1lc3RhbXAgKG1zKSB3aGVuIGRhdGEgd2FzIGxhc3QgZmV0Y2hlZApsZXQgcHJvZ3Jlc3NUaW1lciA9IG51bGw7ICAgICAgICAvLyBjb3VudGRvd24gcHJvZ3Jlc3MgYmFyIHRpbWVyCi8vIEZpbHRyIHByb2ZpbHU6IG51bGwgPSB3c3p5c3RraWUgcHJvZmlsZSwgaW5hY3plaiBuYXp3YSBwcm9maWx1CmxldCBhY3RpdmVQcm9maWxlID0gbnVsbDsKCi8vID09PT09IEhFTFBFUlMgPT09PT0KZnVuY3Rpb24gZm9ybWF0TnVtYmVyKG4pIHsKICBpZiAobiA9PSBudWxsKSByZXR1cm4gJy0tJzsKICBpZiAobiA+PSAxXzAwMF8wMDApIHJldHVybiAobiAvIDFfMDAwXzAwMCkudG9GaXhlZCgxKSArICdNJzsKICBpZiAobiA+PSAxXzAwMCkgcmV0dXJuIChuIC8gMV8wMDApLnRvRml4ZWQoMSkgKyAnayc7CiAgcmV0dXJuIG4udG9Mb2NhbGVTdHJpbmcoJ3BsLVBMJyk7Cn0KCmZ1bmN0aW9uIGZvcm1hdENvc3QodXNkKSB7CiAgaWYgKHVzZCA9PSBudWxsKSByZXR1cm4gJy0tJzsKICByZXR1cm4gJyQnICsgdXNkLnRvRml4ZWQoMik7Cn0KCmZ1bmN0aW9uIGZvcm1hdER1cmF0aW9uKHNlY29uZHMpIHsKICBpZiAoc2Vjb25kcyA9PSBudWxsKSByZXR1cm4gJy0tJzsKICBpZiAoc2Vjb25kcyA8IDYwKSByZXR1cm4gTWF0aC5yb3VuZChzZWNvbmRzKSArICdzJzsKICBpZiAoc2Vjb25kcyA8IDM2MDApIHJldHVybiBNYXRoLnJvdW5kKHNlY29uZHMgLyA2MCkgKyAnbSc7CiAgcmV0dXJuIChzZWNvbmRzIC8gMzYwMCkudG9GaXhlZCgxKSArICdoJzsKfQoKZnVuY3Rpb24gdGltZUFnbyhpc29TdHIpIHsKICBpZiAoIWlzb1N0cikgcmV0dXJuICctLSc7CiAgY29uc3QgbXMgPSBEYXRlLm5vdygpIC0gbmV3IERhdGUoaXNvU3RyKS5nZXRUaW1lKCk7CiAgcmV0dXJuIGZvcm1hdER1cmF0aW9uKG1zIC8gMTAwMCkgKyAnIHRlbXUnOwp9CgpmdW5jdGlvbiBlc2NhcGVIdG1sKHMpIHsKICBpZiAoIXMpIHJldHVybiAnJzsKICBjb25zdCBkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgZC50ZXh0Q29udGVudCA9IHM7CiAgcmV0dXJuIGQuaW5uZXJIVE1MOwp9CgovLyA9PT09PSBDTE9DSyA9PT09PQpmdW5jdGlvbiB1cGRhdGVDbG9jaygpIHsKICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpOwogIGNvbnN0IGNldCA9IG5ldyBEYXRlKG5vdy50b0xvY2FsZVN0cmluZygnZW4tVVMnLCB7dGltZVpvbmU6J0V1cm9wZS9XYXJzYXcnfSkpOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjbG9jaycpLnRleHRDb250ZW50ID0KICAgIGNldC50b0xvY2FsZVRpbWVTdHJpbmcoJ3BsLVBMJywge2hvdXI6JzItZGlnaXQnLG1pbnV0ZTonMi1kaWdpdCd9KSArICcgQ0VUJzsKfQpzZXRJbnRlcnZhbCh1cGRhdGVDbG9jaywgMTAwMCk7CnVwZGF0ZUNsb2NrKCk7CgovLyA9PT09PSBUT0FTVFMgPT09PT0KZnVuY3Rpb24gc2hvd1RvYXN0KG1zZywgbGV2ZWwpIHsKICBjb25zdCBjb250YWluZXIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndG9hc3RzJyk7CiAgY29uc3QgZWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICBlbC5jbGFzc05hbWUgPSAndG9hc3QgJyArIChsZXZlbHx8JycpOwogIGVsLnRleHRDb250ZW50ID0gbXNnOwogIGNvbnRhaW5lci5hcHBlbmRDaGlsZChlbCk7CiAgc2V0VGltZW91dCgoKSA9PiBlbC5yZW1vdmUoKSwgNTAwMCk7Cn0KCi8vID09PT09IExBWU9VVCBTV0lUQ0hFUiA9PT09PQpmdW5jdGlvbiBzd2l0Y2hMYXlvdXQobGF5b3V0KSB7CiAgZG9jdW1lbnQuYm9keS5zZXRBdHRyaWJ1dGUoJ2RhdGEtbGF5b3V0JywgbGF5b3V0KTsKICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShMQVlPVVRfS0VZLCBsYXlvdXQpOwoKICAvLyBVcGRhdGUgYnV0dG9ucwogIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJyNsYXlvdXQtc3dpdGNoZXIgYnV0dG9uJykuZm9yRWFjaChidG4gPT4gewogICAgYnRuLmNsYXNzTGlzdC50b2dnbGUoJ2FjdGl2ZScsIGJ0bi5kYXRhc2V0LmxheW91dCA9PT0gbGF5b3V0KTsKICB9KTsKCiAgLy8gUGlwLUJveTogZGlzcG9zZSBFQ2hhcnRzLCBIZXJtZXM6IHJlaW5pdGlhbGl6ZQogIGlmIChsYXlvdXQgPT09ICdwaXBib3knKSB7CiAgICBpZiAodXNhZ2VDaGFydCkgeyB1c2FnZUNoYXJ0LmRpc3Bvc2UoKTsgdXNhZ2VDaGFydCA9IG51bGw7IH0KICAgIGlmIChtb2RlbHNDaGFydCkgeyBtb2RlbHNDaGFydC5kaXNwb3NlKCk7IG1vZGVsc0NoYXJ0ID0gbnVsbDsgfQogIH0KCiAgLy8gUmVmcmVzaCBhbGwgZGF0YSAocmUtcmVuZGVycyBldmVyeXRoaW5nIGZvciBuZXcgbGF5b3V0KQogIHJlZnJlc2hBbGwoKTsKfQoKZnVuY3Rpb24gaW5pdExheW91dFN3aXRjaGVyKCkgewogIGNvbnN0IHNhdmVkID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oTEFZT1VUX0tFWSkgfHwgJ2RlZmF1bHQnOwogIGNvbnN0IGJ1dHRvbnMgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcjbGF5b3V0LXN3aXRjaGVyIGJ1dHRvbicpOwogIAogIC8vIEFwcGx5IHNhdmVkIGxheW91dAogIHN3aXRjaExheW91dChzYXZlZCk7CiAgCiAgLy8gQ2xpY2sgaGFuZGxlcnMKICBidXR0b25zLmZvckVhY2goYnRuID0+IHsKICAgIGJ0bi5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHN3aXRjaExheW91dChidG4uZGF0YXNldC5sYXlvdXQpKTsKICB9KTsKfQoKLy8gPT09PT0gRkVUQ0ggV0lUSCBFUlJPUiBIQU5ETElORyA9PT09PQphc3luYyBmdW5jdGlvbiBhcGlGZXRjaChwYXRoKSB7CiAgdHJ5IHsKICAgIGNvbnN0IHNlcCA9IHBhdGguaW5jbHVkZXMoJz8nKSA/ICcmJyA6ICc/JzsKICAgIGNvbnN0IHVybCA9IEFQSV9CQVNFICsgcGF0aCArIHNlcCArICd2PScgKyBBUElfVkVSU0lPTjsKICAgIGNvbnN0IHJlc3AgPSBhd2FpdCBmZXRjaCh1cmwpOwogICAgaWYgKCFyZXNwLm9rKSB0aHJvdyBuZXcgRXJyb3IoJ0hUVFAgJyArIHJlc3Auc3RhdHVzKTsKICAgIHJldHVybiBhd2FpdCByZXNwLmpzb24oKTsKICB9IGNhdGNoKGUpIHsKICAgIHJldHVybiB7X2Vycm9yOiBlLm1lc3NhZ2V9OwogIH0KfQoKLy8gPT09PT0gUkVGUkVTSCBQUk9HUkVTUyBCQVIgPT09PT0KLy8gUGFzZWsgb2RtaWVyemEgb2RzZXRlayBjemFzdSwga3TDs3J5IG1pbsSFxYIgb2Qgb3N0YXRuaWVnbyBvZMWbd2llxbxlbmlhCi8vIHd6Z2zEmWRlbSBiaWXFvMSFY2VnbyBpbnRlcndhxYJ1IFJFRlJFU0hfSU5URVJWQUwuIFJlc2V0dWplIHNpxJkgcG8ga2HFvGR5bQovLyBvZMWbd2llxbxlbml1IChhdXRvbWF0eWN6bnltLCByxJljem55bSBsdWIgem1pYW5pZSBpbnRlcndhxYJ1KS4KZnVuY3Rpb24gdXBkYXRlUHJvZ3Jlc3NCYXIoKSB7CiAgY29uc3QgYmFyID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3JlZnJlc2gtYmFyLWZpbGwnKTsKICBjb25zdCBwY3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyZWZyZXNoLWJhci1wY3QnKTsKICBjb25zdCBuZXh0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncmVmcmVzaC1iYXItbmV4dCcpOwogIGlmICghYmFyKSByZXR1cm47CiAgaWYgKGxhc3RSZWZyZXNoQXQgPT09IDApIHsKICAgIGJhci5zdHlsZS53aWR0aCA9ICcwJSc7IGJhci5jbGFzc05hbWUgPSAnZmlsbCc7CiAgICBpZiAocGN0RWwpIHBjdEVsLnRleHRDb250ZW50ID0gJzAlJzsKICAgIGlmIChuZXh0RWwpIG5leHRFbC50ZXh0Q29udGVudCA9ICctLSc7CiAgICByZXR1cm47CiAgfQogIGNvbnN0IHRvdGFsID0gUkVGUkVTSF9JTlRFUlZBTDsKICBjb25zdCBlbGFwc2VkID0gRGF0ZS5ub3coKSAtIGxhc3RSZWZyZXNoQXQ7CiAgY29uc3QgcmVtYWluaW5nID0gTWF0aC5tYXgoMCwgTWF0aC5yb3VuZCgodG90YWwgKiAxMDAwIC0gZWxhcHNlZCkgLyAxMDAwKSk7CiAgY29uc3QgcGN0ID0gTWF0aC5taW4oMTAwLCBNYXRoLm1heCgwLCBNYXRoLnJvdW5kKGVsYXBzZWQgLyB0b3RhbCAvIDEwKSkpOwogIGJhci5zdHlsZS53aWR0aCA9IHBjdCArICclJzsKICBiYXIuY2xhc3NOYW1lID0gJ2ZpbGwnICsgKHBjdCA+PSAxMDAgPyAnIGNyaXQnIDogKHBjdCA+PSA4NSA/ICcgd2FybicgOiAnJykpOwogIGlmIChwY3RFbCkgcGN0RWwudGV4dENvbnRlbnQgPSBwY3QgKyAnJSc7CiAgLy8gUG9rYXp1aiBjemFzIGRvIG5hc3RlcG5lZ28gb2Rzd2llemVuaWEKICBpZiAobmV4dEVsKSB7CiAgICBpZiAocmVtYWluaW5nIDw9IDApIHsKICAgICAgbmV4dEVsLnRleHRDb250ZW50ID0gJ29kc3dpZXphbmllLi4uJzsKICAgICAgbmV4dEVsLnN0eWxlLmNvbG9yID0gJ3ZhcigtLXdhcm5pbmcpJzsKICAgIH0gZWxzZSB7CiAgICAgIGNvbnN0IHJtID0gTWF0aC5mbG9vcihyZW1haW5pbmcgLyA2MCk7CiAgICAgIGNvbnN0IHJzID0gcmVtYWluaW5nICUgNjA7CiAgICAgIG5leHRFbC50ZXh0Q29udGVudCA9IHJtICsgJzonICsgU3RyaW5nKHJzKS5wYWRTdGFydCgyLCAnMCcpOwogICAgICBuZXh0RWwuc3R5bGUuY29sb3IgPSAnJzsKICAgIH0KICB9CiAgLy8gcG8gcHJ6ZWtyb2N6ZW5pdSAxMDAlIChzcG96bmlvbmUgb2Rzd2llemVuaWUpIOKAlCB3c2theiAidGVyYXogb2Rzd2llemFtIgogIGlmIChwY3QgPj0gMTAwICYmIHBjdEVsKSBwY3RFbC50ZXh0Q29udGVudCA9ICcxMDAlJzsKfQoKZnVuY3Rpb24gc3RhcnRQcm9ncmVzc1RpbWVyKCkgewogIGlmIChwcm9ncmVzc1RpbWVyKSBjbGVhckludGVydmFsKHByb2dyZXNzVGltZXIpOwogIHVwZGF0ZVByb2dyZXNzQmFyKCk7CiAgcHJvZ3Jlc3NUaW1lciA9IHNldEludGVydmFsKHVwZGF0ZVByb2dyZXNzQmFyLCAyNTApOwp9CgpmdW5jdGlvbiBtYXJrRGF0YVRzKGlzb1N0cikgewogIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3JlZnJlc2gtYmFyLWRhdGEnKTsKICBpZiAoIWVsKSByZXR1cm47CiAgaWYgKGlzb1N0cikgewogICAgY29uc3QgZCA9IG5ldyBEYXRlKGlzb1N0cik7CiAgICBpZiAoIWlzTmFOKGQuZ2V0VGltZSgpKSkgewogICAgICBlbC50ZXh0Q29udGVudCA9IGQudG9Mb2NhbGVEYXRlU3RyaW5nKCdwbC1QTCcsIHtkYXk6JzItZGlnaXQnLG1vbnRoOicyLWRpZ2l0Jyx5ZWFyOidudW1lcmljJ30pICsKICAgICAgICAnICcgKyBkLnRvTG9jYWxlVGltZVN0cmluZygncGwtUEwnLCB7aG91cjonMi1kaWdpdCcsbWludXRlOicyLWRpZ2l0JyxzZWNvbmQ6JzItZGlnaXQnfSk7CiAgICAgIHJldHVybjsKICAgIH0KICB9CiAgZWwudGV4dENvbnRlbnQgPSAnLS0nOwp9CgovLyA9PT09PSBSRU5ERVI6IFNUQVRVUyBTVFJJUCA9PT09PQpmdW5jdGlvbiByZW5kZXJTdGF0dXNTdHJpcChzdGF0dXNEYXRhKSB7CiAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3RhdHVzLXN0cmlwLWlubmVyJyk7CiAgaWYgKCFzdGF0dXNEYXRhIHx8IHN0YXR1c0RhdGEuX2Vycm9yIHx8ICFzdGF0dXNEYXRhLnByb2ZpbGVzKSB7CiAgICBlbC5pbm5lckhUTUwgPSAnPGRpdiBjbGFzcz0ic3RhdGUtbXNnIj48ZGl2IGNsYXNzPSJib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSI+QnJhayBkYW55Y2ggbyBzdGF0dXNpZTwvZGl2PjwvZGl2Pic7CiAgICByZXR1cm47CiAgfQoKICAvLyBVcGRhdGUgdG9wYmFyIGRvdAogIGNvbnN0IGFsbFJ1bm5pbmcgPSBzdGF0dXNEYXRhLnN1bW1hcnk/LnByb2ZpbGVzX3RvdGFsID09PSBzdGF0dXNEYXRhLnN1bW1hcnk/LnByb2ZpbGVzX3J1bm5pbmc7CiAgY29uc3QgZG90ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RvcGJhci1kb3QnKTsKICBkb3Quc3R5bGUuYmFja2dyb3VuZCA9IGFsbFJ1bm5pbmcgPyAndmFyKC0tc3VjY2VzcyknIDogJ3ZhcigtLXdhcm5pbmcpJzsKCiAgZWwuaW5uZXJIVE1MID0gc3RhdHVzRGF0YS5wcm9maWxlcy5tYXAocCA9PiB7CiAgICBjb25zdCBnd1J1bm5pbmcgPSBwLmdhdGV3YXk/LnJ1bm5pbmc7CiAgICBjb25zdCBzdGF0ZSA9IGd3UnVubmluZyA/ICdvbmxpbmUnIDogJ29mZmxpbmUnOwogICAgY29uc3QgbmFtZSA9IHAucHJvZmlsZTsKICAgIGNvbnN0IGFjdGl2ZUNscyA9IChhY3RpdmVQcm9maWxlID09PSBuYW1lKSA/ICcgYWN0aXZlJyA6ICcnOwogICAgCiAgICAvLyBDb3VudCBjb25uZWN0ZWQgcGxhdGZvcm1zCiAgICBjb25zdCBwbGF0Zm9ybXMgPSAocC5nYXRld2F5ICYmIHAuZ2F0ZXdheS5wbGF0Zm9ybXMpID8gcC5nYXRld2F5LnBsYXRmb3JtcyA6IFtdOwogICAgY29uc3QgY29ubmVjdGVkQ291bnQgPSBwbGF0Zm9ybXMuZmlsdGVyKHBsID0+IHBsLnN0YXRlID09PSAnY29ubmVjdGVkJykubGVuZ3RoOwogICAgY29uc3QgdG90YWxQbGF0cyA9IHBsYXRmb3Jtcy5sZW5ndGg7CiAgICBjb25zdCBwbGF0Zm9ybUluZm8gPSB0b3RhbFBsYXRzID4gMCA/IGNvbm5lY3RlZENvdW50ICsgJy8nICsgdG90YWxQbGF0cyArICcgcGxhdGYuJyA6ICcnOwogICAgCiAgICByZXR1cm4gJzxkaXYgY2xhc3M9InN0YXR1cy1jaGlwJyArIGFjdGl2ZUNscyArICciIG9uY2xpY2s9InNldFByb2ZpbGVGaWx0ZXIoXCcnICsgZW5jb2RlVVJJQ29tcG9uZW50KG5hbWUpICsgJ1wnKSIgdGl0bGU9IlBva2HFvCBkYW5lIHR5bGtvIGRsYSB0ZWdvIHByb2ZpbHUiPicgKwogICAgICAnPGRpdiBjbGFzcz0iZG90ICcgKyBzdGF0ZSArICciJyArIChnd1J1bm5pbmcgPyAnIHN0eWxlPSJhbmltYXRpb246cHVsc2UgMnMgaW5maW5pdGUiJyA6ICcnKSArICc+PC9kaXY+JyArCiAgICAgICc8c3BhbiBjbGFzcz0ibmFtZSI+JyArIGVzY2FwZUh0bWwobmFtZSkgKyAnPC9zcGFuPicgKwogICAgICAocC5nYXRld2F5Py5hY3RpdmVfYWdlbnRzID4gMCA/ICc8c3BhbiBjbGFzcz0ibW9uby1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXByaW1hcnkpIj4nICsgcC5nYXRld2F5LmFjdGl2ZV9hZ2VudHMgKyAnIGFnLjwvc3Bhbj4nIDogJycpICsKICAgICAgKHBsYXRmb3JtSW5mbyA/ICc8c3BhbiBjbGFzcz0icGxhdGZvcm0iPicgKyBwbGF0Zm9ybUluZm8gKyAnPC9zcGFuPicgOiAnJykgKwogICAgJzwvZGl2Pic7CiAgfSkuam9pbignJykgfHwgJzxzcGFuIGNsYXNzPSJib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKTtwYWRkaW5nOjAgdmFyKC0tc3BhY2Utc20pIj5CcmFrIHByb2ZpbGk8L3NwYW4+JzsKfQoKLy8gPT09PT0gUkVOREVSOiBQUk9GSUxFIENBUkRTID09PT09CmZ1bmN0aW9uIHJlbmRlclByb2ZpbGVDYXJkcyhzdGF0dXNEYXRhLCBzZXNzaW9uc0RhdGEsIHVzYWdlRGF0YSkgewogIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3Byb2ZpbGUtY2FyZHMtZ3JpZCcpOwogIGlmICghc3RhdHVzRGF0YSB8fCBzdGF0dXNEYXRhLl9lcnJvciB8fCAhc3RhdHVzRGF0YS5wcm9maWxlcykgewogICAgZWwuaW5uZXJIVE1MID0gJyc7CiAgICByZXR1cm47CiAgfQoKICB2YXIgaXNQaXBCb3kgPSBkb2N1bWVudC5ib2R5LmdldEF0dHJpYnV0ZSgnZGF0YS1sYXlvdXQnKSA9PT0gJ3BpcGJveSc7CgogIC8vIEJ1aWxkIHBlci1wcm9maWxlIGxvb2t1cCBtYXBzIGZyb20gc2Vzc2lvbnMvdXNhZ2UgZGF0YQogIHZhciBwcm9maWxlU2Vzc2lvbnMgPSB7fTsKICB2YXIgcHJvZmlsZVVzYWdlID0ge307CgogIC8vIE1hcCBzZXNzaW9ucyB0byBwcm9maWxlcwogIChzdGF0dXNEYXRhLnByb2ZpbGVzIHx8IFtdKS5mb3JFYWNoKGZ1bmN0aW9uKHApIHsKICAgIHByb2ZpbGVTZXNzaW9uc1twLnByb2ZpbGVdID0gMDsKICAgIHByb2ZpbGVVc2FnZVtwLnByb2ZpbGVdID0ge3Rva2VuczogMCwgY29zdDogMH07CiAgfSk7CgogIGlmIChzZXNzaW9uc0RhdGEgJiYgc2Vzc2lvbnNEYXRhLnNlc3Npb25zKSB7CiAgICBzZXNzaW9uc0RhdGEuc2Vzc2lvbnMuZm9yRWFjaChmdW5jdGlvbihzKSB7CiAgICAgIGlmIChzLl9wcm9maWxlICYmIHByb2ZpbGVTZXNzaW9ucy5oYXNPd25Qcm9wZXJ0eShzLl9wcm9maWxlKSkgewogICAgICAgIHByb2ZpbGVTZXNzaW9uc1tzLl9wcm9maWxlXSsrOwogICAgICB9CiAgICB9KTsKICB9CgogIGlmICh1c2FnZURhdGEgJiYgdXNhZ2VEYXRhLl9wcm9maWxlVXNhZ2UpIHsKICAgIE9iamVjdC5rZXlzKHVzYWdlRGF0YS5fcHJvZmlsZVVzYWdlKS5mb3JFYWNoKGZ1bmN0aW9uKHApIHsKICAgICAgcHJvZmlsZVVzYWdlW3BdID0gdXNhZ2VEYXRhLl9wcm9maWxlVXNhZ2VbcF07CiAgICB9KTsKICB9CgogIGVsLmlubmVySFRNTCA9IChzdGF0dXNEYXRhLnByb2ZpbGVzIHx8IFtdKS5tYXAoZnVuY3Rpb24ocCkgewogICAgdmFyIGd3ID0gcC5nYXRld2F5IHx8IHt9OwogICAgdmFyIHJ1bm5pbmcgPSBndy5ydW5uaW5nOwogICAgdmFyIHN0YXRlQ2xzID0gcnVubmluZyA/ICdvbmxpbmUnIDogKGd3LnN0YXRlID09PSAnc3RhbGUnID8gJ3N0YWxlJyA6ICdvZmZsaW5lJyk7CiAgICB2YXIgcGxhdEluZm8gPSAoZ3cucGxhdGZvcm1zICYmIEFycmF5LmlzQXJyYXkoZ3cucGxhdGZvcm1zKSkgPyBndy5wbGF0Zm9ybXMgOiBbXTsKICAgIHZhciBjb25uZWN0ZWRQbGF0cyA9IHBsYXRJbmZvLmZpbHRlcihmdW5jdGlvbihrKSB7IHJldHVybiBrLnN0YXRlID09PSAnY29ubmVjdGVkJzsgfSk7CiAgICB2YXIgYWdlbnRzID0gZ3cuYWN0aXZlX2FnZW50cyB8fCAwOwoKICAgIHZhciBwcmVmaXhIdG1sID0gJyc7CiAgICB2YXIgY2FyZEFjdGl2ZUNscyA9IChhY3RpdmVQcm9maWxlID09PSBwLnByb2ZpbGUpID8gJyBhY3RpdmUnIDogJyc7CiAgICBpZiAoaXNQaXBCb3kpIHsKICAgICAgdmFyIHByZWZpeENvbG9yID0gcnVubmluZyA/ICd2YXIoLS1zdWNjZXNzKScgOiAoc3RhdGVDbHMgPT09ICdzdGFsZScgPyAndmFyKC0td2FybmluZyknIDogJ3ZhcigtLWNyaXRpY2FsKScpOwogICAgICB2YXIgcHJlZml4ID0gcnVubmluZyA/ICdbT05MXScgOiAoc3RhdGVDbHMgPT09ICdzdGFsZScgPyAnW1NUTF0nIDogJ1tPRkZdJyk7CiAgICAgIHByZWZpeEh0bWwgPSAnPHNwYW4gY2xhc3M9InBjLXN0YXR1cy1wcmVmaXgiIHN0eWxlPSJjb2xvcjonICsgcHJlZml4Q29sb3IgKyAnIj4nICsgcHJlZml4ICsgJzwvc3Bhbj4nOwogICAgfQoKICAgIHZhciBzZXNoQ291bnQgPSBwcm9maWxlU2Vzc2lvbnNbcC5wcm9maWxlXSB8fCAwOwogICAgdmFyIHRva0NvdW50ID0gcHJvZmlsZVVzYWdlW3AucHJvZmlsZV0gPyBwcm9maWxlVXNhZ2VbcC5wcm9maWxlXS50b2tlbnMgOiAwOwogICAgdmFyIGNvc3RWYWwgPSBwcm9maWxlVXNhZ2VbcC5wcm9maWxlXSA/IHByb2ZpbGVVc2FnZVtwLnByb2ZpbGVdLmNvc3QgOiAwOwoKICAgIHJldHVybiAnPGRpdiBjbGFzcz0icHJvZmlsZS1jYXJkJyArIGNhcmRBY3RpdmVDbHMgKyAnIiBvbmNsaWNrPSJzZXRQcm9maWxlRmlsdGVyKFwnJyArIGVuY29kZVVSSUNvbXBvbmVudChwLnByb2ZpbGUpICsgJ1wnKSIgdGl0bGU9IlBva2HFvCBkYW5lIHR5bGtvIGRsYSB0ZWdvIHByb2ZpbHUiPicgKwogICAgICAnPGRpdiBjbGFzcz0icGMtaGVhZGVyIj4nICsKICAgICAgICAoaXNQaXBCb3kgPyBwcmVmaXhIdG1sIDogJzxkaXYgY2xhc3M9InBjLWRvdCAnICsgc3RhdGVDbHMgKyAnIj48L2Rpdj4nKSArCiAgICAgICAgJzxzcGFuIGNsYXNzPSJwYy1uYW1lIj4nICsgZXNjYXBlSHRtbChwLnByb2ZpbGUpICsgJzwvc3Bhbj4nICsKICAgICAgJzwvZGl2PicgKwogICAgICAnPGRpdiBjbGFzcz0icGMtbWV0YSI+JyArCiAgICAgICAgJzxzcGFuIGNsYXNzPSJwYy1tZXRhLWl0ZW0iPkFHRU5UUzonICsgYWdlbnRzICsgJzwvc3Bhbj4nICsKICAgICAgICAnPHNwYW4gY2xhc3M9InBjLW1ldGEtaXRlbSI+U0VTU0lPTlM6JyArIHNlc2hDb3VudCArICc8L3NwYW4+JyArCiAgICAgICAgJzxzcGFuIGNsYXNzPSJwYy1tZXRhLWl0ZW0iPlRPS0VOUzonICsgZm9ybWF0TnVtYmVyKHRva0NvdW50KSArICc8L3NwYW4+JyArCiAgICAgICAgJzxzcGFuIGNsYXNzPSJwYy1tZXRhLWl0ZW0iPkNPU1Q6JyArIGZvcm1hdENvc3QoY29zdFZhbCkgKyAnPC9zcGFuPicgKwogICAgICAnPC9kaXY+JyArCiAgICAgIChjb25uZWN0ZWRQbGF0cy5sZW5ndGggPiAwID8KICAgICAgICAnPGRpdiBjbGFzcz0icGMtcGxhdGZvcm1zIj4nICsKICAgICAgICAgIHBsYXRJbmZvLm1hcChmdW5jdGlvbihwbCkgewogICAgICAgICAgICB2YXIgY2xzID0gcGwuc3RhdGUgPT09ICdjb25uZWN0ZWQnID8gJ2Nvbm5lY3RlZCcgOiAnJzsKICAgICAgICAgICAgcmV0dXJuICc8c3BhbiBjbGFzcz0icGMtcGxhdC1jaGlwICcgKyBjbHMgKyAnIj4nICsgZXNjYXBlSHRtbCgocGwubmFtZXx8JycpLnN1YnN0cmluZygwLDYpKSArICc8L3NwYW4+JzsKICAgICAgICAgIH0pLmpvaW4oJycpICsKICAgICAgICAnPC9kaXY+JyA6ICcnKSArCiAgICAgICc8ZGl2IGNsYXNzPSJwYy1mb290ZXIiPicgKwogICAgICAgIChndy51cGRhdGVkX2F0ID8gJ1VQRDonICsgdGltZUFnbyhndy51cGRhdGVkX2F0KSA6ICcnKSArCiAgICAgICAgKGd3LnByb2Nlc3NfY21kbGluZSA/ICcgfCAnICsgKGd3LnByb2Nlc3NfY21kbGluZSB8fCAnJykuc3BsaXQoJy8nKS5wb3AoKS5zdWJzdHJpbmcoMCwyMCkgOiAnJykgKwogICAgICAnPC9kaXY+JyArCiAgICAnPC9kaXY+JzsKICB9KS5qb2luKCcnKTsKfQoKLy8gPT09PT0gUFJPRklMRSBGSUxURVIgPT09PT0KZnVuY3Rpb24gc2V0UHJvZmlsZUZpbHRlcihlbmNvZGVkTmFtZSkgewogIGNvbnN0IG5hbWUgPSBhY3RpdmVQcm9maWxlICYmIGFjdGl2ZVByb2ZpbGUgPT09IGRlY29kZVVSSUNvbXBvbmVudChlbmNvZGVkTmFtZSkgPyBudWxsIDogZGVjb2RlVVJJQ29tcG9uZW50KGVuY29kZWROYW1lKTsKICBhY3RpdmVQcm9maWxlID0gbmFtZTsKICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdhbGwtcHJvZmlsZXMtYnRuJyk7CiAgaWYgKGVsKSBlbC5zdHlsZS5kaXNwbGF5ID0gYWN0aXZlUHJvZmlsZSA/ICdpbmxpbmUtYmxvY2snIDogJ25vbmUnOwogIHJlZnJlc2hBbGwoKTsKfQoKLy8gPT09PT0gUkVOREVSOiBLUEkgR1JJRCA9PT09PQpmdW5jdGlvbiByZW5kZXJLcGlHcmlkKHN0YXR1c0RhdGEsIHVzYWdlRGF0YSwgc2Vzc2lvbnNEYXRhLCBrYW5iYW5EYXRhLCBhbGVydHNEYXRhLCBrZXlzRGF0YSkgewogIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2twaS1ncmlkJyk7CiAgaWYgKHN0YXR1c0RhdGE/Ll9lcnJvciAmJiB1c2FnZURhdGE/Ll9lcnJvcikgewogICAgZWwuaW5uZXJIVE1MID0gJzxkaXYgY2xhc3M9InN0YXRlLW1zZyI+PGRpdiBjbGFzcz0iaWNvbiI+JiN4MjZBMDsmI3hGRTBGOzwvZGl2PjxkaXYgY2xhc3M9InRpdGxlIGhlYWRpbmctbWQiPk5pZSBtbyYjeDE3QztuYSB6YSYjeDE0MjthZG93YSYjeDEwNzsgbWV0cnlrPC9kaXY+PGRpdiBjbGFzcz0iZGVzYyBib2R5LXNtIj5CYWNrZW5kIG5pZSBvZHBvd2lhZGE8L2Rpdj48L2Rpdj4nOwogICAgcmV0dXJuOwogIH0KCiAgY29uc3Qgc3VtbWFyeSA9IHN0YXR1c0RhdGE/LnN1bW1hcnkgfHwge307CiAgY29uc3Qgc2Vzc2lvbnMgPSBzZXNzaW9uc0RhdGE/LnNlc3Npb25zIHx8IFtdOwogIGNvbnN0IHVzYWdlID0gdXNhZ2VEYXRhPy5kYWlseSB8fCBbXTsKICBjb25zdCB0b2RheVVzYWdlID0gdXNhZ2UubGVuZ3RoID4gMCA/IHVzYWdlW3VzYWdlLmxlbmd0aCAtIDFdIDogbnVsbDsKCiAgLy8gQWN0aXZlIHByb2ZpbGUgZmlsdGVyOiBpZiBhIHByb2ZpbGUgaXMgc2VsZWN0ZWQsIHNob3cgb25seSBpdHMgZGF0YQogIGNvbnN0IHByb2ZpbGVMaXN0ID0gKHN0YXR1c0RhdGE/LnByb2ZpbGVzIHx8IFtdKS5maWx0ZXIocCA9PiAhYWN0aXZlUHJvZmlsZSB8fCBwLnByb2ZpbGUgPT09IGFjdGl2ZVByb2ZpbGUpOwoKICAvLyBUb2RheTogdXNhZ2VEYXRhLmRhaWx5IGlzIGFscmVhZHkgYWdncmVnYXRlZCBhY3Jvc3MgdGhlIHNjb3BlIChhbGwgcHJvZmlsZXMsIG9yIHRoZSBzaW5nbGUKICAvLyBzZWxlY3RlZCBwcm9maWxlIHdoZW4gZmlsdGVyZWQg4oCUIHJlZnJlc2hBbGwgb25seSBmZXRjaGVzIHRoYXQgcHJvZmlsZSkuIExhc3QgZW50cnkgPSB0b2RheS4KICBjb25zdCB0b2RheURhdGEgPSB0b2RheVVzYWdlIHx8IHt0b2tlbnM6e2lucHV0OjAsb3V0cHV0OjB9LCBjb3N0Ontlc3RpbWF0ZWRfdXNkOjB9LCBzZXNzaW9uX2NvdW50OjAsIGRheTogbnVsbH07CiAgY29uc3QgZGF5TGFiZWwgPSB0b2RheURhdGEuZGF5ID8gdG9kYXlEYXRhLmRheSA6ICctLSc7CgogIC8vIEFjdGl2ZSBhZ2VudHMgYWNyb3NzIChmaWx0ZXJlZCBvciBhbGwpIHByb2ZpbGVzCiAgbGV0IGFjdGl2ZUFnZW50cyA9IDA7CiAgcHJvZmlsZUxpc3QuZm9yRWFjaChwID0+IHsgYWN0aXZlQWdlbnRzICs9IHAuZ2F0ZXdheT8uYWN0aXZlX2FnZW50cyB8fCAwOyB9KTsKCiAgLy8gQWdncmVnYXRlZCB0b3RhbHMgb3ZlciB0aGUgZGFpbHkgd2luZG93IChhbGwgZGF5cykgZm9yIHRoZSAicmF6ZW0iIHRpbGVzCiAgbGV0IHRvdGFsVG9rZW5zSW4gPSAwLCB0b3RhbFRva2Vuc091dCA9IDAsIHRvdGFsQ29zdEVzdCA9IDA7CiAgKHVzYWdlIHx8IFtdKS5mb3JFYWNoKGRheSA9PiB7CiAgICB0b3RhbFRva2Vuc0luICs9IGRheS50b2tlbnM/LmlucHV0IHx8IDA7CiAgICB0b3RhbFRva2Vuc091dCArPSBkYXkudG9rZW5zPy5vdXRwdXQgfHwgMDsKICAgIHRvdGFsQ29zdEVzdCArPSBkYXkuY29zdD8uZXN0aW1hdGVkX3VzZCB8fCAwOwogIH0pOwoKICAvLyBTZXNzaW9uIGNvdW50IGZvciB0aGUgZGF0YSBzY29wZSAoYWxsIHByb2ZpbGVzIHZzIHNpbmdsZSBwcm9maWxlKQogIGNvbnN0IHNlc3Npb25zU2NvcGUgPSBhY3RpdmVQcm9maWxlCiAgICA/ICh0b2RheVVzYWdlID8gdG9kYXlVc2FnZS5zZXNzaW9uX2NvdW50IHx8IDAgOiAwKQogICAgOiAoc2Vzc2lvbnMubGVuZ3RoKTsKCiAgY29uc3QgdGlsZXMgPSBbCiAgICB7CiAgICAgIGxhYmVsOiAnUHJvZmlsZSBvbmxpbmUnLAogICAgICB2YWx1ZTogKHN1bW1hcnkucHJvZmlsZXNfcnVubmluZyB8fCAwKSArICcvJyArIChzdW1tYXJ5LnByb2ZpbGVzX3RvdGFsIHx8IDApLAogICAgICBzdWI6IHN1bW1hcnkucHJvZmlsZXNfcnVubmluZyA9PT0gc3VtbWFyeS5wcm9maWxlc190b3RhbCA/ICdXc3p5c3RraWUgT0snIDogJ05pZWt0b3JlIG9mZmxpbmUnLAogICAgICBjbHM6ICcnCiAgICB9LAogICAgewogICAgICBsYWJlbDogJ0FrdHl3bmUgUHJvZmlsZScsCiAgICAgIHZhbHVlOiBhY3RpdmVBZ2VudHMsCiAgICAgIHN1YjogYWN0aXZlUHJvZmlsZSA/ICgncHJvZmlsOiAnICsgYWN0aXZlUHJvZmlsZSkgOiAnc3VicHJvY2Vzc3kgZ2F0ZXdheScsCiAgICAgIGNsczogJycKICAgIH0sCiAgICB7CiAgICAgIGxhYmVsOiAnVG9rZW55IGxhY3puaWUnLAogICAgICB2YWx1ZTogZm9ybWF0TnVtYmVyKHRvdGFsVG9rZW5zSW4gKyB0b3RhbFRva2Vuc091dCksCiAgICAgIHN1YjogZm9ybWF0TnVtYmVyKHRvdGFsVG9rZW5zSW4pICsgJyBpbiAvICcgKyBmb3JtYXROdW1iZXIodG90YWxUb2tlbnNPdXQpICsgJyBvdXQnLAogICAgICBjbHM6ICcnCiAgICB9LAogICAgewogICAgICBsYWJlbDogJ1Rva2VueSAob3V0cHV0LHN1bWEpJywKICAgICAgdmFsdWU6IGZvcm1hdE51bWJlcih0b2RheVVzYWdlPy50b2tlbnM/Lm91dHB1dCB8fCAwKSwKICAgICAgc3ViOiAnc2VzamE6ICcgKyBzZXNzaW9uc1Njb3BlICsgJyDCtyBkemllxYQ6ICcgKyBkYXlMYWJlbCwKICAgICAgY2xzOiAnJwogICAgfSwKICAgIHsKICAgICAgbGFiZWw6ICdUb2tlbnkgKGlucHV0LHN1bWEpJywKICAgICAgdmFsdWU6IGZvcm1hdE51bWJlcih0b2RheVVzYWdlPy50b2tlbnM/LmlucHV0IHx8IDApLAogICAgICBzdWI6ICdzZXNqYTogJyArIHNlc3Npb25zU2NvcGUgKyAoYWN0aXZlUHJvZmlsZSA/ICcgwrcgJyArIGFjdGl2ZVByb2ZpbGUgOiAnJykgKyAnIMK3IGR6aWXFhDogJyArIGRheUxhYmVsLAogICAgICBjbHM6ICcnCiAgICB9LAogICAgewogICAgICBsYWJlbDogJ0tvc3p0IGxhY3puaWUgKGVzdC4pJywKICAgICAgdmFsdWU6IGZvcm1hdENvc3QodG90YWxDb3N0RXN0KSwKICAgICAgc3ViOiBhY3RpdmVQcm9maWxlID8gJ3Byb2ZpbDogJyArIGFjdGl2ZVByb2ZpbGUgOiAnV3N6eXN0a2llIHByb2ZpbGUnLAogICAgICBjbHM6ICcnCiAgICB9LAogICAgewogICAgICBsYWJlbDogJ0tvc3p0IGR6aXMgKGVzdC4pJywKICAgICAgdmFsdWU6IGZvcm1hdENvc3QodG9kYXlVc2FnZT8uY29zdD8uZXN0aW1hdGVkX3VzZCB8fCAwKSwKICAgICAgc3ViOiAodXNhZ2VEYXRhPy5ieV9tb2RlbD8ubGVuZ3RoIHx8IDApICsgJyBtb2RlbGUnLAogICAgICBjbHM6ICcnCiAgICB9LAogICAgewogICAgICBsYWJlbDogJ0JsZWR5ICgxaCknLAogICAgICB2YWx1ZTogc3VtbWFyeS5lcnJvcnNfMWggfHwgMCwKICAgICAgc3ViOiBzdW1tYXJ5LmVycm9yc18xaCA+IDAgPyAnV3ltYWdhIHV3YWdpJyA6ICdDenlzdG8nLAogICAgICBjbHM6IHN1bW1hcnkuZXJyb3JzXzFoID4gMCA/ICdjcml0aWNhbCcgOiAnJwogICAgfQogIF07CgogIGVsLmlubmVySFRNTCA9IHRpbGVzLm1hcCh0ID0+ICcnCiAgICArICc8ZGl2IGNsYXNzPSJtZXRyaWMtdGlsZSAnICsgdC5jbHMgKyAnIj4nCiAgICArICc8ZGl2IGNsYXNzPSJ0aWxlLWxhYmVsIGJvZHktc20iPicgKyB0LmxhYmVsICsgJzwvZGl2PicKICAgICsgJzxkaXYgY2xhc3M9InRpbGUtdmFsdWUgbWV0cmljLXhsIj4nICsgdC52YWx1ZSArICc8L2Rpdj4nCiAgICArICc8ZGl2IGNsYXNzPSJ0aWxlLXN1YiBib2R5LXNtIj4nICsgdC5zdWIgKyAnPC9kaXY+JwogICAgKyAnPC9kaXY+JwogICkuam9pbignJyk7Cn0KCi8vID09PT09IFJFTkRFUjogVVNBR0UgQ0hBUlQgKEVDaGFydHMgb3IgQVNDSUkgZm9yIFBpcC1Cb3kpID09PT09CmZ1bmN0aW9uIHJlbmRlclVzYWdlQ2hhcnQodXNhZ2VEYXRhKSB7CiAgY29uc3QgZG9tID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2NoYXJ0LXVzYWdlJyk7CiAgdmFyIGlzUGlwQm95ID0gZG9jdW1lbnQuYm9keS5nZXRBdHRyaWJ1dGUoJ2RhdGEtbGF5b3V0JykgPT09ICdwaXBib3knOwoKICBpZiAoaXNQaXBCb3kpIHsKICAgIHJlbmRlclVzYWdlQXNjaWkodXNhZ2VEYXRhLCBkb20pOwogICAgcmV0dXJuOwogIH0KICBpZiAoIXVzYWdlRGF0YSB8fCB1c2FnZURhdGEuX2Vycm9yIHx8ICF1c2FnZURhdGEuZGFpbHk/Lmxlbmd0aCkgewogICAgaWYgKHVzYWdlQ2hhcnQpIHsgdXNhZ2VDaGFydC5kaXNwb3NlKCk7IHVzYWdlQ2hhcnQgPSBudWxsOyB9CiAgICBkb20uaW5uZXJIVE1MID0gJzxkaXYgY2xhc3M9InN0YXRlLW1zZyIgc3R5bGU9Im1pbi1oZWlnaHQ6MjAwcHgiPjxkaXYgY2xhc3M9ImRlc2MgYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRNdXRlZCkiPkJyYWsgZGFueWNoIG8genV6eWNpdTwvZGl2PjwvZGl2Pic7CiAgICByZXR1cm47CiAgfQoKICBpZiAoIXVzYWdlQ2hhcnQpIHsKICAgIGRvbS5pbm5lckhUTUwgPSAnJzsKICAgIHVzYWdlQ2hhcnQgPSBlY2hhcnRzLmluaXQoZG9tLCBudWxsLCB7cmVuZGVyZXI6J2NhbnZhcyd9KTsKICB9IGVsc2UgewogICAgdXNhZ2VDaGFydC5yZXNpemUoKTsKICB9CgogIGNvbnN0IGRheXMgPSB1c2FnZURhdGEuZGFpbHkuc2xpY2UoKS5yZXZlcnNlKCk7CiAgY29uc3QgZGF0ZXMgPSBkYXlzLm1hcChkID0+IGQuZGF5LnNsaWNlKDUpKTsKICBjb25zdCBpbnB1dHMgPSBkYXlzLm1hcChkID0+IGQudG9rZW5zPy5pbnB1dCB8fCAwKTsKICBjb25zdCBvdXRwdXRzID0gZGF5cy5tYXAoZCA9PiBkLnRva2Vucz8ub3V0cHV0IHx8IDApOwogIGNvbnN0IGNvc3RzID0gZGF5cy5tYXAoZCA9PiBkLmNvc3Q/LmVzdGltYXRlZF91c2QgfHwgMCk7CgogIHVzYWdlQ2hhcnQuc2V0T3B0aW9uKHsKICAgIGRhcmtNb2RlOiB0cnVlLAogICAgYmFja2dyb3VuZENvbG9yOiAndHJhbnNwYXJlbnQnLAogICAgdG9vbHRpcDogewogICAgICB0cmlnZ2VyOidheGlzJywKICAgICAgZm9ybWF0dGVyOiBmdW5jdGlvbihwYXJhbXMpIHsKICAgICAgICB2YXIgYXJyID0gQXJyYXkuaXNBcnJheShwYXJhbXMpID8gcGFyYW1zIDogW3BhcmFtc107CiAgICAgICAgcmV0dXJuIGFyci5tYXAoZnVuY3Rpb24ocCkgewogICAgICAgICAgdmFyIG1hcmtlciA9IHAubWFya2VyIHx8ICcnOwogICAgICAgICAgaWYgKHAuc2VyaWVzTmFtZSA9PT0gJ0tvc3p0ICgkKScpIHsKICAgICAgICAgICAgcmV0dXJuIG1hcmtlciArIHAuc2VyaWVzTmFtZSArICc6IDxiPiQnICsgKE51bWJlcihwLnZhbHVlKXx8MCkudG9GaXhlZCgyKSArICc8L2I+JzsKICAgICAgICAgIH0KICAgICAgICAgIHJldHVybiBtYXJrZXIgKyBwLnNlcmllc05hbWUgKyAnOiA8Yj4nICsgZm9ybWF0TnVtYmVyKHAudmFsdWUpICsgJzwvYj4nOwogICAgICAgIH0pLmpvaW4oJzxici8+Jyk7CiAgICAgIH0KICAgIH0sCiAgICBsZWdlbmQ6IHtkYXRhOlsnSW5wdXQgdG9rZW5zJywnT3V0cHV0IHRva2VucycsJ0tvc3p0ICgkKSddLHRleHRTdHlsZTp7Y29sb3I6JyM5NEEzQjgnfSxib3R0b206MH0sCiAgICBncmlkOiB7bGVmdDoxMiwgcmlnaHQ6MTIsIHRvcDoxMiwgYm90dG9tOjMyfSwKICAgIHhBeGlzOiB7dHlwZTonY2F0ZWdvcnknLGRhdGE6ZGF0ZXMsYXhpc0xpbmU6e2xpbmVTdHlsZTp7Y29sb3I6JyMxRTMzNEYnfX0sYXhpc0xhYmVsOntjb2xvcjonIzY0NzQ4QicsZm9udFNpemU6MTB9fSwKICAgIHlBeGlzOiBbCiAgICAgIHt0eXBlOid2YWx1ZScsYXhpc0xhYmVsOntjb2xvcjonIzY0NzQ4QicsZm9udFNpemU6MTAsZm9ybWF0dGVyOnY9PmZvcm1hdE51bWJlcih2KX0sc3BsaXRMaW5lOntsaW5lU3R5bGU6e2NvbG9yOicjMUUzMzRGJ319fSwKICAgICAge3R5cGU6J3ZhbHVlJyxheGlzTGFiZWw6e2NvbG9yOicjNjQ3NDhCJyxmb250U2l6ZToxMCxmb3JtYXR0ZXI6dj0+JyQnK3YudG9GaXhlZCgyKX0sc3BsaXRMaW5lOntzaG93OmZhbHNlfX0KICAgIF0sCiAgICBzZXJpZXM6IFsKICAgICAge25hbWU6J0lucHV0IHRva2VucycsdHlwZTonYmFyJyxkYXRhOmlucHV0cyxpdGVtU3R5bGU6e2NvbG9yOicjMzhCREY4J30sYmFyTWF4V2lkdGg6MjB9LAogICAgICB7bmFtZTonT3V0cHV0IHRva2VucycsdHlwZTonYmFyJyxkYXRhOm91dHB1dHMsaXRlbVN0eWxlOntjb2xvcjonIzgxOENGOCd9LGJhck1heFdpZHRoOjIwfSwKICAgICAge25hbWU6J0tvc3p0ICgkKScsdHlwZTonbGluZScseUF4aXNJbmRleDoxLGRhdGE6Y29zdHMsbGluZVN0eWxlOntjb2xvcjonI0Y1OUUwQicsd2lkdGg6Mn0sc3ltYm9sOidjaXJjbGUnLHN5bWJvbFNpemU6NixpdGVtU3R5bGU6e2NvbG9yOicjRjU5RTBCJ319CiAgICBdCiAgfSk7Cn0KCi8vID09PT09IFJFTkRFUjogTU9ERUxTIFRBQkxFIChib3RoIGxheW91dHMg4oCUIHRhYmxlIHNvcnRlZCBieSBjb3N0IGRlc2MpID09PT09CmZ1bmN0aW9uIHJlbmRlck1vZGVsc0NoYXJ0KHVzYWdlRGF0YSkgewogIGNvbnN0IGRvbSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjaGFydC1tb2RlbHMnKTsKICBpZiAobW9kZWxzQ2hhcnQpIHsgbW9kZWxzQ2hhcnQuZGlzcG9zZSgpOyBtb2RlbHNDaGFydCA9IG51bGw7IH0KCiAgaWYgKCF1c2FnZURhdGEgfHwgdXNhZ2VEYXRhLl9lcnJvciB8fCAhdXNhZ2VEYXRhLmJ5X21vZGVsPy5sZW5ndGgpIHsKICAgIGRvbS5pbm5lckhUTUwgPSAnPGRpdiBjbGFzcz0ic3RhdGUtbXNnIiBzdHlsZT0ibWluLWhlaWdodDoxNTBweCI+PGRpdiBjbGFzcz0iZGVzYyBib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSI+QnJhayBkYW55Y2ggbyBtb2RlbGFjaDwvZGl2PjwvZGl2Pic7CiAgICByZXR1cm47CiAgfQoKICAvLyBTb3J0dWogb2QgbmFqYmFyZHppZWogZG8gbmFqbW5pZWogdcW8eXdhbmVnbyBwb2QgV1pHTMSYREVNIEtPU1pUw5NXIChkZXNjKQogIGNvbnN0IG1vZGVscyA9ICh1c2FnZURhdGEuYnlfbW9kZWwgfHwgW10pLnNsaWNlKCkuc29ydChmdW5jdGlvbihhLGIpIHsKICAgIHJldHVybiAoTnVtYmVyKGIuZXN0aW1hdGVkX2Nvc3RfdXNkKXx8MCkgLSAoTnVtYmVyKGEuZXN0aW1hdGVkX2Nvc3RfdXNkKXx8MCk7CiAgfSk7CgogIGZ1bmN0aW9uIG5tKG0pIHsKICAgIHJldHVybiAoKG0ubW9kZWx8fCc/JykucmVwbGFjZSgvXmRlZXBzZWVrLS8sJycpLnJlcGxhY2UoL15vcGVuYWlcLy8sJycpLnN1YnN0cmluZygwLDMyKSk7CiAgfQoKICBkb20uaW5uZXJIVE1MID0KICAgICc8dGFibGUgY2xhc3M9Im1vZGVscy10YWJsZSI+JyArCiAgICAnPHRoZWFkPjx0cj4nICsKICAgICAgJzx0aCBjbGFzcz0ibS1yYW5rIj4jPC90aD48dGg+TW9kZWw8L3RoPicgKwogICAgICAnPHRoIGNsYXNzPSJtLXRva2VucyI+VG9rZW55PC90aD48dGggY2xhc3M9Im0tY29zdCI+S29zenQgKGVzdC4pPC90aD48dGggY2xhc3M9Im0tY2FsbHMiPld5d2/FgmFuaWE8L3RoPicgKwogICAgJzwvdHI+PC90aGVhZD48dGJvZHk+JyArCiAgICBtb2RlbHMuc2xpY2UoMCwgMTUpLm1hcChmdW5jdGlvbihtLCBpKSB7CiAgICAgIHZhciB0ID0gKG0udG9rZW5zPy5pbnB1dHx8MCkgKyAobS50b2tlbnM/Lm91dHB1dHx8MCk7CiAgICAgIHJldHVybiAnPHRyPicgKwogICAgICAgICc8dGQgY2xhc3M9Im0tcmFuayI+JyArIChpKzEpICsgJzwvdGQ+JyArCiAgICAgICAgJzx0ZCBjbGFzcz0ibS1uYW1lIj4nICsgZXNjYXBlSHRtbChubShtKSkgKyAnPC90ZD4nICsKICAgICAgICAnPHRkIGNsYXNzPSJtLXRva2VucyI+JyArIGZvcm1hdE51bWJlcih0KSArICc8L3RkPicgKwogICAgICAgICc8dGQgY2xhc3M9Im0tY29zdCI+JyArIGZvcm1hdENvc3QobS5lc3RpbWF0ZWRfY29zdF91c2QpICsgJzwvdGQ+JyArCiAgICAgICAgJzx0ZCBjbGFzcz0ibS1jYWxscyI+JyArIGZvcm1hdE51bWJlcihtLmFwaV9jYWxscykgKyAnPC90ZD4nICsKICAgICAgJzwvdHI+JzsKICAgIH0pLmpvaW4oJycpICsKICAgICc8L3Rib2R5PjwvdGFibGU+JzsKfQoKLy8gPT09PT0gUElQLUJPWTogQVNDSUkgVVNBR0UgQ0hBUlQgPT09PT0KZnVuY3Rpb24gcmVuZGVyVXNhZ2VBc2NpaSh1c2FnZURhdGEsIGRvbSkgewogIGlmICh1c2FnZUNoYXJ0KSB7IHVzYWdlQ2hhcnQuZGlzcG9zZSgpOyB1c2FnZUNoYXJ0ID0gbnVsbDsgfQogIGRvbS5pbm5lckhUTUwgPSAnJzsKCiAgaWYgKCF1c2FnZURhdGEgfHwgdXNhZ2VEYXRhLl9lcnJvciB8fCAhdXNhZ2VEYXRhLmRhaWx5Py5sZW5ndGgpIHsKICAgIGRvbS5pbm5lckhUTUwgPSAnPHByZSBjbGFzcz0iYXNjaWktY2hhcnQiIHN0eWxlPSJtaW4taGVpZ2h0OjIwMHB4O2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjtjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpO2ZvbnQtZmFtaWx5OlwnSmV0QnJhaW5zIE1vbm9cJyxtb25vc3BhY2U7Zm9udC1zaXplOjAuN3JlbTtwYWRkaW5nOnZhcigtLXNwYWNlLWxnKSI+QlJBSyBEQU5ZQ0ggTyBaVVpZQ0lVPC9wcmU+JzsKICAgIHJldHVybjsKICB9CgogIGNvbnN0IGRheXMgPSB1c2FnZURhdGEuZGFpbHkuc2xpY2UoKS5yZXZlcnNlKCkuc2xpY2UoLTE0KTsKICBjb25zdCBtYXhUb2tlbnMgPSBNYXRoLm1heC5hcHBseShudWxsLCBkYXlzLm1hcChmdW5jdGlvbihkKSB7IHJldHVybiAoZC50b2tlbnM/LmlucHV0fHwwKSArIChkLnRva2Vucz8ub3V0cHV0fHwwKTsgfSkpIHx8IDE7CiAgY29uc3QgbWF4Q29zdCA9IE1hdGgubWF4LmFwcGx5KG51bGwsIGRheXMubWFwKGZ1bmN0aW9uKGQpIHsgcmV0dXJuIGQuY29zdD8uZXN0aW1hdGVkX3VzZHx8MDsgfSkpIHx8IDE7CiAgY29uc3QgYmFyQ2hhcnMgPSBbJ+KWgScsJ+KWgicsJ+KWgycsJ+KWhCcsJ+KWhScsJ+KWhicsJ+KWhycsJ+KWiCddOwoKICB2YXIgbGluZXMgPSBbXTsKICBsaW5lcy5wdXNoKCcgIFRPS0VOIFVTQUdFIChvc3QuICcgKyBkYXlzLmxlbmd0aCArICcgZG5pKScpOwogIGxpbmVzLnB1c2goJyAgJyArICfilIAnLnJlcGVhdCg1MCkpOwogIGRheXMuZm9yRWFjaChmdW5jdGlvbihkKSB7CiAgICB2YXIgdG90YWwgPSAoZC50b2tlbnM/LmlucHV0fHwwKSArIChkLnRva2Vucz8ub3V0cHV0fHwwKTsKICAgIHZhciBpZHggPSBNYXRoLm1pbihNYXRoLmZsb29yKHRvdGFsIC8gbWF4VG9rZW5zICogNyksIDcpOwogICAgdmFyIGJhciA9IGJhckNoYXJzW2lkeF0ucmVwZWF0KE1hdGgubWF4KDEsIE1hdGguZmxvb3IodG90YWwgLyBtYXhUb2tlbnMgKiAzMCkpKTsKICAgIHZhciBsYWJlbCA9IChkLmRheXx8JycpLnNsaWNlKDUpOwogICAgbGluZXMucHVzaCgnICAnICsgbGFiZWwgKyAnIOKUgicgKyBiYXIgKyAnICcgKyBmb3JtYXROdW1iZXIodG90YWwpKTsKICB9KTsKICBsaW5lcy5wdXNoKCcgICcgKyAn4pSAJy5yZXBlYXQoNTApKTsKCiAgZG9tLmlubmVySFRNTCA9ICc8cHJlIGNsYXNzPSJhc2NpaS1jaGFydCIgc3R5bGU9Im1hcmdpbjowO3BhZGRpbmc6dmFyKC0tc3BhY2UtbWQpO2NvbG9yOnZhcigtLXByaW1hcnkpO2ZvbnQtZmFtaWx5OlwnSmV0QnJhaW5zIE1vbm9cJyxtb25vc3BhY2U7Zm9udC1zaXplOjAuNjVyZW07bGluZS1oZWlnaHQ6MS42O3RleHQtc2hhZG93OjAgMCA0cHggcmdiYSgyMCwyNTUsMjMsMC4zKTtvdmVyZmxvdy14OmF1dG8iPicgKyBlc2NhcGVIdG1sKGxpbmVzLmpvaW4oJ1xuJykpICsgJzwvcHJlPic7Cn0KCi8vID09PT09IFBJUC1CT1k6IFRFWFQgTU9ERUwgTElTVCAocmVwbGFjZWQgYnkgdGFibGUpID09PT09CgovLyA9PT09PSBSRU5ERVI6IFNFU1NJT05TID09PT09CmZ1bmN0aW9uIHJlbmRlclNlc3Npb25zKHNlc3Npb25zRGF0YSkgewogIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3Nlc3Npb25zLWxpc3QnKTsKICBjb25zdCBjb3VudEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3Nlc3Npb24tY291bnQnKTsKCiAgaWYgKCFzZXNzaW9uc0RhdGEgfHwgc2Vzc2lvbnNEYXRhLl9lcnJvcikgewogICAgZWwuaW5uZXJIVE1MID0gJzxkaXYgY2xhc3M9InN0YXRlLW1zZyIgc3R5bGU9Im1pbi1oZWlnaHQ6MTUwcHgiPjxkaXYgY2xhc3M9ImRlc2MgYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRNdXRlZCkiPk5pZSBtb3puYSB6YWxhZG93YWMgc2Vzamk8L2Rpdj48L2Rpdj4nOwogICAgY291bnRFbC50ZXh0Q29udGVudCA9ICctLSc7CiAgICByZXR1cm47CiAgfQoKICBjb25zdCBzZXNzaW9ucyA9IHNlc3Npb25zRGF0YS5zZXNzaW9ucyB8fCBbXTsKICBjb3VudEVsLnRleHRDb250ZW50ID0gc2Vzc2lvbnMuc2xpY2UoMCwgMTApLmxlbmd0aCArICcgc2VzamknOwoKICBpZiAoc2Vzc2lvbnMubGVuZ3RoID09PSAwKSB7CiAgICBlbC5pbm5lckhUTUwgPSAnPGRpdiBjbGFzcz0ic3RhdGUtbXNnIiBzdHlsZT0ibWluLWhlaWdodDoxNTBweCI+PGRpdiBjbGFzcz0iZGVzYyBib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSI+QnJhayBzZXNqaTwvZGl2PjwvZGl2Pic7CiAgICByZXR1cm47CiAgfQoKICBlbC5pbm5lckhUTUwgPSBzZXNzaW9ucy5zbGljZSgwLCAxMCkubWFwKHMgPT4gewogICAgdmFyIGlzUGlwQm95ID0gZG9jdW1lbnQuYm9keS5nZXRBdHRyaWJ1dGUoJ2RhdGEtbGF5b3V0JykgPT09ICdwaXBib3knOwogICAgdmFyIHNvdXJjZUljb247CiAgICBpZiAoaXNQaXBCb3kpIHsKICAgICAgc291cmNlSWNvbiA9IHMuc291cmNlID09PSAndGVsZWdyYW0nID8gJ1tUXScgOiBzLnNvdXJjZSA9PT0gJ2thbmJhbicgPyAnW0tdJyA6ICdbQ10nOwogICAgfSBlbHNlIHsKICAgICAgc291cmNlSWNvbiA9IHMuc291cmNlID09PSAndGVsZWdyYW0nID8gJ1QnIDogcy5zb3VyY2UgPT09ICdrYW5iYW4nID8gJ0snIDogJ0MnOwogICAgfQogICAgY29uc3QgbmFtZSA9IHMuZGlzcGxheV9uYW1lIHx8IHMuaWQ/LnNsaWNlKDAsIDE2KSB8fCAnLS0nOwogICAgcmV0dXJuICc8ZGl2IGNsYXNzPSJzZXNzaW9uLXJvdyI+JyArCiAgICAgICc8ZGl2IHRpdGxlPSInICsgZXNjYXBlSHRtbChzLnNvdXJjZSkgKyAnIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKTtmb250LXNpemU6MC43cmVtO2ZvbnQtd2VpZ2h0OjYwMCI+JyArIHNvdXJjZUljb24gKyAnPC9kaXY+JyArCiAgICAgICc8c3BhbiBjbGFzcz0icHJvZmlsZS1jaGlwLW1pbmkiPicgKyBlc2NhcGVIdG1sKHMuX3Byb2ZpbGUgfHwgJz8nKSArICc8L3NwYW4+JyArCiAgICAgICc8ZGl2PicgKwogICAgICAgICc8ZGl2IGNsYXNzPSJib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dFByaW1hcnkpIj4nICsgZXNjYXBlSHRtbChuYW1lKSArICc8L2Rpdj4nICsKICAgICAgICAnPGRpdiBjbGFzcz0iYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRNdXRlZCkiPicgKyBlc2NhcGVIdG1sKHMubW9kZWx8fCctLScpICsgJyAvICcgKyAocy5tZXNzYWdlX2NvdW50fHwwKSArICcgbXNnIC8gJyArIChzLmFwaV9jYWxsX2NvdW50fHwwKSArICcgY2FsbDwvZGl2PicgKwogICAgICAnPC9kaXY+JyArCiAgICAgICc8ZGl2IGNsYXNzPSJoaWRlLW1vYmlsZSBtb25vLXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSkiPicgKyBmb3JtYXROdW1iZXIocy50b2tlbnM/LnRvdGFsfHwwKSArICcgdG9rLjwvZGl2PicgKwogICAgICAnPGRpdiBjbGFzcz0iaGlkZS1tb2JpbGUgbW9uby1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRTZWNvbmRhcnkpIj4nICsgZm9ybWF0Q29zdChzLmNvc3Q/LmVzdGltYXRlZF91c2QpICsgJzwvZGl2PicgKwogICAgICAnPGRpdiBjbGFzcz0iaGlkZS1tb2JpbGUgYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRNdXRlZCkiPicgKyB0aW1lQWdvKHMubGFzdF9hY3Rpdml0eV9hdCkgKyAnPC9kaXY+JyArCiAgICAnPC9kaXY+JzsKICB9KS5qb2luKCcnKTsKfQoKLy8gPT09PT0gUkVOREVSOiBHQVRFV0FZID09PT09Ci8vIEZvcm1hdG93YW5pZSBjemFzdSBwcmFjeSAvIHdpZWt1CmZ1bmN0aW9uIGZtdER1cihzKSB7CiAgaWYgKHMgPT0gbnVsbCB8fCBpc05hTihzKSkgcmV0dXJuICctLSc7CiAgaWYgKHMgPCA2MCkgcmV0dXJuIE1hdGgucm91bmQocykgKyAncyc7CiAgaWYgKHMgPCAzNjAwKSByZXR1cm4gTWF0aC5yb3VuZChzIC8gNjApICsgJ20nOwogIGlmIChzIDwgODY0MDApIHJldHVybiAocyAvIDM2MDApLnRvRml4ZWQoMSkgKyAnaCc7CiAgcmV0dXJuIChzIC8gODY0MDApLnRvRml4ZWQoMSkgKyAnZCc7Cn0KLy8gS2F0ZWdvcmlhIGtyb3BraSBzdGF0dXN1IHByb2ZpbHU6IG9rIC8gd2FybiAvIGVyciAvIG5vbmUKZnVuY3Rpb24gZ3dTdGF0dXMoZ3cpIHsKICBpZiAoIWd3IHx8ICFndy5oYXNPd25Qcm9wZXJ0eSgnc3RhdGUnKSkgcmV0dXJuICdub25lJzsKICBpZiAoZ3cuc3RhdGUgIT09ICdydW5uaW5nJykgcmV0dXJuICdlcnInOwogIC8vIHJ1bm5pbmc6IG1hcnR3eSBjcm9uIHRpY2tlciAvIGLFgsSZZHkgLyBjesSZxZvEhyBwbGF0Zm9ybSBkaXNjb25uZWN0ZWQgPT4gd2FybgogIGlmIChndy5jcm9uX2FsaXZlID09PSBmYWxzZSkgcmV0dXJuICd3YXJuJzsKICBpZiAoKGd3LmVycm9yc18xaCB8fCAwKSA+IDApIHJldHVybiAnd2Fybic7CiAgdmFyIHBsYXRzID0gZ3cucGxhdGZvcm1zIHx8IFtdOwogIGlmIChwbGF0cy5sZW5ndGggPiAwKSB7CiAgICB2YXIgY29ubmVjdGVkID0gcGxhdHMuZmlsdGVyKGZ1bmN0aW9uKHgpIHsgcmV0dXJuIHguc3RhdGUgPT09ICdjb25uZWN0ZWQnOyB9KS5sZW5ndGg7CiAgICBpZiAoY29ubmVjdGVkIDwgcGxhdHMubGVuZ3RoKSByZXR1cm4gJ3dhcm4nOwogIH0KICByZXR1cm4gJ29rJzsKfQovLyBTdGFuIHN6Y3plZ8OzxYJvd3kgKyBkZXNpcmVkX3N0YXRlCmZ1bmN0aW9uIGd3U3RhdGVNZXRhKGd3KSB7CiAgdmFyIHN0ID0gZ3cuc3RhdGUgfHwgJ3Vua25vd24nOwogIHZhciBkcyA9IGd3LmRlc2lyZWRfc3RhdGU7CiAgaWYgKHN0ID09PSAncnVubmluZycpIHsKICAgIGlmIChkcyAmJiBkcyAhPT0gJ3J1bm5pbmcnICYmIGRzICE9PSAndXAnKSByZXR1cm4geyBsYWJlbDogJ3J1bm5pbmcnLCBjbGllbnQ6ICd1cCAoY2hjZSAnICsgZHMgKyAnKScgfTsKICAgIHJldHVybiB7IGxhYmVsOiAncnVubmluZycsIGNsaWVudDogbnVsbCB9OwogIH0KICBpZiAoZHMgJiYgZHMgIT09IHN0KSByZXR1cm4geyBsYWJlbDogc3QsIGNsaWVudDogJ2NoY2UgJyArIGRzIH07CiAgcmV0dXJuIHsgbGFiZWw6IHN0LCBjbGllbnQ6IG51bGwgfTsKfQpmdW5jdGlvbiByZW5kZXJHYXRld2F5KHN0YXR1c0RhdGEpIHsKICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdnYXRld2F5LWxpc3QnKTsKICBjb25zdCBjb3VudEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2dhdGV3YXktY291bnQnKTsKCiAgaWYgKCFzdGF0dXNEYXRhIHx8IHN0YXR1c0RhdGEuX2Vycm9yIHx8ICFzdGF0dXNEYXRhLnByb2ZpbGVzKSB7CiAgICBlbC5pbm5lckhUTUwgPSAnPGRpdiBjbGFzcz0ic3RhdGUtbXNnIiBzdHlsZT0ibWluLWhlaWdodDoxNTBweCI+PGRpdiBjbGFzcz0iZGVzYyBib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSI+QnJhayBkYW55Y2ggbyBnYXRld2F5PC9kaXY+PC9kaXY+JzsKICAgIGNvdW50RWwudGV4dENvbnRlbnQgPSAnLS0nOwogICAgcmV0dXJuOwogIH0KCiAgdmFyIHByb2ZpbGVzID0gc3RhdHVzRGF0YS5wcm9maWxlcyB8fCBbXTsKICB2YXIgYWdncmVnYXRvcnMgPSB7IHVwOiAwLCB3YXJuOiAwLCBkb3duOiAwLCBub25lOiAwLCBvbmxpbmU6IDAsIHRvdGFsOiAwIH07CiAgcHJvZmlsZXMuZm9yRWFjaChmdW5jdGlvbihwKSB7CiAgICB2YXIgZyA9IHAuZ2F0ZXdheSB8fCB7fTsKICAgIHZhciBjYXQgPSBnd1N0YXR1cyhnKTsKICAgIGlmIChjYXQgPT09ICdvaycpIGFnZ3JlZ2F0b3JzLnVwKys7CiAgICBlbHNlIGlmIChjYXQgPT09ICd3YXJuJykgYWdncmVnYXRvcnMud2FybisrOwogICAgZWxzZSBpZiAoY2F0ID09PSAnZXJyJykgYWdncmVnYXRvcnMuZG93bisrOwogICAgZWxzZSBhZ2dyZWdhdG9ycy5ub25lKys7CiAgICAoZy5wbGF0Zm9ybXMgfHwgW10pLmZvckVhY2goZnVuY3Rpb24ocGwpIHsgYWdncmVnYXRvcnMudG90YWwrKzsgaWYgKHBsLnN0YXRlID09PSAnY29ubmVjdGVkJykgYWdncmVnYXRvcnMub25saW5lKys7IH0pOwogIH0pOwoKICB2YXIgaHRtbCA9IHByb2ZpbGVzLm1hcChmdW5jdGlvbihwKSB7CiAgICB2YXIgZyA9IHAuZ2F0ZXdheSB8fCB7fTsKICAgIHZhciBjYXQgPSBnd1N0YXR1cyhnKTsKICAgIHZhciBtZXRhID0gZ3dTdGF0ZU1ldGEoZyk7CiAgICB2YXIgcGlkID0gZy5waWQ7CiAgICB2YXIgdXBUeHQgPSBmbXREdXIoZy51cHRpbWUpOwogICAgdmFyIGFnZVR4dCA9IChnLmFnZV9zZWNvbmRzICE9IG51bGwgJiYgZy5hZ2Vfc2Vjb25kcyA8IDg2NDAwKQogICAgICA/IGZtdER1cihnLmFnZV9zZWNvbmRzKSArICcgdGVtdScgOiBmbXREdXIoZy5hZ2Vfc2Vjb25kcyk7CiAgICAvLyB6bmFjemVrIG9kxZt3aWXFvGVuaWEgdHlsa28gZ2R5IGRhbmUgaXN0bmllasSFCiAgICB2YXIgYWdlSHRtbCA9IChnLnVwZGF0ZWRfYXQpID8gJzxzcGFuPnVwZGF0ZSA8c3BhbiBjbGFzcz0ib2t2Ij4nICsgZXNjYXBlSHRtbChhZ2VUeHQpICsgJzwvc3Bhbj48L3NwYW4+JyA6ICcnOwogICAgLy8gZXhpdF9yZWFzb24gdHlsa28gZ2R5IG5pZSBudWxsCiAgICB2YXIgZXhpdEh0bWwgPSAoZy5leGl0X3JlYXNvbiAhPSBudWxsICYmIGcuZXhpdF9yZWFzb24gIT09ICcnKSA/ICc8c3BhbiBjbGFzcz0iZmxhZy1leGl0IiB0aXRsZT0iJyArIGVzY2FwZUh0bWwoZy5leGl0X3JlYXNvbikgKyAnIj5leGl0OiAnICsgZXNjYXBlSHRtbChTdHJpbmcoZy5leGl0X3JlYXNvbikpICsgJzwvc3Bhbj4nIDogJyc7CiAgICAvLyByZXN0YXJ0X3JlcXVlc3RlZAogICAgdmFyIHJlc3RhcnRIdG1sID0gZy5yZXN0YXJ0X3JlcXVlc3RlZCA/ICc8c3BhbiBjbGFzcz0iZmxhZy1yZXN0YXJ0IiB0aXRsZT0iUmVzdGFydCDFvMSFZGFueSI+UkVTVEFSVDwvc3Bhbj4nIDogJyc7CiAgICAvLyBixYLEmWR5IDFoCiAgICB2YXIgZXJySHRtbCA9IChnLmVycm9yc18xaCB8fCAwKSA+IDAgPyAnPHNwYW4gY2xhc3M9ImJhZCI+JyArIChnLmVycm9yc18xaCkgKyAnIGLFgi48L3NwYW4+JyA6ICcnOwogICAgLy8gY3JvbiB0aWNrZXIKICAgIHZhciBjcm9uSHRtbCA9IChnLmNyb25fYWxpdmUgPT09IGZhbHNlKSA/ICc8c3BhbiBjbGFzcz0iYmFkIj5jcm9uICcgKyBmbXREdXIoZy5jcm9uX2hlYXJ0YmVhdF9hZ2Vfc2Vjb25kcykgKyAnK3M8L3NwYW4+JyA6ICcnOwogICAgLy8gb3BpcyBzdGFudSBjesSZxZtjaW93ZWdvIHBvZCBrcm9wa8SFCiAgICB2YXIgcGFydGlhbE5vdGUgPSBudWxsOwogICAgaWYgKGNhdCA9PT0gJ3dhcm4nKSB7CiAgICAgIHZhciBiaXRzID0gW107CiAgICAgIGlmIChnLmNyb25fYWxpdmUgPT09IGZhbHNlKSBiaXRzLnB1c2goJ2Nyb24gKycgKyBmbXREdXIoZy5jcm9uX2hlYXJ0YmVhdF9hZ2Vfc2Vjb25kcyB8fCAwKSk7CiAgICAgIGlmICgoZy5lcnJvcnNfMWggfHwgMCkgPiAwKSBiaXRzLnB1c2goKGcuZXJyb3JzXzFoKSArICcgYsWCxJlkw7N3Jyk7CiAgICAgIHZhciBwbGF0cyA9IGcucGxhdGZvcm1zIHx8IFtdOwogICAgICBwbGF0cy5mb3JFYWNoKGZ1bmN0aW9uKHBsKSB7IGlmIChwbC5zdGF0ZSAhPT0gJ2Nvbm5lY3RlZCcpIGJpdHMucHVzaChwbC5uYW1lICsgJyAnICsgcGwuc3RhdGUpOyB9KTsKICAgICAgcGFydGlhbE5vdGUgPSBiaXRzLmpvaW4oJywgJyk7CiAgICB9CgogICAgLy8gcG9kLXNrbGVwIHBsYXRmb3JtIChleHBhbmRlcikKICAgIHZhciBwbGF0cyA9IGcucGxhdGZvcm1zIHx8IFtdOwogICAgdmFyIHBsYXRIdG1sID0gJyc7CiAgICBpZiAocGxhdHMubGVuZ3RoID4gMCkgewogICAgICB2YXIgcGxSb3dzID0gcGxhdHMubWFwKGZ1bmN0aW9uKHBsKSB7CiAgICAgICAgdmFyIHMgPSBwbC5zdGF0ZSB8fCAndW5rbm93bic7CiAgICAgICAgdmFyIGRvdENscyA9IHMgPT09ICdjb25uZWN0ZWQnID8gJ2Nvbm5lY3RlZCcgOiAocyA9PT0gJ2Rpc2Nvbm5lY3RlZCcgPyAnZGlzY29ubmVjdGVkJyA6IChzID09PSAnc3RhcnRpbmcnIHx8IHMgPT09ICdjb25uZWN0aW5nJyA/ICdzdGFydGluZycgOiAndW5rbm93bicpKTsKICAgICAgICB2YXIgZXJyVHh0ID0gcGwuZXJyb3JfY29kZSAhPSBudWxsID8gKCcgwrcgJyArIGVzY2FwZUh0bWwoU3RyaW5nKHBsLmVycm9yX2NvZGUpKSkgOiAnJzsKICAgICAgICBpZiAocGwuZXJyb3JfbWVzc2FnZSkgZXJyVHh0ICs9ICcgwrcgJyArIGVzY2FwZUh0bWwoU3RyaW5nKHBsLmVycm9yX21lc3NhZ2UpKTsKICAgICAgICByZXR1cm4gJzxkaXYgY2xhc3M9Imd3LXBsYXRmb3JtLXJvdyI+PGRpdiBjbGFzcz0icGwtc3RhdGUiPjxzcGFuIGNsYXNzPSJndy1wbC1kb3QgJyArIGRvdENscyArICciPjwvc3Bhbj48c3Bhbj4nICsgZXNjYXBlSHRtbChwbC5uYW1lKSArICc8L3NwYW4+PHNwYW4gc3R5bGU9ImNvbG9yOnZhcigtLXRleHRNdXRlZCkiPicgKyBlc2NhcGVIdG1sKHMpICsgJzwvc3Bhbj48L2Rpdj4nICsgKGVyclR4dCA/ICc8c3BhbiBjbGFzcz0icGwtZXJyIiB0aXRsZT0iJyArIGVyclR4dCArICciPicgKyBlcnJUeHQgKyAnPC9zcGFuPicgOiAnJykgKyAnPC9kaXY+JzsKICAgICAgfSkuam9pbignJyk7CiAgICAgIHBsYXRIdG1sID0gJzxkaXYgY2xhc3M9Imd3LXBsYXRmb3JtcyI+PGRpdiBjbGFzcz0iZ3ctcGxhdGZvcm0tcm93IiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSk7Zm9udC13ZWlnaHQ6NjAwIj48c3Bhbj5QbGF0Zm9ybXk8L3NwYW4+PHNwYW4+JyArIHBsYXRzLmZpbHRlcihmdW5jdGlvbih4KXtyZXR1cm4geC5zdGF0ZT09PSdjb25uZWN0ZWQnO30pLmxlbmd0aCArICcvJyArIHBsYXRzLmxlbmd0aCArICcgb25saW5lPC9zcGFuPjwvZGl2PicgKyBwbFJvd3MgKyAnPC9kaXY+JzsKICAgIH0KCiAgICB2YXIgbWV0YVBhcnRzID0gW107CiAgICBtZXRhUGFydHMucHVzaChwaWQgIT0gbnVsbCAmJiBwaWQgIT09ICcnID8gJ3BpZCAnICsgcGlkIDogJ3BpZCDiiJInKTsKICAgIG1ldGFQYXJ0cy5wdXNoKCd1cCAnICsgdXBUeHQpOwogICAgbWV0YVBhcnRzLnB1c2goYWdlSHRtbCk7CiAgICBpZiAocmVzdGFydEh0bWwpIG1ldGFQYXJ0cy5wdXNoKHJlc3RhcnRIdG1sKTsKICAgIGlmIChleGl0SHRtbCkgbWV0YVBhcnRzLnB1c2goZXhpdEh0bWwpOwogICAgaWYgKGVyckh0bWwpIG1ldGFQYXJ0cy5wdXNoKGVyckh0bWwpOwogICAgaWYgKGNyb25IdG1sKSBtZXRhUGFydHMucHVzaChjcm9uSHRtbCk7CiAgICB2YXIgbWV0YUh0bWwgPSBtZXRhUGFydHMuam9pbignPHNwYW4gc3R5bGU9Im9wYWNpdHk6MC4zIj58PC9zcGFuPicpOwoKICAgIHZhciBzdGF0dXNMYWJlbCA9IChjYXQgPT09ICdvaycpID8gJ1VQJyA6IChjYXQgPT09ICdlcnInID8gJ0RPV04nIDogKGNhdCA9PT0gJ3dhcm4nID8gJ0NaxJjFmkNJT1dPJyA6ICdCUkFLJykpOwogICAgdmFyIHN0YXR1c0NvbG9yID0gY2F0ID09PSAnb2snID8gJ3ZhcigtLXN1Y2Nlc3MpJyA6IChjYXQgPT09ICdlcnInID8gJ3ZhcigtLWNyaXRpY2FsKScgOiAoY2F0ID09PSAnd2FybicgPyAnI2VhYjMwOCcgOiAndmFyKC0tdGV4dE11dGVkKScpKTsKCiAgICB2YXIgbGluZSA9ICc8ZGl2IGNsYXNzPSJnYXRld2F5LXJvdyI+JwogICAgICArICc8ZGl2IGNsYXNzPSJndy1sZWZ0Ij4nCiAgICAgICAgKyAnPGRpdiBjbGFzcz0iZ3ctaW5mbyI+JwogICAgICAgICAgKyAnPGRpdj48c3BhbiBjbGFzcz0iZ3ctbmFtZSI+JyArIGVzY2FwZUh0bWwocC5wcm9maWxlKSArICc8L3NwYW4+JwogICAgICAgICAgICArIChnLmFjdGl2ZV9hZ2VudHMgPyAnPHNwYW4gY2xhc3M9Imd3LWFnZW50cyI+JyArIGcuYWN0aXZlX2FnZW50cyArICcgYWcuPC9zcGFuPicgOiAnJykKICAgICAgICAgICAgKyAnPHNwYW4gY2xhc3M9Imd3LXN1YiI+JyArIGVzY2FwZUh0bWwobWV0YS5sYWJlbCkgKyAobWV0YS5jbGllbnQgPyAnICgnICsgZXNjYXBlSHRtbChtZXRhLmNsaWVudCkgKyAnKScgOiAnJykgKyAnPC9zcGFuPjwvZGl2PicKICAgICAgICAgICsgJzxkaXYgY2xhc3M9Imd3LW1ldGEiPicgKyBtZXRhSHRtbCArICc8L2Rpdj4nCiAgICAgICAgICArIChwYXJ0aWFsTm90ZSA/ICc8ZGl2IHN0eWxlPSJmb250LXNpemU6MC42cmVtO2NvbG9yOnZhcigtLXRleHRNdXRlZCkiPicgKyBlc2NhcGVIdG1sKHBhcnRpYWxOb3RlKSArICc8L2Rpdj4nIDogJycpCiAgICAgICAgKyAnPC9kaXY+JwogICAgICArICc8L2Rpdj4nCiAgICAgICsgJzxkaXYgY2xhc3M9Imd3LXN0YXR1cyI+JwogICAgICAgICsgJzxkaXYgY2xhc3M9Imd3LWRvdCAnICsgY2F0ICsgJyI+PC9kaXY+JwogICAgICAgICsgJzxzcGFuIHN0eWxlPSJjb2xvcjonICsgc3RhdHVzQ29sb3IgKyAnIj4nICsgc3RhdHVzTGFiZWwgKyAnPC9zcGFuPicKICAgICAgICArIChwbGF0cy5sZW5ndGggPyAnPGJ1dHRvbiBjbGFzcz0iZ3ctZXhwYW5kIiBkYXRhLXByb2ZpbGU9IicgKyBlc2NhcGVIdG1sKHAucHJvZmlsZSkgKyAnIj5wbGF0Zm9ybXkgJyArIHBsYXRzLmZpbHRlcihmdW5jdGlvbih4KXtyZXR1cm4geC5zdGF0ZT09PSdjb25uZWN0ZWQnO30pLmxlbmd0aCArICcvJyArIHBsYXRzLmxlbmd0aCArICc8L2J1dHRvbj4nIDogJycpCiAgICAgICsgJzwvZGl2PicKICAgICsgJzwvZGl2PicKICAgICsgcGxhdEh0bWw7CgogICAgcmV0dXJuIGxpbmU7CiAgfSkuam9pbignJyk7CgogIGNvdW50RWwudGV4dENvbnRlbnQgPSBwcm9maWxlcy5sZW5ndGggKyAnIGd3LCAnICsgYWdncmVnYXRvcnMudXAgKyAnIFVQLCAnICsgYWdncmVnYXRvcnMud2FybiArICcgY3rEhXN0LiwgJyArIGFnZ3JlZ2F0b3JzLmRvd24gKyAnIERPV04gwrcgJyArIGFnZ3JlZ2F0b3JzLm9ubGluZSArICcvJyArIGFnZ3JlZ2F0b3JzLnRvdGFsICsgJyBwbGF0Zm9ybSBvbmxpbmUnOwogIGVsLmlubmVySFRNTCA9IGh0bWw7CgogIC8vIERlbGVnYXRlIGNsaWNrIG5hIGV4cGFuZGVyeSBwbGF0Zm9ybSAobmFqcGllcncgdXN1d2FteSBzdGFyeSBoYW5kbGVyKQogIGlmIChlbC5fZ3dFeHBhbmRIYW5kbGVyKSBlbC5yZW1vdmVFdmVudExpc3RlbmVyKCdjbGljaycsIGVsLl9nd0V4cGFuZEhhbmRsZXIpOwogIGVsLl9nd0V4cGFuZEhhbmRsZXIgPSBmdW5jdGlvbihldikgewogICAgaWYgKGV2LnRhcmdldC5jbGFzc0xpc3QuY29udGFpbnMoJ2d3LWV4cGFuZCcpKSB7CiAgICAgIHZhciByb3cgPSBldi50YXJnZXQuY2xvc2VzdCgnLmdhdGV3YXktcm93Jyk7CiAgICAgIHZhciBwbEVsID0gcm93ID8gcm93Lm5leHRFbGVtZW50U2libGluZyA6IG51bGw7CiAgICAgIGlmIChwbEVsICYmIHBsRWwuY2xhc3NMaXN0LmNvbnRhaW5zKCdndy1wbGF0Zm9ybXMnKSkgewogICAgICAgIHBsRWwuY2xhc3NMaXN0LnRvZ2dsZSgnb3BlbicpOwogICAgICAgIHZhciBhY3RpdmUgPSBwbEVsLmNsYXNzTGlzdC5jb250YWlucygnb3BlbicpOwogICAgICAgIHZhciBjb25uZWN0ZWQgPSBwbEVsLnF1ZXJ5U2VsZWN0b3JBbGwoJy5ndy1wbC1kb3QuY29ubmVjdGVkJykubGVuZ3RoOwogICAgICAgIHZhciB0b3RhbCA9IHBsRWwucXVlcnlTZWxlY3RvckFsbCgnLmd3LXBsYXRmb3JtLXJvdycpLmxlbmd0aCAtIDE7CiAgICAgICAgZXYudGFyZ2V0LnRleHRDb250ZW50ID0gYWN0aXZlID8gJ3BsYXRmb3JteSDilrwnIDogKCdwbGF0Zm9ybXkgJyArIGNvbm5lY3RlZCArICcvJyArIHRvdGFsKTsKICAgICAgfQogICAgfQogIH07CiAgZWwuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCBlbC5fZ3dFeHBhbmRIYW5kbGVyKTsKfQoKLy8gPT09PT0gUkVOREVSOiBGT09URVIgPT09PT0KZnVuY3Rpb24gcmVuZGVyRm9vdGVyKGtleXNEYXRhLCBrYW5iYW5EYXRhLCBzdGF0dXNEYXRhKSB7CiAgLy8gS2V5cyAoYWdncmVnYXRlZCBmcm9tIGFsbCBwcm9maWxlcykKICBjb25zdCBrZXlzRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZm9vdGVyLWtleXMnKTsKICBpZiAoa2V5c0RhdGEgJiYgIWtleXNEYXRhLl9lcnJvciAmJiBrZXlzRGF0YS5hcGlfa2V5c19zZXQ/Lmxlbmd0aCkgewogICAga2V5c0VsLmlubmVySFRNTCA9IGtleXNEYXRhLmFwaV9rZXlzX3NldC5tYXAoayA9PiAnPHNwYW4gY2xhc3M9ImtleS1jaGlwIj4nICsgZXNjYXBlSHRtbChrKSArICc8L3NwYW4+Jykuam9pbignJyk7CiAgfSBlbHNlIHsKICAgIGtleXNFbC5pbm5lckhUTUwgPSAnPGRpdiBjbGFzcz0iYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRNdXRlZCkiPkJyYWsgZGFueWNoPC9kaXY+JzsKICB9CgogIC8vIEthbmJhbgogIGNvbnN0IGthbmJhbkVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2Zvb3Rlci1rYW5iYW4nKTsKICBpZiAoa2FuYmFuRGF0YSAmJiAha2FuYmFuRGF0YS5fZXJyb3IgJiYga2FuYmFuRGF0YS50YXNrc19ieV9zdGF0dXMpIHsKICAgIGNvbnN0IHMgPSBrYW5iYW5EYXRhLnRhc2tzX2J5X3N0YXR1czsKICAgIGthbmJhbkVsLmlubmVySFRNTCA9ICcnCiAgICAgICsgJzxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6dmFyKC0tc3BhY2UtbWQpO2ZsZXgtd3JhcDp3cmFwIj4nCiAgICAgICsgJzxkaXY+PHNwYW4gY2xhc3M9ImJhZGdlIG9rIj5kb25lPC9zcGFuPiA8c3BhbiBjbGFzcz0ibWV0cmljLW1kIj4nICsgKHMuZG9uZXx8MCkgKyAnPC9zcGFuPjwvZGl2PicKICAgICAgKyAnPGRpdj48c3BhbiBjbGFzcz0iYmFkZ2UiIHN0eWxlPSJiYWNrZ3JvdW5kOiMxRTNBNUY7Y29sb3I6dmFyKC0tcHJpbWFyeSkiPnJ1bm5pbmc8L3NwYW4+IDxzcGFuIGNsYXNzPSJtZXRyaWMtbWQiPicgKyAocy5ydW5uaW5nfHwwKSArICc8L3NwYW4+PC9kaXY+JwogICAgICArICc8ZGl2PjxzcGFuIGNsYXNzPSJiYWRnZSIgc3R5bGU9ImJhY2tncm91bmQ6dmFyKC0tYmdIb3Zlcik7Y29sb3I6dmFyKC0tdGV4dFNlY29uZGFyeSkiPnRvZG88L3NwYW4+IDxzcGFuIGNsYXNzPSJtZXRyaWMtbWQiPicgKyAocy50b2RvfHwwKSArICc8L3NwYW4+PC9kaXY+JwogICAgICArICc8ZGl2PjxzcGFuIGNsYXNzPSJiYWRnZSB3YXJuIj5ibG9ja2VkPC9zcGFuPiA8c3BhbiBjbGFzcz0ibWV0cmljLW1kIj4nICsgKHMuYmxvY2tlZHx8MCkgKyAnPC9zcGFuPjwvZGl2PicKICAgICAgKyAnPC9kaXY+JzsKICB9IGVsc2UgewogICAga2FuYmFuRWwuaW5uZXJIVE1MID0gJzxkaXYgY2xhc3M9ImJvZHktc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0TXV0ZWQpIj5CcmFrIGRhbnljaDwvZGl2Pic7CiAgfQoKICAvLyBTeXN0ZW0gaW5mbwogIGNvbnN0IHN5c0VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2Zvb3Rlci1zeXN0ZW0nKTsKICBjb25zdCBzdW1tYXJ5ID0gc3RhdHVzRGF0YT8uc3VtbWFyeSB8fCB7fTsKICBzeXNFbC5pbm5lckhUTUwgPSAnJwogICAgKyAnPGRpdiBjbGFzcz0iYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRTZWNvbmRhcnkpIj5Qcm9maWxpOiA8c3BhbiBjbGFzcz0ibW9uby1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRQcmltYXJ5KSI+JyArIChzdW1tYXJ5LnByb2ZpbGVzX3RvdGFsfHwnLS0nKSArICc8L3NwYW4+PC9kaXY+JwogICAgKyAnPGRpdiBjbGFzcz0iYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRTZWNvbmRhcnkpIj5Ba3R5d25lIGFnZW50eTogPHNwYW4gY2xhc3M9Im1vbm8tc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0UHJpbWFyeSkiPicgKyAoc3VtbWFyeS5hY3RpdmVfYWdlbnRzfHwwKSArICc8L3NwYW4+PC9kaXY+JwogICAgKyAnPGRpdiBjbGFzcz0iYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRTZWNvbmRhcnkpIj5CYWNrZW5kOiA8c3BhbiBjbGFzcz0ibW9uby1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRQcmltYXJ5KSI+MTI3LjAuMC4xOjkxMTg8L3NwYW4+PC9kaXY+JwogICAgKyAnPGRpdiBjbGFzcz0iYm9keS1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRTZWNvbmRhcnkpIj5PZHN3aWV6YW5pZTogPHNwYW4gY2xhc3M9Im1vbm8tc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0UHJpbWFyeSkiPicgKyAoUkVGUkVTSF9PUFRJT05TW1JFRlJFU0hfSU5URVJWQUxdIHx8IChSRUZSRVNIX0lOVEVSVkFMLzEwMDApKydzJykgKyAnPC9zcGFuPjwvZGl2PicKICAgICsgJzxkaXYgY2xhc3M9ImJvZHktc20iIHN0eWxlPSJjb2xvcjp2YXIoLS10ZXh0U2Vjb25kYXJ5KSI+TGF5b3V0OiA8c3BhbiBjbGFzcz0ibW9uby1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHRQcmltYXJ5KSIgaWQ9InN5cy1sYXlvdXQiPicgKyAoZG9jdW1lbnQuYm9keS5nZXRBdHRyaWJ1dGUoJ2RhdGEtbGF5b3V0JykgPT09ICdwaXBib3knID8gJ1BpcC1Cb3knIDogJ0hlcm1lcycpICsgJzwvc3Bhbj48L2Rpdj4nOwp9CgovLyA9PT09PSBNQUlOIFJFRlJFU0ggPT09PT0KYXN5bmMgZnVuY3Rpb24gcmVmcmVzaEFsbCgpIHsKICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpOwogIGNvbnN0IGNldCA9IG5ldyBEYXRlKG5vdy50b0xvY2FsZVN0cmluZygnZW4tVVMnLCB7dGltZVpvbmU6J0V1cm9wZS9XYXJzYXcnfSkpOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdsYXN0LXJlZnJlc2gnKS50ZXh0Q29udGVudCA9CiAgICBjZXQudG9Mb2NhbGVEYXRlU3RyaW5nKCdwbC1QTCcsIHtkYXk6JzItZGlnaXQnLG1vbnRoOicyLWRpZ2l0J30pICsgJyAnICsKICAgIGNldC50b0xvY2FsZVRpbWVTdHJpbmcoJ3BsLVBMJywge2hvdXI6JzItZGlnaXQnLG1pbnV0ZTonMi1kaWdpdCd9KSArICcgQ0VUJzsKCiAgLy8gUmVzZXQgbGljem5payBvZMWbd2llxbxhbmlhIOKAlCBwYXNlayB6YWN6eW5hIG9kbWllcnphxIcgb2Qgbm93YQogIGxhc3RSZWZyZXNoQXQgPSBEYXRlLm5vdygpOwogIHVwZGF0ZVByb2dyZXNzQmFyKCk7CgogIHRyeSB7CiAgICAvLyBGZXRjaCBzbmFwc2hvdCAoYWxsIHByb2ZpbGVzLCBrZXlzLCBrYW5iYW4sIGFsZXJ0cyBpbiBvbmUgY2FsbCkKICAgIGNvbnN0IHNuYXBzaG90ID0gYXdhaXQgYXBpRmV0Y2goJy9hcGkvc25hcHNob3QnKTsKICAgIAogICAgaWYgKHNuYXBzaG90Ll9lcnJvcikgewogICAgICBzaG93VG9hc3QoJ0JhY2tlbmQgbmllIG9kcG93aWFkYTogJyArIHNuYXBzaG90Ll9lcnJvciwgJ2NyaXRpY2FsJyk7CiAgICAgIHJldHVybjsKICAgIH0KCiAgICAvLyBQb2thxbwgZGF0xJkgaSBnb2R6aW7EmSB6IGt0w7NyZWogcG9jaG9kesSFIGRhbmUKICAgIG1hcmtEYXRhVHMoc25hcHNob3QudHNfaXNvIHx8IG51bGwpOwogICAgCiAgICAvLyBFeHRyYWN0IGRhdGEgZnJvbSBzbmFwc2hvdAogICAgY29uc3Qgc3RhdHVzRGF0YSA9IHsKICAgICAgdHM6IHNuYXBzaG90LnRzLAogICAgICBzaWduYWxfYnJpZGdlOiBzbmFwc2hvdC5zaWduYWxfYnJpZGdlLAogICAgICBzdW1tYXJ5OiBzbmFwc2hvdC5zdW1tYXJ5LAogICAgICBwcm9maWxlczogKHNuYXBzaG90LnByb2ZpbGVzIHx8IFtdKS5tYXAoZnVuY3Rpb24ocCkgewogICAgICAgIHJldHVybiB7CiAgICAgICAgICBwcm9maWxlOiBwLnByb2ZpbGUsCiAgICAgICAgICBob21lOiBwLmhvbWUsCiAgICAgICAgICBnYXRld2F5OiBwLmdhdGV3YXksCiAgICAgICAgICBjcm9uX3RpY2tlcjogcC5jcm9uX3RpY2tlciwKICAgICAgICAgIHVzYWdlOiBwLnVzYWdlLAogICAgICAgICAgYXBpX2tleXNfc2V0OiBwLmFwaV9rZXlzX3NldAogICAgICAgIH07CiAgICAgIH0pCiAgICB9OwogICAgY29uc3Qga2FuYmFuRGF0YSA9IHNuYXBzaG90LmthbmJhbjsKICAgIGNvbnN0IGFsZXJ0c0RhdGEgPSBzbmFwc2hvdC5hbGVydHMgPyB7YWxlcnRzOiBzbmFwc2hvdC5hbGVydHN9IDogbnVsbDsKICAgIAogICAgLy8gQWdncmVnYXRlIGtleXMgYWNyb3NzIGFsbCBwcm9maWxlcyAoZGVkdXBsaWNhdGVkKQogICAgdmFyIGFsbEtleXMgPSB7fTsKICAgIChzbmFwc2hvdC5wcm9maWxlcyB8fCBbXSkuZm9yRWFjaChmdW5jdGlvbihwKSB7CiAgICAgIChwLmFwaV9rZXlzX3NldCB8fCBbXSkuZm9yRWFjaChmdW5jdGlvbihrKSB7IGFsbEtleXNba10gPSB0cnVlOyB9KTsKICAgIH0pOwogICAgY29uc3Qga2V5c0RhdGEgPSB7YXBpX2tleXNfc2V0OiBPYmplY3Qua2V5cyhhbGxLZXlzKS5zb3J0KCl9OwoKICAgIC8vIEZldGNoIHBlci1wcm9maWxlIHNlc3Npb25zIGFuZCB1c2FnZTsgd2hlbiBhIHByb2ZpbGUgaXMgc2VsZWN0ZWQsIG9ubHkgdGhhdCBvbmUKICAgIGxldCBwcm9maWxlcyA9IChzbmFwc2hvdC5wcm9maWxlcyB8fCBbXSkKICAgICAgLm1hcChmdW5jdGlvbihwKSB7IHJldHVybiBwLnByb2ZpbGU7IH0pCiAgICAgIC5maWx0ZXIoZnVuY3Rpb24ocCkgeyByZXR1cm4gIWFjdGl2ZVByb2ZpbGUgfHwgcCA9PT0gYWN0aXZlUHJvZmlsZTsgfSk7CiAgICBpZiAocHJvZmlsZXMubGVuZ3RoID09PSAwICYmIGFjdGl2ZVByb2ZpbGUpIHsKICAgICAgLy8gcmVxdWVzdCBwcm9maWxlIG5vdCBpbiBzbmFwc2hvdCDigJQgZmFsbCBiYWNrIHRvIGFsbAogICAgICBwcm9maWxlcyA9IChzbmFwc2hvdC5wcm9maWxlcyB8fCBbXSkubWFwKGZ1bmN0aW9uKHApIHsgcmV0dXJuIHAucHJvZmlsZTsgfSk7CiAgICB9CiAgICAvLyBVcGRhdGUgc2Vzc2lvbiBwYW5lbCBoZWFkZXIgdG8gcmVmbGVjdCB0aGUgZmlsdGVyCiAgICBjb25zdCBzZXNzaW9uSGVhZGVyID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvcignLnNlc3Npb25zLWNhcmQgLmhlYWRpbmctbWQnKTsKICAgIGlmIChzZXNzaW9uSGVhZGVyKSB7CiAgICAgIHNlc3Npb25IZWFkZXIudGV4dENvbnRlbnQgPSBhY3RpdmVQcm9maWxlCiAgICAgICAgPyAnT3N0YXRuaWUgc2VzamUgKHByb2ZpbDogJyArIGFjdGl2ZVByb2ZpbGUgKyAnKScKICAgICAgICA6ICdPc3RhdG5pZSBzZXNqZSAod3N6eXN0a2llIHByb2ZpbGUpJzsKICAgIH0KICAgIC8vIFVwZGF0ZSAiS2V5cyIgZm9vdGVyIGhlYWRlciB0byByZWZsZWN0IHRoZSBmaWx0ZXIKICAgIGNvbnN0IGtleXNIZWFkZXIgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCcjZm9vdGVyLXNlY3Rpb24gLmZvb3Rlci1jYXJkIC5mYy1oZWFkZXInKTsKICAgIGlmIChrZXlzSGVhZGVyKSB7CiAgICAgIGtleXNIZWFkZXIudGV4dENvbnRlbnQgPSBhY3RpdmVQcm9maWxlCiAgICAgICAgPyAnS2x1Y3plIEFQSSAocHJvZmlsOiAnICsgYWN0aXZlUHJvZmlsZSArICcpJwogICAgICAgIDogJ0tsdWN6ZSBBUEkgKHdzenlzdGtpZSBwcm9maWxlKSc7CiAgICB9CiAgICAKICAgIC8vIEZldGNoIHNlc3Npb25zIGZyb20gYWxsIHByb2ZpbGVzICh1cCB0byAxNSBwZXIgcHJvZmlsZSkKICAgIGNvbnN0IHNlc3Npb25zUmVzdWx0cyA9IGF3YWl0IFByb21pc2UuYWxsKAogICAgICBwcm9maWxlcy5tYXAoZnVuY3Rpb24ocCkgewogICAgICAgIHJldHVybiBhcGlGZXRjaCgnL2FwaS9zZXNzaW9ucz9wcm9maWxlPScgKyBlbmNvZGVVUklDb21wb25lbnQocCkgKyAnJmxpbWl0PTE1Jyk7CiAgICAgIH0pCiAgICApOwogICAgLy8gTWVyZ2UgYWxsIHNlc3Npb25zLCBzb3J0IGJ5IGxhc3RfYWN0aXZpdHkgZGVzYwogICAgdmFyIGFsbFNlc3Npb25zID0gW107CiAgICBzZXNzaW9uc1Jlc3VsdHMuZm9yRWFjaChmdW5jdGlvbihyZXN1bHQsIGlkeCkgewogICAgICBpZiAocmVzdWx0ICYmICFyZXN1bHQuX2Vycm9yICYmIHJlc3VsdC5zZXNzaW9ucykgewogICAgICAgIHJlc3VsdC5zZXNzaW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHMpIHsKICAgICAgICAgIHMuX3Byb2ZpbGUgPSBwcm9maWxlc1tpZHhdOwogICAgICAgICAgYWxsU2Vzc2lvbnMucHVzaChzKTsKICAgICAgICB9KTsKICAgICAgfQogICAgfSk7CiAgICBhbGxTZXNzaW9ucy5zb3J0KGZ1bmN0aW9uKGEsIGIpIHsKICAgICAgdmFyIGRhID0gYS5sYXN0X2FjdGl2aXR5X2F0ID8gbmV3IERhdGUoYS5sYXN0X2FjdGl2aXR5X2F0KS5nZXRUaW1lKCkgOiAwOwogICAgICB2YXIgZGIgPSBiLmxhc3RfYWN0aXZpdHlfYXQgPyBuZXcgRGF0ZShiLmxhc3RfYWN0aXZpdHlfYXQpLmdldFRpbWUoKSA6IDA7CiAgICAgIHJldHVybiBkYiAtIGRhOwogICAgfSk7CiAgICBjb25zdCBzZXNzaW9uc0RhdGEgPSB7c2Vzc2lvbnM6IGFsbFNlc3Npb25zLnNsaWNlKDAsIDEwKX07CgogICAgLy8gRmV0Y2ggdXNhZ2UgZnJvbSBhbGwgcHJvZmlsZXMgZm9yIGNoYXJ0cyAoMTQgZGF5cykKICAgIGNvbnN0IHVzYWdlUmVzdWx0cyA9IGF3YWl0IFByb21pc2UuYWxsKAogICAgICBwcm9maWxlcy5tYXAoZnVuY3Rpb24ocCkgewogICAgICAgIHJldHVybiBhcGlGZXRjaCgnL2FwaS91c2FnZT9wcm9maWxlPScgKyBlbmNvZGVVUklDb21wb25lbnQocCkgKyAnJmRheXM9MTQnKTsKICAgICAgfSkKICAgICk7CiAgICAvLyBBZ2dyZWdhdGUgZGFpbHkgdXNhZ2UgYWNyb3NzIGFsbCBwcm9maWxlcwogICAgdmFyIGRhaWx5TWFwID0ge307CiAgICB2YXIgbW9kZWxNYXAgPSB7fTsKICAgIHZhciBwcm9maWxlVXNhZ2VNYXAgPSB7fTsgIC8vIHBlci1wcm9maWxlOiB7dG9rZW5zLCBjb3N0fQogICAgdXNhZ2VSZXN1bHRzLmZvckVhY2goZnVuY3Rpb24ocmVzdWx0KSB7CiAgICAgIGlmICghcmVzdWx0IHx8IHJlc3VsdC5fZXJyb3IpIHJldHVybjsKICAgICAgKHJlc3VsdC5kYWlseSB8fCBbXSkuZm9yRWFjaChmdW5jdGlvbihkYXkpIHsKICAgICAgICBpZiAoIWRhaWx5TWFwW2RheS5kYXldKSB7CiAgICAgICAgICBkYWlseU1hcFtkYXkuZGF5XSA9IHtkYXk6IGRheS5kYXksIHNlc3Npb25fY291bnQ6IDAsIHRva2Vuczoge2lucHV0OjAsIG91dHB1dDowLCByZWFzb25pbmc6MH0sIGNvc3Q6IHtlc3RpbWF0ZWRfdXNkOjAsIGFjdHVhbF91c2Q6MH19OwogICAgICAgIH0KICAgICAgICBkYWlseU1hcFtkYXkuZGF5XS5zZXNzaW9uX2NvdW50ICs9IGRheS5zZXNzaW9uX2NvdW50IHx8IDA7CiAgICAgICAgZGFpbHlNYXBbZGF5LmRheV0udG9rZW5zLmlucHV0ICs9IGRheS50b2tlbnMgPyAoZGF5LnRva2Vucy5pbnB1dCB8fCAwKSA6IDA7CiAgICAgICAgZGFpbHlNYXBbZGF5LmRheV0udG9rZW5zLm91dHB1dCArPSBkYXkudG9rZW5zID8gKGRheS50b2tlbnMub3V0cHV0IHx8IDApIDogMDsKICAgICAgICBkYWlseU1hcFtkYXkuZGF5XS50b2tlbnMucmVhc29uaW5nICs9IGRheS50b2tlbnMgPyAoZGF5LnRva2Vucy5yZWFzb25pbmcgfHwgMCkgOiAwOwogICAgICAgIGRhaWx5TWFwW2RheS5kYXldLmNvc3QuZXN0aW1hdGVkX3VzZCArPSBkYXkuY29zdCA/IChkYXkuY29zdC5lc3RpbWF0ZWRfdXNkIHx8IDApIDogMDsKICAgICAgfSk7CiAgICAgIChyZXN1bHQuYnlfbW9kZWwgfHwgW10pLmZvckVhY2goZnVuY3Rpb24obSkgewogICAgICAgIHZhciBrZXkgPSBtLm1vZGVsOwogICAgICAgIGlmICghbW9kZWxNYXBba2V5XSkgewogICAgICAgICAgbW9kZWxNYXBba2V5XSA9IHttb2RlbDogbS5tb2RlbCwgcHJvdmlkZXI6IG0ucHJvdmlkZXIsIGFwaV9jYWxsczowLCB0b2tlbnM6e2lucHV0OjAsIG91dHB1dDowLCByZWFzb25pbmc6MH0sIGVzdGltYXRlZF9jb3N0X3VzZDowfTsKICAgICAgICB9CiAgICAgICAgbW9kZWxNYXBba2V5XS5hcGlfY2FsbHMgKz0gbS5hcGlfY2FsbHMgfHwgMDsKICAgICAgICBtb2RlbE1hcFtrZXldLnRva2Vucy5pbnB1dCArPSBtLnRva2VucyA/IChtLnRva2Vucy5pbnB1dCB8fCAwKSA6IDA7CiAgICAgICAgbW9kZWxNYXBba2V5XS50b2tlbnMub3V0cHV0ICs9IG0udG9rZW5zID8gKG0udG9rZW5zLm91dHB1dCB8fCAwKSA6IDA7CiAgICAgICAgbW9kZWxNYXBba2V5XS50b2tlbnMucmVhc29uaW5nICs9IG0udG9rZW5zID8gKG0udG9rZW5zLnJlYXNvbmluZyB8fCAwKSA6IDA7CiAgICAgICAgbW9kZWxNYXBba2V5XS5lc3RpbWF0ZWRfY29zdF91c2QgKz0gbS5lc3RpbWF0ZWRfY29zdF91c2QgfHwgMDsKICAgICAgfSk7CiAgICB9KTsKICAgIC8vIEJ1aWxkIHBlci1wcm9maWxlIHVzYWdlIGZyb20gbGF0ZXN0IGRhaWx5IGRhdGEKICAgIHVzYWdlUmVzdWx0cy5mb3JFYWNoKGZ1bmN0aW9uKHJlc3VsdCwgaWR4KSB7CiAgICAgIHZhciBwcm9mID0gcHJvZmlsZXNbaWR4XTsKICAgICAgaWYgKCFwcm9mIHx8ICFyZXN1bHQgfHwgcmVzdWx0Ll9lcnJvcikgcmV0dXJuOwogICAgICB2YXIgdG90YWxUb2tlbnMgPSAwLCB0b3RhbENvc3QgPSAwOwogICAgICAocmVzdWx0LmRhaWx5IHx8IFtdKS5mb3JFYWNoKGZ1bmN0aW9uKGQpIHsKICAgICAgICB0b3RhbFRva2VucyArPSAoZC50b2tlbnM/LmlucHV0fHwwKSArIChkLnRva2Vucz8ub3V0cHV0fHwwKTsKICAgICAgICB0b3RhbENvc3QgKz0gZC5jb3N0Py5lc3RpbWF0ZWRfdXNkfHwwOwogICAgICB9KTsKICAgICAgcHJvZmlsZVVzYWdlTWFwW3Byb2ZdID0ge3Rva2VuczogdG90YWxUb2tlbnMsIGNvc3Q6IHRvdGFsQ29zdH07CiAgICB9KTsKICAgIHZhciBkYWlseUFyciA9IFtdOwogICAgZm9yICh2YXIgZCBpbiBkYWlseU1hcCkgZGFpbHlBcnIucHVzaChkYWlseU1hcFtkXSk7CiAgICBkYWlseUFyci5zb3J0KGZ1bmN0aW9uKGEsIGIpIHsgcmV0dXJuIGEuZGF5LmxvY2FsZUNvbXBhcmUoYi5kYXkpOyB9KTsKICAgIHZhciBtb2RlbEFyciA9IFtdOwogICAgZm9yICh2YXIgbWsgaW4gbW9kZWxNYXApIG1vZGVsQXJyLnB1c2gobW9kZWxNYXBbbWtdKTsKICAgIG1vZGVsQXJyLnNvcnQoZnVuY3Rpb24oYSwgYikgeyByZXR1cm4gYi5lc3RpbWF0ZWRfY29zdF91c2QgLSBhLmVzdGltYXRlZF9jb3N0X3VzZDsgfSk7CiAgICBjb25zdCB1c2FnZURhdGEgPSB7ZGFpbHk6IGRhaWx5QXJyLCBieV9tb2RlbDogbW9kZWxBcnIsIF9wcm9maWxlVXNhZ2U6IHByb2ZpbGVVc2FnZU1hcH07CgogICAgcmVuZGVyU3RhdHVzU3RyaXAoc3RhdHVzRGF0YSk7CiAgICByZW5kZXJQcm9maWxlQ2FyZHMoc3RhdHVzRGF0YSwgc2Vzc2lvbnNEYXRhLCB1c2FnZURhdGEpOwogICAgcmVuZGVyS3BpR3JpZChzdGF0dXNEYXRhLCB1c2FnZURhdGEsIHNlc3Npb25zRGF0YSwga2FuYmFuRGF0YSwgYWxlcnRzRGF0YSwga2V5c0RhdGEpOwogICAgcmVuZGVyU2Vzc2lvbnMoc2Vzc2lvbnNEYXRhKTsKICAgIHJlbmRlckdhdGV3YXkoc3RhdHVzRGF0YSk7CiAgICByZW5kZXJGb290ZXIoa2V5c0RhdGEsIGthbmJhbkRhdGEsIHN0YXR1c0RhdGEpOwoKICAgIC8vIENoYXJ0cwogICAgcmVuZGVyVXNhZ2VDaGFydCh1c2FnZURhdGEpOwogICAgcmVuZGVyTW9kZWxzQ2hhcnQodXNhZ2VEYXRhKTsKICB9IGNhdGNoKGUpIHsKICAgIHNob3dUb2FzdCgnQmxhZCBvZHN3aWV6YW5pYTogJyArIGUubWVzc2FnZSwgJ2NyaXRpY2FsJyk7CiAgfQp9CgovLyA9PT09PSBJTklUID09PT09CmZ1bmN0aW9uIGluaXQoKSB7CiAgLy8gSW5pdCBsYXlvdXQgc3dpdGNoZXIKICBpbml0TGF5b3V0U3dpdGNoZXIoKTsKCiAgLy8gUmVmcmVzaCBjb250cm9sczogbWFudWFsIHJlZnJlc2ggYnV0dG9uICsgaW50ZXJ2YWwgc2VsZWN0b3IKICBjb25zdCByZWZyZXNoU2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3JlZnJlc2gtaW50ZXJ2YWwnKTsKICByZWZyZXNoU2VsZWN0LnZhbHVlID0gU3RyaW5nKFJFRlJFU0hfSU5URVJWQUwpOwogIHJlZnJlc2hTZWxlY3QuYWRkRXZlbnRMaXN0ZW5lcignY2hhbmdlJywgZnVuY3Rpb24oKSB7CiAgICBSRUZSRVNIX0lOVEVSVkFMID0gcGFyc2VJbnQocmVmcmVzaFNlbGVjdC52YWx1ZSwgMTApIHx8IDkwMDsKICAgIGlmIChyZWZyZXNoVGltZXIpIGNsZWFySW50ZXJ2YWwocmVmcmVzaFRpbWVyKTsKICAgIHJlZnJlc2hUaW1lciA9IHNldEludGVydmFsKHJlZnJlc2hBbGwsIFJFRlJFU0hfSU5URVJWQUwgKiAxMDAwKTsKICAgIC8vIFptaWFuYSBpbnRlcndhxYJ1IHJlc2V0dWplIGxpY3puaWsg4oCUIHBhc2VrIG9kbWllcnphIG9kIG5vd2Egd3pnbMSZZGVtIG5vd2VnbyBpbnRlcndhxYJ1CiAgICBsYXN0UmVmcmVzaEF0ID0gRGF0ZS5ub3coKTsKICAgIHVwZGF0ZVByb2dyZXNzQmFyKCk7CiAgICBzaG93VG9hc3QoJ09kc3dpZXphbmllIGNvICcgKyAoUkVGUkVTSF9PUFRJT05TW1JFRlJFU0hfSU5URVJWQUxdIHx8IChSRUZSRVNIX0lOVEVSVkFMLzEwMDApKydzJyksICcnKTsKICB9KTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbWFudWFsLXJlZnJlc2gnKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGZ1bmN0aW9uKCkgewogICAgLy8gUmVzZXQgZG8gZG9tecWbbG5lZ28gaW50ZXJ3YcWCdSAxNSBtaW4KICAgIFJFRlJFU0hfSU5URVJWQUwgPSA5MDA7CiAgICBjb25zdCByZWZyZXNoU2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3JlZnJlc2gtaW50ZXJ2YWwnKTsKICAgIHJlZnJlc2hTZWxlY3QudmFsdWUgPSAnOTAwJzsKICAgIGlmIChyZWZyZXNoVGltZXIpIGNsZWFySW50ZXJ2YWwocmVmcmVzaFRpbWVyKTsKICAgIHJlZnJlc2hUaW1lciA9IHNldEludGVydmFsKHJlZnJlc2hBbGwsIFJFRlJFU0hfSU5URVJWQUwgKiAxMDAwKTsKICAgIGxhc3RSZWZyZXNoQXQgPSBEYXRlLm5vdygpOwogICAgdXBkYXRlUHJvZ3Jlc3NCYXIoKTsKICAgIC8vIFBvYmllcnogYWt0dWFsbmUgZGFuZQogICAgcmVmcmVzaEFsbCgpOwogICAgc2hvd1RvYXN0KCdPZHN3aWV6YW5pZSBjbyAxNSBtaW4gKGRvbXlzbG5lKScsICcnKTsKICB9KTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYWxsLXByb2ZpbGVzLWJ0bicpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgZnVuY3Rpb24oKSB7CiAgICBhY3RpdmVQcm9maWxlID0gbnVsbDsKICAgIHRoaXMuc3R5bGUuZGlzcGxheSA9ICdub25lJzsKICAgIHJlZnJlc2hBbGwoKTsKICB9KTsKCiAgLy8gU2hvdyBsb2FkaW5nIHNrZWxldG9ucwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdrcGktZ3JpZCcpLmlubmVySFRNTCA9IEFycmF5KDgpLmZpbGwoJzxkaXYgY2xhc3M9Im1ldHJpYy10aWxlIj48ZGl2IGNsYXNzPSJza2VsZXRvbiBza2VsZXRvbi10ZXh0Ij48L2Rpdj48ZGl2IGNsYXNzPSJza2VsZXRvbiBza2VsZXRvbi12YWx1ZSI+PC9kaXY+PGRpdiBjbGFzcz0ic2tlbGV0b24gc2tlbGV0b24tdGV4dCIgc3R5bGU9IndpZHRoOjQwJSI+PC9kaXY+PC9kaXY+Jykuam9pbignJyk7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3Nlc3Npb25zLWxpc3QnKS5pbm5lckhUTUwgPSAnPGRpdiBjbGFzcz0ic3RhdGUtbXNnIiBzdHlsZT0ibWluLWhlaWdodDoxNTBweCI+PGRpdiBjbGFzcz0iZGVzYyBib2R5LXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dE11dGVkKSI+TGFkb3dhbmllLi4uPC9kaXY+PC9kaXY+JzsKCiAgLy8gU2tlbGV0b24gY2hpcHMgZm9yIHN0YXR1cyBzdHJpcAogIGNvbnN0IHNrZWxldG9uQ2hpcHMgPSBBcnJheSg2KS5maWxsKCc8ZGl2IGNsYXNzPSJzdGF0dXMtY2hpcCBza2VsZXRvbi1jaGlwIj48ZGl2IGNsYXNzPSJza2VsZXRvbiIgc3R5bGU9IndpZHRoOjhweDtoZWlnaHQ6OHB4O2JvcmRlci1yYWRpdXM6NTAlO2ZsZXgtc2hyaW5rOjAiPjwvZGl2PjxkaXYgY2xhc3M9InNrZWxldG9uIHNrZWxldG9uLXRleHQiIHN0eWxlPSJ3aWR0aDo2MHB4O2hlaWdodDowLjc1cmVtO21hcmdpbjowIj48L2Rpdj48L2Rpdj4nKS5qb2luKCcnKTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3RhdHVzLXN0cmlwLWlubmVyJykuaW5uZXJIVE1MID0gc2tlbGV0b25DaGlwczsKCiAgLy8gU2tlbGV0b24gY2FyZHMgZm9yIHByb2ZpbGUgY2FyZHMgc2VjdGlvbgogIGNvbnN0IHNrZWxldG9uQ2FyZHMgPSBBcnJheSg3KS5maWxsKCc8ZGl2IGNsYXNzPSJwcm9maWxlLWNhcmQgc2tlbGV0b24tY2FyZCI+PGRpdiBjbGFzcz0icGMtaGVhZGVyIj48ZGl2IGNsYXNzPSJza2VsZXRvbiIgc3R5bGU9IndpZHRoOjEwcHg7aGVpZ2h0OjEwcHg7Ym9yZGVyLXJhZGl1czo1MCU7ZmxleC1zaHJpbms6MCI+PC9kaXY+PGRpdiBjbGFzcz0ic2tlbGV0b24gc2tlbGV0b24tdGV4dCIgc3R5bGU9IndpZHRoOjcwcHg7aGVpZ2h0OjAuOXJlbTttYXJnaW46MCI+PC9kaXY+PC9kaXY+PGRpdiBjbGFzcz0icGMtbWV0YSI+PGRpdiBjbGFzcz0ic2tlbGV0b24gc2tlbGV0b24tdGV4dCIgc3R5bGU9IndpZHRoOjkwcHg7aGVpZ2h0OjAuN3JlbTttYXJnaW46MCI+PC9kaXY+PGRpdiBjbGFzcz0ic2tlbGV0b24gc2tlbGV0b24tdGV4dCIgc3R5bGU9IndpZHRoOjYwcHg7aGVpZ2h0OjAuN3JlbTttYXJnaW46MCI+PC9kaXY+PGRpdiBjbGFzcz0ic2tlbGV0b24gc2tlbGV0b24tdGV4dCIgc3R5bGU9IndpZHRoOjgwcHg7aGVpZ2h0OjAuN3JlbTttYXJnaW46MCI+PC9kaXY+PC9kaXY+PC9kaXY+Jykuam9pbignJyk7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3Byb2ZpbGUtY2FyZHMtZ3JpZCcpLmlubmVySFRNTCA9IHNrZWxldG9uQ2FyZHM7CgogIC8vIEluaXRpYWwgbG9hZAogIHJlZnJlc2hBbGwoKTsKCiAgLy8gQXV0by1yZWZyZXNoIChSRUZSRVNIX0lOVEVSVkFMIGplc3QgdyBTRUtVTkRBQ0g7IHNldEludGVydmFsIHBvdHJ6ZWJ1amUgbXMpCiAgcmVmcmVzaFRpbWVyID0gc2V0SW50ZXJ2YWwocmVmcmVzaEFsbCwgUkVGUkVTSF9JTlRFUlZBTCAqIDEwMDApOwoKICAvLyBDb3VudGRvd24gcHJvZ3Jlc3MgYmFyCiAgc3RhcnRQcm9ncmVzc1RpbWVyKCk7CgogIC8vIFJlc2l6ZSBjaGFydHMgb24gd2luZG93IHJlc2l6ZQogIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdyZXNpemUnLCBmdW5jdGlvbigpIHsKICAgIGlmICh1c2FnZUNoYXJ0KSB1c2FnZUNoYXJ0LnJlc2l6ZSgpOwogICAgaWYgKG1vZGVsc0NoYXJ0KSBtb2RlbHNDaGFydC5yZXNpemUoKTsKICB9KTsKfQoKZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignRE9NQ29udGVudExvYWRlZCcsIGluaXQpOwo8L3NjcmlwdD4KPC9ib2R5Pgo8L2h0bWw+"

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