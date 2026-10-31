"""SQLite access and domain writes — CyberAudit 3.10.5 tenant-aware."""

from __future__ import annotations

import datetime
import json
import logging
import sqlite3
from pathlib import Path
from typing import Any, Optional

from cyberaudit import config

logger = logging.getLogger("CyberAuditDashboard")

_socketio = None


def set_socketio(sio) -> None:
    global _socketio
    _socketio = sio


def _db_path() -> Path:
    try:
        from cyberaudit.tenant_context import resolve_db_path
        p = Path(resolve_db_path())
    except Exception:
        p = Path(config.DB_PATH)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return p


def init_db() -> None:
    path = _db_path()
    with sqlite3.connect(str(path)) as conn:
        c = conn.cursor()
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE,
                start_time TEXT,
                end_time TEXT,
                target TEXT,
                status TEXT,
                findings_count INTEGER DEFAULT 0,
                high_severity INTEGER DEFAULT 0,
                medium_severity INTEGER DEFAULT 0,
                low_severity INTEGER DEFAULT 0,
                compliance_score REAL,
                report_path TEXT,
                notes TEXT
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS live_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                module TEXT,
                event_type TEXT,
                severity TEXT,
                message TEXT,
                details TEXT
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS module_status (
                module_name TEXT PRIMARY KEY,
                status TEXT,
                last_run TEXT,
                last_result TEXT,
                version TEXT
            )
            """
        )
        for stmt in (
            "ALTER TABLE live_events ADD COLUMN acknowledged INTEGER DEFAULT 0",
            "ALTER TABLE live_events ADD COLUMN acknowledged_by TEXT DEFAULT ''",
            "ALTER TABLE live_events ADD COLUMN acknowledged_at TEXT DEFAULT ''",
        ):
            try:
                c.execute(stmt)
            except sqlite3.OperationalError:
                pass
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                host TEXT,
                port TEXT,
                severity TEXT,
                title TEXT,
                cve TEXT,
                cma_section TEXT,
                evidence TEXT,
                status TEXT DEFAULT 'open',
                created_at TEXT
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT UNIQUE,
                target TEXT,
                requested_by TEXT,
                status TEXT,
                created_at TEXT,
                notes TEXT,
                claimed_by TEXT DEFAULT '',
                claimed_at TEXT DEFAULT '',
                heartbeat_at TEXT DEFAULT '',
                attempt INTEGER DEFAULT 0,
                max_attempts INTEGER DEFAULT 3,
                payload_hash TEXT DEFAULT '',
                session_id TEXT DEFAULT '',
                last_error TEXT DEFAULT '',
                finished_at TEXT DEFAULT ''
            )
            """
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_live_events_ts ON live_events(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id)")
        conn.commit()
    try:
        from cyberaudit.phase1_db import migrate_phase1
        migrate_phase1()
    except Exception as exc:
        logger.warning("phase1 migrate skipped: %s", exc)
    try:
        from cyberaudit.phase5_db import migrate_phase5
        migrate_phase5()
    except Exception as exc:
        logger.warning("phase5 migrate skipped: %s", exc)


def get_db():
    """Open SQLite connection for the active tenant (or default when no tenant scope)."""
    path = _db_path()
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def db_is_empty() -> bool:
    with get_db() as conn:
        return conn.execute("SELECT COUNT(*) FROM module_status").fetchone()[0] == 0


def insert_live_event(
    module: str,
    message: str,
    severity: str = "info",
    event_type: str = "info",
    details: Any = None,
    timestamp: Optional[str] = None,
) -> dict:
    ts = timestamp or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sev = (severity or "info").lower()
    if sev not in ("info", "low", "medium", "high", "critical"):
        sev = "info"
    et = event_type or ("alert" if sev in ("high", "critical") else "info")
    if isinstance(details, (dict, list)):
        details_s = json.dumps(details)
    elif details is None:
        details_s = "{}"
    else:
        details_s = str(details)
    mod = (module or "unknown")[:128]
    msg = (message or "")[:2000]
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO live_events (timestamp, module, event_type, severity, message, details) VALUES (?,?,?,?,?,?)",
            (ts, mod, et, sev, msg, details_s),
        )
        conn.commit()
        row_id = cur.lastrowid
    event = {
        "id": row_id,
        "timestamp": ts,
        "module": mod,
        "event_type": et,
        "severity": sev,
        "message": msg,
        "details": details_s,
        "acknowledged": 0,
    }
    if _socketio:
        try:
            _socketio.emit("live_event", event)
        except Exception as exc:
            logger.debug("socket emit skipped: %s", exc)
    return event


def upsert_module_status(
    module_name: str,
    status: str = "idle",
    last_result: str = "",
    version: str = "",
    last_run: Optional[str] = None,
) -> dict:
    name = (module_name or "").strip()
    if not name:
        raise ValueError("module_name required")
    lr = last_run or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st = (status or "idle")[:64]
    with get_db() as conn:
        conn.execute(
            "INSERT INTO module_status (module_name, status, last_run, last_result, version) VALUES (?,?,?,?,?) "
            "ON CONFLICT(module_name) DO UPDATE SET status=excluded.status, last_run=excluded.last_run, "
            "last_result=excluded.last_result, version=COALESCE(NULLIF(excluded.version,''), module_status.version)",
            (name, st, lr, (last_result or "")[:2000], (version or "")[:64]),
        )
        conn.commit()
    return {
        "module_name": name,
        "status": st,
        "last_run": lr,
        "last_result": last_result or "",
        "version": version or "",
    }


def upsert_audit_session(payload: dict) -> dict:
    sid = (payload.get("session_id") or "").strip()
    if not sid:
        raise ValueError("session_id required")
    fields = {
        "session_id": sid,
        "start_time": payload.get("start_time")
        or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "end_time": payload.get("end_time") or "",
        "target": payload.get("target") or "",
        "status": payload.get("status") or "running",
        "findings_count": int(payload.get("findings_count") or 0),
        "high_severity": int(payload.get("high_severity") or 0),
        "medium_severity": int(payload.get("medium_severity") or 0),
        "low_severity": int(payload.get("low_severity") or 0),
        "compliance_score": float(payload.get("compliance_score") or 0),
        "report_path": payload.get("report_path") or "",
        "notes": payload.get("notes") or "",
    }
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO audit_sessions (
                session_id, start_time, end_time, target, status,
                findings_count, high_severity, medium_severity, low_severity,
                compliance_score, report_path, notes
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(session_id) DO UPDATE SET
                start_time=excluded.start_time, end_time=excluded.end_time,
                target=excluded.target, status=excluded.status,
                findings_count=excluded.findings_count,
                high_severity=excluded.high_severity,
                medium_severity=excluded.medium_severity,
                low_severity=excluded.low_severity,
                compliance_score=excluded.compliance_score,
                report_path=excluded.report_path, notes=excluded.notes
            """,
            tuple(fields.values()),
        )
        conn.commit()
    return fields


def insert_finding(data: dict) -> int:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    evidence = data.get("evidence")
    if isinstance(evidence, (dict, list)):
        evidence = json.dumps(evidence)
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO findings
               (session_id, host, port, severity, title, cve, cma_section, evidence, status, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                data.get("session_id") or "",
                data.get("host") or "",
                str(data.get("port") or ""),
                data.get("severity") or "medium",
                data.get("title") or data.get("message") or "",
                data.get("cve") or "",
                data.get("cma_section") or "",
                evidence or "",
                data.get("status") or "open",
                data.get("created_at") or now,
            ),
        )
        conn.commit()
        return cur.lastrowid


def prune_old_events() -> int:
    if config.EVENT_RETENTION_DAYS <= 0:
        return 0
    cutoff = (
        datetime.datetime.now() - datetime.timedelta(days=config.EVENT_RETENTION_DAYS)
    ).strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        cur = conn.execute("DELETE FROM live_events WHERE timestamp < ?", (cutoff,))
        conn.commit()
        return cur.rowcount
