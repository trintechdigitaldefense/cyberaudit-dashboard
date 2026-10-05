"""SQLite access and domain writes."""

from __future__ import annotations

import datetime
import json
import logging
import sqlite3
from typing import Any, Optional

from cyberaudit import config

logger = logging.getLogger("CyberAuditDashboard")

_socketio = None


def set_socketio(sio) -> None:
    global _socketio
    _socketio = sio


def init_db() -> None:
    with sqlite3.connect(config.DB_PATH) as conn:
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
                notes TEXT
            )
            """
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_live_events_ts ON live_events(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_live_events_id ON live_events(id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id)")
        conn.commit()


def get_db():
    conn = sqlite3.connect(config.DB_PATH, timeout=30)
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


def seed_sample_data() -> None:
    with get_db() as conn:
        c = conn.cursor()
        modules = [
            ("nmap_module", "idle", "2026-08-29 18:12:00", "Ports 22,80,443 open", "1.4.2"),
            ("openvas_module", "idle", "2026-08-29 18:15:30", "3 high, 7 medium findings", "2.0.1"),
            ("tt_compliance_mapper", "idle", "2026-08-29 18:16:00", "Mapped to CMA s.3,6,7", "1.2.0"),
            ("regional_threat_intel", "running", "2026-08-29 21:40:00", "Pulling TT-CSIRT feed", "1.1.3"),
            ("patch_verification_module", "idle", "2026-08-29 17:55:00", "Baseline matched", "1.0.8"),
            ("pdf_report_module", "idle", "2026-08-29 18:20:00", "Report generated", "1.3.0"),
            ("incident_response_module", "idle", "2026-08-28 14:00:00", "No active IR", "1.1.0"),
            ("data_exfiltration_module", "running", "2026-08-29 21:45:00", "Monitoring outbound flows", "1.0.5"),
            ("continuous_ids_module", "running", "2026-08-29 21:50:00", "Log analysis active", "1.2.1"),
            ("database_module", "idle", "2026-08-29 18:21:00", "Session archived", "1.0.2"),
            ("diagnostics_module", "idle", "2026-08-29 16:00:00", "All binaries OK", "1.0.0"),
        ]
        for m in modules:
            c.execute("INSERT OR REPLACE INTO module_status VALUES (?,?,?,?,?)", m)
        sessions = [
            (
                "AUD-20260829-001",
                "2026-08-29 17:30:00",
                "2026-08-29 18:22:00",
                "192.168.10.0/24",
                "completed",
                14,
                3,
                7,
                4,
                78.5,
                "reports/CyberAudit_Report_AUD-20260829-001.pdf",
                "Full internal subnet scan.",
            ),
        ]
        for s in sessions:
            c.execute(
                """INSERT OR IGNORE INTO audit_sessions
                   (session_id, start_time, end_time, target, status,
                    findings_count, high_severity, medium_severity, low_severity,
                    compliance_score, report_path, notes)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                s,
            )
        findings = [
            (
                "AUD-20260829-001",
                "192.168.10.12",
                "443",
                "high",
                "Outdated TLS / weak cipher suite",
                "CVE-2021-3450",
                "Section 6",
                "{}",
                "open",
                "2026-08-29 18:10:00",
            ),
            (
                "AUD-20260829-001",
                "192.168.10.12",
                "22",
                "medium",
                "SSH password auth enabled",
                "",
                "Section 3",
                "{}",
                "open",
                "2026-08-29 18:11:00",
            ),
            (
                "AUD-20260829-001",
                "192.168.10.45",
                "80",
                "high",
                "Unauthenticated admin panel",
                "",
                "Section 7",
                "{}",
                "open",
                "2026-08-29 18:15:00",
            ),
        ]
        for f in findings:
            c.execute(
                """INSERT INTO findings
                   (session_id, host, port, severity, title, cve, cma_section, evidence, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                f,
            )
        conn.commit()
