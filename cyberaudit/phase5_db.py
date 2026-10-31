"""Phase 5 job-control schema + backup — tenant-aware."""
from __future__ import annotations

import logging
import shutil
import sqlite3
from pathlib import Path

logger = logging.getLogger("CyberAuditDashboard")


def migrate_phase5() -> None:
    from cyberaudit.db import _db_path

    path = _db_path()
    conn = sqlite3.connect(str(path))
    try:
        c = conn.cursor()
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
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS job_dedup (
                payload_hash TEXT PRIMARY KEY,
                job_id TEXT,
                created_at TEXT
            )
            """
        )
        for stmt in (
            "ALTER TABLE audit_jobs ADD COLUMN claimed_by TEXT DEFAULT ''",
            "ALTER TABLE audit_jobs ADD COLUMN claimed_at TEXT DEFAULT ''",
            "ALTER TABLE audit_jobs ADD COLUMN heartbeat_at TEXT DEFAULT ''",
            "ALTER TABLE audit_jobs ADD COLUMN attempt INTEGER DEFAULT 0",
            "ALTER TABLE audit_jobs ADD COLUMN max_attempts INTEGER DEFAULT 3",
            "ALTER TABLE audit_jobs ADD COLUMN payload_hash TEXT DEFAULT ''",
            "ALTER TABLE audit_jobs ADD COLUMN session_id TEXT DEFAULT ''",
            "ALTER TABLE audit_jobs ADD COLUMN last_error TEXT DEFAULT ''",
            "ALTER TABLE audit_jobs ADD COLUMN finished_at TEXT DEFAULT ''",
        ):
            try:
                c.execute(stmt)
            except sqlite3.OperationalError:
                pass
        conn.commit()
    finally:
        conn.close()


def backup_db(dest: Path | str) -> Path:
    from cyberaudit.db import _db_path

    src = _db_path()
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(src))
    try:
        conn.execute("PRAGMA wal_checkpoint(FULL)")
    finally:
        conn.close()
    shutil.copy2(src, dest)
    v = sqlite3.connect(str(dest))
    try:
        v.execute("SELECT 1")
    finally:
        v.close()
    return dest


def restore_db(src: Path | str) -> Path:
    from cyberaudit.db import _db_path

    dest = _db_path()
    src = Path(src)
    if not src.is_file():
        raise FileNotFoundError(src)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    conn = sqlite3.connect(str(dest))
    try:
        conn.execute("SELECT 1 FROM sqlite_master LIMIT 1")
    finally:
        conn.close()
    return dest
