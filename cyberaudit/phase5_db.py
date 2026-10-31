"""Phase 5 job-control schema + backup — tenant-aware (3.10.9)."""
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
    """Online SQLite backup API + integrity_check (tenant-aware source)."""
    from cyberaudit.db import _db_path

    src = _db_path()
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    if tmp.exists():
        tmp.unlink()
    src_conn = sqlite3.connect(str(src))
    try:
        dst_conn = sqlite3.connect(str(tmp))
        try:
            src_conn.backup(dst_conn)
            row = dst_conn.execute("PRAGMA integrity_check").fetchone()
            if not row or str(row[0]).lower() != "ok":
                raise RuntimeError(f"backup integrity_check failed: {row}")
        finally:
            dst_conn.close()
    finally:
        src_conn.close()
    tmp.replace(dest)
    return dest


def restore_db(src: Path | str) -> Path:
    """Validate backup then atomic replace of active tenant DB."""
    from cyberaudit.db import _db_path

    src = Path(src)
    if not src.is_file():
        raise FileNotFoundError(src)
    dest = _db_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    check = sqlite3.connect(str(src))
    try:
        row = check.execute("PRAGMA integrity_check").fetchone()
        if not row or str(row[0]).lower() != "ok":
            raise RuntimeError(f"source backup failed integrity_check: {row}")
        check.execute("SELECT 1 FROM sqlite_master LIMIT 1")
    finally:
        check.close()
    if dest.exists():
        pre = dest.with_suffix(dest.suffix + ".prerestore")
        shutil.copy2(dest, pre)
    tmp = dest.with_suffix(dest.suffix + ".restore_tmp")
    if tmp.exists():
        tmp.unlink()
    shutil.copy2(src, tmp)
    verify = sqlite3.connect(str(tmp))
    try:
        row = verify.execute("PRAGMA integrity_check").fetchone()
        if not row or str(row[0]).lower() != "ok":
            raise RuntimeError(f"restored copy failed integrity_check: {row}")
    finally:
        verify.close()
    tmp.replace(dest)
    return dest


def backup_database(dest=None):
    from datetime import datetime, timezone
    from cyberaudit.db import _db_path

    if dest is None:
        dest = _db_path().parent / f"backup_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.db"
    else:
        dest = Path(dest)
        if dest.exists() and dest.is_dir():
            dest = dest / f"backup_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.db"
        elif dest.suffix == "" and not dest.exists():
            dest.mkdir(parents=True, exist_ok=True)
            dest = dest / f"backup_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.db"
    return backup_db(dest)


def restore_database(src, force: bool = False):
    return restore_db(src)
