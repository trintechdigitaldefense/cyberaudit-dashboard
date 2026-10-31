"""Phase 5 schema — job control columns, worker heartbeats, backups."""

from __future__ import annotations

import logging
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from cyberaudit import config

logger = logging.getLogger("CyberAuditDashboard")


def migrate_phase5(conn: sqlite3.Connection | None = None) -> None:
    own = conn is None
    if own:
        conn = sqlite3.connect(str(config.DB_PATH))
    c = conn.cursor()

    for stmt in (
        "ALTER TABLE audit_jobs ADD COLUMN attempt INTEGER DEFAULT 0",
        "ALTER TABLE audit_jobs ADD COLUMN max_attempts INTEGER DEFAULT 3",
        "ALTER TABLE audit_jobs ADD COLUMN claimed_by TEXT DEFAULT ''",
        "ALTER TABLE audit_jobs ADD COLUMN claimed_at TEXT DEFAULT ''",
        "ALTER TABLE audit_jobs ADD COLUMN heartbeat_at TEXT DEFAULT ''",
        "ALTER TABLE audit_jobs ADD COLUMN last_error TEXT DEFAULT ''",
        "ALTER TABLE audit_jobs ADD COLUMN session_id TEXT DEFAULT ''",
        "ALTER TABLE audit_jobs ADD COLUMN finished_at TEXT DEFAULT ''",
        "ALTER TABLE audit_jobs ADD COLUMN payload_hash TEXT DEFAULT ''",
    ):
        try:
            c.execute(stmt)
        except sqlite3.OperationalError:
            pass

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS worker_heartbeats (
            worker_id TEXT PRIMARY KEY,
            last_seen TEXT NOT NULL,
            status TEXT DEFAULT 'alive',
            detail TEXT DEFAULT ''
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS job_dedup (
            payload_hash TEXT PRIMARY KEY,
            job_id TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    if own:
        conn.close()
    logger.info("phase5 schema migrated")


def backup_database(dest_dir: Path | str | None = None) -> Path:
    dest_root = Path(dest_dir) if dest_dir else (config.DATA_DIR / "backups")
    dest_root.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = dest_root / f"cyber_audit_{ts}.db"
    src = Path(config.DB_PATH)
    if not src.is_file():
        raise FileNotFoundError(f"database not found: {src}")
    try:
        conn = sqlite3.connect(str(src))
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
    except Exception as exc:
        logger.warning("wal checkpoint before backup: %s", exc)
    shutil.copy2(src, dest)
    v = sqlite3.connect(str(dest))
    try:
        v.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
    finally:
        v.close()
    logger.info("database backup written: %s", dest)
    return dest


def restore_database(backup_path: Path | str, *, force: bool = False) -> Path:
    src = Path(backup_path)
    if not src.is_file():
        raise FileNotFoundError(str(src))
    dest = Path(config.DB_PATH)
    if dest.exists() and not force:
        raise RuntimeError("database exists — pass force=True to overwrite")
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    conn = sqlite3.connect(str(dest))
    try:
        conn.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
    finally:
        conn.close()
    return dest
