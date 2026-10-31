"""Phase 1 schema migrations — tenant-aware."""
from __future__ import annotations

import logging
import sqlite3

logger = logging.getLogger("CyberAuditDashboard")


def migrate_phase1() -> None:
    from cyberaudit.db import _db_path

    path = _db_path()
    conn = sqlite3.connect(str(path))
    try:
        c = conn.cursor()
        for stmt in (
            "ALTER TABLE audit_sessions ADD COLUMN posture_score REAL",
            "ALTER TABLE audit_sessions ADD COLUMN posture_band TEXT",
            "ALTER TABLE audit_sessions ADD COLUMN client_name TEXT",
            "ALTER TABLE audit_sessions ADD COLUMN baseline_session_id TEXT",
            "ALTER TABLE findings ADD COLUMN cvss_score REAL",
            "ALTER TABLE findings ADD COLUMN cvss_vector TEXT",
            "ALTER TABLE findings ADD COLUMN plain_english TEXT",
            "ALTER TABLE findings ADD COLUMN confidence TEXT",
        ):
            try:
                c.execute(stmt)
            except sqlite3.OperationalError:
                pass
        conn.commit()
    finally:
        conn.close()
