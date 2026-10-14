"""Phase 1 schema migrations — call from init_db() or on startup."""

from __future__ import annotations

import sqlite3

from cyberaudit import config


def migrate_phase1(conn: sqlite3.Connection | None = None) -> None:
    own = conn is None
    if own:
        conn = sqlite3.connect(config.DB_PATH)
    c = conn.cursor()

    for stmt in (
        "ALTER TABLE findings ADD COLUMN cvss_version TEXT DEFAULT '4.0'",
        "ALTER TABLE findings ADD COLUMN cvss_base_score REAL",
        "ALTER TABLE findings ADD COLUMN cvss_severity TEXT DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN cvss_vector TEXT DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN service TEXT DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN status_updated_at TEXT DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN status_updated_by TEXT DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN status_note TEXT DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN fingerprint TEXT DEFAULT ''",
        "ALTER TABLE audit_sessions ADD COLUMN posture_score REAL",
        "ALTER TABLE audit_sessions ADD COLUMN posture_band TEXT DEFAULT ''",
        "ALTER TABLE audit_sessions ADD COLUMN baseline_session_id TEXT DEFAULT ''",
        "ALTER TABLE audit_sessions ADD COLUMN client_name TEXT DEFAULT ''",
    ):
        try:
            c.execute(stmt)
        except sqlite3.OperationalError:
            pass

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_status_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER,
            old_status TEXT,
            new_status TEXT,
            changed_by TEXT,
            note TEXT,
            changed_at TEXT
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS posture_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            target TEXT,
            posture_score REAL,
            posture_band TEXT,
            recorded_at TEXT
        )
        """
    )
    c.execute("CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_posture_target ON posture_history(target)")
    conn.commit()
    if own:
        conn.close()
