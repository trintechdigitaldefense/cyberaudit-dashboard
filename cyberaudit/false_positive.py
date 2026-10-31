"""False-positive review and suppression — CyberAudit 3.10 Phase 2."""

from __future__ import annotations

import datetime
import logging
from typing import Any

from cyberaudit.db import get_db
from cyberaudit.retest import fingerprint

logger = logging.getLogger("CyberAuditDashboard")


def ensure_fp_table() -> None:
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS finding_suppressions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT,
                host TEXT,
                port TEXT,
                service TEXT,
                reason TEXT,
                created_by TEXT,
                created_at TEXT,
                active INTEGER DEFAULT 1
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_fp_fingerprint ON finding_suppressions(fingerprint)"
        )
        conn.commit()


def add_suppression(
    *,
    finding: dict | None = None,
    fingerprint_value: str = "",
    host: str = "",
    port: str = "",
    service: str = "",
    reason: str = "",
    created_by: str = "",
) -> int:
    ensure_fp_table()
    if finding:
        fingerprint_value = fingerprint_value or fingerprint(finding)
        host = host or str(finding.get("host") or "")
        port = port or str(finding.get("port") or "")
        service = service or str(finding.get("service") or "")
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO finding_suppressions
               (fingerprint, host, port, service, reason, created_by, created_at, active)
               VALUES (?,?,?,?,?,?,?,1)""",
            (
                fingerprint_value[:256],
                host[:128],
                str(port)[:32],
                service[:64],
                (reason or "operator false-positive")[:500],
                (created_by or "")[:128],
                now,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def load_suppressions(*, active_only: bool = True) -> list[dict[str, Any]]:
    ensure_fp_table()
    with get_db() as conn:
        if active_only:
            rows = conn.execute(
                "SELECT * FROM finding_suppressions WHERE active=1 ORDER BY id DESC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM finding_suppressions ORDER BY id DESC"
            ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["active"] = bool(d.get("active", 1))
        out.append(d)
    return out


def deactivate_suppression(suppression_id: int) -> None:
    ensure_fp_table()
    with get_db() as conn:
        conn.execute(
            "UPDATE finding_suppressions SET active=0 WHERE id=?",
            (suppression_id,),
        )
        conn.commit()


def mark_finding_false_positive(
    finding_id: int,
    *,
    changed_by: str = "",
    reason: str = "",
    also_suppress: bool = True,
) -> dict:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            raise ValueError(f"finding {finding_id} not found")
        finding = dict(row)
        conn.execute(
            "UPDATE findings SET status=?, status_updated_at=?, status_updated_by=?, status_note=? WHERE id=?",
            (
                "false_positive",
                now,
                (changed_by or "")[:128],
                (reason or "false positive")[:500],
                finding_id,
            ),
        )
        try:
            conn.execute(
                """INSERT INTO finding_status_history
                   (finding_id, old_status, new_status, changed_by, note, changed_at)
                   VALUES (?,?,?,?,?,?)""",
                (
                    finding_id,
                    finding.get("status") or "open",
                    "false_positive",
                    changed_by or "",
                    reason or "",
                    now,
                ),
            )
        except Exception:
            pass
        conn.commit()

    if also_suppress:
        add_suppression(
            finding=finding,
            reason=reason or "false positive",
            created_by=changed_by,
        )
    return {"id": finding_id, "status": "false_positive"}
