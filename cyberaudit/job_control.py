"""Job control plane — CyberAudit 3.10.8.

Atomic claims, ownership-aware heartbeats and terminal transitions,
stale recovery with conditional UPDATE.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import time
from datetime import datetime, timezone
from typing import Any

from cyberaudit.db import get_db
from cyberaudit.phase5_db import migrate_phase5

logger = logging.getLogger("CyberAuditDashboard")

DEFAULT_MAX_ATTEMPTS = 3
STALE_SECONDS = int(os.environ.get("CYBERAUDIT_JOB_STALE_SECONDS", "900"))
WORKER_ID = os.environ.get("CYBERAUDIT_WORKER_ID") or f"{socket.gethostname()}-{os.getpid()}"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def ensure_job_schema() -> None:
    try:
        migrate_phase5()
    except Exception as exc:
        logger.error("job schema migrate FAILED: %s", exc)
        raise RuntimeError(f"job schema migrate failed: {exc}") from exc


def payload_hash(job: dict) -> str:
    key = {
        "target": (job.get("target") or "").strip(),
        "client_name": (job.get("client_name") or job.get("client") or "").strip(),
        "ports": job.get("ports") or [],
    }
    raw = json.dumps(key, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def register_or_reject_duplicate(job: dict) -> tuple[bool, str]:
    ensure_job_schema()
    h = payload_hash(job)
    job_id = job.get("job_id") or ""
    now = _now()
    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """SELECT job_id, status FROM audit_jobs
               WHERE payload_hash=? AND status IN ('queued','running','claimed') LIMIT 1""",
            (h,),
        ).fetchone()
        if row and str(row["job_id"]) != str(job_id):
            conn.commit()
            return False, f"duplicate of active job {row['job_id']} (status={row['status']})"
        try:
            conn.execute(
                """INSERT INTO job_dedup (payload_hash, job_id, created_at) VALUES (?,?,?)
                   ON CONFLICT(payload_hash) DO UPDATE SET job_id=excluded.job_id, created_at=excluded.created_at""",
                (h, job_id, now),
            )
        except Exception:
            pass
        conn.execute("UPDATE audit_jobs SET payload_hash=? WHERE job_id=?", (h, job_id))
        conn.commit()
    return True, "ok"


def ensure_job_row(job: dict) -> None:
    ensure_job_schema()
    job_id = job.get("job_id") or ""
    if not job_id:
        return
    with get_db() as conn:
        if conn.execute("SELECT job_id FROM audit_jobs WHERE job_id=?", (job_id,)).fetchone():
            return
        conn.execute(
            """INSERT INTO audit_jobs
               (job_id, target, requested_by, status, created_at, notes, attempt, max_attempts, payload_hash)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                job_id,
                (job.get("target") or "")[:256],
                (job.get("requested_by") or job.get("user") or "")[:128],
                "queued",
                _now(),
                "",
                0,
                int(job.get("max_attempts") or DEFAULT_MAX_ATTEMPTS),
                payload_hash(job),
            ),
        )
        conn.commit()


def claim_job(job_id: str, *, worker_id: str | None = None) -> bool:
    """Atomically claim. Running jobs only reclaimable after stale heartbeat."""
    ensure_job_schema()
    wid = worker_id or WORKER_ID
    now = _now()
    try:
        from datetime import timedelta
        stale_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=STALE_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        stale_cutoff = "1970-01-01 00:00:00"

    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT job_id FROM audit_jobs WHERE job_id=?", (job_id,)
        ).fetchone()
        if not row:
            conn.execute(
                """INSERT OR IGNORE INTO audit_jobs (job_id, status, attempt, max_attempts, created_at)
                   VALUES (?, 'queued', 0, ?, ?)""",
                (job_id, DEFAULT_MAX_ATTEMPTS, now),
            )
        cur = conn.execute(
            """UPDATE audit_jobs
               SET status='running', claimed_by=?, claimed_at=?, heartbeat_at=?,
                   attempt=COALESCE(attempt,0)+1
               WHERE job_id=?
                 AND status != 'completed'
                 AND (
                   status IN ('queued', 'stale')
                   OR (status = 'failed' AND COALESCE(attempt,0) < COALESCE(max_attempts, 3))
                   OR (status IN ('running', 'claimed') AND claimed_by = ?)
                   OR (
                     status IN ('running', 'claimed')
                     AND heartbeat_at IS NOT NULL AND heartbeat_at != '' AND heartbeat_at < ?
                   )
                 )""",
            (wid, now, now, job_id, wid, stale_cutoff),
        )
        ok = cur.rowcount >= 1
        conn.commit()
        return bool(ok)


def heartbeat(job_id: str, detail: str = "", *, worker_id: str | None = None) -> bool:
    wid = worker_id or WORKER_ID
    now = _now()
    with get_db() as conn:
        cur = conn.execute(
            """UPDATE audit_jobs SET heartbeat_at=? WHERE job_id=? AND claimed_by=?
               AND status IN ('running','claimed')""",
            (now, job_id, wid),
        )
        conn.commit()
        return cur.rowcount >= 1


def recover_stale_jobs(stale_seconds: int = STALE_SECONDS) -> list[str]:
    ensure_job_schema()
    recovered: list[str] = []
    try:
        from datetime import timedelta
        stale_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=stale_seconds)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        stale_cutoff = "1970-01-01 00:00:00"
    now = _now()
    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            """SELECT job_id, attempt, max_attempts FROM audit_jobs
               WHERE status IN ('running','claimed')
                 AND (heartbeat_at IS NULL OR heartbeat_at = '' OR heartbeat_at < ?)""",
            (stale_cutoff,),
        ).fetchall()
        for row in rows:
            jid = row["job_id"]
            attempt = int(row["attempt"] or 0)
            max_a = int(row["max_attempts"] or DEFAULT_MAX_ATTEMPTS)
            if attempt >= max_a:
                cur = conn.execute(
                    """UPDATE audit_jobs SET status='failed', last_error=?, finished_at=?
                       WHERE job_id=? AND status IN ('running','claimed')
                         AND (heartbeat_at IS NULL OR heartbeat_at = '' OR heartbeat_at < ?)""",
                    ("stale exhausted", now, jid, stale_cutoff),
                )
            else:
                cur = conn.execute(
                    """UPDATE audit_jobs SET status='stale', claimed_by='', claimed_at='', heartbeat_at=''
                       WHERE job_id=? AND status IN ('running','claimed')
                         AND (heartbeat_at IS NULL OR heartbeat_at = '' OR heartbeat_at < ?)""",
                    (jid, stale_cutoff),
                )
            if cur.rowcount >= 1:
                recovered.append(jid)
        conn.commit()
    return recovered


def mark_job(
    job_id: str,
    status: str,
    error: str = "",
    session_id: str = "",
    *,
    worker_id: str | None = None,
    require_owner: bool = True,
) -> bool:
    ensure_job_schema()
    wid = worker_id or WORKER_ID
    now = _now()
    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT status, claimed_by FROM audit_jobs WHERE job_id=?", (job_id,)
        ).fetchone()
        if not row:
            conn.commit()
            return False
        cur_status = (row["status"] or "").lower()
        if cur_status == "completed" and status != "completed":
            conn.commit()
            return False
        if require_owner and cur_status in ("running", "claimed") and status in ("completed", "failed"):
            owner = row["claimed_by"] or ""
            if owner and owner != wid:
                conn.commit()
                return False
        if status in ("completed", "failed"):
            if require_owner:
                cur = conn.execute(
                    """UPDATE audit_jobs SET status=?, session_id=COALESCE(NULLIF(?,''), session_id),
                       last_error=?, finished_at=?, heartbeat_at=?
                       WHERE job_id=?
                         AND (claimed_by=? OR claimed_by IS NULL OR claimed_by='' OR status NOT IN ('running','claimed'))
                         AND status != 'completed'""",
                    (status, session_id, (error or "")[:500], now, now, job_id, wid),
                )
            else:
                cur = conn.execute(
                    """UPDATE audit_jobs SET status=?, session_id=COALESCE(NULLIF(?,''), session_id),
                       last_error=?, finished_at=?, heartbeat_at=? WHERE job_id=? AND status != 'completed'""",
                    (status, session_id, (error or "")[:500], now, now, job_id),
                )
        else:
            cur = conn.execute(
                "UPDATE audit_jobs SET status=?, last_error=? WHERE job_id=?",
                (status, (error or "")[:500], job_id),
            )
        ok = cur.rowcount >= 1
        conn.commit()
        return bool(ok)


def transactional_finalize(result: dict, job_id: str = "", *, worker_id: str | None = None) -> dict:
    jid = job_id or (result.get("job_id") if isinstance(result, dict) else "") or ""
    if not isinstance(result, dict):
        result = {"status": "failed", "error": "invalid result"}
    status = (result.get("status") or "failed").lower()
    try:
        from cyberaudit.finalization import finalize_audit_result
        result = finalize_audit_result(result)
        status = (result.get("status") or status).lower()
    except Exception as exc:
        logger.error("finalize_audit_result failed: %s", exc)
        status = "failed"
        result["status"] = "failed"
        result["error"] = str(exc)[:300]
    if status == "completed":
        mark_job(jid, "completed", session_id=str(result.get("session_id") or ""), worker_id=worker_id)
    else:
        mark_job(jid, "failed", error=str(result.get("error") or status)[:500], worker_id=worker_id)
    return result
