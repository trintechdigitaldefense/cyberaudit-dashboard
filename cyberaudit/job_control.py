"""Job control plane — CyberAudit 3.10 Phase 5.

Idempotent claiming, bounded retries, heartbeats, stale recovery,
transactional status sync with audit sessions.
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
        logger.warning("job schema migrate: %s", exc)


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
    with get_db() as conn:
        row = conn.execute(
            "SELECT job_id, status FROM audit_jobs WHERE payload_hash=? AND status IN ('queued','running','claimed')",
            (h,),
        ).fetchone()
        if row and str(row["job_id"]) != str(job_id):
            return False, f"duplicate of active job {row['job_id']} (status={row['status']})"
        try:
            conn.execute(
                """INSERT INTO job_dedup (payload_hash, job_id, created_at)
                   VALUES (?,?,?)
                   ON CONFLICT(payload_hash) DO UPDATE SET job_id=excluded.job_id, created_at=excluded.created_at""",
                (h, job_id, _now()),
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
        existing = conn.execute("SELECT job_id FROM audit_jobs WHERE job_id=?", (job_id,)).fetchone()
        if existing:
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
    ensure_job_schema()
    wid = worker_id or WORKER_ID
    now = _now()
    with get_db() as conn:
        row = conn.execute(
            "SELECT status, claimed_by, heartbeat_at, claimed_at, attempt, max_attempts FROM audit_jobs WHERE job_id=?",
            (job_id,),
        ).fetchone()
        if not row:
            conn.execute(
                """INSERT OR IGNORE INTO audit_jobs (job_id, status, created_at, attempt, max_attempts, claimed_by, claimed_at, heartbeat_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (job_id, "claimed", now, 1, DEFAULT_MAX_ATTEMPTS, wid, now, now),
            )
            conn.commit()
            return True

        status = (row["status"] or "").lower()
        if status in ("completed",):
            return False
        if status == "failed":
            attempt = int(row["attempt"] or 0)
            max_a = int(row["max_attempts"] or DEFAULT_MAX_ATTEMPTS)
            if attempt >= max_a:
                return False
        if status in ("running", "claimed") and row["claimed_by"] and row["claimed_by"] != wid:
            hb = row["heartbeat_at"] or row["claimed_at"] or ""
            if hb and not _is_stale(hb):
                return False

        attempt = int(row["attempt"] or 0) + 1
        conn.execute(
            """UPDATE audit_jobs SET status=?, claimed_by=?, claimed_at=?, heartbeat_at=?, attempt=?
               WHERE job_id=?""",
            ("running", wid, now, now, attempt, job_id),
        )
        conn.commit()
        return True


def heartbeat(job_id: str | None = None, *, worker_id: str | None = None, detail: str = "") -> None:
    ensure_job_schema()
    wid = worker_id or WORKER_ID
    now = _now()
    with get_db() as conn:
        conn.execute(
            """INSERT INTO worker_heartbeats (worker_id, last_seen, status, detail)
               VALUES (?,?,?,?)
               ON CONFLICT(worker_id) DO UPDATE SET last_seen=excluded.last_seen, status=excluded.status, detail=excluded.detail""",
            (wid, now, "alive", detail[:200]),
        )
        if job_id:
            conn.execute(
                "UPDATE audit_jobs SET heartbeat_at=? WHERE job_id=? AND claimed_by=?",
                (now, job_id, wid),
            )
        conn.commit()


def _is_stale(ts: str, stale_seconds: int = STALE_SECONDS) -> bool:
    try:
        dt = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
        age = time.time() - dt.replace(tzinfo=timezone.utc).timestamp()
        return age > stale_seconds
    except Exception:
        return True


def recover_stale_jobs(stale_seconds: int = STALE_SECONDS) -> list[str]:
    ensure_job_schema()
    recovered = []
    with get_db() as conn:
        rows = conn.execute(
            "SELECT job_id, heartbeat_at, claimed_at, attempt, max_attempts FROM audit_jobs WHERE status IN ('running','claimed')"
        ).fetchall()
        for row in rows:
            hb = row["heartbeat_at"] or row["claimed_at"] or ""
            if not _is_stale(hb, stale_seconds):
                continue
            attempt = int(row["attempt"] or 0)
            max_a = int(row["max_attempts"] or DEFAULT_MAX_ATTEMPTS)
            if attempt >= max_a:
                conn.execute(
                    "UPDATE audit_jobs SET status=?, last_error=?, finished_at=? WHERE job_id=?",
                    ("failed", "stale — max attempts exceeded", _now(), row["job_id"]),
                )
            else:
                conn.execute(
                    """UPDATE audit_jobs SET status=?, claimed_by='', claimed_at='', heartbeat_at='',
                       last_error=? WHERE job_id=?""",
                    ("queued", "stale claim released for retry", row["job_id"]),
                )
            recovered.append(row["job_id"])
        conn.commit()
    if recovered:
        logger.warning("recovered stale jobs: %s", recovered)
    return recovered


def mark_job(
    job_id: str,
    status: str,
    *,
    session_id: str = "",
    error: str = "",
    sync_session: bool = True,
) -> None:
    ensure_job_schema()
    now = _now()
    with get_db() as conn:
        conn.execute(
            """UPDATE audit_jobs SET status=?, session_id=COALESCE(NULLIF(?,''), session_id),
               last_error=?, finished_at=CASE WHEN ? IN ('completed','failed') THEN ? ELSE finished_at END,
               heartbeat_at=?
               WHERE job_id=?""",
            (status, session_id, (error or "")[:500], status, now, now, job_id),
        )
        if sync_session and session_id and status in ("completed", "failed"):
            try:
                conn.execute(
                    "UPDATE audit_sessions SET status=? WHERE session_id=?",
                    (status, session_id),
                )
            except Exception:
                pass
        conn.commit()


def transactional_finalize(
    result: dict[str, Any],
    *,
    job_id: str | None = None,
) -> dict[str, Any]:
    from cyberaudit.finalization import finalize_audit_result

    r = dict(result)
    if r.get("report") and not r.get("executive_txt"):
        r["executive_txt"] = r["report"]
    if r.get("report_technical") and not r.get("technical_txt"):
        r["technical_txt"] = r["report_technical"]

    finalized = finalize_audit_result(r, session_id=r.get("session_id"), job_id=job_id or r.get("job_id"))
    jid = job_id or finalized.get("job_id")
    if jid:
        mark_job(
            jid,
            finalized.get("status") or "failed",
            session_id=str(finalized.get("session_id") or ""),
            error=str(finalized.get("error") or ""),
            sync_session=True,
        )
    return finalized
