"""Background workers: real job runner, inbox poller, retention, optional demo sim."""

from __future__ import annotations

import json
import logging
import random
import time
from pathlib import Path

from cyberaudit import config
from cyberaudit.db import (
    get_db,
    insert_live_event,
    prune_old_events,
    upsert_audit_session,
    upsert_module_status,
)

logger = logging.getLogger("CyberAuditDashboard")

_simulator_running = False


def process_inbox_file(path: Path) -> bool:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.error("Inbox parse failed %s: %s", path.name, e)
        return False
    kind = (data.get("type") or data.get("kind") or "event").lower()
    try:
        if kind in ("event", "live_event", "alert"):
            insert_live_event(
                module=data.get("module") or path.stem,
                message=data.get("message") or data.get("msg") or "",
                severity=data.get("severity") or "info",
                event_type=data.get("event_type") or "info",
                details=data.get("details"),
                timestamp=data.get("timestamp"),
            )
        elif kind in ("module", "module_status"):
            upsert_module_status(
                module_name=data.get("module_name") or data.get("module") or "",
                status=data.get("status") or "idle",
                last_result=data.get("last_result") or data.get("result") or "",
                version=data.get("version") or "",
                last_run=data.get("last_run"),
            )
        elif kind in ("session", "audit_session"):
            upsert_audit_session(data)
        elif kind in ("playbook_trigger",):
            insert_live_event(
                module="incident_response_module",
                message=f"Playbook request: {data.get('playbook')} host={data.get('host')}",
                severity="high",
                event_type="playbook",
                details=data,
            )
        else:
            logger.warning("Unknown inbox type %s in %s", kind, path.name)
            return False
        return True
    except Exception as e:
        logger.error("Inbox apply failed %s: %s", path.name, e)
        return False


def _mark_job_status(job_id: str, status: str) -> None:
    """Last-resort status write when job_control is unavailable."""
    try:
        with get_db() as conn:
            conn.execute(
                "UPDATE audit_jobs SET status=? WHERE job_id=?",
                (status, job_id),
            )
            conn.commit()
    except Exception as e:
        logger.error("job status update failed: %s", e)


def process_job_file(path: Path) -> bool:
    """Execute a queued audit job with claim, heartbeat, and transactional finalize."""
    try:
        job = json.loads(path.read_text(encoding="utf-8"))
        try:
            from cyberaudit.hardening import validate_job_payload
            job = validate_job_payload(job)
        except ValueError as vex:
            logger.error("job validation failed %s: %s", path.name, vex)
            raise
    except Exception as e:
        logger.error("Job parse failed %s: %s", path.name, e)
        return False

    if (job.get("type") or "") == "playbook_trigger":
        insert_live_event(
            module="incident_response_module",
            message=f"Playbook queued: {job.get('playbook')} target={job.get('host')}",
            severity="high",
            event_type="playbook",
            details=job,
        )
        upsert_module_status(
            module_name="incident_response_module",
            status="ok",
            last_result=f"Playbook {job.get('playbook')} acknowledged — operator action required",
        )
        return True

    job_id = job.get("job_id") or path.stem
    job["job_id"] = job_id
    target = (job.get("target") or "").strip()
    if not target:
        logger.error("Job %s missing target", job_id)
        _mark_job_status(job_id, "failed")
        return False

    try:
        from cyberaudit.job_control import (
            ensure_job_row,
            register_or_reject_duplicate,
            claim_job,
            heartbeat,
            transactional_finalize,
            mark_job,
        )
        ensure_job_row(job)
        allowed, reason = register_or_reject_duplicate(job)
        if not allowed:
            logger.warning("job %s rejected: %s", job_id, reason)
            insert_live_event(
                module="dashboard",
                message=f"Duplicate job skipped: {job_id} — {reason}",
                severity="info",
                event_type="job",
                details={"job_id": job_id, "reason": reason},
            )
            return True
        if not claim_job(job_id):
            logger.info("job %s not claimed (held by another worker or exhausted)", job_id)
            return False
        heartbeat(job_id, detail="pipeline start")
    except Exception as exc:
        logger.error("job_control bootstrap failed: %s", exc)
        try:
            from cyberaudit.job_control import mark_job
            mark_job(job_id, "failed", error=f"job_control: {exc}"[:400])
        except Exception:
            _mark_job_status(job_id, "failed")
        return False

    insert_live_event(
        module="dashboard",
        message=f"Real audit pipeline started: {job_id} → {target}",
        severity="info",
        event_type="job",
        details=job,
    )

    try:
        from cyberaudit.pipeline_engine import run_audit_job
        from cyberaudit.hardening import fail_safe_job, audit_event

        result = fail_safe_job(run_audit_job, job)
        try:
            heartbeat(job_id, detail="pipeline finished")
        except Exception:
            pass

        try:
            from cyberaudit.job_control import transactional_finalize
            result = transactional_finalize(
                result if isinstance(result, dict) else {"status": "failed"},
                job_id=job_id,
            )
        except Exception as fexc:
            logger.error("finalization error: %s", fexc)
            if isinstance(result, dict):
                result["status"] = "failed"
                result["error"] = str(fexc)[:300]
            mark_job(job_id, "failed", error=str(fexc)[:300])

        if result.get("status") == "failed":
            raise RuntimeError(result.get("error") or "job failed")
        try:
            audit_event("scan_complete", detail={"job_id": job_id, "session_id": result.get("session_id")})
        except Exception:
            pass
        insert_live_event(
            module="dashboard",
            message=(
                f"Audit completed: {result.get('session_id')} "
                f"open_ports={result.get('open_ports')} findings={result.get('findings')}"
            ),
            severity="info",
            event_type="job",
            details=result,
        )
        return True
    except Exception as e:
        logger.exception("Audit job %s failed: %s", job_id, e)
        try:
            from cyberaudit.job_control import mark_job
            mark_job(job_id, "failed", error=str(e)[:500])
        except Exception:
            _mark_job_status(job_id, "failed")
        insert_live_event(
            module="dashboard",
            message=f"Audit job failed: {job_id} — {e}",
            severity="high",
            event_type="job",
            details={"error": str(e)[:500], "job_id": job_id},
        )
        try:
            from cyberaudit.hardening import fail_safe_cleanup_partial
            fail_safe_cleanup_partial(job_id)
        except Exception:
            pass
        return False


def job_runner() -> None:
    """Always-on worker: pick up jobs from data/jobs/*.json and run real audits."""
    config.JOBS_DIR.mkdir(parents=True, exist_ok=True)
    done = config.JOBS_DIR / "done"
    failed = config.JOBS_DIR / "failed"
    done.mkdir(parents=True, exist_ok=True)
    failed.mkdir(parents=True, exist_ok=True)
    logger.info("Job runner watching %s (REAL pipeline)", config.JOBS_DIR)
    while True:
        try:
            from cyberaudit.schedule_windows import filter_runnable_jobs
            paths = [p for p in sorted(config.JOBS_DIR.glob("*.json")) if p.is_file()]
            runnable = filter_runnable_jobs(paths)
            for path, _job in runnable:
                ok = process_job_file(path)
                dest_dir = done if ok else failed
                dest = dest_dir / f"{path.stem}_{int(time.time())}{path.suffix}"
                try:
                    path.rename(dest)
                except Exception:
                    try:
                        path.unlink()
                    except Exception:
                        pass
        except Exception as e:
            logger.error("Job runner error: %s", e)
        time.sleep(2.0)


def inbox_poller() -> None:
    logger.info("Inbox poller watching %s", config.INBOX_DIR)
    while True:
        try:
            for path in sorted(config.INBOX_DIR.glob("*.json")):
                if not path.is_file():
                    continue
                ok = process_inbox_file(path)
                dest_dir = config.INBOX_DIR / ("processed" if ok else "failed")
                dest = dest_dir / f"{path.stem}_{int(time.time())}{path.suffix}"
                try:
                    path.rename(dest)
                except Exception:
                    try:
                        path.unlink()
                    except Exception:
                        pass
        except Exception as e:
            logger.error("Inbox poller error: %s", e)
        time.sleep(max(1.0, config.INBOX_POLL_SECONDS))


def retention_worker() -> None:
    while True:
        try:
            n = prune_old_events()
            if n:
                logger.info("Pruned %s live_events", n)
        except Exception as e:
            logger.error("Retention error: %s", e)
        time.sleep(max(60, config.RETENTION_INTERVAL_SECONDS))


_ALWAYS_ON = (
    "continuous_ids_module",
    "data_exfiltration_module",
    "regional_threat_intel",
)
_BATCH = (
    "nmap_module",
    "openvas_module",
    "tt_compliance_mapper",
    "patch_verification_module",
    "pdf_report_module",
    "incident_response_module",
    "database_module",
    "diagnostics_module",
)
_ALL_MODULES = _ALWAYS_ON + _BATCH


def live_feed_simulator() -> None:
    """Fake traffic only when DEMO_MODE=1. Prefer real job_runner."""
    global _simulator_running
    if not config.DEMO_MODE:
        logger.info("Simulator skipped (DEMO_MODE=0 — real pipeline only)")
        return
    _simulator_running = True
    logger.warning("DEMO_MODE=1 — synthetic live feed active (not production)")
    while _simulator_running:
        time.sleep(random.uniform(5.0, 12.0))
        if not config.DEMO_MODE:
            break
        try:
            insert_live_event(
                module=random.choice(_ALL_MODULES),
                message="[DEMO] Synthetic event — set DEMO_MODE=0 for real audits",
                severity=random.choice(["info", "low", "medium"]),
                details={"sim": True},
            )
        except Exception as e:
            logger.error("Simulator failed: %s", e)
