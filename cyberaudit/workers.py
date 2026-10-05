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
    except Exception as exc:
        logger.error("Inbox parse failed %s: %s", path.name, exp)
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
    except Exception as exc:
        logger.error("Inbox apply failed %s: %s", path.name, exp)
        return False


def _mark_job_status(job_id: str, status: str) -> None:
    try:
        with get_db() as conn:
            conn.execute("UPDATE audit_jobs SET status=? WHERE job_id=?", (status, job_id))
            conn.commit()
    except Exception as exc:
        logger.error("job status update failed: %s", exp)


def process_job_file(path: Path) -> bool:
    try:
        job = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.error("Job parse failed %s: %s", path.name, exp)
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
            last_result=f"Playbook {job.get('playbook')} acknowledged",
        )
        return True
    job_id = job.get("job_id") or path.stem
    target = (job.get("target") or "").strip()
    if not target:
        logger.error("Job %s missing target", job_id)
        _mark_job_status(job_id, "failed")
        return False
    _mark_job_status(job_id, "running")
    insert_live_event(
        module="dashboard",
        message=f"Real audit pipeline started: {job_id} -> {target}",
        severity="info",
        event_type="job",
        details=job,
    )
    try:
        from cyberaudit.pipeline_engine import run_audit_job
        result = run_audit_job(job)
        _mark_job_status(job_id, "completed")
        insert_live_event(
            module="dashboard",
            message=f"Audit completed: {result.get('session_id')} findings={result.get('findings')}",
            severity="info",
            event_type="job",
            details=result,
        )
        return True
    except Exception as exc:
        logger.exception("Audit job %s failed: %s", job_id, exp)
        _mark_job_status(job_id, "failed")
        insert_live_event(
            module="dashboard",
            message=f"Audit job failed: {job_id} — {exc}",
            severity="high",
            event_type="job",
        )
        return False


def job_runner() -> None:
    config.JOBS_DIR.mkdir(parents=True, exist_ok=True)
    done = config.JOBS_DIR / "done"
    failed = config.JOBS_DIR / "failed"
    done.mkdir(parents=True, exist_ok=True)
    failed.mkdir(parents=True, exist_ok=True)
    logger.info("Job runner watching %s (REAL pipeline)", config.JOBS_DIR)
    while True:
        try:
            for path in sorted(config.JOBS_DIR.glob("*.json")):
                if not path.is_file():
                    continue
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
        except Exception as exc:
            logger.error("Job runner error: %s", exp)
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
        except Exception as exc:
            logger.error("Inbox poller error: %s", exp)
        time.sleep(max(1.0, config.INBOX_POLL_SECONDS))


def retention_worker() -> None:
    while True:
        try:
            n = prune_old_events()
            if n:
                logger.info("Pruned %s live_events", n)
        except Exception as exc:
            logger.error("Retention error: %s", exp)
        time.sleep(max(60, config.RETENTION_INTERVAL_SECONDS))


def live_feed_simulator() -> None:
    global _simulator_running
    if not config.DEMO_MODE:
        logger.info("Simulator skipped (DEMO_MODE=0 — real pipeline only)")
        return
    _simulator_running = True
    logger.warning("DEMO_MODE=1 — synthetic feed (not for production)")
    while _simulator_running:
        time.sleep(random.uniform(5.0, 12.0))
        if not config.DEMO_MODE:
            break
        try:
            insert_live_event(
                module="continuous_ids_module",
                message="[DEMO] Synthetic event — set DEMO_MODE=0 for real audits",
                severity="info",
                details={"sim": True},
            )
        except Exception as exc:
            logger.error("Simulator failed: %s", exp)
