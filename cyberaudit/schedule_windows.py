"""Scheduled engagement windows — fail closed (CyberAudit 3.10).

Jobs only start inside defined ROE time windows.
Misconfigured or missing required windows REJECT — never allow by default
when a window object is present but incomplete.
"""

from __future__ import annotations

import datetime
import json
import logging
from typing import Any

from cyberaudit import config
from cyberaudit.db import get_db

logger = logging.getLogger("CyberAuditDashboard")


def _parse_hhmm(value: str) -> datetime.time | None:
    value = (value or "").strip()
    for fmt in ("%H:%M", "%H:%M:%S"):
        try:
            return datetime.datetime.strptime(value, fmt).time()
        except ValueError:
            continue
    return None


def window_allows_now(
    window: dict | None,
    now: datetime.datetime | None = None,
    *,
    fail_closed: bool = True,
) -> tuple[bool, str]:
    if not window:
        return True, "no window object on job"
    if window.get("enabled") is False:
        return True, "window explicitly disabled"
    enabled = window.get("enabled")
    if enabled is None and (window.get("start") or window.get("end")):
        enabled = True
    if not enabled:
        return True, "no window restriction"

    now = now or datetime.datetime.now()
    days = window.get("days")
    if days is not None and len(days) > 0:
        try:
            day_set = {int(d) for d in days}
        except (TypeError, ValueError):
            if fail_closed:
                return False, "window misconfigured — invalid days list (fail closed)"
            day_set = set()
        if day_set and now.weekday() not in day_set:
            return False, f"outside ROE weekdays (today={now.strftime('%A')})"

    start = _parse_hhmm(str(window.get("start") or ""))
    end = _parse_hhmm(str(window.get("end") or ""))
    if not start or not end:
        if fail_closed:
            return False, "window misconfigured — start/end required (fail closed)"
        return True, "window misconfigured — allowing (legacy)"

    t = now.time()
    if start <= end:
        ok = start <= t <= end
    else:
        ok = t >= start or t <= end
    if ok:
        return True, "inside ROE window"
    return False, f"outside ROE window {window.get('start')}-{window.get('end')} (now {t.strftime('%H:%M')})"


def job_window(job: dict) -> dict | None:
    w = job.get("roe_window") or job.get("window") or job.get("schedule")
    if not w and isinstance(job.get("roe"), dict):
        w = job["roe"].get("window") or job["roe"].get("roe_window")
    if isinstance(w, str):
        try:
            w = json.loads(w)
        except json.JSONDecodeError:
            return None
    return w if isinstance(w, dict) else None


def assert_window_or_raise(job: dict) -> None:
    window = job_window(job)
    if window is None:
        return
    allowed, reason = window_allows_now(window, fail_closed=True)
    if not allowed:
        raise PermissionError(f"ROE window enforced: {reason}")


def enqueue_scheduled_job(job: dict) -> str:
    config.JOBS_DIR.mkdir(parents=True, exist_ok=True)
    job = dict(job)
    job.setdefault("job_id", f"JOB-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}")
    job["scheduled"] = True
    job["created_at"] = datetime.datetime.now().isoformat()
    path = config.JOBS_DIR / f"{job['job_id']}.json"
    path.write_text(json.dumps(job, indent=2), encoding="utf-8")
    return str(path)


def filter_runnable_jobs(job_files: list) -> list:
    runnable = []
    for path in job_files:
        try:
            job = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        window = job_window(job)
        if window is None:
            runnable.append((path, job))
            continue
        allowed, reason = window_allows_now(window, fail_closed=True)
        if allowed:
            runnable.append((path, job))
        else:
            logger.info("job %s deferred: %s", path.name, reason)
    return runnable
