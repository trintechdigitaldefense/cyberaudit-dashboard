# CyberAudit Changelog

## 3.10.9 — 2026-10-30

### Production hardening

- Unique claim tokens (`worker_id|token`) per claim execution.
- Ownership-required terminal transitions; blank owner cannot complete/fail running jobs.
- Heartbeat ownership loss signals pipeline stop.
- `_mark_job_status` disabled (raises).
- Dedup write failures fail closed.
- VERSION 3.10.9.

## 3.10.8 — 2026-10-30

Ownership mark_job foundation, strict claim, stale recovery, coverage honesty.
