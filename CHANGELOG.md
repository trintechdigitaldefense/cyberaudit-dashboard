# CyberAudit Changelog

## 3.10.9 — 2026-10-30/31

### Production hardening (continued)

- No exec loader: `app.py` imports `app_impl` statically.
- Claim tokens + ownership-stop heartbeat + disabled `_mark_job_status`.
- Dedup fail-closed on write errors.
- SQLite online backup API + integrity_check; atomic restore.
- Atomic engagement pack publish (`.partial` → verified → replace).
- PDF structural validation in pack builder.
- `safe_next_url` open-redirect guard.
- Tenant-aware reports/jobs helpers in app_impl and board_summary.

## 3.10.8 — 2026-10-30

Ownership mark_job foundation, strict claim, stale recovery, coverage honesty.
