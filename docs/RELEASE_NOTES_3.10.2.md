# CyberAudit 3.10.2

Reliability integration. Point-in-time authorized audits only — not continuous monitoring.

## Verified at release (local pytest)

- Pipeline rejects missing/out-of-scope ROE via real `run_audit_job` path.
- Empty discovery does not invent hosts.
- Job claim blocks duplicate workers.
- Tenant-scoped DB paths isolate real writes between clients.
- CI runs pytest; pip-audit is not suppressed.

## Deployment limitation

Prefer one active tenant per worker process for multi-client production.
