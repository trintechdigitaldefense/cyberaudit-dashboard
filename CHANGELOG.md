# CyberAudit Changelog

## 3.10.7 — 2026-10-30

### Reliability and security repair

- **Atomic claim_job**: `BEGIN IMMEDIATE` + conditional UPDATE (rowcount ownership).
- **Ownership-aware heartbeat**: only the claiming worker can heartbeat.
- **Atomic duplicate registration** under IMMEDIATE transaction.
- **ensure_job_schema fail-closed** on migration failure.
- **verify_manifest** requires `sig_alg=HMAC-SHA256` (no empty alg).
- **pdf_validate**: structural checks (pypdf when available; rejects header-only).
- **VERSION** 3.10.7.

## 3.10.6 — 2026-10-30

Tenant migrations, REPORT_SECRET-only signing, workers job-control integration.
