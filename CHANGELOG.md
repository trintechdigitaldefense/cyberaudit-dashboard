# CyberAudit Changelog

## 3.10.2 — 2026-10-30

### Mandatory reliability integration

- **pipeline_authorized.py**: sole `run_audit_job` entry — ROE before any network I/O.
- **pipeline_engine.py**: re-exports authorized entry only (stale body_2 cannot win).
- Zero live-host invention on active path.
- Real tenant DB isolation tests with actual writes.
- CI: pytest + non-suppressed pip-audit.
- Honest module status: not_run / skipped / partial / success / failed.

## 3.10.1 — 2026-10-30

Integration attempt; superseded by 3.10.2 for pipeline authority.

## 3.10.0 — 2026-10-30

Phases 1–9 foundation modules and tests.
