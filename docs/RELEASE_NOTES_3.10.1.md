# CyberAudit 3.10.1 — Integration release

**Date:** 2026-10-30  
**Focus:** Connect ROE, pipeline, job control, tenant context, evidence, and CI — not new features.

## Fixes vs independent review

1. Authorization is on the live `run_audit_job` path (`assert_authorized` before discovery).
2. Legacy pipeline without ROE is stripped at load so it cannot be the entry point.
3. No `candidates[:16]` live-host invention on the active body.
4. Workers use claim/finalize and fail closed if job control cannot start.
5. Thread-local tenant scopes reduce cross-client path races.
6. PDF validation requires `%%EOF`; production engagement packs require signing.
7. CI runs pytest against the 3.10 regression and integration suites.

## Not claimed

- Fully concurrent multi-process multi-tenant isolation under one shared worker pool is still best operated as one active tenant per worker process.
- Production readiness still requires operator ROE, strong secrets, and DoD checklist sign-off.

## Verify

```bash
export DEMO_MODE=1
export CYBERAUDIT_SECRET=$(openssl rand -hex 32)
export CYBERAUDIT_ROE_SECRET=$(openssl rand -hex 32)
python3 -m pytest tests/test_phase3101_integration.py tests/test_phase8_regression.py -q
```
