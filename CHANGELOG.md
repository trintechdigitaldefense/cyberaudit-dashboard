# CyberAudit Changelog

## 3.10.1 — 2026-10-30

### Critical integration (second review)

- **Pipeline:** body_1 legacy `run_audit_job` stripped at load; only body_2 authorized path runs.
- **ROE:** audit log on authorize/deny; tenant/ROE cross-check in production.
- **Classifier:** `classify_exposure` + `enrich_findings_complete` on active pipeline path.
- **Workers:** job_control claim hard-fails (no soft bypass to running).
- **Tenant:** `tenant_context.py` thread-local scopes; `get_db()` respects active tenant.
- **Evidence:** PDF requires header + `%%EOF`; production packs require signature.
- **CI:** pytest workflow for Phases 1–9 + 3.10.1 integration tests.
- **Tests:** `tests/test_phase3101_integration.py`.

## 3.10.0 — 2026-10-30

Phases 1–9 foundation (ROE, classifier, enrichment, reports, jobs, surfaces, enterprise, regression, docs).
