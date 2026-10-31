# CyberAudit Changelog

## 3.10.0 — 2026-10-30

### Phase 6 — Dashboard surfaces

- **dashboard_surfaces.py**: executive overview, jobs, assets, heatmap, remediation board, history, retest candidates, compliance, activity log, honest system health, evidence archive.
- New pages: `/jobs` `/assets` `/heatmap` `/remediation` `/history` `/retest` `/compliance` `/activity` `/health-ui` + `/api/surfaces/*`.
- Sidebar nav expanded; module health never treats idle as operational.
- Tests: `tests/test_phase6_surfaces.py` (2 passed).

### Phase 5 — Database and worker reliability

- job_control, phase5_db, claim/heartbeat/stale recovery, transactional finalize.

### Phase 4 — Reporting and evidence integrity

- report_signing, mandatory pack artefacts, PDF validation.

### Phase 3 — Intelligence and risk translation

- finding_enrichment complete package.

### Phase 2 — Audit engine corrections

- finding_classifier, false_positive, CVSS inputs.

### Phase 1 — Critical security and authorization (P0)

- Signed ROE, fail-closed windows, no invented live hosts.

## 3.9.1-strengthen — 2026-10-30

- Findings Director quality, engagement pack baseline, fail-safe cleanup.
