# CyberAudit Changelog

## 3.10.0 — 2026-10-30

### Phase 7 — Enterprise multi-client isolation

- **enterprise.py**: tenant resolution (client role cannot override header), client registry, ROE client match, engagement lifecycle, retention dry-run/apply, secure archive, environment profile.
- API: `/api/enterprise/tenants`, select-tenant, engagements, retention, archive-client, environment, validate-roe.
- Isolation rule: one client never sees another client's data.
- Tests: `tests/test_phase7_enterprise.py` (7 passed).

### Phase 6 — Dashboard surfaces

- dashboard_surfaces + jobs/assets/heatmap/remediation/history/retest/compliance/activity/health pages.

### Phase 5 — Database and worker reliability

- job_control, heartbeats, stale recovery, transactional finalize.

### Phase 4 — Reporting and evidence integrity

- report_signing, mandatory pack artefacts, PDF validation.

### Phase 3 — Intelligence and risk translation

- finding_enrichment complete package.

### Phase 2 — Audit engine corrections

- finding_classifier, false_positive, CVSS inputs.

### Phase 1 — Critical security and authorization (P0)

- Signed ROE, fail-closed windows, no invented live hosts.
