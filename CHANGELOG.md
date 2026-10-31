# CyberAudit Changelog

## 3.10.0 — 2026-10-30

### Phase 9 — Documentation & Definition of Done

- **docs/RELEASE_NOTES_3.10.md** — honest release notes (shipped only).
- **docs/DOD_CHECKLIST_3.10.md** — pre-release / pre-client checklist.
- Version bumped to **3.10.0** in config and README.

### Phase 8 — Full regression suite

- **tests/test_phase8_regression.py**: 18 acceptance tests.
- Combined Phases 1–8 core suite: **59 passed**.

### Phase 7 — Enterprise multi-client isolation

- enterprise.py: tenant lock, ROE client match, engagement lifecycle, retention, archive.

### Phase 6 — Dashboard surfaces

- jobs, assets, heatmap, remediation, history, retest, compliance, activity, health.

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
