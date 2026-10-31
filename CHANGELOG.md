# CyberAudit Changelog

## 3.10.0 — 2026-10-30

### Phase 3 — Intelligence and risk translation

- **finding_enrichment.py**: every finding gets technical description, evidence, plain language, business impact, confidence, remediation priority/deadline, verification steps.
- Financial figures always labelled **estimates** with assumptions (money_risk).
- findings_ui: fixed estimate_cost(severity) bug → estimate_cost(finding); wires complete package.
- CMA/privacy remain informational — not legal advice.
- Tests: `tests/test_phase3_intel.py` (4 tests).

### Phase 2 — Audit engine corrections

- **finding_classifier.py**: potential_exposure / version_suspect; version extraction; CVE hints only with banner evidence.
- Deduplication + false_positive suppressions.
- CVSS 4.0 documents scoring inputs; non-NVD note.
- Tests: Phase 2 classifier suite.

### Phase 1 — Critical security and authorization (P0)

- Signed ROE (`cyberaudit/roe.py`), fail-closed windows, no invented live hosts.
- PDF integrity, module status honesty, finalization gate.
- Tests: `tests/test_phase1_roe.py`.

## 3.9.1-strengthen — 2026-10-30

- Findings Director quality, engagement pack, fail-safe cleanup.
