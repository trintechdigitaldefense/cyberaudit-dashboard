# CyberAudit Changelog

## 3.10.0 — 2026-10-30

### Phase 4 — Reporting and evidence integrity

- **report_signing.py**: HMAC-SHA256 signed MANIFEST; pack verification (ZIP + checksums + signature).
- **engagement_export.py**: mandatory Client+Technical artefacts required; fake PDFs excluded; auth reference in manifest; version/scope/time recorded.
- **finalization.py**: clearer mandatory checks (executive_txt|report, technical_txt|report_technical).
- Missing mandatory artefacts → completed status refused.
- Tests: `tests/test_phase4_reports.py` (6 passed).

### Phase 3 — Intelligence and risk translation

- **finding_enrichment.py**: technical, evidence, plain language, business impact, confidence, remediation priority/deadline, verification steps.
- Financial figures labelled estimates with assumptions.
- findings_ui wires complete package; money path fixed.

### Phase 2 — Audit engine corrections

- finding_classifier, false_positive, CVSS input documentation.

### Phase 1 — Critical security and authorization (P0)

- Signed ROE, fail-closed windows, no invented live hosts, finalization foundation.

## 3.9.1-strengthen — 2026-10-30

- Findings Director quality, engagement pack baseline, fail-safe cleanup.
