# CyberAudit Changelog

## 3.10.0 — 2026-10-30

### Phase 2 — Audit engine corrections

- **finding_classifier.py**: evidence-based classification (`potential_exposure` / `version_suspect`); version extraction; optional CVE *hints* only with banner evidence; never auto-confirmed from port alone.
- **Deduplication**: fingerprint lifecycle merge keeps higher confidence.
- **false_positive.py**: suppression table + mark FP with optional lasting suppress.
- **CVSS 4.0**: documents scoring inputs; dampens pure exposure scores; explicit non-NVD note.
- **Tests**: `tests/test_phase2_classifier.py` (6 tests). Combined Phase 1+2: 17 passed.

### Phase 1 — Critical security and authorization (P0)

- **Signed ROE** (`cyberaudit/roe.py`): HMAC-SHA256; mandatory fields; expiration; IP/CIDR scope; fail closed.
- **Window enforcement**: misconfigured windows DENY; pipeline does not skip window errors.
- **Host discovery**: removed unresponsive-as-live fallbacks.
- **Finding honesty**: port heuristics as potential_exposure with confidence.
- **CMA mapping**: rationale + needs_human_review.
- **PDF integrity**: no text-as-PDF; magic-byte check.
- **Module status honesty**: idle when not executed.
- **Finalization** (`finalization.py`): completed only with mandatory artefacts.
- **Session fixation**: rotation after clear.
- **Tests**: `tests/test_phase1_roe.py` — 11 tests.

## 3.9.1-strengthen — 2026-10-30

- Findings Director quality, engagement pack, fail-safe cleanup.
