# CyberAudit Changelog

## 3.10.0 — 2026-10-30

### Phase 1 — Critical security and authorization (P0)

- **Signed ROE** (`cyberaudit/roe.py`): HMAC-SHA256 authorization records; mandatory fields; expiration; exact IP/CIDR scope containment; fail closed.
- **Window enforcement**: misconfigured windows DENY (no longer allow); unexpected window errors no longer skipped in pipeline.
- **Host discovery**: removed fallback that treated unresponsive candidates as live (`candidates[:16]` and single-host force-live).
- **Finding honesty**: port heuristics classified as `potential_exposure` with confidence scores — not confirmed vulnerabilities.
- **CMA mapping**: requires rationale and `needs_human_review` — no severity-only legal auto-assignment.
- **PDF integrity**: never write plain-text disguised as PDF; magic-byte validation; optional failure explicit.
- **Module status honesty**: regional intel / patch / IDS modules marked idle when not actually executed.
- **Finalization** (`finalization.py`): completed status only when mandatory deliverables exist.
- **Session fixation**: login rotation sets fresh CSRF and permanent session flag after clear.
- **Tests**: `tests/test_phase1_roe.py` — 11 regression tests (authorization, scope, windows, discovery, PDF, classification).

## 3.9.1-strengthen — 2026-10-30

### Strengthen existing paths

- Findings Director quality, real executive PDF path, engagement pack, fail-safe cleanup.
