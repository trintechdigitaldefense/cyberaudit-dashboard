# CyberAudit Changelog

## 3.10.5 — 2026-10-30

### Integration repair and release gate

- **db.get_db / init_db**: always use `resolve_db_path()` + mkdir parent.
- **claim_job**: `BEGIN IMMEDIATE` + conditional UPDATE (one winner).
- **Version**: authoritative `cyberaudit/VERSION` (3.10.5) loaded by config.
- **Tests**: `test_phase3105_gate.py` — tenant isolation, claim, ROE, signing, no version drift.
- **pipeline_authorized**: remove dead `exp if False else` expressions.
- **report_signing**: dedicated `CYBERAUDIT_REPORT_SECRET` (demo-only fallback).

## 3.10.4 — 2026-10-30

Sync release with static helpers and authorized entry.

## 3.10.3 — 2026-10-30

Core integration attempt.
