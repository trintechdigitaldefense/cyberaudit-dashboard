# CyberAudit Changelog

## 3.10.3 — 2026-10-30

### Core integration completion

- **db.get_db / init_db**: use `resolve_db_path()` — tenant isolation without mutating config.DB_PATH.
- **pipeline_helpers.py**: static helpers (no runtime exec of body text).
- **pipeline_authorized**: imports helpers module; ROE-first path retained.
- **report_signing**: unsigned packs never marked verified when secret configured.
- **tests/test_phase3103_core.py**: real tenant DB isolation without config mutation.
- Version unified to **3.10.3**.

## 3.10.2 — 2026-10-30

Authorized pipeline entry; zero-host honesty; CI pip-audit hard fail.

## 3.10.1 / 3.10.0 — 2026-10-30

Foundation phases and earlier integration attempts.
