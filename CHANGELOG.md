# CyberAudit Changelog

## 3.10.6 — 2026-10-30

### Production integration repair

- Migrations (`phase1_db`, `phase5_db`) and backups use active tenant `_db_path()`.
- Report signing uses **only** `CYBERAUDIT_REPORT_SECRET` (no ROE/app fallback).
- Strict pack verification: checksum coverage, path traversal rejection, signature required.
- Concurrent claim race tests (threaded).
- Version **3.10.6** from `cyberaudit/VERSION`.

## 3.10.5 — 2026-10-30

Tenant-aware get_db, atomic claim, VERSION source.
