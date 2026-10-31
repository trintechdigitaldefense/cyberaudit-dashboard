# CyberAudit Changelog

## 3.10.0 — 2026-10-30

### Phase 5 — Database and worker reliability

- **job_control.py**: atomic claim, payload-hash dedup, heartbeats, stale recovery, bounded attempts, transactional finalize.
- **phase5_db.py**: job control columns, worker_heartbeats, job_dedup, backup_database / restore_database.
- **workers.py**: claim before run, heartbeat in loop, finalize before completed status, consistent failure cleanup.
- **hardening.fail_safe_job**: mandatory deliverable validation before honouring completed.
- **db.init_db**: runs migrate_phase5.
- Tests: `tests/test_phase5_jobs.py` (5 passed).

### Phase 4 — Reporting and evidence integrity

- report_signing, engagement pack mandatory gate, finalization, fake PDF rejection.

### Phase 3 — Intelligence and risk translation

- finding_enrichment complete package; money estimates labelled.

### Phase 2 — Audit engine corrections

- finding_classifier, false_positive, CVSS inputs.

### Phase 1 — Critical security and authorization (P0)

- Signed ROE, fail-closed windows, no invented live hosts.

## 3.9.1-strengthen — 2026-10-30

- Findings Director quality, engagement pack baseline, fail-safe cleanup.
