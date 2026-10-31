# CyberAudit Changelog

## 3.10.8 — 2026-10-30

### Final reliability and security repair

- Ownership-aware `mark_job`.
- Tightened `claim_job` (no empty-owner reclaim of fresh running jobs).
- Transactional conditional `recover_stale_jobs`.
- Zero-host discovery as partial/no_coverage.
- PDF production requires pypdf.
- VERSION 3.10.8.
