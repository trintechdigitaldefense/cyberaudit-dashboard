# CyberAudit 3.10.5

Integration repair. Point-in-time authorized audits — not continuous monitoring.

## Fixed

- Tenant DB connections via `resolve_db_path()`
- Atomic job claim
- Single version source (`cyberaudit/VERSION` = 3.10.5)
- Report signing secret preference
- Clean authorized pipeline warnings

## Limitations

- Prefer one tenant per worker process
- Confirm GitHub Actions green on this SHA before production use
