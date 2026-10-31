# CyberAudit 3.10.7

Reliability and security repair toward 3.11.0 Production Candidate.

Point-in-time authorized audits — not continuous monitoring.

## Changes

- Atomic job claims and ownership-aware heartbeats
- Fail-closed job schema migration
- Strict evidence signature algorithm requirement
- PDF structural validation helper

## Production env (required)

```bash
export DEMO_MODE=0
export CYBERAUDIT_SECRET=$(openssl rand -hex 32)
export CYBERAUDIT_REPORT_SECRET=$(openssl rand -hex 32)
export CYBERAUDIT_ROE_SECRET=$(openssl rand -hex 32)
export CYBERAUDIT_USER=admin
export CYBERAUDIT_PASSWORD='<strong-unique-password>'
```

Confirm GitHub Actions on the release SHA before production use.
