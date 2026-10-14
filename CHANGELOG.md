# CyberAudit Changelog

## 3.4.0-hardened — 2026-10-14

### Phase 4 — A-class hardening (H1–H10)

| ID | Control | Implementation |
|----|---------|----------------|
| H1 | Session security | HttpOnly, SameSite=Lax, TTL 8h, secure cookies when configured |
| H2 | Rate limiting | Login 8/min; decorator for scan endpoints |
| H3 | TLS expectations | HSTS header in prod; bind 127.0.0.1; cookie secure |
| H4 | Input validation | `validate_job_payload` / target schema — no shell metacharacters |
| H5 | Secrets gate | Refuses admin/admin, weak passwords, missing secret, 0.0.0.0 without flag |
| H6 | Audit logging | Hash-chained SQLite `audit_log.db` (tamper-evident) |
| H7 | Dependency audit | `pip-audit -r requirements.txt` documented |
| H8 | Fail-safe jobs | `fail_safe_job()` — crashes never hang the queue |
| H9 | Security headers | CSP, nosniff, DENY frame, Referrer-Policy |
| H10 | CSRF | Session token + `X-CSRF-Token` / form field |

### Production startup

```bash
export DEMO_MODE=0
export CYBERAUDIT_SECRET=$(openssl rand -hex 32)
export CYBERAUDIT_PASSWORD='long-random-password-here'
export CYBERAUDIT_COOKIE_SECURE=1
export CYBERAUDIT_HOST=127.0.0.1
# never admin/admin — process exits if weak secrets detected
```

### Prior

- 3.3.0 Phase 3 RBAC / windows / encryption / alerts / tenants / DPA
- 3.2.0 Phase 2 auth / wireless / web / translator / sectors
- 3.1.0 Phase 1 CVSS / posture / retest / exec PDF
