# CyberAudit 3.4 — Hardening Guide (H1–H10)

## Production checklist

```bash
export DEMO_MODE=0
export CYBERAUDIT_SECRET=$(openssl rand -hex 32)
export CYBERAUDIT_USER=admin
export CYBERAUDIT_PASSWORD='$(openssl rand -base64 24)'   # >= 12 chars, not in weak list
export CYBERAUDIT_HOST=127.0.0.1
export CYBERAUDIT_COOKIE_SECURE=1
export CYBERAUDIT_DATA_KEY=$(openssl rand -hex 32)
# Optional: CYBERAUDIT_ALLOW_BIND_ALL=1 only behind a locked-down firewall
```

Secrets gate **exits the process** if admin/admin, weak passwords, short secret, or unbound 0.0.0.0 without flag.

## Controls

| ID | Control | How |
|----|---------|-----|
| H1 | Session | HttpOnly + SameSite + TTL; rotate on login |
| H2 | Rate limit | Login 8 attempts / 60s per IP |
| H3 | TLS | Reverse-proxy TLS; HSTS header; secure cookies |
| H4 | Input validation | `validate_job_payload` rejects `; \| & \` ..` |
| H5 | Secrets | Startup gate — no weak defaults in prod |
| H6 | Audit log | `data/audit_log.db` hash chain — `verify_audit_chain()` |
| H7 | Deps | `pip-audit -r requirements.txt` |
| H8 | Fail-safe | Job exceptions → status=failed, queue continues |
| H9 | Headers | CSP, nosniff, X-Frame-Options DENY |
| H10 | CSRF | `csrf_token` in templates; `X-CSRF-Token` header |

## Do / Don't (Definition of Done)

- NEVER ship admin/admin in production
- NEVER bind 0.0.0.0 carelessly
- NEVER scan outside ROE scope / window
- ALWAYS run fresh clone + venv smoke test before client engagement
