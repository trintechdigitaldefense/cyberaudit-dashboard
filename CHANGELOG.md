# CyberAudit Changelog

## 3.3.0-phase3 — 2026-10-14

### Phase 3 — Operate at Scale

10. **RBAC** (`rbac.py`) — admin / analyst / viewer permission matrix
11. **ROE windows** (`schedule_windows.py`) — jobs only run inside start–end hours; enforced in pipeline + job_runner
12. **Encryption at rest** (`encryption.py`) — AES-256-GCM via CYBERAUDIT_DATA_KEY; secure_delete helper
13. **Alerts** (`alerts.py`) — operator webhook/email; optional client webhook with opt-in
14. **Multi-tenant** (`tenants.py`) — data/tenants/<client_id>/ isolation
15. **DPA + GDPR mapping** (`privacy_mapper.py`) — personal-data relevance tags on findings

### Env

```
CYBERAUDIT_ANALYST_USER / CYBERAUDIT_ANALYST_PASSWORD
CYBERAUDIT_VIEWER_USER / CYBERAUDIT_VIEWER_PASSWORD
CYBERAUDIT_DATA_KEY          # 64-hex or passphrase
CYBERAUDIT_ALERT_WEBHOOK
CYBERAUDIT_ALERT_EMAIL + SMTP_*
```

### Job fields

```json
{
  "roe_window": {"enabled": true, "start": "02:00", "end": "04:00", "days": [0,1,2,3,4]},
  "client_webhook": "https://...",
  "client_alerts_opt_in": true
}
```
