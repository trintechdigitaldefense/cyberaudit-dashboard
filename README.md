# CyberAudit Operations Dashboard

**TrinTech Digital Defense** · **v2.4.0-p3** · Port **1881**

Modular: `dashboard_app.py` + `cyberaudit/` package.

| Tier | Features |
|------|----------|
| P0 | Auth, path-safe downloads, env secrets, localhost bind |
| P1 | Ingest APIs, inbox, retention, Docker/gunicorn |
| P2 | Ack, start-audit jobs, findings API, RBAC, CI |
| P3 | Findings UI, playbook Trigger, finding status updates |

```bash
export DEMO_MODE=1 CYBERAUDIT_USER=admin CYBERAUDIT_PASSWORD=change-me
export CYBERAUDIT_SECRET=$(openssl rand -hex 32)
pip install -r requirements.txt && python3 dashboard_app.py
```

`/findings` · `POST /api/playbooks/<name>/trigger` (operator)
