# CyberAudit Operations Dashboard

**TrinTech Digital Defense** · Port **1881** · **v2.3.0-p2**

| Tier | Features |
|------|----------|
| **P0** | Session auth, path-safe downloads, env secrets/CORS, localhost bind, demo-gated simulator |
| **P1** | Pipeline ingest APIs, JSON inbox, event retention, Docker/gunicorn |
| **P2** | Operator ack, start-audit jobs, findings API, viewer/operator RBAC, CI |

## Quick start (demo)

```bash
export DEMO_MODE=1
export CYBERAUDIT_USER=admin
export CYBERAUDIT_PASSWORD='change-me-now'
export CYBERAUDIT_SECRET=$(openssl rand -hex 32)
export CYBERAUDIT_INGEST_TOKEN=$(openssl rand -hex 24)
python3 -m pip install -r requirements.txt
python3 dashboard_app.py
```

## Operator actions (P2)

- `POST /api/events/<id>/ack` — acknowledge alert (operator only)
- `POST /api/jobs/start_audit` — `{target}` → `data/jobs/JOB-*.json` + optional trigger cmd
- `GET /api/jobs` / `GET /api/findings` / `GET /api/sessions/<id>` / `GET /api/me`

RBAC: operator = `CYBERAUDIT_USER`; viewer = `CYBERAUDIT_VIEWER_USER`.

## Pipeline ingest (P1)

`X-CyberAudit-Token` + `/api/ingest/*` or drop JSON in `CYBERAUDIT_INBOX_DIR`.

## Production

```bash
gunicorn --worker-class eventlet -w 1 -b 127.0.0.1:1881 dashboard_app:app
```
