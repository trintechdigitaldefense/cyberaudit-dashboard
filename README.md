# CyberAudit Operations Dashboard

**TrinTech Digital Defense** · **v2.4.0-p3** · Port **1881**

## Clone and run

```bash
git clone https://github.com/trintechdigitaldefense/cyberaudit-dashboard.git
cd cyberaudit-dashboard

python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

export DEMO_MODE=1
export CYBERAUDIT_USER=admin
export CYBERAUDIT_PASSWORD='change-me-now'
export CYBERAUDIT_SECRET=$(openssl rand -hex 32)
export CYBERAUDIT_INGEST_TOKEN=$(openssl rand -hex 24)

python3 dashboard_app.py
```

Open **http://127.0.0.1:1881** — login with `admin` / your password.

## Layout

- `dashboard_app.py` — entrypoint
- `cyberaudit/` — package (`config`, `security`, `db`, `workers`, `app.py` + `app_body_0..7.txt`)
- `templates/` — UI (Overview, Live, Findings, Reports, Playbooks)

## Features (P0–P3)

- Auth (operator / viewer), path-safe downloads, env secrets
- Pipeline ingest APIs + inbox + retention
- Start audit jobs, ack events, playbook trigger, findings UI

## Production

```bash
export DEMO_MODE=0
gunicorn --worker-class eventlet -w 1 -b 127.0.0.1:1881 dashboard_app:app
```
