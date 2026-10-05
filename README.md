# CyberAudit Operations Dashboard

**TrinTech Digital Defense** · Default port **1881** · Version **2.1.1-p0**

Live monitoring, report download, and playbook console for the CyberAudit 11-module pipeline.

> **P0 hardened:** session auth, path-safe downloads, env-based secrets, CORS lockdown, localhost bind by default, demo simulator gated.

## Quick Start (demo)

```bash
export DEMO_MODE=1
export CYBERAUDIT_USER=admin
export CYBERAUDIT_PASSWORD='change-me-now'
export CYBERAUDIT_SECRET=$(openssl rand -hex 32)

cd cyberaudit-dashboard   # or cyber_audit_dashboard
python3 -m pip install -r requirements.txt
python3 dashboard_app.py
```

Open: http://127.0.0.1:1881  
Login with the user/password you set.

## Production (minimum)

```bash
export DEMO_MODE=0
export CYBERAUDIT_HOST=127.0.0.1
export CYBERAUDIT_PORT=1881
export CYBERAUDIT_USER=ops
export CYBERAUDIT_PASSWORD='long-random-password'
export CYBERAUDIT_SECRET=$(openssl rand -hex 32)
export CYBERAUDIT_DB_PATH=/var/lib/cyberaudit/cyber_audit.db
export CYBERAUDIT_REPORTS_DIR=/var/lib/cyberaudit/reports
export CYBERAUDIT_PLAYBOOKS_DIR=/var/lib/cyberaudit/playbooks
# optional: export CYBERAUDIT_ALLOWED_ORIGINS=https://audit.example.tt
# optional behind TLS: export CYBERAUDIT_COOKIE_SECURE=1

python3 dashboard_app.py
```

Put **nginx/Caddy** in front with TLS. Prefer gunicorn + eventlet for multi-client production (not the built-in Werkzeug server).

## Environment variables

| Variable | Default | Purpose |
|----------|---------|--------|
| `DEMO_MODE` | `0` | `1` = seed sample data + live event simulator |
| `CYBERAUDIT_SECRET` | required if not demo | Flask session secret |
| `CYBERAUDIT_USER` / `CYBERAUDIT_PASSWORD` | empty | If both set, login is required |
| `CYBERAUDIT_HOST` | `127.0.0.1` | Bind address (`0.0.0.0` only behind firewall/proxy) |
| `CYBERAUDIT_PORT` | `1881` | Listen port |
| `CYBERAUDIT_DB_PATH` | `./data/cyber_audit.db` | SQLite path (point at real pipeline DB) |
| `CYBERAUDIT_REPORTS_DIR` | `./reports` | PDF reports directory |
| `CYBERAUDIT_PLAYBOOKS_DIR` | `./playbooks` | Markdown playbooks |
| `CYBERAUDIT_DATA_DIR` | `./data` | Data directory |
| `CYBERAUDIT_ALLOWED_ORIGINS` | localhost variants | Comma-separated CORS origins for Socket.IO |
| `CYBERAUDIT_COOKIE_SECURE` | off | Set `1` when serving only over HTTPS |

## Features

| Page | Path | Description |
|------|------|-------------|
| Login | `/login` | Session auth (when credentials configured) |
| Overview | `/` | KPIs, module status, recent sessions, live preview |
| Live Feed | `/live` | WebSocket event stream |
| Reports | `/reports` | List & download PDFs (path-safe) |
| Playbooks | `/playbooks` | View & download IR playbooks (path-safe) |
| About | `/about` | Business / legal mapping |
| Health | `/health` | Unauthenticated liveness (db + flags only) |

## API (authenticated when auth enabled)

- `GET /api/status` – modules + events + sessions
- `GET /api/events` – live events
- `GET /api/sessions` – audit history
- `GET /api/modules` – module status
- `GET /download/report/<file>` – PDF (must stay under reports dir)
- `GET /download/playbook/<file>` – playbook (must stay under playbooks dir)

## Security notes (P0)

- Downloads resolve paths and **reject traversal** outside reports/playbooks roots.
- Socket.IO connections require an authenticated session when auth is enabled.
- Default bind is **127.0.0.1**, not the public internet.
- Simulator and sample PDFs run **only** when `DEMO_MODE=1`.
- `/health` does not require login but does not return secrets or findings.

## Next (P1)

Wire real `cyber_audit.db` + module status from the pipeline; remove reliance on demo seed for production use.
