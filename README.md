# CyberAudit Operations Dashboard

**TrinTech Digital Defense** · Port **1881**

Live monitoring, report download, and playbook console for the CyberAudit 11-module pipeline.

## Quick Start

```bash
cd cyber_audit_dashboard
python3 -m pip install -r requirements.txt
python3 dashboard_app.py
```

Open: http://localhost:1881

## Features

| Page | Path | Description |
|------|------|-------------|
| Overview | `/` | KPIs, module status, recent sessions, live event preview |
| Live Feed | `/live` | Real-time WebSocket event stream from IDS / exfil / intel modules |
| Reports | `/reports` | List & download PDF compliance reports |
| Playbooks | `/playbooks` | View & download IR playbooks (Markdown) |
| About | `/about` | Full business details, legal mapping, contact |

## API Endpoints

- `GET /health` – health check
- `GET /api/status` – full snapshot (modules + events + sessions)
- `GET /api/events` – live events
- `GET /api/sessions` – audit history
- `GET /api/modules` – module status
- `GET /download/report/<file>` – PDF download
- `GET /download/playbook/<file>` – playbook download

## Business Details Embedded

- Company: TrinTech Digital Defense
- Registration: TT-C-2023-88421
- Address: Level 3, Maritime Centre, 29 Tenth Avenue, Barataria, Trinidad and Tobago
- Legal focus: Computer Misuse Act Chap. 11:17 (Sections 3, 6, 7)
- TT-CSIRT / CARICOM IMPACS alignment

## Notes

- Sample data and placeholder PDFs are auto-seeded on first run.
- Background simulator injects realistic live events for demonstration.
- Production: replace placeholders with real output from `pdf_report_module` and connect to the live `cyber_audit.db`.
- For production use a proper WSGI server (gunicorn + eventlet) behind a reverse proxy.
