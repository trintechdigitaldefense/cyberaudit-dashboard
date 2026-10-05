# CyberAudit Operations Dashboard

**TrinTech Digital Defense** · Real audit pipeline · Port **1881**

This is **not** a toy demo by default. Queued audits run a real reconnaissance → assessment → TT Computer Misuse Act mapping → report → SQLite archive pipeline.

## Production run (recommended)

```bash
git clone https://github.com/trintechdigitaldefense/cyberaudit-dashboard.git
cd cyberaudit-dashboard

python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

export DEMO_MODE=0
export CYBERAUDIT_USER=admin
export CYBERAUDIT_PASSWORD='your-strong-password'
export CYBERAUDIT_SECRET=$(openssl rand -hex 32)
export CYBERAUDIT_INGEST_TOKEN=$(openssl rand -hex 24)

python3 dashboard_app.py
```

Open **http://127.0.0.1:1881** → sign in → **Overview** → enter a target (IP, hostname, or small CIDR) → **Queue job**.

The **job runner** will:

1. Run TCP connect recon (uses **nmap** automatically if installed)
2. Apply vulnerability heuristics on open services
3. Map findings to **Computer Misuse Act Chap. 11:17** Sections 3 / 6 / 7
4. Write a report under `reports/`
5. Archive the session and findings in SQLite

Watch **Live**, **Findings**, and **Reports** for real output.

## Optional: DEMO_MODE=1

Synthetic live-feed only. Do **not** use for client work.

## Contact

- **Email:** trintechdigitaldefense@gmail.com
- **Phone:** 1-868-362-0679
- **Web:** https://trintechdigitaldefense.github.io
- **Ops:** Remote · Trinidad and Tobago

## Architecture

| Component | Role |
|-----------|------|
| `dashboard_app.py` | Entrypoint |
| `cyberaudit/pipeline_engine.py` | **Real** audit execution |
| `cyberaudit/workers.py` | Job runner + inbox + retention |
| `cyberaudit/db.py` | SQLite archive |
| `data/jobs/` | Queued audit jobs (JSON) |
| `reports/` | Generated reports |

External scanners (OpenVAS/GVM, full IDS) can still push via **ingest APIs** / **inbox** JSON using `CYBERAUDIT_INGEST_TOKEN`.
