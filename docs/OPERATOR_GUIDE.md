# CyberAudit Operator Guide (C4)

**Goal:** Productive in one day.

## Setup
```bash
git clone https://github.com/trintechdigitaldefense/cyberaudit-dashboard.git
cd cyberaudit-dashboard && bash install.sh
export CYBERAUDIT_SECRET=$(openssl rand -hex 32)
export CYBERAUDIT_PASSWORD='$(openssl rand -base64 18)'
export DEMO_MODE=0
./venv/bin/python dashboard_app.py
```

## First job
Put JSON in `data/jobs/` with `target`, `client_name`, `sector`, optional `roe_window`.

## Backup / restore
```bash
python3 -c "from cyberaudit.backups import run_backup; print(run_backup())"
```

## Health
`curl -s http://127.0.0.1:1881/health`

trintechdigitaldefense@gmail.com · 1-868-362-0679
