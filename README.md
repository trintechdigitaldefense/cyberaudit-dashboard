# CyberAudit 3.0 Client Dashboard

**TrinTech Digital Defense** — point-in-time network auditing for Trinidad & Tobago and Caribbean engagements.

When you run an audit, CyberAudit maps live systems, open services, risk findings, TT Computer Misuse Act context, and produces **plain-language client reports** plus a technical annex.

## Quick start (operator)

```bash
git clone https://github.com/trintechdigitaldefense/cyberaudit-dashboard.git
cd cyberaudit-dashboard
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

export DEMO_MODE=0
export CYBERAUDIT_USER=admin
export CYBERAUDIT_PASSWORD=admin   # change for real clients
export CYBERAUDIT_SECRET=$(openssl rand -hex 32)

python3 dashboard_app.py
# → http://127.0.0.1:1881
```

Queue a target (e.g. `127.0.0.1` or an authorised subnet). Modules run end-to-end; reports appear under **Reports**.

## Production

```bash
gunicorn --worker-class eventlet -w 1 -b 127.0.0.1:1881 --timeout 300 dashboard_app:app
```

See `CLIENT_RUNBOOK.md`, `deploy/cyberaudit.service`, and `docker-compose.yml`.

## What a run produces

| Output | Audience |
|--------|----------|
| `CyberAudit_Client_*.txt` / `.html` | Management — plain English |
| `CyberAudit_Technical_*.txt` | IT / security team |
| `CyberAudit_NetworkMap_*.json` | Machine-readable inventory |
| Findings + sessions in SQLite | Operator dashboard |

## Contact

trintechdigitaldefense@gmail.com · 1-868-362-0679 · https://trintechdigitaldefense.github.io
