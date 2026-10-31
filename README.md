# CyberAudit 3.10.9

**TrinTech Digital Defense**

Point-in-time network auditing for Trinidad & Tobago and Caribbean engagements — map what's alive, understand the risk in plain English, tied to local law.

**Version:** 3.10.9 · **Port:** 1881

CyberAudit is a **point-in-time** authorised audit tool — not continuous 24/7 monitoring.

## Production environment (required)

```bash
export DEMO_MODE=0
export CYBERAUDIT_SECRET=$(openssl rand -hex 32)
export CYBERAUDIT_REPORT_SECRET=$(openssl rand -hex 32)
export CYBERAUDIT_ROE_SECRET=$(openssl rand -hex 32)
export CYBERAUDIT_USER=admin
export CYBERAUDIT_PASSWORD='<strong-unique-password>'
```

Never commit secrets.

## Quick start (lab)

```bash
git clone https://github.com/trintechdigitaldefense/cyberaudit-dashboard.git
cd cyberaudit-dashboard
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export DEMO_MODE=1
export CYBERAUDIT_SECRET=$(openssl rand -hex 32)
export CYBERAUDIT_REPORT_SECRET=$(openssl rand -hex 32)
python3 dashboard_app.py
```

## Contact

trintechdigitaldefense@gmail.com · 1-868-362-0679 · https://trintechdigitaldefense.github.io

**Product:** CyberAudit · **Version:** 3.10.9
