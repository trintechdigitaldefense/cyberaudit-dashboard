# CyberAudit 3.0 — Client Engagement Runbook

**TrinTech Digital Defense** · Point-in-time network audit (not 24/7 monitoring)

## Before you arrive on site

1. Signed **Rules of Engagement** (scope IPs/CIDRs, windows, contacts).
2. Strong credentials — never leave `admin`/`admin` on a client network.
3. Laptop or VM with Python 3.12+, optional `nmap`, VPN to management VLAN only.

```bash
git clone https://github.com/trintechdigitaldefense/cyberaudit-dashboard.git
cd cyberaudit-dashboard
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

export DEMO_MODE=0
export CYBERAUDIT_USER=ops
export CYBERAUDIT_PASSWORD='(strong unique password)'
export CYBERAUDIT_SECRET=$(openssl rand -hex 32)

# Lab only:
python3 dashboard_app.py

# Client site (production WSGI):
gunicorn --worker-class eventlet -w 1 -b 127.0.0.1:1881 --timeout 300 dashboard_app:app
```

Or Docker: set `CYBERAUDIT_PASSWORD` and `CYBERAUDIT_SECRET` then `docker compose up --build`.

## During the audit

1. Open http://127.0.0.1:1881 — sign in.
2. Overview → enter **only in-scope** targets (IP, hostname, or small CIDR).
3. Queue job → modules move idle → running → ok.
4. Live feed shows progress; Findings list technical items.
5. Reports: download **CyberAudit_Client_*.txt** or **.html** (plain language for management) and **Technical_*** annex.

## After the audit

1. Deliver executive HTML/TXT to the client contact.
2. Keep technical annex for IT remediation tracking.
3. Delete or encrypt engagement data when the retention period ends.
4. Do not leave the dashboard bound to 0.0.0.0 on a client LAN without agreement.

## Contact

- trintechdigitaldefense@gmail.com
- 1-868-362-0679
- https://trintechdigitaldefense.github.io
