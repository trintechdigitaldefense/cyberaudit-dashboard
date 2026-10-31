# CyberAudit 3.10.7

**TrinTech Digital Defense**

Point-in-time network auditing for Trinidad & Tobago and Caribbean engagements — map what's alive, understand the risk in plain English, tied to local law.

**Version:** 3.10.7 · **Port:** 1881

---

## What CyberAudit does

A modular audit pipeline you run under a signed Rules of Engagement:

1. **Discover** — Find live hosts and open services on the authorised target.
2. **Assess** — Classify exposures with evidence and confidence.
3. **Map** — Tie findings to T&T Computer Misuse Act (Chap. 11:17 ss.3/6/7) and regional context.
4. **Report** — Executive and technical deliverables, optional engagement evidence pack.
5. **Verify** — Mandatory deliverables and signatures before an audit is marked complete.

CyberAudit is a **point-in-time** authorised audit tool — not continuous 24/7 monitoring.

---

## Production environment (required)

```bash
export DEMO_MODE=0
export CYBERAUDIT_SECRET=$(openssl rand -hex 32)
export CYBERAUDIT_REPORT_SECRET=$(openssl rand -hex 32)
export CYBERAUDIT_ROE_SECRET=$(openssl rand -hex 32)
export CYBERAUDIT_USER=admin
export CYBERAUDIT_PASSWORD='<strong-unique-password>'
# Optional: password hash instead of plaintext
# export CYBERAUDIT_PASSWORD_HASH=$(python3 -c "from cyberaudit.auth_hardening import hash_password; print(hash_password('your-password'))")
```

Never commit secrets. Bind to localhost or a private interface; terminate TLS at a reverse proxy for remote access.

---

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
# http://127.0.0.1:1881
```

---

## Contact

trintechdigitaldefense@gmail.com · 1-868-362-0679 · https://trintechdigitaldefense.github.io

**Product:** CyberAudit · **Version:** 3.10.7

TrinTech Digital Defense — hardened and auditable, not "impenetrable".
