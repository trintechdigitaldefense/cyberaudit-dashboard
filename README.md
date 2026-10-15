# CyberAudit

**TrinTech Digital Defense**

Point-in-time network auditing for Trinidad & Tobago and Caribbean engagements — map what's alive, understand the risk in plain English, tied to local law.

**Version:** 3.9.0-complete · **Port:** 1881

---

## What CyberAudit does

A modular audit pipeline you run under a signed Rules of Engagement:

1. **Discover** — Find live hosts and open services on the authorised target.
2. **Map** — Build a network picture of what is reachable from the scan location.
3. **Assess** — Score findings (including CVSS-style estimates), posture, and remediation status.
4. **Legal context** — Tag relevant issues against Trinidad & Tobago Computer Misuse Act Chap. 11:17 (ss. 3, 6, 7) — informational, not legal advice.
5. **Report** — Produce director-readable board summaries, technical annexes, and optional executive PDF.
6. **Operate** — Track findings, retest deltas, live event feed, and operator presence on the dashboard.

This is a **point-in-time** engagement tool. It is **hardened and auditable**. It is **not** 24/7 monitoring.

---

## Key features

### Scanning & discovery

- Host and service discovery (nmap-backed where available)
- Banner / risk heuristics and web application checks (TLS, headers, common admin paths)
- Optional GVM/OpenVAS report ingest (complements enterprise scanners)
- Optional authenticated scan hooks and wireless / cloud snapshot checks
- ROE time windows so jobs respect agreed scan periods

### Risk & reporting

- CVSS-style base score estimates on findings
- Posture score (0–100) with Caribbean SME-oriented bands
- Plain-language risk translator and **Director mode** (IT language ↔ board English)
- TT$ recovery-cost ranges on critical findings (order-of-magnitude, cited as estimates)
- One-page **board summary** and branded executive PDF
- Retest delta: closed / still open / newly introduced
- Spanish board summary option (`language: es`)

### Security & operations

- Dashboard authentication, RBAC roles, CSRF and security headers
- Production startup refuses weak default credentials
- AES-256 data encryption option, audit log, rate limiting
- Automated encrypted backups with tested restore path
- Partner API (`/api/v1/`) with API keys
- Air-gapped mode (no outbound webhooks/email)
- Operator **presence**: who is connected, when they connected, when they left (to the second)

### For clients

- Plain-language portal view and board-ready one-pagers
- Computer Misuse Act context on relevant findings
- Community tier for eligible NGOs, schools, and churches (host limits apply)
- Workshop-in-a-box materials for owner education

AI-assisted wording in reports is intended for **human review** before client delivery.

---

## What it is not

- **Not** a replacement for a full enterprise vulnerability management platform — GVM ingest is optional complement, not a claim that CyberAudit replaces OpenVAS/Nessus in every environment.
- **Not** a SOC, MDR, or continuous monitoring product.
- **Not** “impenetrable” software — it is **hardened and auditable** for professional engagements.

It **is** a fast, local, ROE-friendly network picture with client-ready reports for Caribbean businesses.

---

## Who it’s for

| Audience | Why they care |
|----------|----------------|
| SME / mid-market owners | Clear picture of what’s exposed, in money and plain English |
| Boards | One-page summary they can actually read in a meeting |
| IT managers | Technical annex, CVSS-style scores, retest deltas |
| Compliance-minded organisations | CMA context, ROE discipline, audit trail |

---

## Packages

Price to your market — amounts are **not** listed here.

| Package | Scope (typical) | Deliverable |
|---------|-----------------|-------------|
| **Snapshot** | Single site / subnet, one window | Board summary + technical annex + network map |
| **Campus** | Multiple segments or sites under one ROE | Full findings set, posture, executive PDF |
| **Retest** | After remediation | Delta report (closed / open / new) |

Community tier is available for eligible non-commercial organisations in T&T (limited host count).

---

## Legal & compliance

- Findings can be mapped to **Computer Misuse Act, Chap. 11:17, Sections 3, 6, and 7** for awareness.
- That mapping is **informational**. It is **not legal advice**.
- **Scanning requires a signed Rules of Engagement** (scope, window, contacts, authorisation).
- CyberAudit must not be used to scan systems outside authorised scope.

---

## Quick start

### Install

```bash
git clone https://github.com/trintechdigitaldefense/cyberaudit-dashboard.git
cd cyberaudit-dashboard
bash install.sh
# or:
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### Lab / demo run

```bash
export DEMO_MODE=1
export CYBERAUDIT_SECRET=$(openssl rand -hex 32)
python3 dashboard_app.py
# → http://127.0.0.1:1881
```

### Production run

```bash
export DEMO_MODE=0
export CYBERAUDIT_USER=operator
export CYBERAUDIT_PASSWORD='$(openssl rand -base64 18)'   # strong secret — required
export CYBERAUDIT_SECRET=$(openssl rand -hex 32)
python3 dashboard_app.py
# or:
gunicorn --worker-class eventlet -w 1 -b 127.0.0.1:1881 --timeout 300 wsgi:app
```

Production mode **refuses** to start with weak defaults such as `admin` / `admin`.

### Docker

```bash
docker compose up --build
```

See `CLIENT_RUNBOOK.md`, `docs/OPERATOR_GUIDE.md`, and `deploy/cyberaudit.service`.

### Health

```bash
curl -s http://127.0.0.1:1881/health
```

---

## Security

- Prefer **127.0.0.1** or VPN-only binding; do not expose the dashboard carelessly to the public internet.
- Set strong `CYBERAUDIT_SECRET` and password; enable TLS at the reverse proxy when serving remotely.
- Retain and back up `data/` and `reports/` according to client agreement.
- **We refuse:** startup with default admin/admin in production; scanning outside ROE scope; marketing continuous monitoring we do not provide.

Air-gap: `export CYBERAUDIT_AIRGAP=1` disables outbound alerts/webhooks.

---

## Outputs

| Output | Audience |
|--------|----------|
| Board summary (TXT) | Directors / owners — plain English |
| Client report (TXT / HTML) | Management |
| Executive PDF | Printable board pack |
| Technical annex | IT / security |
| Network map JSON | Automation / inventory |
| Retest delta | Proof of remediation progress |
| Live feed + presence | Operators — who is on console, event stream |

---

## Contact

**TrinTech Digital Defense**  
trintechdigitaldefense@gmail.com · 1-868-362-0679  
https://trintechdigitaldefense.github.io  

Remote operations · Trinidad and Tobago  

**Product:** CyberAudit · **Version:** 3.9.0-complete · **Updated:** 14 October 2026

---

## License & confidentiality

© 2026 TrinTech Digital Defense.  
Engagement reports and client data remain confidential under NDA and ROE terms.  
Reuse of public methodology language with attribution is permitted for education and media; commercial republication of TrinTech materials requires written permission.

**Caribbean Cyber Resilience · Trinidad & Tobago**
