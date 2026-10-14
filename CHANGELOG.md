# CyberAudit Changelog

## 3.1.1 — 2026-10-14

### Pipeline hook (Phase 1 complete)

- `run_audit_job` (via `pipeline_body_2.txt`) calls `apply_phase1()` → CVSS, posture, executive PDF, retest delta
- `init_db()` runs `migrate_phase1()` for schema columns and history tables
- Findings persist with CVSS scores and fingerprints (no double-insert)

### Phase 2 started (Scan Deeper)

- **Web application module** (`webapp_module.py`): TLS version/cert expiry, security headers, default/admin paths
- **Plain-language risk translator** (`risk_translator.py`): what / what could happen / this week / this month
- **Sector templates** (`sector_templates.py`): general, retail, finance, healthcare, education

### Still Phase 2

- Authenticated scanning (WinRM/SSH/SMB)
- Wireless audit module
