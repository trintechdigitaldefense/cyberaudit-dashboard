# CyberAudit Changelog

## 3.9.1-strengthen — 2026-10-30

### Strengthen existing paths (no new product surface)

- **Findings Director quality**: `findings_ui.enrich_finding_row` always fills plain_what / plain_risk / plain_action via risk_translator → director_mode → hard fallbacks (Director Test).
- **Real executive PDF on every write**: `write_client_reports` calls `generate_executive_pdf` (reportlab); stub only if PDF engine unavailable; core TXT/HTML/technical guaranteed non-empty.
- **Engagement evidence pack**: `engagement_export.py` builds `CyberAudit_EngagementPack_{session}.zip` with MANIFEST.json + SHA-256 checksums from existing artefacts; auto-attached after successful pipeline.
- **Fail-safe hardening**: job failures clean partial tiny report files; completed jobs verified for primary report presence; worker error message bug fixed (`exp` → exception).
- **Persist plain language**: Phase 1 finding insert embeds translator pack into evidence JSON for recovery if UI enrichment misses.
- **Result metadata**: pipeline result now includes `board_summary`, `report_technical`, preferred `executive_pdf`, `client_name`, `engagement_pack`.

## 3.1.1 — 2026-10-14

### Pipeline hook (Phase 1 complete)

- `run_audit_job` now calls `apply_phase1()` → CVSS, posture, executive PDF, retest delta
- `init_db()` runs `migrate_phase1()` for schema columns and history tables
- Findings persist with CVSS scores and fingerprints (no double-insert)

### Phase 2 started (Scan Deeper)

- **Web application module** (`webapp_module.py`): TLS version/cert expiry, security headers, default/admin paths
- **Plain-language risk translator** (`risk_translator.py`): what / what could happen / this week / this month
- **Sector templates** (`sector_templates.py`): general, retail, finance, healthcare, education

### Still Phase 2

- Authenticated scanning (WinRM/SSH/SMB)
- Wireless audit module


## 3.1.0-phase1 — 2026-10-14

### Phase 1 — Sell Harder (shipped)

1. **CVSS 4.0 scoring overlay** (`cyberaudit/cvss.py`)
2. **Remediation tracking + retest delta** (`cyberaudit/retest.py`)
3. **Branded executive PDF** (`cyberaudit/exec_pdf.py`)

See repository history for full prior entries.
