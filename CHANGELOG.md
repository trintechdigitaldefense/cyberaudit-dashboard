# CyberAudit Changelog

## 3.1.0-phase1 — 2026-10-14

### Phase 1 — Sell Harder (shipped)

1. **CVSS 4.0 scoring overlay** (`cyberaudit/cvss.py`)
   - Every finding receives `cvss_base_score`, `cvss_severity`, `cvss_vector`, rationale.
   - Heuristic base scores by service class (RDP, SMB, Telnet, databases, etc.).
   - Labelled as CyberAudit estimates for prioritisation (not NVD official scores).

2. **Remediation tracking + retest delta** (`cyberaudit/retest.py`)
   - Finding lifecycle: `open` → `in_remediation` → `closed` → `new` / `accepted_risk`.
   - Status history table for audit trail.
   - Retest delta report auto-generated when a prior completed session exists for the same target.
   - Outputs: `CyberAudit_RetestDelta_{session}.txt` + `.json` (closed / still open / newly introduced).

3. **Branded executive PDF** (`cyberaudit/exec_pdf.py`)
   - Printable board pack: posture score, severity distribution, top-5 risks, trend arrow.
   - Client name + optional logo path.
   - TrinTech branding, CMA disclaimer, contact block.

4. **Posture score 0–100** (`cyberaudit/posture.py`)
   - Weighted model from critical/high/medium/low findings.
   - Caribbean SME comparison bands (Excellent → Critical posture).
   - `posture_history` table for trend over engagements.

### Integration

- `cyberaudit/phase1_db.py` — schema migrations (safe ALTER IF missing).
- `cyberaudit/phase1_integrate.py` — single entry `apply_phase1()` for the pipeline.
- Tests: `tests/test_phase1.py`.

### Dependencies

- `reportlab>=4.0` added for executive PDF generation.

### Operator notes

- Pipeline should call `apply_phase1()` after CMA mapping and before/during archive.
- Finding status API: use `retest.set_finding_status(id, status, changed_by=...)`.
- Default login remains env-driven; never ship `admin`/`admin` to client sites.
