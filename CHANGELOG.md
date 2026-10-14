# CyberAudit Changelog

## 3.7.0-ecosystem — 2026-10-14

### Phase 7 — Build the Ecosystem

| ID | Feature | Proof |
|----|---------|-------|
| P7.1 | Partner/MSP API `/api/v1/` | issue_partner_key + verify + POST jobs |
| P7.2 | Air-gapped edition | CYBERAUDIT_AIRGAP=1 blocks webhooks/email |
| P7.3 | Phishing simulation add-on | campaign ingest + director narrative |
| P7.4 | Spanish board summary | `language: es` → RESUMEN PARA LA JUNTA |
| P7.5 | Certification pathway | CERTIFICATION_PATHWAY.md started |

### Env
```
CYBERAUDIT_PARTNER_KEYS=ca_xxx,ca_yyy
CYBERAUDIT_AIRGAP=1
```

### Prior
- 3.6.0 intel · 3.5.0 director · 3.4.0 hardened · 3.3–3.1 foundation
