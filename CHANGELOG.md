# CyberAudit Changelog

## 3.6.0-intel — 2026-10-14

### Phase 6 — Intelligence Layer

| ID | Feature | Module | Proof |
|----|---------|--------|-------|
| P6.1 | GVM/OpenVAS ingestion | `gvm_ingest.py` | XML/JSON parse + merge |
| P6.2 | Credential leak check | `credential_leak.py` | Corpus match + remediation plain language |
| P6.3 | Cloud posture (AWS/Azure snapshot) | `cloud_posture.py` | Public buckets, open SGs, root MFA |
| P6.4 | Anonymized benchmarks | `benchmarks.py` | Consent-gated sector averages |

Job fields: `openvas_report`, `domain`/`emails`, `cloud_snapshot`, `benchmark_consent: true`.

Honesty: we complement scanners; breach results only reflect loaded corpus; cloud checks use operator snapshot JSON.

### Prior releases
- 3.5.0 Phase 5 Director mode / TT$ money / board summary / portal / Caribbean intel
- 3.4.0 Phase 4 H1–H10 hardening
- 3.3.0 Phase 3 RBAC / windows / encryption / alerts / tenants / DPA
- 3.2.0 Phase 2 auth / wireless / web
- 3.1.0 Phase 1 CVSS / posture / retest / exec PDF
