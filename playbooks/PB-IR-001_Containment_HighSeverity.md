# Incident Response Playbook – High Severity Containment
**ID:** PB-IR-001  
**Owner:** TrinTech Digital Defense – Incident Response  
**Trigger:** Critical / High severity finding from OpenVAS or IDS  

## 1. Immediate Actions (0-15 min)
1. Isolate affected host(s) via firewall (incident_response_module auto-action).
2. Snapshot volatile memory and disk if forensics required.
3. Notify on-call SOC analyst and legal liaison.

## 2. Containment
- Apply temporary ACL blocking outbound C2 indicators.
- Disable compromised service accounts.
- Force password reset on adjacent systems if lateral movement suspected.

## 3. Eradication & Recovery
- Apply vendor patches or compensating controls.
- Re-image if rootkit / persistent backdoor confirmed.
- Verify with post-remediation scan (patch_verification_module).

## 4. Legal Mapping
- Document under Trinidad & Tobago Computer Misuse Act Sections 3, 6, 7.
- Preserve evidence chain for potential TT-CSIRT escalation.

## 5. Lessons Learned
- Update detection rules.
- Feed indicators into regional_threat_intel module.
