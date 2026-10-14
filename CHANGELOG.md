# CyberAudit Changelog

## 3.2.0-phase2 — 2026-10-14

### Phase 2 — Scan Deeper (complete)

5. **Authenticated scanning** (`auth_scan_module.py`)
   - SSH (paramiko optional), SMB (smbclient), WinRM (pywinrm optional)
   - Credentials only from job JSON or env — never in code
   - Skips entirely when no credentials supplied

6. **Web application module** (`webapp_module.py`)

7. **Wireless audit** (`wireless_module.py`)
   - Operator survey JSON in job (`wireless_survey`) or optional nmcli local radio
   - Open/WEP/WPA1 findings, guest SSID isolation notes

8. **Plain-language risk translator** — wireless pack added

9. **Sector templates** wired into pipeline + executive reports
   - Job fields: `sector`, `client_name`

### Optional deps

```
pip install paramiko pywinrm
```

System: `smbclient` for SMB enumeration; `nmcli` for local Wi-Fi survey.
