# Playbook – Suspected Data Exfiltration
**ID:** PB-EXFIL-002  
**Module:** data_exfiltration_module  

## Detection Signals
- Sustained high-volume outbound to non-business destinations
- Unusual protocol / port combinations
- Encrypted tunnels outside approved channels

## Response Steps
1. Quarantine source IP / host.
2. Capture full packet (if capacity allows) for 15 minutes.
3. Correlate with continuous_ids_module alerts.
4. Notify Data Protection Officer (Data Protection Act 2011).
5. Generate formal report via pdf_report_module.
