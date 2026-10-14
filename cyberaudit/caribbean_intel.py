"""P5.5 — Threat intel in local Caribbean / T&T terms."""

from __future__ import annotations
from typing import Any

INTEL = [
    {"keys": ("smb", "smbv1", "null session"), "headline": "Ransomware groups still use old file-sharing weaknesses",
     "local": "Across the Caribbean, several 2023–2025 business disruptions began with exposed Windows file sharing. Treat SMBv1 or open shares as priority.",
     "sources": ["CISA StopRansomware", "Regional MSP incident patterns (anonymised)"]},
    {"keys": ("rdp", "vnc", "winrm"), "headline": "Remote access left open is a top entry point",
     "local": "Caribbean SMEs with direct remote desktop on the public internet are frequently targeted with password-guessing. Prefer VPN and multi-factor access.",
     "sources": ["TT-CSIRT awareness guidance on exposed RDP", "Global remote-access brute-force reports"]},
    {"keys": ("mysql", "mssql", "postgres", "mongodb", "redis", "elasticsearch"), "headline": "Databases on the open network invite data theft",
     "local": "When a database port answers on a wide network, scanners will find it. For firms holding customer records in T&T, this raises Data Protection Act duties.",
     "sources": ["Data Protection Act 2011 (awareness)", "Public database-exposure research"]},
    {"keys": ("http", "tls", "ssl", "admin path"), "headline": "Weak or missing web encryption still shows up in audits",
     "local": "Login pages without strong encryption remain a source of account takeover against Caribbean professional-services sites.",
     "sources": ["OWASP transport security", "Regional account-takeover reports"]},
    {"keys": ("wireless", "wep", "open wi-fi", "wpa"), "headline": "Open or legacy Wi-Fi is an office-level risk",
     "local": "In shared buildings and retail across T&T, weak guest Wi-Fi often sits near tills or back-office PCs. Separate guest traffic; retire WEP/open networks.",
     "sources": ["WPA2/WPA3 baselines", "Retail engagement patterns (anonymised)"]},
]

def match_intel(findings: list[dict]) -> list[dict]:
    blob_parts, hosts_by_key = [], {}
    for f in findings:
        text = " ".join(str(f.get(k) or "") for k in ("service", "title", "evidence")).lower()
        host = str(f.get("host") or "")
        blob_parts.append(text)
        for item in INTEL:
            for key in item["keys"]:
                if key in text:
                    hosts_by_key.setdefault(key, set()).add(host)
    blob = " ".join(blob_parts)
    cards = []
    for item in INTEL:
        matched = [k for k in item["keys"] if k in blob]
        if not matched:
            continue
        hosts = set()
        for k in matched:
            hosts |= hosts_by_key.get(k, set())
        hosts.discard("")
        cards.append({
            "headline": item["headline"], "local": item["local"], "sources": item["sources"],
            "matched_keys": matched, "host_count": len(hosts), "hosts": sorted(hosts)[:12],
            "director_line": item["headline"] + (". This pattern matches " + str(len(hosts)) + " system(s) in your results." if hosts else ". This pattern matches findings in your results."),
        })
    return cards

def intel_report_section(findings: list[dict]) -> str:
    cards = match_intel(findings)
    if not cards:
        return "No curated Caribbean threat patterns matched this scan's findings. Continue routine patching and access reviews."
    lines = ["THREAT CONTEXT (Caribbean-focused, sources cited)", ""]
    for c in cards:
        lines += [f"• {c['director_line']}", f"  {c['local']}", f"  Sources: {'; '.join(c['sources'])}", ""]
    lines.append("This context is for awareness. It is not a prediction that you will be attacked, and it is not 24/7 monitoring.")
    return "\n".join(lines)
