"""Plain-language risk translator — Phase 2 feature #8.

Every finding: WHAT this is → WHAT could happen → WHAT to do this week / this month.
Written for a Trinidad & Tobago business owner, not a security engineer.
"""

from __future__ import annotations

from typing import Any

TRANSLATIONS: dict[str, dict[str, str]] = {
    "telnet": {
        "what": "An old remote-access tool (Telnet) is reachable on your network.",
        "happen": "Someone watching network traffic could read passwords and commands in plain text — like a postcard anyone can read.",
        "week": "Ask IT to turn Telnet off on this device today.",
        "month": "Confirm no other legacy remote tools remain; standardise on VPN + SSH.",
    },
    "ftp": {
        "what": "File transfer (FTP) is available without modern encryption.",
        "happen": "Files and login details may travel unprotected across the network.",
        "week": "Stop using FTP for sensitive files; move to SFTP or a secure share.",
        "month": "Decommission FTP servers or lock them to internal-only use.",
    },
    "http": {
        "what": "A website or web app is running without HTTPS encryption.",
        "happen": "Staff or customers may expose passwords on the path between their device and the server.",
        "week": "Enable HTTPS with a certificate (free options exist) and redirect HTTP to HTTPS.",
        "month": "Review all public sites for the same issue and set a company standard.",
    },
    "https": {
        "what": "An encrypted web service was found that may need certificate or header attention.",
        "happen": "Expired certificates break trust and can interrupt business; missing headers make browser attacks easier.",
        "week": "Renew any expiring certificates; fix critical header gaps.",
        "month": "Add certificate monitoring so expiry never surprises you again.",
    },
    "rdp": {
        "what": "Windows Remote Desktop (RDP) is reachable from the scanned network.",
        "happen": "Attackers often use open RDP as a doorway for ransomware. This is one of the most common breach paths worldwide.",
        "week": "Restrict RDP to VPN or a jump host only; disable it on machines that do not need it.",
        "month": "Require multi-factor authentication for all remote access; review who still has RDP rights.",
    },
    "smb": {
        "what": "Windows file-sharing (SMB) is exposed on the scanned network.",
        "happen": "Misconfigured shares can leak confidential files; unpatched SMB has powered major outbreaks.",
        "week": "Confirm only intended folders are shared and who can open them.",
        "month": "Apply security updates; block SMB from the internet edge permanently.",
    },
    "redis": {
        "what": "A Redis data store is reachable without strong network controls.",
        "happen": "Open Redis installs have been used for full data theft and server takeover.",
        "week": "Bind Redis to localhost or a private network; set a strong password.",
        "month": "Ensure Redis is never published to the public internet.",
    },
    "elasticsearch": {
        "what": "An Elasticsearch service is network-reachable.",
        "happen": "Open Elasticsearch clusters have leaked large amounts of customer data globally.",
        "week": "Require authentication and place it behind a firewall.",
        "month": "Audit indices for personal data and tighten retention.",
    },
    "ssh": {
        "what": "Secure Shell (SSH) remote administration is available.",
        "happen": "SSH is normal and useful, but weak passwords or unused accounts raise risk.",
        "week": "Prefer SSH keys over passwords; disable root login if practical.",
        "month": "Review authorised keys and remove leavers' access.",
    },
    "mysql": {
        "what": "A MySQL database port is open on the network.",
        "happen": "Databases should rarely be reachable beyond application servers — exposure increases data-theft risk.",
        "week": "Firewall the database to application hosts only.",
        "month": "Enforce strong credentials and encryption in transit.",
    },
    "mssql": {
        "what": "A Microsoft SQL Server database port is open on the network.",
        "happen": "Database exposure is a high-value target for attackers seeking customer or financial records.",
        "week": "Restrict access by firewall rules immediately.",
        "month": "Enable encryption and review privileged accounts.",
    },
    "postgres": {
        "what": "A PostgreSQL database port is open on the network.",
        "happen": "Same as other databases — limit who can reach it.",
        "week": "Firewall the port to application servers only.",
        "month": "Use strong passwords or certificates; review grants.",
    },
    "vnc": {
        "what": "Remote screen-sharing (VNC) is reachable.",
        "happen": "Weak or missing VNC passwords can give an attacker a live view and control of a desktop.",
        "week": "Disable VNC if unused, or require a VPN and a strong password.",
        "month": "Replace ad-hoc VNC with a managed remote-support tool.",
    },
    "admin_path": {
        "what": "A default or admin web page responded on a public or internal web service.",
        "happen": "Attackers probe these paths first. If login is weak, they may take over the application.",
        "week": "Remove or restrict admin paths; enforce strong passwords and MFA.",
        "month": "Put admin interfaces behind VPN or IP allow-lists.",
    },
    "tls_expired": {
        "what": "The website's security certificate has expired.",
        "happen": "Browsers will warn customers; some integrations will fail. Trust and sales can drop overnight.",
        "week": "Renew the certificate and confirm auto-renew is working.",
        "month": "Add monitoring alerts 30 days before expiry.",
    },
    "default": {
        "what": "A network service was found that may need review.",
        "happen": "Every open service increases the surface attackers can probe.",
        "week": "Confirm with IT whether this service is required; close it if not.",
        "month": "Document approved services and remove the rest.",
    },
}


def _pick_key(finding: dict) -> str:
    title = (finding.get("title") or "").lower()
    service = (finding.get("service") or "").lower()
    if "expired" in title and "cert" in title:
        return "tls_expired"
    if "admin path" in title or "default/admin" in title:
        return "admin_path"
    for k in TRANSLATIONS:
        if k in service or k in title:
            return k
    return "default"


def translate(finding: dict) -> dict[str, str]:
    key = _pick_key(finding)
    pack = TRANSLATIONS.get(key, TRANSLATIONS["default"])
    return {
        "what": pack["what"],
        "what_could_happen": pack["happen"],
        "do_this_week": pack["week"],
        "do_this_month": pack["month"],
        "translator_key": key,
    }


def enrich_with_plain_language(findings: list[dict]) -> list[dict]:
    out = []
    for f in findings:
        row = dict(f)
        row["plain"] = translate(f)
        out.append(row)
    return out
