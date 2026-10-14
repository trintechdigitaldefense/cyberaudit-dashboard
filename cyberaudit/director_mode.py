"""P5.1 — Explain Like I'm a Director."""

from __future__ import annotations
from typing import Any

TERM_MAP: dict[str, str] = {
    "smb": "an old Windows file-sharing method that ransomware often uses to spread",
    "smbv1": "an outdated file-sharing setting criminals still exploit for ransomware",
    "rdp": "remote desktop access that lets someone control a computer from outside",
    "ssh": "a secure remote login channel used by IT staff",
    "telnet": "an old remote-login method that sends passwords in plain text",
    "ftp": "an old file-transfer service that often lacks modern encryption",
    "http": "a website connection that is not encrypted",
    "https": "an encrypted website connection",
    "tls": "the encryption that protects data in transit",
    "vnc": "remote screen-sharing software reachable on the network",
    "winrm": "a Windows management channel that can control servers remotely",
    "mysql": "a database that may hold business or customer records",
    "mssql": "a Microsoft database that may hold business or customer records",
    "postgres": "a database that may hold business or customer records",
    "mongodb": "a database that may hold business or customer records",
    "redis": "an in-memory data store that should never be open to the whole network",
    "elasticsearch": "a search database that can expose large amounts of stored data",
    "wireless": "Wi-Fi",
    "wep": "a broken Wi-Fi security setting that should never be used",
    "ransomware": "malware that locks systems until a payment is demanded",
    "posture": "overall security health score",
}

TITLE_TRANSLATIONS: list[tuple[str, str]] = [
    ("smbv1", "An outdated file-sharing method that ransomware groups still use is switched on."),
    ("smb null", "Anyone on the network can list file shares without logging in — a common first step in ransomware attacks."),
    ("rdp", "Remote desktop is reachable on the network. If passwords are weak, an outsider can take control of that computer."),
    ("telnet", "An ancient remote-login service is on. It sends passwords in clear text and should be turned off."),
    ("http service without tls", "A website is serving pages without encryption — logins and data can be intercepted."),
    ("open wi-fi", "A Wi-Fi network has no password. Anyone nearby can join and potentially reach business systems."),
    ("wep", "Wi-Fi is using a broken security setting. Treat it as effectively open."),
    ("guest ssid", "A guest Wi-Fi name was found — confirm guests cannot reach tills, servers, or cameras."),
    ("redis", "A high-speed data store is open on the network. Attackers use this to steal or wipe data quickly."),
    ("mysql", "A business database port is open on the network — restrict it to trusted systems only."),
    ("vnc", "Remote screen sharing is reachable — lock it down or require a VPN."),
    ("winrm", "Windows remote management is available on the network — treat it like a master key."),
]


def translate_term(term: str) -> str:
    return TERM_MAP.get((term or "").strip().lower(), term)


def director_title(finding: dict) -> str:
    title = (finding.get("title") or "").lower()
    for needle, plain in TITLE_TRANSLATIONS:
        if needle in title:
            return plain
    svc = (finding.get("service") or "").lower()
    if svc in TERM_MAP:
        sev = (finding.get("severity") or "medium").lower()
        urgency = {
            "critical": "This needs same-day attention.",
            "high": "This should be fixed this week.",
            "medium": "Plan a fix within the next month.",
            "low": "Track and improve when practical.",
        }.get(sev, "Review with IT.")
        return f"Issue involving {TERM_MAP[svc]}. {urgency}"
    raw = finding.get("title") or "A security issue was recorded"
    return f"{raw} — ask IT for the technical detail; the action list below is what matters for leadership."


def director_view(finding: dict) -> dict[str, str]:
    plain = finding.get("plain") or {}
    title = director_title(finding)
    return {
        "title_director": title,
        "what": plain.get("what") or title,
        "what_could_happen": plain.get("happen") or "If left open, this kind of gap is how opportunistic attackers get a foothold.",
        "do_this_week": plain.get("do_this_week") or plain.get("week") or "Assign an owner in IT or your managed service provider this week.",
        "do_this_month": plain.get("do_this_month") or plain.get("month") or "Confirm the fix and keep a short written record.",
        "severity": (finding.get("severity") or "medium").lower(),
        "host": finding.get("host") or "",
    }


def enrich_director_mode(findings: list[dict]) -> list[dict]:
    return [{**f, "director": director_view(f)} for f in findings]
