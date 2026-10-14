"""Sector report language packs — Phase 2 feature #9.

One engine, four dialects: retail, finance, healthcare, education.
"""

from __future__ import annotations

from typing import Any

SECTORS: dict[str, dict[str, Any]] = {
    "general": {
        "label": "General business",
        "audience": "business leadership and IT",
        "risk_intro": (
            "This audit maps devices and services reachable during the engagement window. "
            "Findings are prioritised so you can protect operations and customer trust."
        ),
        "priority_note": "Focus first on remote access and any service that handles customer or payment data.",
    },
    "retail": {
        "label": "Retail",
        "audience": "store and operations leadership",
        "risk_intro": (
            "Retail networks often mix point-of-sale, inventory, and guest Wi-Fi. "
            "A single weak remote desktop or open share can put cardholder and customer data at risk."
        ),
        "priority_note": (
            "Prioritise anything that could touch payment terminals, back-office PCs, or customer databases. "
            "Guest Wi-Fi must stay isolated from store systems."
        ),
    },
    "finance": {
        "label": "Finance / professional services",
        "audience": "partners, compliance, and IT",
        "risk_intro": (
            "Financial and professional firms are high-value targets for fraud and data theft. "
            "Exposed remote access and databases are treated as urgent until proven contained."
        ),
        "priority_note": (
            "Treat open RDP, databases, and admin web panels as board-level items. "
            "Align remediation with your confidentiality and client-money obligations."
        ),
    },
    "healthcare": {
        "label": "Healthcare / clinic",
        "audience": "clinic administrators and IT support",
        "risk_intro": (
            "Clinics hold sensitive personal and medical information. "
            "Network exposure can affect patient privacy, continuity of care, and regulatory standing."
        ),
        "priority_note": (
            "Protect systems that store patient records first. "
            "Remote access to clinical workstations must be tightly controlled."
        ),
    },
    "education": {
        "label": "Education",
        "audience": "school or campus leadership",
        "risk_intro": (
            "Education networks serve staff, students, and sometimes parents. "
            "Open services and weak remote access can disrupt learning and expose personal data."
        ),
        "priority_note": (
            "Prioritise staff admin systems and student information systems. "
            "Segment student/guest networks from administrative systems."
        ),
    },
}


def get_sector(name: str | None) -> dict[str, Any]:
    key = (name or "general").strip().lower()
    return SECTORS.get(key, SECTORS["general"])


def sector_preamble(sector_name: str | None, client_name: str = "") -> str:
    s = get_sector(sector_name)
    who = client_name or "your organisation"
    return (
        f"Sector focus: {s['label']} (written for {s['audience']}).\n"
        f"{s['risk_intro']}\n"
        f"For {who}: {s['priority_note']}"
    )
