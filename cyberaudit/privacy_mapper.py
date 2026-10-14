"""Data Protection Act (T&T) + GDPR-style mapping — Phase 3 feature #15."""

from __future__ import annotations

from typing import Any

_PERSONAL_DATA_SIGNALS = (
    "mysql", "mssql", "postgres", "mongodb", "elasticsearch", "redis",
    "ldap", "http", "https", "smb", "ftp", "admin", "database",
)

DPA_TAGS = {
    "security_safeguards": "DPA — appropriate security safeguards for personal data",
    "unauthorised_access": "DPA — risk of unauthorised access to personal data",
    "integrity": "DPA — integrity and confidentiality of personal data",
}

GDPR_TAGS = {
    "art32": "GDPR Art. 32 — security of processing (technical measures)",
    "art5": "GDPR Art. 5 — integrity and confidentiality principle",
    "art33": "GDPR Art. 33 — personal data breach notification readiness",
}


def _looks_personal_data_related(finding: dict) -> bool:
    blob = " ".join(
        str(finding.get(k) or "")
        for k in ("service", "title", "host", "evidence", "cma_section")
    ).lower()
    return any(s in blob for s in _PERSONAL_DATA_SIGNALS)


def map_privacy(finding: dict) -> dict[str, Any]:
    if not _looks_personal_data_related(finding):
        return {
            "personal_data_relevant": False,
            "dpa_tags": [],
            "gdpr_tags": [],
            "privacy_note": "",
        }
    sev = (finding.get("severity") or "").lower()
    dpa = [DPA_TAGS["security_safeguards"]]
    gdpr = [GDPR_TAGS["art32"]]
    if sev in ("critical", "high"):
        dpa.append(DPA_TAGS["unauthorised_access"])
        gdpr.append(GDPR_TAGS["art5"])
        if sev == "critical":
            gdpr.append(GDPR_TAGS["art33"])
    dpa.append(DPA_TAGS["integrity"])
    return {
        "personal_data_relevant": True,
        "dpa_tags": dpa,
        "gdpr_tags": gdpr,
        "privacy_note": (
            "This finding may affect systems that store or process personal data. "
            "Under Trinidad & Tobago's Data Protection Act 2011, organisations must "
            "apply appropriate safeguards. If EU/UK personal data is in scope, GDPR "
            "security-of-processing duties may also apply. This is awareness mapping — "
            "not a formal legal opinion."
        ),
    }


def enrich_with_privacy(findings: list[dict]) -> list[dict]:
    out = []
    for f in findings:
        row = dict(f)
        row["privacy"] = map_privacy(f)
        out.append(row)
    return out
