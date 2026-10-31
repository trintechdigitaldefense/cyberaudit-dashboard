"""CVSS 4.0 base-score overlay for CyberAudit findings.

Scores are heuristic (network exposure + service class + optional version evidence),
not full NVD metrics. Labelled as CyberAudit-CVSS4 estimates in reports.

Scoring inputs (documented):
  - service class (telnet, rdp, smb, …)
  - declared severity floor from the finding
  - classification (potential_exposure vs version_suspect)
  - confidence (low/medium/high)
  - never claims NVD official scoring
"""

from __future__ import annotations

from typing import Any


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 0.1:
        return "Low"
    return "None"


_SERVICE_CVSS: dict[str, tuple[float, str, str]] = {
    "telnet": (9.3, "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", "Cleartext remote admin"),
    "ftp": (7.5, "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N", "Cleartext file transfer"),
    "http": (5.3, "AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N", "Unencrypted web service"),
    "rdp": (8.8, "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", "Remote desktop exposure"),
    "smb": (8.6, "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L", "Windows file sharing exposure"),
    "redis": (9.1, "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", "Often unauthenticated data store"),
    "elasticsearch": (8.7, "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N", "Search cluster data exposure"),
    "mysql": (7.5, "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N", "Database port network-reachable"),
    "mssql": (7.5, "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N", "Database port network-reachable"),
    "postgres": (7.5, "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N", "Database port network-reachable"),
    "vnc": (8.2, "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L", "Remote desktop sharing"),
    "ssh": (3.7, "AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N", "Admin service — hardening recommended"),
    "https": (2.0, "AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N", "Encrypted web — informational"),
    "default": (5.0, "AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N", "Exposed network service"),
}

_SEV_FLOOR = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 0.1,
}


def score_finding(
    *,
    service: str = "",
    title: str = "",
    severity: str = "",
    port: str | int = "",
    classification: str = "",
    confidence: str = "",
) -> dict[str, Any]:
    key = (service or "").lower().strip()
    title_l = (title or "").lower()
    matched = "default"
    for k in _SERVICE_CVSS:
        if k == "default":
            continue
        if k in key or k in title_l:
            matched = k
            break

    base, vector, rationale = _SERVICE_CVSS[matched]
    floor = _SEV_FLOOR.get((severity or "").lower())
    if floor is not None and base < floor:
        base = floor

    if (severity or "").lower() in ("low", "info") and matched == "ssh":
        base = min(base, 3.7)

    cls = (classification or "").lower()
    conf = (confidence or "").lower()
    if cls == "potential_exposure" and matched not in ("telnet", "redis"):
        base = min(base, 8.5)
    if conf == "low" and cls == "potential_exposure":
        base = min(base, max(base * 0.95, floor or 0.1))

    base = round(min(10.0, max(0.0, base)), 1)
    return {
        "cvss_version": "4.0",
        "cvss_base_score": base,
        "cvss_severity": severity_from_score(base),
        "cvss_vector": f"CVSS:4.0/{vector}",
        "cvss_rationale": rationale,
        "cvss_service_key": matched,
        "cvss_inputs": {
            "service": service,
            "severity": severity,
            "classification": classification or "unspecified",
            "confidence": confidence or "unspecified",
            "matched_key": matched,
        },
        "cvss_note": (
            "CyberAudit CVSS 4.0 estimate for prioritisation — not an NVD official score. "
            "Based on service exposure class and available evidence only."
        ),
    }


def enrich_finding(finding: dict) -> dict:
    out = dict(finding)
    overlay = score_finding(
        service=str(out.get("service") or ""),
        title=str(out.get("title") or ""),
        severity=str(out.get("severity") or ""),
        port=out.get("port") or "",
        classification=str(out.get("classification") or ""),
        confidence=str(out.get("confidence") or ""),
    )
    out.update(overlay)
    return out


def enrich_findings(findings: list[dict]) -> list[dict]:
    return [enrich_finding(f) for f in findings]
