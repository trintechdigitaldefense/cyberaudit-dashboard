"""Complete finding package — CyberAudit 3.10 Phase 3.

Every finding carries technical description, evidence, plain-language explanation,
business impact, risk confidence, remediation instructions, priority, suggested
deadline, and verification steps.

Financial figures are always labelled estimates with documented assumptions.
No manufactured legal conclusions.
"""

from __future__ import annotations

import json
from typing import Any

PRIORITY_DEADLINE = {
    "critical": ("P1 — immediate", "48 hours"),
    "high": ("P2 — urgent", "7 days"),
    "medium": ("P3 — planned", "30 days"),
    "low": ("P4 — backlog", "90 days"),
    "info": ("P5 — informational", "next maintenance window"),
}


def _evidence_text(finding: dict) -> str:
    raw = finding.get("evidence") or finding.get("evidence_obj")
    if isinstance(raw, dict):
        return json.dumps(raw, ensure_ascii=False)[:800]
    if isinstance(raw, str) and raw.strip():
        return raw.strip()[:800]
    parts = []
    for k in ("host", "port", "service", "banner", "version", "cve"):
        v = finding.get(k)
        if v not in (None, ""):
            parts.append(f"{k}={v}")
    return "; ".join(parts) if parts else "Probe evidence recorded during point-in-time scan."


def _technical_description(finding: dict) -> str:
    host = finding.get("host") or "unknown-host"
    port = finding.get("port")
    service = finding.get("service") or "unknown"
    title = finding.get("title") or "Exposed service"
    cls = finding.get("classification") or "potential_exposure"
    conf = finding.get("confidence") or "low"
    version = finding.get("version") or ""
    base = f"{title} on {host}"
    if port not in (None, ""):
        base += f":{port}"
    base += f" (service={service}, classification={cls}, confidence={conf}"
    if version:
        base += f", version={version}"
    base += ")"
    if finding.get("cve"):
        base += f". CVE hint: {finding.get('cve')} — requires human validation against patch state."
    return base


def _verification_steps(finding: dict) -> list[str]:
    service = (finding.get("service") or "").lower()
    port = finding.get("port")
    host = finding.get("host") or "<host>"
    steps = [
        f"Confirm the service is still reachable only within authorised scope (host {host}"
        + (f", port {port}" if port else "")
        + ").",
        "Apply the agreed remediation under change control.",
        "Re-scan the same host/port in a follow-up engagement (retest package).",
        "Record the new result and mark the finding closed only when the exposure is gone or accepted in writing.",
    ]
    if service in ("rdp", "vnc", "telnet", "ssh"):
        steps.insert(1, "Verify remote-access path is limited to VPN or approved jump host.")
    if service in ("smb",):
        steps.insert(1, "Confirm SMBv1 is disabled and share ACLs match the business need.")
    if service in ("mysql", "mssql", "postgres", "redis", "elasticsearch", "mongodb"):
        steps.insert(1, "Confirm database listens only on private interfaces and requires authentication.")
    return steps


def enrich_finding_complete(finding: dict[str, Any]) -> dict[str, Any]:
    out = dict(finding)
    sev = (out.get("severity") or "medium").lower()
    if sev not in PRIORITY_DEADLINE:
        sev = "medium"

    try:
        from cyberaudit.risk_translator import translate
        plain = translate(out)
    except Exception:
        plain = {
            "what": out.get("title") or "Network exposure requiring review",
            "what_could_happen": "Open services increase attack surface.",
            "do_this_week": "Confirm with IT whether this service is required.",
            "do_this_month": "Document approved services and remove the rest.",
            "translator_key": "default",
        }

    try:
        from cyberaudit.director_mode import director_title
        director = director_title(out)
    except Exception:
        director = plain.get("what") or out.get("title") or ""

    money = None
    try:
        from cyberaudit.money_risk import estimate_cost
        if sev in ("critical", "high", "medium"):
            money = dict(estimate_cost(out))
            money["is_estimate"] = True
            money["assumptions"] = (
                "Order-of-magnitude recovery cost for a T&T SME if this gap were exploited. "
                "Assumes emergency IT labour, limited downtime, and basic forensics. "
                "Excludes regulatory fines, full brand damage, and insurance recoveries. "
                "Not an actuarial quote or insurance valuation."
            )
    except Exception:
        money = None

    privacy = None
    try:
        from cyberaudit.privacy_mapper import map_privacy
        privacy = map_privacy(out)
    except Exception:
        privacy = None

    priority, deadline = PRIORITY_DEADLINE[sev]
    confidence = out.get("confidence") or "low"
    classification = out.get("classification") or "potential_exposure"

    technical = _technical_description(out)
    evidence = _evidence_text(out)
    business_impact = plain.get("what_could_happen") or plain.get("happen") or ""
    if money and money.get("sentence"):
        business_impact = (
            f"{business_impact} {money['sentence']} "
            f"(estimate — see assumptions)."
        ).strip()

    remediation = {
        "this_week": plain.get("do_this_week") or plain.get("week") or "",
        "this_month": plain.get("do_this_month") or plain.get("month") or "",
        "priority": priority,
        "suggested_deadline": deadline,
        "owner_suggestion": "Assign named IT/owner before the deadline; escalate critical items to leadership the same day.",
    }

    package = {
        "technical_description": technical,
        "evidence": evidence,
        "plain_language": director or plain.get("what") or "",
        "plain_what": plain.get("what") or director or "",
        "plain_risk": plain.get("what_could_happen") or "",
        "plain_action": remediation["this_week"],
        "business_impact": business_impact,
        "risk_confidence": confidence,
        "classification": classification,
        "remediation": remediation,
        "verification_steps": _verification_steps(out),
        "money_estimate": money,
        "privacy_context": privacy,
        "cma_note": (
            (out.get("cma_rationale") or "Informational Computer Misuse Act context only.")
            + " Not legal advice; human review required."
        ).strip(),
        "honesty": {
            "point_in_time": True,
            "not_confirmed_vuln_unless": classification == "confirmed_weakness",
            "financials_are_estimates": True,
            "legal_not_advice": True,
        },
    }

    out["intel"] = package
    out["plain_what"] = package["plain_what"]
    out["plain_risk"] = package["plain_risk"]
    out["plain_action"] = package["plain_action"]
    out["business_impact"] = package["business_impact"]
    out["remediation_priority"] = priority
    out["suggested_deadline"] = deadline
    out["verification_steps"] = package["verification_steps"]
    if money:
        out["money"] = money
    return out


def enrich_findings_complete(findings: list[dict]) -> list[dict]:
    return [enrich_finding_complete(f) for f in findings]
