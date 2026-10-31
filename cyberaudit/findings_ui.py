"""Enrich findings for the client-facing findings table (Director Test).

Guarantee: every row has plain_what, plain_risk, plain_action — never blank
for a director reading the dashboard without an analyst in the room.
"""

from __future__ import annotations

from typing import Any


def enrich_finding_row(f: dict[str, Any]) -> dict[str, Any]:
    """Add plain-English fields for the client table. Always fills all three."""
    out = dict(f)
    title = (f.get("title") or "").strip()
    severity = (f.get("severity") or "info").lower()
    host = f.get("host") or "—"
    port = f.get("port")
    service = (f.get("service") or "").strip()
    host_disp = f"{host}:{port}" if port not in (None, "", "—") else str(host)

    plain_what = ""
    plain_risk = ""
    plain_action = ""

    # 1) Prefer risk_translator packs (most complete)
    try:
        from cyberaudit.risk_translator import translate
        pack = translate(
            {
                "title": title,
                "service": service or title,
                "severity": severity,
                "host": host,
            }
        )
        if isinstance(pack, dict):
            plain_what = (pack.get("what") or "").strip()
            plain_risk = (pack.get("what_could_happen") or pack.get("happen") or "").strip()
            plain_action = (pack.get("do_this_week") or pack.get("week") or "").strip()
    except Exception:
        pass

    # 2) Director mode overlay (title polish + structured view)
    try:
        from cyberaudit.director_mode import director_view, director_title
        finding_in = {
            "title": title,
            "severity": severity,
            "host": host,
            "service": service,
            "plain": {
                "what": plain_what,
                "happen": plain_risk,
                "do_this_week": plain_action,
            },
        }
        dv = director_view(finding_in)
        if isinstance(dv, dict):
            plain_what = (dv.get("what") or plain_what or director_title(finding_in) or "").strip()
            plain_risk = (
                dv.get("what_could_happen") or dv.get("happen") or dv.get("risk") or plain_risk or ""
            ).strip()
            plain_action = (
                dv.get("do_this_week") or dv.get("action") or plain_action or ""
            ).strip()
    except Exception:
        pass

    # 3) Hard fallbacks — Director Test must never see empty cells
    low = title.lower()
    if not plain_what:
        if "smb" in low or "445" in low:
            plain_what = "Outdated or exposed file-sharing (SMB) is reachable on the network"
        elif "rdp" in low or "3389" in low:
            plain_what = "Remote desktop is reachable from the scanned network"
        elif "ssl" in low or "tls" in low or "certificate" in low:
            plain_what = "Encryption or certificate issue on a web service"
        elif title:
            plain_what = f"{title} — ask IT for technical detail; action below is what leadership needs"
        else:
            plain_what = "A network service was found that may need review"

    if not plain_risk:
        if severity in ("critical", "high"):
            plain_risk = (
                "This gap could be used to access systems or data without permission. "
                "It is the kind of opening opportunistic attackers and ransomware operators look for."
            )
        elif severity == "medium":
            plain_risk = "Worth fixing before it becomes a larger problem for the business."
        else:
            plain_risk = "Low urgency; include in routine maintenance."

    if not plain_action:
        if severity in ("critical", "high"):
            plain_action = "Assign an owner and fix within 7 days; confirm closure in writing."
        elif severity == "medium":
            plain_action = "Schedule remediation this month with your IT contact."
        else:
            plain_action = "Track and close when convenient; keep a short record."

    money = ""
    try:
        from cyberaudit.money_risk import estimate_cost
        est = estimate_cost(severity)
        if isinstance(est, dict):
            money = est.get("range_tt") or est.get("display") or ""
        elif isinstance(est, str):
            money = est
    except Exception:
        pass

    if money and plain_risk and "TT$" not in plain_risk:
        plain_risk = f"{plain_risk} Estimated recovery impact: {money}."

    status = (f.get("status") or "open").lower()
    status_label = {
        "open": "Open",
        "new": "Open",
        "in_remediation": "In Remediation",
        "mitigated": "Closed",
        "closed": "Closed",
        "accepted": "Accepted",
        "false_positive": "False Positive",
    }.get(status, status.replace("_", " ").title())

    cma = (f.get("cma_section") or "").strip()
    out["plain_what"] = plain_what
    out["plain_risk"] = plain_risk
    out["plain_action"] = plain_action
    out["host_display"] = host_disp
    out["status_label"] = status_label
    out["cma_display"] = cma if cma else "—"
    try:
        out["cvss_display"] = (
            f"{float(f['cvss_base_score']):.1f}"
            if f.get("cvss_base_score") is not None
            else "—"
        )
    except (TypeError, ValueError):
        out["cvss_display"] = "—"
    return out


def enrich_list(rows: list[dict]) -> list[dict]:
    return [enrich_finding_row(r) for r in rows]
