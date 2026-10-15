"""Enrich findings for the client-facing findings table (Director Test)."""
from __future__ import annotations
from typing import Any

def enrich_finding_row(f: dict[str, Any]) -> dict[str, Any]:
    out = dict(f)
    title = (f.get("title") or "").strip()
    severity = (f.get("severity") or "info").lower()
    host = f.get("host") or "—"
    port = f.get("port")
    host_disp = f"{host}:{port}" if port else str(host)
    plain_what = title
    plain_risk = ""
    plain_action = "Review with your IT contact this month."
    try:
        from cyberaudit.director_mode import director_view, director_title
        plain_what = director_title(title) if title else title
        dv = director_view({"title": title, "severity": severity, "host": host})
        if isinstance(dv, dict):
            plain_what = dv.get("what") or dv.get("title") or plain_what
            plain_risk = dv.get("happen") or dv.get("risk") or plain_risk
            plain_action = dv.get("do_this_week") or dv.get("action") or plain_action
    except Exception:
        pass
    low = title.lower()
    if not plain_risk:
        if "smb" in low or "445" in low:
            plain_risk = "Attackers can spread ransomware through old file sharing."
            plain_action = "Turn off SMBv1 and restrict file shares this week."
            plain_what = plain_what or "Outdated file-sharing service is exposed"
        elif "rdp" in low or "3389" in low:
            plain_risk = "Remote desktop exposure invites password guessing and break-ins."
            plain_action = "Limit remote desktop to VPN or known IPs this week."
            plain_what = plain_what or "Remote desktop is reachable from the network"
        elif "ssl" in low or "tls" in low or "certificate" in low:
            plain_risk = "Weak encryption can expose logins and data in transit."
            plain_action = "Update TLS settings and certificates this month."
        elif severity in ("critical", "high"):
            plain_risk = "This gap could be used to access systems or data without permission."
            plain_action = "Assign an owner and fix within 7 days."
        elif severity == "medium":
            plain_risk = "Worth fixing before it becomes a larger problem."
            plain_action = "Schedule remediation this month."
        else:
            plain_risk = "Low urgency; include in routine maintenance."
            plain_action = "Track and close when convenient."
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
        "open": "Open", "new": "Open", "in_remediation": "In Remediation",
        "mitigated": "Closed", "closed": "Closed", "accepted": "Accepted",
        "false_positive": "False Positive",
    }.get(status, status.replace("_", " ").title())
    out["plain_what"] = plain_what
    out["plain_risk"] = plain_risk
    out["plain_action"] = plain_action
    out["host_display"] = host_disp
    out["status_label"] = status_label
    out["cma_display"] = f.get("cma_section") or "—"
    out["cvss_display"] = (
        f"{float(f['cvss_base_score']):.1f}" if f.get("cvss_base_score") is not None else "—"
    )
    return out

def enrich_list(rows: list[dict]) -> list[dict]:
    return [enrich_finding_row(r) for r in rows]
