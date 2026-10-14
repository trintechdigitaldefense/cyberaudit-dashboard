"""P5.2 — Risk translated into money (TT$)."""

from __future__ import annotations
from typing import Any

COST_TABLE = {
    "ransomware_path": {"critical": (150_000, 600_000), "high": (80_000, 250_000), "medium": (25_000, 80_000), "low": (5_000, 25_000)},
    "remote_access": {"critical": (100_000, 400_000), "high": (60_000, 200_000), "medium": (20_000, 70_000), "low": (5_000, 20_000)},
    "database_exposure": {"critical": (120_000, 500_000), "high": (70_000, 220_000), "medium": (25_000, 90_000), "low": (8_000, 30_000)},
    "web_exposure": {"critical": (50_000, 200_000), "high": (30_000, 100_000), "medium": (10_000, 40_000), "low": (3_000, 15_000)},
    "wireless": {"critical": (40_000, 150_000), "high": (25_000, 80_000), "medium": (8_000, 30_000), "low": (2_000, 10_000)},
    "default": {"critical": (50_000, 200_000), "high": (30_000, 100_000), "medium": (10_000, 40_000), "low": (3_000, 15_000), "info": (0, 5_000)},
}

SOURCE_NOTE = (
    "Estimated recovery cost ranges for a Trinidad & Tobago SME if this gap were exploited. "
    "Drawn from published breach-cost research (IBM Cost of a Data Breach), Caribbean incident "
    "response patterns, and local IT professional services rates. Figures exclude regulatory fines "
    "and full brand damage. Decision aids — not formal actuarial quotes."
)
TT_PER_USD = 6.8


def _category(finding: dict) -> str:
    blob = " ".join(str(finding.get(k) or "") for k in ("service", "title", "cve", "evidence")).lower()
    if any(x in blob for x in ("smb", "ransomware", "null session", "smbv1")):
        return "ransomware_path"
    if any(x in blob for x in ("rdp", "vnc", "winrm", "ssh", "telnet", "remote")):
        return "remote_access"
    if any(x in blob for x in ("mysql", "mssql", "postgres", "mongo", "redis", "elastic", "database")):
        return "database_exposure"
    if any(x in blob for x in ("http", "https", "tls", "ssl", "web", "admin path")):
        return "web_exposure"
    if any(x in blob for x in ("wifi", "wi-fi", "wireless", "wpa", "wep")):
        return "wireless"
    return "default"


def estimate_cost(finding: dict) -> dict[str, Any]:
    sev = (finding.get("severity") or "medium").lower()
    if sev not in ("critical", "high", "medium", "low", "info"):
        sev = "medium"
    cat = _category(finding)
    table = COST_TABLE.get(cat) or COST_TABLE["default"]
    low, high = table.get(sev) or COST_TABLE["default"].get(sev) or (10_000, 40_000)
    return {
        "category": cat, "severity": sev, "tt_low": low, "tt_high": high,
        "tt_display": f"TT${low:,.0f} – TT${high:,.0f}",
        "usd_display": f"US${low/TT_PER_USD:,.0f} – US${high/TT_PER_USD:,.0f}",
        "sentence": f"If exploited, recovery for a T&T business of this size is estimated at TT${low:,.0f}–{high:,.0f} (about US${low/TT_PER_USD:,.0f}–{high/TT_PER_USD:,.0f}).",
        "source_note": SOURCE_NOTE,
    }


def enrich_with_money(findings: list[dict]) -> list[dict]:
    out = []
    for f in findings:
        row = dict(f)
        row["money"] = estimate_cost(f) if (f.get("severity") or "").lower() in ("critical", "high", "medium") else None
        out.append(row)
    return out


def portfolio_exposure(findings: list[dict]) -> dict[str, Any]:
    highs = []
    for f in findings:
        if (f.get("severity") or "").lower() not in ("critical", "high"):
            continue
        m = f.get("money") or estimate_cost(f)
        highs.append(m["tt_high"])
    if not highs:
        return {"tt_high_sum": 0, "display": "TT$0 (no critical/high items)", "note": "No major recovery-cost band estimated."}
    highs_sorted = sorted(highs, reverse=True)
    combined = highs_sorted[0] + int(sum(highs_sorted[1:]) * 0.3)
    return {
        "tt_high_sum": combined, "count": len(highs),
        "display": f"TT${combined:,.0f} combined upper estimate across {len(highs)} high/critical item(s)",
        "note": "Combined upper estimate assumes partial overlap. A single ransomware event can dominate total cost.",
        "source_note": SOURCE_NOTE,
    }
