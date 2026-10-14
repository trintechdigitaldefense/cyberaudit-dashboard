"""Network posture score (0–100) with Caribbean SME comparison bands.

Used to sell the retest ladder: clients must SEE improvement over time.
"""

from __future__ import annotations

from typing import Any


BANDS = [
    (90, 100, "Excellent", "Top quartile vs Caribbean SME baseline"),
    (75, 89, "Good", "Above typical Caribbean SME baseline"),
    (60, 74, "Fair", "Near typical Caribbean SME baseline"),
    (40, 59, "Needs improvement", "Below typical Caribbean SME baseline"),
    (0, 39, "Critical posture", "Urgent remediation recommended"),
]


def compute_posture_score(
    *,
    findings: list[dict] | None = None,
    hosts_up: int = 0,
    open_ports: int = 0,
) -> dict[str, Any]:
    findings = findings or []
    crit = sum(1 for v in findings if (v.get("severity") or "").lower() == "critical")
    high = sum(1 for v in findings if (v.get("severity") or "").lower() == "high")
    med = sum(1 for v in findings if (v.get("severity") or "").lower() == "medium")
    low = sum(1 for v in findings if (v.get("severity") or "").lower() == "low")

    score = 100.0 - crit * 25 - high * 12 - med * 5 - low * 1

    if hosts_up > 0 and open_ports > hosts_up * 8:
        score -= 5.0

    score = max(0.0, min(100.0, round(score, 1)))
    band_name, band_note = "Critical posture", "Urgent remediation recommended"
    for lo, hi, name, note in BANDS:
        if lo <= score <= hi:
            band_name, band_note = name, note
            break

    return {
        "posture_score": score,
        "band": band_name,
        "band_note": band_note,
        "counts": {
            "critical": crit,
            "high": high,
            "medium": med,
            "low": low,
            "total": len(findings),
            "hosts_up": hosts_up,
            "open_ports": open_ports,
        },
        "caribbean_sme_context": (
            "Bands are CyberAudit internal comparisons for Caribbean SMEs — "
            "not a regulatory grade. Use to track improvement after remediation."
        ),
    }


def trend_arrow(previous: float | None, current: float) -> str:
    if previous is None:
        return "→ baseline"
    delta = current - previous
    if delta >= 5:
        return f"↑ +{delta:.0f}"
    if delta <= -5:
        return f"↓ {delta:.0f}"
    return f"→ {delta:+.0f}"
