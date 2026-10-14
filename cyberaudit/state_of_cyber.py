"""P8.1 — Annual State of Cybersecurity in T&T (anonymized benchmarks only)."""
from __future__ import annotations
import datetime
from pathlib import Path
from typing import Any
from cyberaudit import config
from cyberaudit.benchmarks import SECTORS, init_benchmarks, sector_stats
COMPANY = config.COMPANY

def _all_sector_stats() -> list[dict[str, Any]]:
    init_benchmarks()
    return [sector_stats(s) for s in SECTORS]

def build_state_report(year: int | None = None) -> str:
    year = year or datetime.datetime.now().year
    rows = _all_sector_stats()
    total_n = sum(r.get("sample_size") or 0 for r in rows)
    scored = [r for r in rows if (r.get("sample_size") or 0) > 0]
    national_avg = None
    if scored:
        national_avg = sum(r["average"] * r["sample_size"] for r in scored) / sum(r["sample_size"] for r in scored)
    lines = [
        "═" * 72, f"  {COMPANY['name']}".center(72),
        f"  STATE OF CYBERSECURITY IN TRINIDAD & TOBAGO — {year}".center(72),
        f"  {COMPANY['tagline']}".center(72), "═" * 72, "",
        f"Published: {datetime.datetime.now().strftime('%d %B %Y')}",
        "Method: Anonymized engagement baselines only (consent-gated).",
        "No organisation names, network addresses, or personal data are included.", "",
        "─" * 72, "NATIONAL SNAPSHOT", "─" * 72,
        f"  Anonymized samples in dataset:  {total_n}",
        (f"  Weighted average posture:       {national_avg:.0f} / 100" if national_avg is not None else "  Weighted average posture:       insufficient data"),
        "", "  Posture bands: 80–100 Strong · 60–79 Manageable · 40–59 Needs work · <40 Urgent", "",
        "─" * 72, "BY SECTOR", "─" * 72,
    ]
    for r in rows:
        n = r.get("sample_size") or 0
        if n == 0:
            lines.append(f"  {r['sector'].title():12}  n=0   (no anonymized samples yet)")
            continue
        provisional = "  [provisional — small sample]" if n < 5 else ""
        lines.append(f"  {r['sector'].title():12}  avg={r['average']:.0f}/100  top≈{r['top_quartile']:.0f}  range {r['min']:.0f}–{r['max']:.0f}  n={n}{provisional}")
    lines += ["", "─" * 72, "WHAT THIS MEANS FOR OWNERS AND BOARDS", "─" * 72,
              "  1. Most gaps are basic: open remote access, weak file sharing, missing MFA.",
              "  2. A point-in-time audit is not 24/7 monitoring.",
              "  3. Fixing the top three risks moves posture faster than buying unused tools.", "",
              "─" * 72, "METHODOLOGY & LIMITS", "─" * 72,
              "  • Data enters only with explicit benchmark_consent.",
              "  • Stored: sector, posture score, finding counts, year-month.",
              "  • Sectors with n<5 marked provisional. Not a named ranking.", "",
              "─" * 72, "ABOUT THE PUBLISHER", "─" * 72,
              f"  {COMPANY['name']} · {COMPANY['email']} · {COMPANY['phone']}",
              f"  {COMPANY['website']}", "═" * 72]
    return "\n".join(lines)

def write_state_report(year: int | None = None) -> Path:
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    year = year or datetime.datetime.now().year
    path = config.REPORTS_DIR / f"State_of_Cybersecurity_TT_{year}.txt"
    path.write_text(build_state_report(year), encoding="utf-8")
    return path
