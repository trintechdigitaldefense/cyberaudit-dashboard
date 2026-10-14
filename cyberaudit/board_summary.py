"""P5.3 — One-page board summary."""

from __future__ import annotations
import datetime
from pathlib import Path
from typing import Any
from cyberaudit import config
from cyberaudit.director_mode import director_title
from cyberaudit.money_risk import estimate_cost, portfolio_exposure, SOURCE_NOTE

COMPANY = config.COMPANY

def _top_risks(findings: list[dict], n: int = 3) -> list[dict]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ranked = sorted(findings, key=lambda f: (order.get((f.get("severity") or "info").lower(), 9), f.get("title") or ""))
    top = []
    for f in ranked[:n]:
        money = f.get("money") or (estimate_cost(f) if (f.get("severity") or "").lower() in ("critical", "high", "medium") else None)
        top.append({
            "severity": (f.get("severity") or "").upper(),
            "title_director": (f.get("director") or {}).get("title_director") or director_title(f),
            "host": f.get("host") or "",
            "money": money["tt_display"] if money else "—",
            "action": (f.get("director") or {}).get("do_this_week") or (f.get("plain") or {}).get("do_this_week") or "Assign an owner this week.",
        })
    return top

def build_board_summary_text(*, session_id, client_name, target, posture_score, posture_band, findings, delta=None, sector="general") -> str:
    score = f"{posture_score:.0f}" if posture_score is not None else "n/a"
    top = _top_risks(findings)
    exposure = portfolio_exposure(findings)
    delta = delta or {}
    fixed = delta.get("closed_count") or delta.get("closed") or 0
    still = delta.get("still_open_count") or delta.get("still_open") or 0
    new = delta.get("new_count") or delta.get("new") or 0
    if isinstance(fixed, list): fixed = len(fixed)
    if isinstance(still, list): still = len(still)
    if isinstance(new, list): new = len(new)
    lines = [
        "═" * 72, f"  {COMPANY['name']}".center(72), "  BOARD SUMMARY — ONE PAGE".center(72),
        f"  {COMPANY['tagline']}".center(72), "═" * 72, "",
        f"Client:        {client_name or 'Authorised engagement'}", f"Engagement:    {session_id}",
        f"Date:          {datetime.datetime.now().strftime('%d %B %Y')}", f"Scope:         {target}",
        f"Sector:        {sector}", "", "─" * 72, "SECURITY HEALTH (like a check-up score)", "─" * 72,
        f"  Posture score:   {score} / 100", f"  Band:            {posture_band or 'n/a'}", "",
        "  80–100 Strong foundation   60–79 Manageable gaps",
        "  40–59 Needs focused work   Below 40 Urgent attention", "",
        "─" * 72, "TOP RISKS FOR LEADERSHIP", "─" * 72,
    ]
    if not top:
        lines.append("  No high-priority issues were flagged in this scan window.")
    else:
        for i, r in enumerate(top, 1):
            lines += [f"  {i}. [{r['severity']}] {r['title_director']}",
                      f"      Where: {r['host']}" if r["host"] else "",
                      f"      Estimated recovery if exploited: {r['money']}",
                      f"      Do this week: {r['action']}", ""]
    lines += ["─" * 72, "MONEY AT STAKE (order-of-magnitude)", "─" * 72,
              f"  {exposure['display']}", f"  {exposure.get('note', '')}", "",
              "─" * 72, "PROGRESS SINCE LAST SCAN (if retest)", "─" * 72,
              f"  Fixed / closed:   {fixed}", f"  Still open:       {still}", f"  Newly introduced: {new}", "",
              "─" * 72, "WHAT TO DO NEXT", "─" * 72,
              "  1. Assign an owner for each top risk this week.",
              "  2. Ask IT or your managed provider for a one-page fix plan.",
              "  3. Schedule a retest after fixes — we measure the delta.",
              "  4. Keep this sheet with board papers; technical annex is available.", "",
              "─" * 72, "HONEST SCOPE", "─" * 72,
              "  This is a point-in-time network audit under agreed rules of engagement.",
              "  It is not 24/7 monitoring.", "",
              "─" * 72, "SOURCES FOR COST RANGES", "─" * 72, f"  {SOURCE_NOTE}", "",
              f"  Contact: {COMPANY['email']} · {COMPANY['phone']}", f"  Web:     {COMPANY['website']}", "═" * 72]
    return "\n".join(x for x in lines if x is not None)

def write_board_summary(session_id, *, client_name, target, posture_score, posture_band, findings, delta=None, sector="general") -> Path:
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    text = build_board_summary_text(session_id=session_id, client_name=client_name, target=target,
        posture_score=posture_score, posture_band=posture_band, findings=findings, delta=delta, sector=sector)
    path = config.REPORTS_DIR / f"CyberAudit_BoardSummary_{session_id}.txt"
    path.write_text(text, encoding="utf-8")
    return path
