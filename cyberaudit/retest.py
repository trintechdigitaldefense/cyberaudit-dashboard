"""Remediation lifecycle + retest delta reports.

Lifecycle: open → in_remediation → closed → (retest may introduce) new
Retest package builds itself from prior session findings vs new scan.
"""

from __future__ import annotations

import datetime
import json
from typing import Any

from cyberaudit import config
from cyberaudit.db import get_db


VALID_STATUSES = ("open", "in_remediation", "closed", "new", "accepted_risk")


def fingerprint(finding: dict) -> str:
    host = str(finding.get("host") or "").strip().lower()
    port = str(finding.get("port") or "").strip()
    title = str(finding.get("title") or "").strip().lower()
    service = str(finding.get("service") or "").strip().lower()
    return f"{host}|{port}|{title}|{service}"


def set_finding_status(
    finding_id: int,
    status: str,
    *,
    changed_by: str = "",
    note: str = "",
) -> dict:
    status = (status or "").strip().lower()
    if status not in VALID_STATUSES:
        raise ValueError(f"status must be one of {VALID_STATUSES}")
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            raise ValueError(f"finding {finding_id} not found")
        conn.execute(
            "UPDATE findings SET status=?, status_updated_at=?, status_updated_by=?, status_note=? WHERE id=?",
            (status, now, (changed_by or "")[:128], (note or "")[:500], finding_id),
        )
        try:
            conn.execute(
                """INSERT INTO finding_status_history
                   (finding_id, old_status, new_status, changed_by, note, changed_at)
                   VALUES (?,?,?,?,?,?)""",
                (
                    finding_id,
                    row["status"] if "status" in row.keys() else "open",
                    status,
                    (changed_by or "")[:128],
                    (note or "")[:500],
                    now,
                ),
            )
        except Exception:
            pass
        conn.commit()
    return {"id": finding_id, "status": status, "updated_at": now}


def findings_for_session(session_id: str) -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE session_id=? ORDER BY id",
            (session_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def latest_completed_session(target: str | None = None) -> dict | None:
    with get_db() as conn:
        if target:
            row = conn.execute(
                """SELECT * FROM audit_sessions
                   WHERE status='completed' AND target=?
                   ORDER BY end_time DESC, id DESC LIMIT 1""",
                (target,),
            ).fetchone()
        else:
            row = conn.execute(
                """SELECT * FROM audit_sessions
                   WHERE status='completed'
                   ORDER BY end_time DESC, id DESC LIMIT 1"""
            ).fetchone()
    return dict(row) if row else None


def compute_delta(
    baseline_findings: list[dict],
    current_findings: list[dict],
) -> dict[str, Any]:
    base_map = {fingerprint(f): f for f in baseline_findings}
    curr_map = {fingerprint(f): f for f in current_findings}

    closed = []
    still_open = []
    newly = []

    for fp, bf in base_map.items():
        if fp not in curr_map:
            item = dict(bf)
            item["delta_status"] = "closed"
            closed.append(item)
        else:
            item = dict(curr_map[fp])
            item["delta_status"] = "still_open"
            still_open.append(item)

    for fp, cf in curr_map.items():
        if fp not in base_map:
            item = dict(cf)
            item["delta_status"] = "new"
            newly.append(item)

    return {
        "closed": closed,
        "still_open": still_open,
        "newly_introduced": newly,
        "summary": {
            "baseline_count": len(baseline_findings),
            "current_count": len(current_findings),
            "closed_count": len(closed),
            "still_open_count": len(still_open),
            "new_count": len(newly),
        },
    }


def write_delta_report(
    *,
    session_id: str,
    baseline_session_id: str,
    target: str,
    delta: dict,
) -> str:
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    s = delta["summary"]
    lines = [
        "=" * 72,
        f"  {config.COMPANY['name']}".center(72),
        "  Retest Delta Report".center(72),
        "=" * 72,
        "",
        f"Current session:   {session_id}",
        f"Baseline session:  {baseline_session_id}",
        f"Scope:             {target}",
        f"Generated:         {datetime.datetime.now().strftime('%d %B %Y, %H:%M')}",
        "",
        "-" * 72,
        "SUMMARY",
        "-" * 72,
        f"  Baseline findings:     {s['baseline_count']}",
        f"  Current findings:      {s['current_count']}",
        f"  Closed (fixed):        {s['closed_count']}",
        f"  Still open:            {s['still_open_count']}",
        f"  Newly introduced:      {s['new_count']}",
        "",
    ]

    def _section(title: str, items: list[dict]) -> None:
        lines.append("-" * 72)
        lines.append(title)
        lines.append("-" * 72)
        if not items:
            lines.append("  (none)")
            lines.append("")
            return
        for i, f in enumerate(items, 1):
            lines.append(
                f"  [{i}] {f.get('severity', '').upper()}  "
                f"{f.get('host')}:{f.get('port')} — {f.get('title')}"
            )
            if f.get("cvss_base_score") is not None:
                lines.append(f"      CVSS 4.0: {f.get('cvss_base_score')} ({f.get('cvss_severity')})")
            lines.append("")

    _section("CLOSED — previously seen, not found on retest", delta["closed"])
    _section("STILL OPEN — requires continued remediation", delta["still_open"])
    _section("NEWLY INTRODUCED — appeared since baseline", delta["newly_introduced"])

    lines.extend(
        [
            "-" * 72,
            "NEXT STEPS",
            "-" * 72,
            "  1. Celebrate closed items with the remediation owners.",
            "  2. Re-assign still-open Critical/High items with deadlines.",
            "  3. Investigate newly introduced findings before the next board pack.",
            "",
            f"  Prepared by {config.COMPANY['name']} — {config.COMPANY['email']}",
            "=" * 72,
            "",
        ]
    )
    path = config.REPORTS_DIR / f"CyberAudit_RetestDelta_{session_id}.txt"
    path.write_text("\n".join(lines), encoding="utf-8")
    jpath = config.REPORTS_DIR / f"CyberAudit_RetestDelta_{session_id}.json"
    jpath.write_text(
        json.dumps(
            {
                "session_id": session_id,
                "baseline_session_id": baseline_session_id,
                "target": target,
                "summary": s,
                "closed": delta["closed"],
                "still_open": delta["still_open"],
                "newly_introduced": delta["newly_introduced"],
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    return str(path)
