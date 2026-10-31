"""Phase 6 — dashboard surface data (real DB-backed, honest module status)."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Any

from cyberaudit import config
from cyberaudit.db import get_db


def _safe_rows(sql: str, params: tuple = ()) -> list[dict]:
    try:
        with get_db() as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
    except Exception:
        return []


def _safe_one(sql: str, params: tuple = (), default=0):
    try:
        with get_db() as conn:
            row = conn.execute(sql, params).fetchone()
            return row[0] if row else default
    except Exception:
        return default


def executive_overview() -> dict[str, Any]:
    findings_n = _safe_one("SELECT COUNT(*) FROM findings")
    high_n = _safe_one("SELECT COUNT(*) FROM findings WHERE lower(severity) IN ('high','critical')")
    open_n = _safe_one("SELECT COUNT(*) FROM findings WHERE lower(COALESCE(status,'open')) IN ('open','new','')")
    sessions = _safe_rows("SELECT * FROM audit_sessions ORDER BY start_time DESC LIMIT 8")
    jobs = _safe_rows("SELECT * FROM audit_jobs ORDER BY created_at DESC LIMIT 8")
    posture = None
    for s in sessions:
        if s.get("posture_score") is not None:
            posture = {"score": s.get("posture_score"), "band": s.get("posture_band") or "", "session_id": s.get("session_id")}
            break
    return {
        "findings_total": findings_n,
        "high_critical": high_n,
        "open_findings": open_n,
        "recent_sessions": sessions,
        "recent_jobs": jobs,
        "posture": posture,
        "note": "Point-in-time engagement view — not continuous monitoring.",
    }


def active_jobs() -> list[dict]:
    rows = _safe_rows("""SELECT * FROM audit_jobs WHERE lower(COALESCE(status,'')) IN ('queued','running','claimed') ORDER BY created_at DESC LIMIT 50""")
    if not rows:
        rows = _safe_rows("SELECT * FROM audit_jobs ORDER BY created_at DESC LIMIT 25")
    return rows


def asset_inventory() -> list[dict]:
    assets: dict[str, dict] = {}
    for f in _safe_rows("SELECT host, port, service, severity, status FROM findings ORDER BY id DESC LIMIT 2000"):
        host = (f.get("host") or "").strip() or "unknown"
        a = assets.setdefault(host, {"host": host, "ports": set(), "services": set(), "finding_count": 0, "max_severity": "info"})
        if f.get("port"):
            a["ports"].add(str(f["port"]))
        if f.get("service"):
            a["services"].add(str(f["service"]))
        a["finding_count"] += 1
        sev = (f.get("severity") or "info").lower()
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        if rank.get(sev, 0) > rank.get(a["max_severity"], 0):
            a["max_severity"] = sev
    out = []
    for a in assets.values():
        out.append({
            "host": a["host"],
            "ports": sorted(a["ports"], key=lambda x: int(x) if x.isdigit() else 0),
            "services": sorted(a["services"]),
            "finding_count": a["finding_count"],
            "max_severity": a["max_severity"],
        })
    out.sort(key=lambda x: (-{"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x["max_severity"], 0), x["host"]))
    return out


def risk_heatmap() -> dict[str, Any]:
    cells: dict = defaultdict(Counter)
    hosts = set()
    for f in _safe_rows("SELECT host, severity FROM findings LIMIT 5000"):
        host = (f.get("host") or "unknown").strip()
        sev = (f.get("severity") or "info").lower()
        cells[host][sev] += 1
        hosts.add(host)
    severities = ["critical", "high", "medium", "low", "info"]
    grid = []
    for host in sorted(hosts):
        row = {"host": host}
        total = 0
        for s in severities:
            n = int(cells[host].get(s, 0))
            row[s] = n
            total += n
        row["total"] = total
        grid.append(row)
    grid.sort(key=lambda r: -(r.get("critical", 0) * 10 + r.get("high", 0) * 5 + r.get("medium", 0)))
    return {"severities": severities, "rows": grid[:100]}


def remediation_board() -> dict[str, Any]:
    by_status: dict = defaultdict(list)
    for f in _safe_rows("SELECT id, host, port, title, severity, status, service, session_id FROM findings ORDER BY id DESC LIMIT 500"):
        st = (f.get("status") or "open").lower()
        if st in ("", "new"):
            st = "open"
        by_status[st].append(f)
    return {
        "open": by_status.get("open", [])[:100],
        "in_remediation": by_status.get("in_remediation", [])[:100],
        "closed": by_status.get("closed", [])[:50],
        "false_positive": by_status.get("false_positive", [])[:50],
        "accepted_risk": by_status.get("accepted_risk", [])[:50],
        "counts": {k: len(v) for k, v in by_status.items()},
    }


def session_history() -> list[dict]:
    return _safe_rows("SELECT * FROM audit_sessions ORDER BY start_time DESC LIMIT 40")


def retest_candidates() -> list[dict]:
    sessions = _safe_rows("SELECT * FROM audit_sessions WHERE lower(COALESCE(status,'')) IN ('completed','done','finished') ORDER BY start_time DESC LIMIT 30")
    out = []
    for s in sessions:
        sid = s.get("session_id")
        n = _safe_one("SELECT COUNT(*) FROM findings WHERE session_id=?", (sid,))
        open_n = _safe_one("SELECT COUNT(*) FROM findings WHERE session_id=? AND lower(COALESCE(status,'open')) IN ('open','new','in_remediation','')", (sid,))
        out.append({**s, "findings_count": n, "open_count": open_n})
    return out


def compliance_overview() -> dict[str, Any]:
    rows = _safe_rows("SELECT cma_section, severity, COUNT(*) as n FROM findings GROUP BY cma_section, severity")
    by_section = Counter()
    for r in rows:
        sec = (r.get("cma_section") or "Unmapped").strip() or "Unmapped"
        by_section[sec] += int(r.get("n") or 0)
    return {
        "by_section": dict(by_section),
        "detail": rows,
        "disclaimer": (
            "Computer Misuse Act Chap. 11:17 tags are informational engagement context only — "
            "not legal advice. Human review required before any legal conclusion."
        ),
    }


def activity_log(limit: int = 80) -> list[dict]:
    return _safe_rows("SELECT * FROM live_events ORDER BY id DESC LIMIT ?", (limit,))


def system_health() -> dict[str, Any]:
    modules = _safe_rows("SELECT * FROM module_status ORDER BY module_name")
    honest = []
    for m in modules:
        st = (m.get("status") or "unknown").lower()
        label = {"running": "Running", "ok": "Completed this run", "idle": "Idle — not executed", "failed": "Failed", "error": "Error", "queued": "Queued"}.get(st, st)
        honest.append({**m, "status_label": label, "operational": st in ("running", "ok"), "executed": st in ("running", "ok", "failed", "error")})
    workers = _safe_rows("SELECT * FROM worker_heartbeats ORDER BY last_seen DESC LIMIT 10")
    jobs_running = _safe_one("SELECT COUNT(*) FROM audit_jobs WHERE lower(status) IN ('running','claimed')")
    return {
        "modules": honest,
        "workers": workers,
        "jobs_running": jobs_running,
        "note": "Module 'ok' means that step finished in a past/current run — not continuous protection.",
    }


def evidence_archive(limit: int = 80) -> list[dict]:
    try:
        from cyberaudit.report_archive import list_reports
        return list_reports(query="", limit=limit)
    except Exception:
        out = []
        try:
            for p in sorted(config.REPORTS_DIR.glob("*"), reverse=True)[:limit]:
                if p.is_file():
                    out.append({"name": p.name, "bytes": p.stat().st_size, "path": str(p)})
        except Exception:
            pass
        return out

from collections import Counter, defaultdict
