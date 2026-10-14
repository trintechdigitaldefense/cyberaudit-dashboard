"""Wire Phase 1 into the audit pipeline after findings are produced.

Call from pipeline_engine after vulnerability_heuristics / map_tt_compliance:
    from cyberaudit.phase1_integrate import apply_phase1
    vulns, artifacts = apply_phase1(session_id, target, vulns, hosts_up, open_ports, ...)
"""

from __future__ import annotations

import datetime
import logging
from pathlib import Path
from typing import Any

from cyberaudit.cvss import enrich_findings
from cyberaudit.db import get_db, insert_finding
from cyberaudit.posture import compute_posture_score
from cyberaudit.retest import (
    compute_delta,
    findings_for_session,
    fingerprint,
    latest_completed_session,
    write_delta_report,
)

logger = logging.getLogger("CyberAuditDashboard")


def _previous_posture(target: str) -> float | None:
    try:
        with get_db() as conn:
            row = conn.execute(
                """SELECT posture_score FROM posture_history
                   WHERE target=? ORDER BY id DESC LIMIT 1""",
                (target,),
            ).fetchone()
        if row and row[0] is not None:
            return float(row[0])
    except Exception as exc:
        logger.debug("previous posture lookup: %s", exc)
    return None


def apply_phase1(
    session_id: str,
    target: str,
    vulns: list[dict],
    hosts_up: list[str],
    open_ports: list[dict],
    *,
    client_name: str = "",
    logo_path: str | Path | None = None,
    run_retest_delta: bool = True,
) -> tuple[list[dict], dict[str, Any]]:
    from cyberaudit.phase1_db import migrate_phase1

    migrate_phase1()
    enriched = enrich_findings(vulns)
    posture = compute_posture_score(
        findings=enriched, hosts_up=len(hosts_up), open_ports=len(open_ports)
    )
    prev = _previous_posture(target)
    artifacts: dict[str, Any] = {
        "posture": posture,
        "previous_posture": prev,
        "pdf": None,
        "delta_report": None,
        "baseline_session_id": None,
    }
    try:
        from cyberaudit.exec_pdf import generate_executive_pdf

        pdf_path = generate_executive_pdf(
            session_id=session_id,
            target=target,
            vulns=enriched,
            hosts_up=hosts_up,
            open_ports=open_ports,
            previous_posture=prev,
            client_name=client_name,
            logo_path=logo_path,
        )
        artifacts["pdf"] = str(pdf_path)
    except Exception as exc:
        logger.exception("executive PDF failed: %s", exc)
        artifacts["pdf_error"] = str(exc)

    if run_retest_delta:
        try:
            baseline = latest_completed_session(target)
            if baseline and baseline.get("session_id") != session_id:
                base_findings = findings_for_session(baseline["session_id"])
                delta = compute_delta(base_findings, enriched)
                path = write_delta_report(
                    session_id=session_id,
                    baseline_session_id=baseline["session_id"],
                    target=target,
                    delta=delta,
                )
                artifacts["delta_report"] = path
                artifacts["baseline_session_id"] = baseline["session_id"]
                artifacts["delta_summary"] = delta["summary"]
        except Exception as exc:
            logger.exception("retest delta failed: %s", exc)
            artifacts["delta_error"] = str(exc)

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with get_db() as conn:
            conn.execute(
                """INSERT INTO posture_history
                   (session_id, target, posture_score, posture_band, recorded_at)
                   VALUES (?,?,?,?,?)""",
                (session_id, target, posture["posture_score"], posture["band"], now),
            )
            conn.commit()
    except Exception as exc:
        logger.warning("posture_history write: %s", exc)

    return enriched, artifacts


def persist_enriched_findings(session_id: str, enriched: list[dict]) -> None:
    from cyberaudit.phase1_db import migrate_phase1

    migrate_phase1()
    for v in enriched:
        fp = fingerprint(v)
        data = {
            "session_id": session_id,
            "host": v.get("host"),
            "port": v.get("port"),
            "severity": v.get("severity"),
            "title": v.get("title"),
            "cve": v.get("cve") or "",
            "cma_section": v.get("cma_section") or "",
            "evidence": v.get("evidence") or "",
            "status": "open",
        }
        fid = insert_finding(data)
        try:
            with get_db() as conn:
                conn.execute(
                    """UPDATE findings SET
                        cvss_version=?, cvss_base_score=?, cvss_severity=?,
                        cvss_vector=?, service=?, fingerprint=?
                       WHERE id=?""",
                    (
                        v.get("cvss_version") or "4.0",
                        v.get("cvss_base_score"),
                        v.get("cvss_severity") or "",
                        v.get("cvss_vector") or "",
                        v.get("service") or "",
                        fp,
                        fid,
                    ),
                )
                conn.commit()
        except Exception as exc:
            logger.debug("cvss column update: %s", exc)


def patch_session_posture(
    session_id: str,
    posture: dict,
    *,
    baseline_session_id: str = "",
    client_name: str = "",
    report_path: str = "",
) -> None:
    try:
        with get_db() as conn:
            conn.execute(
                """UPDATE audit_sessions SET
                    posture_score=?, posture_band=?, baseline_session_id=?,
                    client_name=?, compliance_score=?
                   WHERE session_id=?""",
                (
                    posture.get("posture_score"),
                    posture.get("band") or "",
                    baseline_session_id or "",
                    client_name or "",
                    posture.get("posture_score"),
                    session_id,
                ),
            )
            conn.commit()
    except Exception as exc:
        logger.warning("session posture update: %s", exc)
