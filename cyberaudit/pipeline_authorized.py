"""Authorized audit entrypoint — CyberAudit 3.10.4.

ROE before any network activity. Static helpers from pipeline_helpers (no exec).
"""
from __future__ import annotations

import datetime
import logging
import secrets
from pathlib import Path

from cyberaudit import pipeline_helpers as H

logger = logging.getLogger("CyberAuditDashboard")


def run_audit_job(job: dict) -> dict:
    _now = H._now
    _ev = H._ev
    _mod = H._mod
    _nmap_available = H._nmap_available
    _parse_targets = H._parse_targets
    discover_live_hosts = H.discover_live_hosts
    recon_scan = H.recon_scan
    vulnerability_heuristics = H.vulnerability_heuristics
    map_tt_compliance = H.map_tt_compliance
    write_network_map = H.write_network_map
    upsert_audit_session = H.upsert_audit_session

    from cyberaudit.phase1_integrate import apply_phase1, persist_enriched_findings, patch_session_posture
    from cyberaudit.report_generator import write_client_reports

    try:
        from cyberaudit.hardening import validate_job_payload
        job = validate_job_payload(job)
    except ValueError:
        raise
    except Exception as exc:
        logger.warning("job validation skipped: %s", exc)

    job_id = job.get("job_id") or f"JOB-{secrets.token_hex(4)}"
    target = (job.get("target") or "").strip()
    if not target:
        raise ValueError("target required — set scope under Rules of Engagement")

    from cyberaudit.roe import assert_authorized
    from cyberaudit.hardening import audit_event

    try:
        roe = assert_authorized(job)
        try:
            audit_event("roe_authorized", detail={
                "job_id": job_id, "target": target,
                "client_name": roe.get("client_name"),
                "authorized_by": roe.get("authorized_by"),
                "demo": bool(roe.get("demo")),
            })
        except Exception:
            pass
    except Exception as auth_exc:
        try:
            audit_event("roe_denied", detail={"job_id": job_id, "target": target, "error": str(auth_exc)[:300]})
        except Exception:
            pass
        raise

    from cyberaudit.schedule_windows import assert_window_or_raise
    assert_window_or_raise(job)

    session_id = f"AUD-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(2)}"
    client_name = (job.get("client_name") or job.get("client") or roe.get("client_name") or "").strip()
    sector = (job.get("sector") or job.get("industry") or "general").strip().lower()

    _ev("dashboard", f"Client audit started {job_id} scope={target} authorized_by={roe.get('authorized_by')}",
        details={"job_id": job_id, "target": target, "roe_client": roe.get("client_name")})
    upsert_audit_session({
        "session_id": session_id, "start_time": _now(), "target": target,
        "status": "running", "notes": f"job_id={job_id};roe_by={roe.get('authorized_by')}",
    })

    nmap_ok = _nmap_available()
    _mod("diagnostics_module", "success" if nmap_ok else "partial",
         f"nmap={'yes' if nmap_ok else 'no (TCP connect fallback)'}")

    candidates = _parse_targets(target) or [target]
    hosts_up = discover_live_hosts(candidates)
    if not hosts_up:
        _ev("nmap_module", "No live hosts discovered — continuing with empty host set (not assumed live)", "info")
        _mod("nmap_module", "success", "Discovery complete — 0 live hosts")
    else:
        _mod("nmap_module", "success", f"Discovery complete — {len(hosts_up)} live host(s)")

    open_ports = recon_scan(hosts_up) if hosts_up else []
    vulns = vulnerability_heuristics(open_ports)

    try:
        from cyberaudit.finding_classifier import classify_exposure, deduplicate_findings
        classified = []
        for v in vulns:
            try:
                classified.append(classify_exposure(v))
            except Exception:
                classified.append(v)
        vulns = deduplicate_findings(classified)
    except Exception as exc:
        logger.warning("classifier skipped: %s", exc)

    try:
        from cyberaudit.finding_enrichment import enrich_findings_complete
        vulns = enrich_findings_complete(vulns)
    except Exception as exc:
        logger.warning("enrichment skipped: %s", exc)

    try:
        from cyberaudit.webapp_module import assess_web_services
        if open_ports:
            _mod("openvas_module", "running", "Web application checks")
            web_findings = assess_web_services(open_ports)
            vulns.extend(web_findings)
            _mod("openvas_module", "success", f"Web checks — {len(web_findings)} finding(s)")
        else:
            _mod("openvas_module", "skipped", "No open ports — web checks not run")
    except Exception as exc:
        _mod("openvas_module", "failed", str(exc)[:120])
        logger.warning("webapp skipped: %s", exp if False else exc)

    vulns = map_tt_compliance(vulns)
    try:
        from cyberaudit.risk_translator import enrich_with_plain_language
        vulns = enrich_with_plain_language(vulns)
    except Exception as exc:
        logger.warning("risk translator skipped: %s", exp if False else exc)

    _mod("pdf_report_module", "running", "Phase 1: CVSS, posture, reports")
    vulns, p1 = apply_phase1(
        session_id, target, vulns, hosts_up, open_ports,
        client_name=client_name, logo_path=job.get("logo_path"), run_retest_delta=True,
    )
    posture = p1.get("posture") or {}

    for mod, msg in (
        ("regional_threat_intel", "Advisory cross-check not executed this run"),
        ("patch_verification_module", "No baseline comparison this run"),
        ("incident_response_module", "Playbooks available — operator action required"),
        ("data_exfiltration_module", "Not executed — point-in-time only"),
        ("continuous_ids_module", "Not continuous monitoring"),
    ):
        _mod(mod, "not_run", msg)

    map_path = write_network_map(session_id, target, hosts_up, open_ports)
    try:
        paths = write_client_reports(
            session_id, target, open_ports, vulns, hosts_up, sector=sector, client_name=client_name,
        )
    except TypeError:
        paths = write_client_reports(session_id, target, open_ports, vulns, hosts_up)

    primary = paths.get("executive_txt") or paths.get("report")
    if primary:
        _mod("pdf_report_module", "success", f"Reports: {Path(str(primary)).name}")
    else:
        _mod("pdf_report_module", "partial", "Reports generated with limited artefacts")

    persist_enriched_findings(session_id, vulns)
    patch_session_posture(
        session_id, posture,
        baseline_session_id=p1.get("baseline_session_id") or "",
        client_name=client_name, report_path=str(primary) if primary else "",
    )

    result = {
        "job_id": job_id,
        "session_id": session_id,
        "target": target,
        "client_name": client_name,
        "hosts_up": len(hosts_up),
        "open_ports": len(open_ports),
        "findings": len(vulns),
        "posture_score": posture.get("posture_score"),
        "posture_band": posture.get("band"),
        "report": str(primary) if primary else "",
        "report_technical": str(paths.get("technical_txt") or ""),
        "executive_pdf": str(paths.get("executive_pdf") or p1.get("pdf") or ""),
        "network_map": str(map_path) if map_path else "",
        "sector": sector,
        "status": "completed",
        "roe_authorized_by": roe.get("authorized_by"),
        "discovery_empty": len(hosts_up) == 0,
        "coverage_note": (
            "Point-in-time authorized audit. "
            + ("No live hosts discovered." if not hosts_up else f"{len(hosts_up)} live host(s).")
        ),
    }
    try:
        from cyberaudit.engagement_export import ensure_pack_for_result
        result = ensure_pack_for_result(result)
    except Exception as exc:
        logger.warning("engagement pack skipped: %s", exc)

    _ev(
        "dashboard",
        f"Audit complete {session_id}: {len(hosts_up)} hosts, {len(open_ports)} services, {len(vulns)} findings",
        "info" if not vulns else "medium",
        details={k: result[k] for k in ("session_id", "hosts_up", "findings", "status") if k in result},
    )
    return result
