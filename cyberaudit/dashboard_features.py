"""Aggregate shipped features for the operator dashboard (honest capability map)."""
from __future__ import annotations
from typing import Any
from cyberaudit import config

def feature_matrix() -> dict[str, Any]:
    return {
        "product": config.COMPANY["product"],
        "version": config.COMPANY["version"],
        "honesty": {
            "point_in_time": True,
            "not_24x7_monitoring": True,
            "hardened_and_auditable": True,
            "roe_required": True,
        },
        "scanning": [
            "Host/service discovery", "Web application checks", "GVM/OpenVAS report ingest",
            "Credential leak corpus check", "Cloud posture snapshot", "Wireless module",
            "Authenticated scan hooks", "ROE time windows",
        ],
        "risk_reporting": [
            "CVSS-style scores", "Posture score 0–100", "Director mode / plain language",
            "TT$ money risk ranges", "Board summary one-pager", "Executive PDF",
            "Retest delta", "Spanish board option", "CMA Chap. 11:17 mapping",
        ],
        "operations": [
            "Live event feed", "Console presence", "Finding lifecycle status",
            "Report archive & download", "Playbook library", "Partner API /api/v1",
            "Air-gap mode", "Community tier limits", "Backups", "Health endpoints",
        ],
        "client_facing": ["Client portal", "Board summary", "Workshop materials (repo)"],
    }

def system_snapshot() -> dict[str, Any]:
    out: dict[str, Any] = {
        "demo_mode": config.DEMO_MODE,
        "host": config.HOST,
        "port": config.PORT,
        "features": feature_matrix(),
    }
    try:
        from cyberaudit.airgap import airgap_status
        out["airgap"] = airgap_status()
    except Exception as exc:
        out["airgap"] = {"error": str(exc)[:120]}
    try:
        from cyberaudit.community_tier import community_status
        out["community"] = community_status()
    except Exception as exc:
        out["community"] = {"error": str(exc)[:120]}
    try:
        from cyberaudit.license_mgr import validate_license
        out["license"] = validate_license()
    except Exception as exc:
        out["license"] = {"error": str(exc)[:120]}
    try:
        from cyberaudit.presence import snapshot as presence_snapshot
        out["presence"] = presence_snapshot()
    except Exception as exc:
        out["presence"] = {"error": str(exc)[:120]}
    try:
        from cyberaudit.report_archive import list_reports
        out["reports"] = list_reports(limit=20)
    except Exception as exc:
        out["reports"] = []
        out["reports_error"] = str(exc)[:120]
    try:
        from cyberaudit.telemetry import summary as tel_summary
        out["telemetry"] = tel_summary()
    except Exception:
        out["telemetry"] = {"enabled": False}
    return out
