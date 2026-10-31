"""CyberAudit 3.10 Phase 6 — dashboard surface data helpers."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "g" * 32)
os.environ["CYBERAUDIT_DATA_DIR"] = "/tmp/ca310p6_data"
os.environ["CYBERAUDIT_REPORTS_DIR"] = "/tmp/ca310p6_reports"
os.environ["CYBERAUDIT_DB_PATH"] = "/tmp/ca310p6_data/cyber_audit.db"


def _setup():
    Path(os.environ["CYBERAUDIT_DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["CYBERAUDIT_REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)
    import importlib
    import cyberaudit.config as cfg
    importlib.reload(cfg)
    from cyberaudit.db import init_db
    init_db()


def test_surfaces_smoke():
    _setup()
    from cyberaudit.dashboard_surfaces import (
        executive_overview, active_jobs, asset_inventory, risk_heatmap,
        remediation_board, session_history, retest_candidates,
        compliance_overview, activity_log, system_health, evidence_archive,
    )
    assert isinstance(executive_overview(), dict)
    assert isinstance(active_jobs(), list)
    assert isinstance(asset_inventory(), list)
    hm = risk_heatmap()
    assert "rows" in hm and "severities" in hm
    assert isinstance(remediation_board(), dict)
    assert isinstance(session_history(), list)
    assert isinstance(retest_candidates(), list)
    co = compliance_overview()
    assert "disclaimer" in co
    assert "legal advice" in co["disclaimer"].lower()
    assert isinstance(activity_log(10), list)
    sh = system_health()
    assert "modules" in sh
    assert isinstance(evidence_archive(5), list)


def test_health_idle_not_operational():
    _setup()
    from cyberaudit.db import upsert_module_status
    from cyberaudit.dashboard_surfaces import system_health
    upsert_module_status(module_name="nmap_module", status="idle", last_result="not run", last_run="")
    sh = system_health()
    idle = [m for m in sh["modules"] if m.get("module_name") == "nmap_module"]
    if idle:
        assert idle[0].get("operational") is False
        assert "Idle" in (idle[0].get("status_label") or "")
