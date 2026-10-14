"""Phase 3 unit tests."""
from __future__ import annotations
import datetime, os, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "test-secret-phase3")

def test_rbac_permissions():
    from cyberaudit.rbac import can, PERMISSIONS
    assert "scan" in PERMISSIONS["analyst"]
    assert "config" not in PERMISSIONS["analyst"]
    assert can("view", "viewer")
    assert not can("scan", "viewer")

def test_schedule_window():
    from cyberaudit.schedule_windows import window_allows_now
    now = datetime.datetime(2026, 10, 14, 3, 0, 0)
    ok, _ = window_allows_now({"enabled": True, "start": "02:00", "end": "04:00", "days": [0,1,2,3,4]}, now=now)
    assert ok
    bad, reason = window_allows_now({"enabled": True, "start": "02:00", "end": "04:00"}, now=datetime.datetime(2026, 10, 14, 12, 0, 0))
    assert not bad and "outside" in reason

def test_privacy_mapper():
    from cyberaudit.privacy_mapper import map_privacy
    p = map_privacy({"service": "mysql", "title": "MySQL open", "severity": "high"})
    assert p["personal_data_relevant"] is True

def test_tenants():
    from cyberaudit.tenants import validate_client_id, tenant_root, list_tenants
    from cyberaudit import config
    import tempfile
    assert validate_client_id("acme-bank")
    assert not validate_client_id("../evil")
    config.DATA_DIR = Path(tempfile.mkdtemp())
    tenant_root("client-a")
    assert "client-a" in list_tenants()

if __name__ == "__main__":
    test_rbac_permissions()
    test_schedule_window()
    test_privacy_mapper()
    test_tenants()
    print("PHASE3 TESTS PASSED")
