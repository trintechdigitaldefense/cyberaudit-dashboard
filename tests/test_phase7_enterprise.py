"""CyberAudit 3.10 Phase 7 — multi-client isolation, ROE, retention."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "h" * 32)
os.environ["CYBERAUDIT_DATA_DIR"] = "/tmp/ca310p7_data"
os.environ["CYBERAUDIT_REPORTS_DIR"] = "/tmp/ca310p7_reports"
os.environ["CYBERAUDIT_DB_PATH"] = "/tmp/ca310p7_data/cyber_audit.db"


def _setup():
    Path(os.environ["CYBERAUDIT_DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["CYBERAUDIT_REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)
    import importlib
    import cyberaudit.config as cfg
    importlib.reload(cfg)
    from cyberaudit.db import init_db
    init_db()


def test_tenant_paths_isolated():
    _setup()
    from cyberaudit.tenants import apply_tenant_paths, list_tenants
    from cyberaudit import config
    a = apply_tenant_paths("client_alpha")
    b = apply_tenant_paths("client_beta")
    assert a["db"] != b["db"]
    assert a["reports"] != b["reports"]
    assert "client_alpha" in list_tenants()
    assert "client_beta" in list_tenants()
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)


def test_client_cannot_override_tenant_header():
    _setup()
    from cyberaudit.enterprise import current_tenant
    class Sess(dict):
        pass
    s = Sess(role="client", tenant_id="client_alpha", authenticated=True)
    headers = {"X-CyberAudit-Tenant": "client_beta"}
    assert current_tenant(s, headers) == "client_alpha"


def test_roe_client_match():
    _setup()
    from cyberaudit.enterprise import validate_roe_for_client
    ok, _ = validate_roe_for_client({"client_id": "acme"}, "acme")
    assert ok is True
    ok, reason = validate_roe_for_client({"client_id": "other"}, "acme")
    assert ok is False
    assert "does not match" in reason
    ok, reason = validate_roe_for_client({}, "acme")
    assert ok is False


def test_engagement_lifecycle():
    _setup()
    from cyberaudit.enterprise import upsert_engagement, list_engagements
    rec = upsert_engagement({
        "client_id": "acme_tt",
        "status": "authorised",
        "target_scope": "10.0.0.0/24",
        "notes": "Phase 7 test",
    })
    assert rec["engagement_id"]
    assert rec["status"] == "authorised"
    items = list_engagements("acme_tt")
    assert any(e["engagement_id"] == rec["engagement_id"] for e in items)


def test_retention_dry_run():
    _setup()
    from cyberaudit.enterprise import apply_retention, upsert_client
    upsert_client("retain_co", retention_days=30)
    result = apply_retention(client_id="retain_co", dry_run=True)
    assert result["dry_run"] is True
    assert "expired_count" in result


def test_environment_profile():
    _setup()
    from cyberaudit.enterprise import environment_profile
    p = environment_profile()
    assert p["environment"] in ("lab", "production")
    assert "guidance" in p
    assert any("DATA_DIR" in g for g in p["guidance"])


def test_require_tenant_access_staff_global():
    _setup()
    from cyberaudit.enterprise import require_tenant_access
    class Sess(dict):
        pass
    admin = Sess(role="admin", authenticated=True)
    assert require_tenant_access(None, admin) is True
    assert require_tenant_access("any", admin) is True
    client = Sess(role="client", tenant_id="only_me", authenticated=True)
    assert require_tenant_access("only_me", client) is True
    assert require_tenant_access("other", client) is False
    assert require_tenant_access(None, client) is False
