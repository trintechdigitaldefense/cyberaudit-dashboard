"""Phase 4 hardening tests."""
from __future__ import annotations
import os, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "test-secret-phase4-32chars-minimum")

def test_secrets_gate_demo_ok():
    from cyberaudit.hardening import assert_production_secrets
    assert_production_secrets()

def test_secrets_gate_blocks_admin_admin():
    from cyberaudit import config
    from cyberaudit import hardening
    old = (config.DEMO_MODE, config.AUTH_PASSWORD, config.AUTH_USER)
    try:
        config.DEMO_MODE = False
        config.AUTH_PASSWORD = "admin"
        config.AUTH_USER = "admin"
        os.environ["CYBERAUDIT_SECRET"] = "x" * 32
        raised = False
        try:
            hardening.assert_production_secrets()
        except SystemExit:
            raised = True
        assert raised
    finally:
        config.DEMO_MODE, config.AUTH_PASSWORD, config.AUTH_USER = old

def test_rate_limit():
    from cyberaudit.hardening import rate_limit
    key = "t-" + os.urandom(4).hex()
    assert rate_limit(key, 3, 60) and rate_limit(key, 3, 60) and rate_limit(key, 3, 60)
    assert not rate_limit(key, 3, 60)

def test_validate_target():
    from cyberaudit.hardening import validate_target, validate_job_payload
    assert validate_target("192.168.1.0/24") == "192.168.1.0/24"
    for bad in ["192.168.1.1; rm -rf /", "../etc/passwd"]:
        try:
            validate_target(bad)
            assert False, bad
        except ValueError:
            pass
    j = validate_job_payload({"target": "10.0.0.1", "sector": "finance"})
    assert j["sector"] == "finance"

def test_audit_chain():
    from cyberaudit import config
    from cyberaudit.hardening import audit_event, verify_audit_chain, init_audit_log
    config.DATA_DIR = Path(tempfile.mkdtemp())
    init_audit_log()
    audit_event("login", username="admin", role="admin", ip="127.0.0.1")
    ok, msg = verify_audit_chain()
    assert ok, msg

def test_csrf_and_fail_safe():
    from cyberaudit.hardening import generate_csrf_token, validate_csrf, fail_safe_job
    s = {}
    t = generate_csrf_token(s)
    assert validate_csrf(s, t) and not validate_csrf(s, "nope")
    r = fail_safe_job(lambda j: (_ for _ in ()).throw(RuntimeError("x")), {"job_id": "1"})
    assert r["status"] == "failed"

if __name__ == "__main__":
    test_secrets_gate_demo_ok()
    test_secrets_gate_blocks_admin_admin()
    test_rate_limit()
    test_validate_target()
    test_audit_chain()
    test_csrf_and_fail_safe()
    print("PHASE4 TESTS PASSED")
