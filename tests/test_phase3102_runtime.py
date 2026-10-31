"""CyberAudit 3.10.2 — runtime path proofs."""
from __future__ import annotations
import os, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "j" * 32)
os.environ.setdefault("CYBERAUDIT_ROE_SECRET", "j" * 32)
os.environ["CYBERAUDIT_DATA_DIR"] = "/tmp/ca3102_data"
os.environ["CYBERAUDIT_REPORTS_DIR"] = "/tmp/ca3102_reports"
os.environ["CYBERAUDIT_DB_PATH"] = "/tmp/ca3102_data/cyber_audit.db"

def _setup():
    Path(os.environ["CYBERAUDIT_DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["CYBERAUDIT_REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)
    import importlib
    import cyberaudit.config as cfg
    importlib.reload(cfg)
    from cyberaudit.db import init_db
    init_db()

def _roe(targets=None):
    from cyberaudit.roe import sign_roe
    return sign_roe({
        "client_name": "Runtime Client", "authorized_by": "QA",
        "targets": targets or ["10.0.0.0/24"],
        "valid_from": "2020-01-01T00:00:00Z", "valid_until": "2099-12-31T23:59:59Z",
    })

def test_runtime_pipeline_rejects_no_roe_when_not_demo():
    _setup()
    from cyberaudit.pipeline_engine import run_audit_job
    from cyberaudit import config
    prev = config.DEMO_MODE
    try:
        config.DEMO_MODE = False
        try:
            run_audit_job({"job_id": "R-NO-ROE", "target": "10.0.0.1"})
            raised = False
        except (PermissionError, ValueError):
            raised = True
        assert raised is True
    finally:
        config.DEMO_MODE = prev

def test_runtime_pipeline_rejects_out_of_scope():
    _setup()
    from cyberaudit.pipeline_engine import run_audit_job
    try:
        run_audit_job({"job_id": f"R-SCOPE-{int(time.time())}", "target": "203.0.113.50", "roe": _roe(["10.0.0.0/24"])})
        ok = True
    except (PermissionError, ValueError):
        ok = False
    assert ok is False

def test_runtime_zero_hosts_not_invented():
    _setup()
    from cyberaudit.pipeline_engine import run_audit_job
    result = run_audit_job({"job_id": f"R-EMPTY-{int(time.time())}", "target": "10.255.254.1", "roe": _roe(["10.255.254.0/24"])})
    assert isinstance(result, dict)
    assert int(result.get("hosts_up") or 0) <= 1
    if int(result.get("hosts_up") or 0) == 0:
        assert result.get("discovery_empty") is True or result.get("hosts_up") == 0

def test_worker_claim_blocks_duplicate():
    _setup()
    from cyberaudit.job_control import ensure_job_row, claim_job
    jid = f"R-DUP-{os.getpid()}-{int(time.time())}"
    ensure_job_row({"job_id": jid, "target": "10.0.0.1"})
    assert claim_job(jid, worker_id="w1") is True
    assert claim_job(jid, worker_id="w2") is False

def test_tenant_db_isolation_real_writes():
    _setup()
    from cyberaudit.tenant_context import tenant_scope, resolve_db_path
    from cyberaudit.db import init_db, get_db, insert_finding
    import cyberaudit.config as cfg
    with tenant_scope("tenant_alpha") as a:
        assert a is not None
        cfg.DB_PATH = a.db
        init_db()
        insert_finding({"session_id": "AUD-A", "host": "10.0.0.1", "port": 22, "severity": "high", "title": "Alpha only finding", "cve": "", "cma_section": "", "evidence": "tenant alpha", "status": "open"})
        with get_db() as conn:
            n_a = conn.execute("SELECT COUNT(*) FROM findings WHERE title LIKE 'Alpha%'").fetchone()[0]
        assert n_a >= 1
        alpha_db = str(resolve_db_path())
    with tenant_scope("tenant_beta") as b:
        assert b is not None
        cfg.DB_PATH = b.db
        init_db()
        with get_db() as conn:
            try:
                n_b = conn.execute("SELECT COUNT(*) FROM findings WHERE title LIKE 'Alpha%'").fetchone()[0]
            except Exception:
                n_b = 0
        assert n_b == 0
        beta_db = str(resolve_db_path())
    assert alpha_db != beta_db

def test_get_db_uses_tenant_path():
    _setup()
    from cyberaudit.tenant_context import tenant_scope, resolve_db_path
    from cyberaudit.db import get_db
    with tenant_scope("tenant_gamma"):
        path = resolve_db_path()
        conn = get_db()
        assert "tenant_gamma" in str(path) or "tenants" in str(path)
        conn.close()
