"""CyberAudit 3.10.3 — core integration without config.DB_PATH mutation."""
from __future__ import annotations
import os, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "k" * 32)
os.environ.setdefault("CYBERAUDIT_ROE_SECRET", "k" * 32)
os.environ.setdefault("CYBERAUDIT_REPORT_SECRET", "k" * 32)
os.environ["CYBERAUDIT_DATA_DIR"] = "/tmp/ca3103_data"
os.environ["CYBERAUDIT_REPORTS_DIR"] = "/tmp/ca3103_reports"
os.environ["CYBERAUDIT_DB_PATH"] = "/tmp/ca3103_data/cyber_audit.db"

def _setup():
    Path(os.environ["CYBERAUDIT_DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["CYBERAUDIT_REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)
    import importlib
    import cyberaudit.config as cfg
    importlib.reload(cfg)
    from cyberaudit.db import init_db
    init_db()

def test_get_db_follows_tenant_scope_without_config_mutation():
    _setup()
    from cyberaudit.tenant_context import tenant_scope, resolve_db_path
    from cyberaudit.db import init_db, get_db, insert_finding
    with tenant_scope("iso_alpha"):
        init_db()
        insert_finding({"session_id": "AUD-ISO-A", "host": "10.1.1.1", "port": 22, "severity": "high", "title": "ISO-ALPHA-FINDING", "cve": "", "cma_section": "", "evidence": "alpha", "status": "open"})
        with get_db() as conn:
            n = conn.execute("SELECT COUNT(*) FROM findings WHERE title=?", ("ISO-ALPHA-FINDING",)).fetchone()[0]
        assert n >= 1
        path_a = str(resolve_db_path())
    with tenant_scope("iso_beta"):
        init_db()
        with get_db() as conn:
            try:
                n = conn.execute("SELECT COUNT(*) FROM findings WHERE title=?", ("ISO-ALPHA-FINDING",)).fetchone()[0]
            except Exception:
                n = 0
        assert n == 0
        path_b = str(resolve_db_path())
    assert path_a != path_b
    assert "iso_alpha" in path_a and "iso_beta" in path_b

def test_tenant_context_restored_after_exception():
    _setup()
    from cyberaudit.tenant_context import tenant_scope, get_active_tenant
    assert get_active_tenant() is None
    try:
        with tenant_scope("iso_exc"):
            assert get_active_tenant() is not None
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    assert get_active_tenant() is None

def test_worker_claim_only_one_succeeds():
    _setup()
    from cyberaudit.job_control import ensure_job_row, claim_job
    jid = f"ISO-JOB-{os.getpid()}-{int(time.time())}"
    ensure_job_row({"job_id": jid, "target": "10.0.0.1"})
    assert claim_job(jid, worker_id="worker-a") is True
    assert claim_job(jid, worker_id="worker-b") is False

def test_pipeline_authorized_uses_static_helpers():
    import inspect
    import cyberaudit.pipeline_authorized as pa
    src = inspect.getsource(pa)
    assert "exec(compile" not in src
    from cyberaudit.pipeline_engine import run_audit_job
    from cyberaudit import config
    prev = config.DEMO_MODE
    try:
        config.DEMO_MODE = False
        try:
            run_audit_job({"job_id": "ISO-NOROE", "target": "10.0.0.1"})
            raised = False
        except (PermissionError, ValueError):
            raised = True
        assert raised is True
    finally:
        config.DEMO_MODE = prev

def test_unsigned_pack_not_verified_when_secret_set():
    _setup()
    from cyberaudit.report_signing import verify_manifest, secret_configured
    assert secret_configured() is True
    ok, reason = verify_manifest({"session_id": "x", "files": [], "signature": "", "sig_alg": "none"})
    assert ok is False

def test_version_is_3103():
    from cyberaudit import config
    ver = str(getattr(config, "VERSION", "") or config.COMPANY.get("version", ""))
    assert ver.startswith("3.10.3"), ver
