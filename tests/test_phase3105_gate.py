"""CyberAudit 3.10.5 — release gate tests."""
from __future__ import annotations
import os, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "m" * 32)
os.environ.setdefault("CYBERAUDIT_ROE_SECRET", "m" * 32)
os.environ.setdefault("CYBERAUDIT_REPORT_SECRET", "m" * 32)
os.environ["CYBERAUDIT_DATA_DIR"] = "/tmp/ca3105_data"
os.environ["CYBERAUDIT_REPORTS_DIR"] = "/tmp/ca3105_reports"
os.environ["CYBERAUDIT_DB_PATH"] = "/tmp/ca3105_data/cyber_audit.db"

def _setup():
    Path(os.environ["CYBERAUDIT_DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["CYBERAUDIT_REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)
    import importlib
    import cyberaudit.config as cfg
    importlib.reload(cfg)
    from cyberaudit.db import init_db
    init_db()

def test_version_single_source():
    _setup()
    from cyberaudit import config
    ver_file = (ROOT / "cyberaudit" / "VERSION").read_text(encoding="utf-8").strip()
    assert config.VERSION == ver_file
    assert config.COMPANY.get("version") == ver_file
    assert ver_file == "3.10.5"

def test_get_db_uses_resolve_not_only_config():
    src = (ROOT / "cyberaudit" / "db.py").read_text(encoding="utf-8")
    assert "resolve_db_path" in src
    _setup()
    from cyberaudit.tenant_context import tenant_scope, resolve_db_path
    from cyberaudit.db import init_db, get_db, insert_finding
    with tenant_scope("gate_a"):
        init_db()
        insert_finding({"session_id": "AUD-GATE-A", "host": "10.9.9.1", "port": 22, "severity": "high", "title": "GATE-A-ONLY", "cve": "", "cma_section": "", "evidence": "a", "status": "open"})
        path_a = str(resolve_db_path())
        with get_db() as conn:
            n = conn.execute("SELECT COUNT(*) FROM findings WHERE title=?", ("GATE-A-ONLY",)).fetchone()[0]
        assert n >= 1
    with tenant_scope("gate_b"):
        init_db()
        path_b = str(resolve_db_path())
        with get_db() as conn:
            try:
                n = conn.execute("SELECT COUNT(*) FROM findings WHERE title=?", ("GATE-A-ONLY",)).fetchone()[0]
            except Exception:
                n = 0
        assert n == 0
    assert path_a != path_b
    assert "gate_a" in path_a and "gate_b" in path_b

def test_concurrent_claim_one_winner():
    _setup()
    from cyberaudit.job_control import ensure_job_row, claim_job
    jid = f"GATE-CLAIM-{os.getpid()}-{int(time.time())}"
    ensure_job_row({"job_id": jid, "target": "10.0.0.1"})
    assert claim_job(jid, worker_id="w-alpha") is True
    assert claim_job(jid, worker_id="w-beta") is False

def test_completed_job_not_reclaimed():
    _setup()
    from cyberaudit.job_control import ensure_job_row, claim_job, mark_job
    jid = f"GATE-DONE-{os.getpid()}-{int(time.time())}"
    ensure_job_row({"job_id": jid, "target": "10.0.0.2"})
    assert claim_job(jid, worker_id="w1") is True
    mark_job(jid, "completed")
    assert claim_job(jid, worker_id="w2") is False

def test_pipeline_no_exp_if_false():
    src = (ROOT / "cyberaudit" / "pipeline_authorized.py").read_text(encoding="utf-8")
    assert "exp if False else" not in src

def test_roe_before_network_on_engine():
    _setup()
    from cyberaudit.pipeline_engine import run_audit_job
    from cyberaudit import config
    prev = config.DEMO_MODE
    try:
        config.DEMO_MODE = False
        try:
            run_audit_job({"job_id": "GATE-NOROE", "target": "10.0.0.1"})
            raised = False
        except (PermissionError, ValueError):
            raised = True
        assert raised is True
    finally:
        config.DEMO_MODE = prev

def test_unsigned_manifest_rejected_with_report_secret():
    _setup()
    from cyberaudit.report_signing import verify_manifest, secret_configured
    assert secret_configured() is True
    ok, _ = verify_manifest({"files": [], "signature": "", "sig_alg": "none"})
    assert ok is False

def test_workers_uses_claim():
    src = (ROOT / "cyberaudit" / "workers.py").read_text(encoding="utf-8")
    assert "claim_job" in src and "transactional_finalize" in src
