"""3.10.7 extra gates: process claim, finalization missing reports, auth rate limit."""
from __future__ import annotations
import multiprocessing as mp
import os, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "q" * 32)
os.environ.setdefault("CYBERAUDIT_ROE_SECRET", "q" * 32)
os.environ.setdefault("CYBERAUDIT_REPORT_SECRET", "q" * 32)
os.environ["CYBERAUDIT_DATA_DIR"] = "/tmp/ca3107x_data"
os.environ["CYBERAUDIT_REPORTS_DIR"] = "/tmp/ca3107x_reports"
os.environ["CYBERAUDIT_DB_PATH"] = "/tmp/ca3107x_data/cyber_audit.db"

def _setup():
    Path(os.environ["CYBERAUDIT_DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["CYBERAUDIT_REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)
    import importlib
    import cyberaudit.config as cfg
    importlib.reload(cfg)
    from cyberaudit.db import init_db
    init_db()

def _claim_worker(job_id, worker_id, out_path):
    os.environ.setdefault("DEMO_MODE", "1")
    os.environ.setdefault("CYBERAUDIT_SECRET", "q" * 32)
    os.environ["CYBERAUDIT_DATA_DIR"] = "/tmp/ca3107x_data"
    os.environ["CYBERAUDIT_DB_PATH"] = "/tmp/ca3107x_data/cyber_audit.db"
    sys.path.insert(0, str(ROOT))
    from cyberaudit.job_control import claim_job
    ok = claim_job(job_id, worker_id=worker_id)
    Path(out_path).write_text("1" if ok else "0")

def test_process_level_claim_one_winner():
    _setup()
    from cyberaudit.job_control import ensure_job_row
    jid = f"PROC-{os.getpid()}-{int(time.time())}"
    ensure_job_row({"job_id": jid, "target": "10.0.0.9"})
    out_a, out_b = Path("/tmp/ca3107x_claim_a"), Path("/tmp/ca3107x_claim_b")
    for p in (out_a, out_b):
        if p.exists():
            p.unlink()
    pa = mp.Process(target=_claim_worker, args=(jid, "proc-a", str(out_a)))
    pb = mp.Process(target=_claim_worker, args=(jid, "proc-b", str(out_b)))
    pa.start(); pb.start()
    pa.join(timeout=10); pb.join(timeout=10)
    results = [p.read_text().strip() for p in (out_a, out_b) if p.exists()]
    assert results.count("1") == 1, results

def test_finalize_missing_mandatory_fails():
    _setup()
    from cyberaudit.finalization import finalize_audit_result
    out = finalize_audit_result({"status": "completed", "session_id": "AUD-MISS", "job_id": "JOB-MISS"})
    assert out.get("status") == "failed"
    assert out.get("mandatory_missing")

def test_finalize_with_temp_reports_ok():
    _setup()
    from cyberaudit.finalization import finalize_audit_result
    d = Path("/tmp/ca3107x_reports"); d.mkdir(parents=True, exist_ok=True)
    exec_p, tech_p = d / "exec.txt", d / "tech.txt"
    exec_p.write_text("Executive summary\n" * 5)
    tech_p.write_text("Technical annex\n" * 5)
    out = finalize_audit_result({"status": "completed", "session_id": "AUD-OK", "job_id": "JOB-OK", "executive_txt": str(exec_p), "technical_txt": str(tech_p)})
    assert out.get("status") == "completed", out

def test_auth_rate_limit():
    from cyberaudit.auth_hardening import login_allowed, record_login_failure, clear_login_failures, hash_password, verify_password
    key = f"test-ip-{os.getpid()}"
    clear_login_failures(key)
    for _ in range(8):
        record_login_failure(key)
    allowed, reason = login_allowed(key)
    assert allowed is False
    clear_login_failures(key)
    assert login_allowed(key)[0] is True
    h = hash_password("s3cret!")
    assert verify_password("s3cret!", h) and not verify_password("wrong", h)

def test_workers_has_heartbeat_thread():
    src = (ROOT / "cyberaudit" / "workers.py").read_text()
    assert "stop_hb" in src and ("hb_thread" in src or "_hb_loop" in src)

def test_engagement_export_uses_tenant_reports():
    src = (ROOT / "cyberaudit" / "engagement_export.py").read_text()
    assert "_reports_dir" in src or "resolve_reports_dir" in src
