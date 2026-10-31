"""CyberAudit 3.10.7 — reliability & security repair gates."""
from __future__ import annotations
import os, sys, threading, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "p" * 32)
os.environ.setdefault("CYBERAUDIT_ROE_SECRET", "p" * 32)
os.environ.setdefault("CYBERAUDIT_REPORT_SECRET", "p" * 32)
os.environ["CYBERAUDIT_DATA_DIR"] = "/tmp/ca3107_data"
os.environ["CYBERAUDIT_REPORTS_DIR"] = "/tmp/ca3107_reports"
os.environ["CYBERAUDIT_DB_PATH"] = "/tmp/ca3107_data/cyber_audit.db"

def _setup():
    Path(os.environ["CYBERAUDIT_DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["CYBERAUDIT_REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)
    import importlib
    import cyberaudit.config as cfg
    importlib.reload(cfg)
    from cyberaudit.db import init_db
    init_db()

def test_version_3107():
    _setup()
    from cyberaudit import config
    assert (ROOT / "cyberaudit" / "VERSION").read_text().strip() == "3.10.7"
    assert config.VERSION == "3.10.7"

def test_atomic_claim_race_eight_threads():
    _setup()
    from cyberaudit.job_control import ensure_job_row, claim_job
    for r in range(5):
        wins = []
        lock = threading.Lock()
        jid = f"A3107-{os.getpid()}-{r}-{int(time.time()*1000)}"
        ensure_job_row({"job_id": jid, "target": "10.0.0.1"})
        def worker(wid):
            if claim_job(jid, worker_id=wid):
                with lock:
                    wins.append(wid)
        threads = [threading.Thread(target=worker, args=(f"w{i}",)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        assert len(wins) == 1, wins

def test_completed_not_reclaimed():
    _setup()
    from cyberaudit.job_control import ensure_job_row, claim_job, mark_job
    jid = f"DONE3107-{os.getpid()}"
    ensure_job_row({"job_id": jid, "target": "10.0.0.2"})
    assert claim_job(jid, worker_id="a") is True
    mark_job(jid, "completed")
    assert claim_job(jid, worker_id="b") is False

def test_heartbeat_requires_ownership():
    _setup()
    from cyberaudit.job_control import ensure_job_row, claim_job, heartbeat
    jid = f"HB3107-{os.getpid()}"
    ensure_job_row({"job_id": jid, "target": "10.0.0.3"})
    assert claim_job(jid, worker_id="owner") is True
    assert heartbeat(jid, detail="ok", worker_id="owner") is True
    assert heartbeat(jid, detail="steal", worker_id="other") is False

def test_verify_requires_hmac_alg():
    _setup()
    from cyberaudit.report_signing import verify_manifest, sign_manifest
    signed = sign_manifest({"files": [], "session_id": "x"})
    assert signed.get("sig_alg") == "HMAC-SHA256"
    ok, _ = verify_manifest(signed)
    assert ok is True
    bad = dict(signed)
    bad["sig_alg"] = ""
    ok2, reason = verify_manifest(bad)
    assert ok2 is False

def test_pdf_validate_rejects_header_only():
    _setup()
    from cyberaudit.pdf_validate import validate_pdf
    fake = Path("/tmp/ca3107_fake.pdf")
    fake.write_bytes(b"%PDF-1.4\n")
    r = validate_pdf(fake)
    assert r["ok"] is False

def test_workers_uses_job_control():
    src = (ROOT / "cyberaudit" / "workers.py").read_text(encoding="utf-8")
    for tok in ("claim_job", "heartbeat", "transactional_finalize", "register_or_reject_duplicate"):
        assert tok in src

def test_tenant_paths_distinct():
    _setup()
    from cyberaudit.tenant_context import concurrent_isolation_check
    result = concurrent_isolation_check("client_alpha", "client_beta")
    assert result.get("distinct_db") is True
    assert result.get("outer_cleared") is True
