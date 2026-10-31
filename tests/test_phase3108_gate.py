"""CyberAudit 3.10.8 — hardened release gates."""
from __future__ import annotations
import os, sys, threading, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "r" * 32)
os.environ.setdefault("CYBERAUDIT_ROE_SECRET", "r" * 32)
os.environ.setdefault("CYBERAUDIT_REPORT_SECRET", "r" * 32)
os.environ["CYBERAUDIT_DATA_DIR"] = "/tmp/ca3108_data"
os.environ["CYBERAUDIT_REPORTS_DIR"] = "/tmp/ca3108_reports"
os.environ["CYBERAUDIT_DB_PATH"] = "/tmp/ca3108_data/cyber_audit.db"

def _setup():
    Path(os.environ["CYBERAUDIT_DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["CYBERAUDIT_REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)
    import importlib
    import cyberaudit.config as cfg
    importlib.reload(cfg)
    from cyberaudit.db import init_db
    init_db()

def test_version_3108():
    _setup()
    from cyberaudit import config
    assert (ROOT / "cyberaudit" / "VERSION").read_text().strip() == "3.10.8"
    assert config.VERSION == "3.10.8"

def test_claim_rejects_empty_owner_running_without_stale():
    _setup()
    from cyberaudit.job_control import ensure_job_row, claim_job
    from cyberaudit.db import get_db
    jid = f"EMPTY-OWNER-{os.getpid()}"
    ensure_job_row({"job_id": jid, "target": "10.0.0.1"})
    assert claim_job(jid, worker_id="w1") is True
    with get_db() as conn:
        conn.execute("UPDATE audit_jobs SET claimed_by='', status='running', heartbeat_at=? WHERE job_id=?",
                     (time.strftime("%Y-%m-%d %H:%M:%S"), jid))
        conn.commit()
    assert claim_job(jid, worker_id="w2") is False

def test_mark_job_requires_owner():
    _setup()
    from cyberaudit.job_control import ensure_job_row, claim_job, mark_job
    jid = f"OWN-{os.getpid()}"
    ensure_job_row({"job_id": jid, "target": "10.0.0.2"})
    assert claim_job(jid, worker_id="owner") is True
    assert mark_job(jid, "failed", error="x", worker_id="other") is False
    assert mark_job(jid, "failed", error="x", worker_id="owner") is True

def test_completed_cannot_reopen():
    _setup()
    from cyberaudit.job_control import ensure_job_row, claim_job, mark_job
    jid = f"DONE8-{os.getpid()}"
    ensure_job_row({"job_id": jid, "target": "10.0.0.3"})
    claim_job(jid, worker_id="a")
    mark_job(jid, "completed", worker_id="a")
    assert mark_job(jid, "failed", worker_id="a", require_owner=False) is False
    assert claim_job(jid, worker_id="b") is False

def test_race_eight_threads():
    _setup()
    from cyberaudit.job_control import ensure_job_row, claim_job
    for r in range(3):
        wins = []
        lock = threading.Lock()
        jid = f"R8-{os.getpid()}-{r}-{int(time.time()*1000)}"
        ensure_job_row({"job_id": jid, "target": "10.0.0.4"})
        def worker(wid):
            if claim_job(jid, worker_id=wid):
                with lock:
                    wins.append(wid)
        ts = [threading.Thread(target=worker, args=(f"t{i}",)) for i in range(8)]
        for t in ts: t.start()
        for t in ts: t.join(timeout=5)
        assert len(wins) == 1, wins

def test_verify_rejects_empty_sig_alg():
    _setup()
    from cyberaudit.report_signing import sign_manifest, verify_manifest
    m = sign_manifest({"files": [], "session_id": "s"})
    assert verify_manifest(m)[0] is True
    m2 = dict(m); m2["sig_alg"] = ""
    assert verify_manifest(m2)[0] is False

def test_pdf_production_requires_parser():
    _setup()
    from cyberaudit.pdf_validate import validate_pdf
    fake = Path("/tmp/ca3108_fake.pdf")
    fake.write_bytes(b"%PDF-1.4\n%%EOF\n")
    r = validate_pdf(fake, require_parser=True)
    assert r["ok"] is False

def test_coverage_helper_zero_hosts():
    from cyberaudit.pipeline_authorized import _coverage_block
    c = _coverage_block(authorized_scope="10.0.0.0/24", hosts_discovered=[], hosts_assessed=[])
    assert c["coverage_status"] in ("no_coverage", "incomplete")
