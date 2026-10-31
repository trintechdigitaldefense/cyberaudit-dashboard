"""CyberAudit 3.10.9 — production hardening gates."""
from __future__ import annotations
import os, sys, threading, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "s" * 32)
os.environ.setdefault("CYBERAUDIT_ROE_SECRET", "s" * 32)
os.environ.setdefault("CYBERAUDIT_REPORT_SECRET", "s" * 32)
os.environ["CYBERAUDIT_DATA_DIR"] = "/tmp/ca3109_data"
os.environ["CYBERAUDIT_REPORTS_DIR"] = "/tmp/ca3109_reports"
os.environ["CYBERAUDIT_DB_PATH"] = "/tmp/ca3109_data/cyber_audit.db"

def _setup():
    Path(os.environ["CYBERAUDIT_DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["CYBERAUDIT_REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)
    import importlib
    import cyberaudit.config as cfg
    importlib.reload(cfg)
    from cyberaudit.db import init_db
    init_db()

def test_version_3109():
    _setup()
    from cyberaudit import config
    assert (ROOT / "cyberaudit" / "VERSION").read_text().strip() == "3.10.9"
    assert config.VERSION == "3.10.9"

def test_claim_token_unique_per_claim():
    _setup()
    from cyberaudit.job_control import ensure_job_row, claim_job_with_token, mark_job
    from cyberaudit.db import get_db
    jid = f"TOK-{os.getpid()}"
    ensure_job_row({"job_id": jid, "target": "10.0.0.1"})
    ok, tok = claim_job_with_token(jid, worker_id="wA")
    assert ok and tok
    with get_db() as conn:
        claimed = conn.execute("SELECT claimed_by FROM audit_jobs WHERE job_id=?", (jid,)).fetchone()["claimed_by"]
    assert claimed == f"wA|{tok}"
    assert mark_job(jid, "completed", worker_id="wA", claim_token="deadbeef") is False
    assert mark_job(jid, "completed", worker_id="wA", claim_token=tok) is True

def test_blank_owner_cannot_terminal():
    _setup()
    from cyberaudit.job_control import ensure_job_row, claim_job_with_token, mark_job
    from cyberaudit.db import get_db
    jid = f"BLANK-{os.getpid()}"
    ensure_job_row({"job_id": jid, "target": "10.0.0.2"})
    claim_job_with_token(jid, worker_id="w1")
    with get_db() as conn:
        conn.execute("UPDATE audit_jobs SET claimed_by='', status='running' WHERE job_id=?", (jid,))
        conn.commit()
    assert mark_job(jid, "completed", worker_id="anyone", claim_token="x") is False
    assert mark_job(jid, "failed", worker_id="anyone") is False

def test_two_threads_same_process_one_claim():
    _setup()
    from cyberaudit.job_control import ensure_job_row, claim_job_with_token
    jid = f"THR-{os.getpid()}-{int(time.time()*1000)}"
    ensure_job_row({"job_id": jid, "target": "10.0.0.3"})
    wins = []
    lock = threading.Lock()
    def worker(i):
        ok, tok = claim_job_with_token(jid, worker_id=f"same-proc-{i}")
        if ok:
            with lock:
                wins.append(tok)
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in ts: t.start()
    for t in ts: t.join(timeout=5)
    assert len(wins) == 1, wins

def test_workers_disabled_mark_status():
    from cyberaudit.workers import _mark_job_status
    import pytest
    with pytest.raises(RuntimeError):
        _mark_job_status("x", "failed")

def test_mark_job_status_disabled_in_source():
    src = (ROOT / "cyberaudit" / "workers.py").read_text()
    assert "claim_job_with_token" in src and "ownership_lost" in src
