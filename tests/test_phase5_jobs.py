"""CyberAudit 3.10 Phase 5 — job control, backups, transactional finalize."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "e" * 32)
os.environ["CYBERAUDIT_DATA_DIR"] = "/tmp/ca310p5_data"
os.environ["CYBERAUDIT_REPORTS_DIR"] = "/tmp/ca310p5_reports"
os.environ["CYBERAUDIT_DB_PATH"] = "/tmp/ca310p5_data/cyber_audit.db"


def _setup():
    Path(os.environ["CYBERAUDIT_DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["CYBERAUDIT_REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)
    import importlib
    import cyberaudit.config as cfg
    importlib.reload(cfg)
    from cyberaudit.db import init_db
    init_db()


def test_claim_and_duplicate():
    _setup()
    from cyberaudit.job_control import (
        ensure_job_row,
        claim_job,
        register_or_reject_duplicate,
    )
    jid1 = f"JOB-P5-1-{os.getpid()}-{int(time.time())}"
    job = {"job_id": jid1, "target": "10.0.0.1", "client_name": "Acme"}
    ensure_job_row(job)
    assert claim_job(jid1) is True
    other = claim_job(jid1, worker_id="other-worker")
    assert other is False
    job2 = {"job_id": f"JOB-P5-2-{os.getpid()}", "target": "10.0.0.1", "client_name": "Acme"}
    ensure_job_row(job2)
    ok, reason = register_or_reject_duplicate(job2)
    assert ok is False
    assert "duplicate" in reason.lower()


def test_stale_recovery():
    _setup()
    from cyberaudit.job_control import ensure_job_row, claim_job, recover_stale_jobs
    from cyberaudit.db import get_db
    job = {"job_id": "JOB-STALE-1", "target": "10.0.0.9"}
    ensure_job_row(job)
    assert claim_job("JOB-STALE-1")
    with get_db() as conn:
        conn.execute(
            "UPDATE audit_jobs SET heartbeat_at=?, claimed_at=? WHERE job_id=?",
            ("2020-01-01 00:00:00", "2020-01-01 00:00:00", "JOB-STALE-1"),
        )
        conn.commit()
    recovered = recover_stale_jobs(stale_seconds=60)
    assert "JOB-STALE-1" in recovered


def test_transactional_finalize_fails_without_reports():
    _setup()
    from cyberaudit.job_control import ensure_job_row, transactional_finalize
    ensure_job_row({"job_id": "JOB-FIN-1", "target": "10.0.0.2"})
    out = transactional_finalize(
        {"status": "completed", "session_id": "AUD-X", "job_id": "JOB-FIN-1"},
        job_id="JOB-FIN-1",
    )
    assert out["status"] == "failed"
    assert out.get("mandatory_missing")


def test_backup_and_restore():
    _setup()
    from cyberaudit.phase5_db import backup_database, restore_database
    dest = Path("/tmp/ca310p5_backups")
    dest.mkdir(parents=True, exist_ok=True)
    bak = backup_database(dest)
    assert bak.is_file() and bak.stat().st_size > 0
    restored = restore_database(bak, force=True)
    assert restored.is_file()


def test_payload_hash_stable():
    from cyberaudit.job_control import payload_hash
    a = payload_hash({"target": "10.0.0.1", "client_name": "X", "job_id": "1"})
    b = payload_hash({"target": "10.0.0.1", "client_name": "X", "job_id": "2"})
    assert a == b
    c = payload_hash({"target": "10.0.0.2", "client_name": "X"})
    assert a != c
