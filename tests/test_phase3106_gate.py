"""CyberAudit 3.10.6 — production integration gates."""
from __future__ import annotations
import os, sys, threading, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "n" * 32)
os.environ.setdefault("CYBERAUDIT_ROE_SECRET", "n" * 32)
os.environ.setdefault("CYBERAUDIT_REPORT_SECRET", "n" * 32)
os.environ["CYBERAUDIT_DATA_DIR"] = "/tmp/ca3106_data"
os.environ["CYBERAUDIT_REPORTS_DIR"] = "/tmp/ca3106_reports"
os.environ["CYBERAUDIT_DB_PATH"] = "/tmp/ca3106_data/cyber_audit.db"

def _setup():
    Path(os.environ["CYBERAUDIT_DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["CYBERAUDIT_REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)
    import importlib
    import cyberaudit.config as cfg
    importlib.reload(cfg)
    from cyberaudit.db import init_db
    init_db()

def test_version_is_3106():
    _setup()
    from cyberaudit import config
    assert (ROOT / "cyberaudit" / "VERSION").read_text().strip() == "3.10.6"
    assert config.VERSION == "3.10.6"
    assert config.COMPANY["version"] == "3.10.6"

def test_migration_uses_tenant_path():
    for name in ("phase1_db.py", "phase5_db.py"):
        src = (ROOT / "cyberaudit" / name).read_text(encoding="utf-8")
        assert "_db_path" in src

def test_tenant_migration_and_backup_isolation():
    _setup()
    from cyberaudit.tenant_context import tenant_scope, resolve_db_path
    from cyberaudit.db import init_db, insert_finding, get_db
    from cyberaudit.phase5_db import backup_db, migrate_phase5
    with tenant_scope("t6_a"):
        init_db()
        migrate_phase5()
        insert_finding({"session_id": "S-A", "host": "10.0.0.1", "port": 22, "severity": "high", "title": "T6-A", "cve": "", "cma_section": "", "evidence": "a", "status": "open"})
        bak = backup_db(Path(os.environ["CYBERAUDIT_DATA_DIR"]) / "bak_a.db")
        assert bak.is_file()
        path_a = str(resolve_db_path())
    with tenant_scope("t6_b"):
        init_db()
        migrate_phase5()
        with get_db() as conn:
            try:
                n = conn.execute("SELECT COUNT(*) FROM findings WHERE title=?", ("T6-A",)).fetchone()[0]
            except Exception:
                n = 0
        assert n == 0
        assert str(resolve_db_path()) != path_a

def test_concurrent_claim_race_threads():
    _setup()
    from cyberaudit.job_control import ensure_job_row, claim_job
    wins = []
    lock = threading.Lock()
    def worker(wid, jid):
        ok = claim_job(jid, worker_id=wid)
        if ok:
            with lock:
                wins.append(wid)
    for round_i in range(5):
        wins.clear()
        jid = f"RACE-{os.getpid()}-{round_i}-{int(time.time()*1000)}"
        ensure_job_row({"job_id": jid, "target": "10.0.0.1"})
        threads = [threading.Thread(target=worker, args=(f"w{i}", jid)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        assert len(wins) == 1, f"round {round_i} winners={wins}"

def test_workers_process_uses_job_control_source():
    src = (ROOT / "cyberaudit" / "workers.py").read_text(encoding="utf-8")
    for token in ("ensure_job_row", "register_or_reject_duplicate", "claim_job", "heartbeat", "transactional_finalize"):
        assert token in src, token

def test_report_secret_only_no_roe_fallback():
    _setup()
    import importlib
    import cyberaudit.report_signing as rs
    old = os.environ.pop("CYBERAUDIT_REPORT_SECRET", None)
    try:
        importlib.reload(rs)
        assert rs._secret() == b""
        ok, reason = rs.verify_manifest({"signature": "abc", "sig_alg": "HMAC-SHA256"})
        assert ok is False
    finally:
        if old is not None:
            os.environ["CYBERAUDIT_REPORT_SECRET"] = old
        importlib.reload(rs)

def test_sign_requires_secret_in_production_mode():
    _setup()
    from cyberaudit import config
    import cyberaudit.report_signing as rs
    old = os.environ.pop("CYBERAUDIT_REPORT_SECRET", None)
    prev = config.DEMO_MODE
    try:
        config.DEMO_MODE = False
        try:
            rs.sign_manifest({"files": []})
            raised = False
        except RuntimeError:
            raised = True
        assert raised is True
    finally:
        config.DEMO_MODE = prev
        if old is not None:
            os.environ["CYBERAUDIT_REPORT_SECRET"] = old
