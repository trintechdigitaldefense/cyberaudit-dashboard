"""3.10.9 remaining P0: no-exec app, safe redirect, backup integrity."""
from __future__ import annotations
import os, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "t" * 32)
os.environ.setdefault("CYBERAUDIT_ROE_SECRET", "t" * 32)
os.environ.setdefault("CYBERAUDIT_REPORT_SECRET", "t" * 32)
os.environ["CYBERAUDIT_DATA_DIR"] = "/tmp/ca3109p0_data"
os.environ["CYBERAUDIT_REPORTS_DIR"] = "/tmp/ca3109p0_reports"
os.environ["CYBERAUDIT_DB_PATH"] = "/tmp/ca3109p0_data/cyber_audit.db"

def _setup():
    Path(os.environ["CYBERAUDIT_DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["CYBERAUDIT_REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)
    import importlib
    import cyberaudit.config as cfg
    importlib.reload(cfg)
    from cyberaudit.db import init_db
    init_db()

def test_app_py_no_exec():
    src = (ROOT / "cyberaudit" / "app.py").read_text()
    assert "exec(" not in src and "app_impl" in src

def test_safe_next_url_blocks_open_redirect():
    from cyberaudit.hardening import safe_next_url
    assert safe_next_url("/dashboard") == "/dashboard"
    assert safe_next_url("//evil.example") == "/"
    assert safe_next_url("https://evil.example") == "/"
    assert safe_next_url(None) == "/"

def test_backup_integrity():
    _setup()
    from cyberaudit.phase5_db import backup_db
    from cyberaudit.db import get_db
    with get_db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS t_backup_probe (id INTEGER)")
        conn.execute("INSERT INTO t_backup_probe(id) VALUES (1)")
        conn.commit()
    dest = Path("/tmp/ca3109p0_backup.db")
    if dest.exists(): dest.unlink()
    out = backup_db(dest)
    assert out.exists()
    import sqlite3
    c = sqlite3.connect(str(out))
    try:
        assert str(c.execute("PRAGMA integrity_check").fetchone()[0]).lower() == "ok"
        assert c.execute("SELECT id FROM t_backup_probe").fetchone()[0] == 1
    finally:
        c.close()

def test_verify_manifest_requires_alg():
    _setup()
    from cyberaudit.report_signing import sign_manifest, verify_manifest
    m = sign_manifest({"files": [], "session_id": "s"})
    assert verify_manifest(m)[0] is True
    bad = dict(m); bad["sig_alg"] = ""
    assert verify_manifest(bad)[0] is False

def test_tenant_paths_isolated():
    _setup()
    from cyberaudit.tenant_context import concurrent_isolation_check
    assert concurrent_isolation_check("ten_a", "ten_b").get("distinct_db") is True
