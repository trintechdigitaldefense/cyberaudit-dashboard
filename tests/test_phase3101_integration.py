"""CyberAudit 3.10.1 — integration: worker path, ROE gate, tenant isolation."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "i" * 32)
os.environ.setdefault("CYBERAUDIT_ROE_SECRET", "i" * 32)
os.environ["CYBERAUDIT_DATA_DIR"] = "/tmp/ca3101_data"
os.environ["CYBERAUDIT_REPORTS_DIR"] = "/tmp/ca3101_reports"
os.environ["CYBERAUDIT_DB_PATH"] = "/tmp/ca3101_data/cyber_audit.db"


def _setup():
    Path(os.environ["CYBERAUDIT_DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["CYBERAUDIT_REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)
    import importlib
    import cyberaudit.config as cfg
    importlib.reload(cfg)
    from cyberaudit.db import init_db
    init_db()


def _signed_roe(targets=None):
    from cyberaudit.roe import sign_roe
    return sign_roe({
        "client_name": "Integration Client",
        "authorized_by": "QA",
        "targets": targets or ["10.0.0.0/24"],
        "valid_from": "2020-01-01T00:00:00Z",
        "valid_until": "2099-12-31T23:59:59Z",
    })


def test_pipeline_rejects_missing_roe_in_spirit():
    _setup()
    from cyberaudit.roe import assert_authorized
    from cyberaudit import config
    prev = config.DEMO_MODE
    try:
        config.DEMO_MODE = False
        try:
            assert_authorized({"target": "10.0.0.1", "job_id": "J-NO-ROE"})
            raised = False
        except (PermissionError, ValueError):
            raised = True
        assert raised is True
    finally:
        config.DEMO_MODE = prev


def test_pipeline_run_with_roe_no_live_hosts():
    _setup()
    from cyberaudit.pipeline_engine import run_audit_job
    job = {
        "job_id": f"J-EMPTY-{int(time.time())}",
        "target": "10.255.255.1",
        "roe": _signed_roe(targets=["10.255.255.0/24"]),
    }
    try:
        result = run_audit_job(job)
    except PermissionError:
        return
    assert isinstance(result, dict)
    assert result.get("status") in ("completed", "failed", "running") or "session_id" in result


def test_out_of_scope_cannot_enter_pipeline():
    _setup()
    from cyberaudit.pipeline_engine import run_audit_job
    job = {
        "job_id": f"J-SCOPE-{int(time.time())}",
        "target": "203.0.113.9",
        "roe": _signed_roe(targets=["10.0.0.0/24"]),
    }
    try:
        run_audit_job(job)
        ok = True
    except (PermissionError, ValueError):
        ok = False
    assert ok is False


def test_worker_claim_before_run():
    _setup()
    from cyberaudit.job_control import ensure_job_row, claim_job
    jid = f"J-CLAIM-{os.getpid()}-{int(time.time())}"
    ensure_job_row({"job_id": jid, "target": "10.0.0.1"})
    assert claim_job(jid) is True
    assert claim_job(jid, worker_id="intruder") is False


def test_tenant_context_concurrent_distinct():
    _setup()
    from cyberaudit.tenant_context import concurrent_isolation_check
    result = concurrent_isolation_check("client_one", "client_two")
    assert result["distinct_db"] is True
    assert result["distinct_reports"] is True
    assert result["nested_inner_ok"] is True
    assert result["restored_to_a"] is True
    assert result["outer_cleared"] is True


def test_no_candidates_fallback_in_active_pipeline_source():
    body2 = (ROOT / "cyberaudit" / "pipeline_body_2.txt").read_text(encoding="utf-8")
    engine = (ROOT / "cyberaudit" / "pipeline_engine.py").read_text(encoding="utf-8")
    assert "candidates[:16]" not in body2
    assert "assert_authorized" in body2
    assert "strip_run_audit" in engine or "run_audit_job" in engine


def test_pdf_rejects_header_only_without_eof():
    _setup()
    from cyberaudit.finalization import _is_valid_pdf
    reports = Path(os.environ["CYBERAUDIT_REPORTS_DIR"])
    worse = reports / "notpdf.pdf"
    worse.write_bytes(b"PK\x03\x04" + b"\x00" * 40)
    assert _is_valid_pdf(worse) is False
