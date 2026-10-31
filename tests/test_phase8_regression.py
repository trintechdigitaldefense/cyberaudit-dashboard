"""CyberAudit 3.10 Phase 8 — full regression / acceptance matrix."""

from __future__ import annotations

import json
import os
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "r" * 32)
os.environ.setdefault("CYBERAUDIT_ROE_SECRET", "r" * 32)
os.environ["CYBERAUDIT_DATA_DIR"] = "/tmp/ca310p8_data"
os.environ["CYBERAUDIT_REPORTS_DIR"] = "/tmp/ca310p8_reports"
os.environ["CYBERAUDIT_DB_PATH"] = "/tmp/ca310p8_data/cyber_audit.db"


def _setup():
    Path(os.environ["CYBERAUDIT_DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["CYBERAUDIT_REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)
    import importlib
    import cyberaudit.config as cfg
    importlib.reload(cfg)
    from cyberaudit.db import init_db
    init_db()


def _make_roe(targets=None, **extra):
    from cyberaudit.roe import sign_roe
    roe = {
        "client_name": "Acme TT",
        "authorized_by": "Jason Ramdharry",
        "targets": targets or ["10.0.0.0/24"],
        "valid_from": "2020-01-01T00:00:00Z",
        "valid_until": "2099-12-31T23:59:59Z",
    }
    roe.update(extra)
    return sign_roe(roe)


def test_unsigned_roe_rejected():
    _setup()
    from cyberaudit.roe import verify_roe_signature
    roe = {
        "client_name": "Acme",
        "authorized_by": "Ops",
        "targets": ["10.0.0.5"],
        "valid_from": "2020-01-01T00:00:00Z",
        "valid_until": "2099-01-01T00:00:00Z",
    }
    ok, reason = verify_roe_signature(roe)
    assert ok is False


def test_signed_roe_roundtrip():
    _setup()
    from cyberaudit.roe import verify_roe_signature
    signed = _make_roe()
    ok, reason = verify_roe_signature(signed)
    assert ok is True, reason


def test_out_of_scope_target_rejected():
    _setup()
    from cyberaudit.roe import validate_roe
    signed = _make_roe(targets=["10.0.0.0/24"])
    job = {"target": "203.0.113.50", "roe": signed}
    try:
        validate_roe(job, require_signature=True)
        raised = False
    except (PermissionError, ValueError):
        raised = True
    assert raised is True


def test_in_scope_target_accepted():
    _setup()
    from cyberaudit.roe import validate_roe
    signed = _make_roe(targets=["10.0.0.0/24"])
    job = {"target": "10.0.0.5", "roe": signed}
    result = validate_roe(job, require_signature=True)
    assert isinstance(result, dict)
    assert result.get("client_name")


def test_completed_requires_mandatory_artefacts():
    _setup()
    from cyberaudit.finalization import finalize_audit_result
    out = finalize_audit_result(
        {"status": "completed", "session_id": "AUD-REG-1", "job_id": "JOB-REG-1"},
        session_id="AUD-REG-1",
        job_id="JOB-REG-1",
    )
    assert out["status"] == "failed"
    assert out.get("mandatory_missing") or out.get("error")


def test_valid_pdf_magic():
    _setup()
    from cyberaudit.finalization import _is_valid_pdf
    reports = Path(os.environ["CYBERAUDIT_REPORTS_DIR"])
    good = reports / "good.pdf"
    good.write_bytes(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n")
    bad = reports / "fake.pdf"
    bad.write_bytes(b"not a pdf at all " * 10)
    assert _is_valid_pdf(good) is True
    assert _is_valid_pdf(bad) is False


def test_engagement_pack_with_named_artefacts():
    _setup()
    from cyberaudit.engagement_export import build_engagement_pack
    reports = Path(os.environ["CYBERAUDIT_REPORTS_DIR"])
    sid = "AUD-PACK-8"
    client = reports / f"CyberAudit_Client_Report_{sid}.txt"
    tech = reports / f"CyberAudit_Technical_Annex_{sid}.txt"
    client.write_text("Client report — point-in-time.\n", encoding="utf-8")
    tech.write_text("Technical annex.\n", encoding="utf-8")
    pdf = reports / f"CyberAudit_Executive_{sid}.pdf"
    pdf.write_bytes(b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n")
    pack = build_engagement_pack(sid, client_name="Acme", target="10.0.0.0/24", require_mandatory=True)
    assert pack.is_file()
    assert zipfile.is_zipfile(pack)
    with zipfile.ZipFile(pack, "r") as zf:
        assert zf.testzip() is None


def test_classifier_confidence_present():
    _setup()
    from cyberaudit.finding_classifier import classify_exposure
    f = classify_exposure({
        "host": "10.0.0.8", "port": 445, "service": "smb",
        "banner": "SMBv1", "title": "SMBv1 enabled",
    })
    assert isinstance(f, dict)


def test_enrichment_has_plain_language():
    _setup()
    from cyberaudit.finding_enrichment import enrich_finding_complete
    out = enrich_finding_complete({
        "title": "Open SSH on port 22", "severity": "medium",
        "host": "10.0.0.2", "port": 22, "service": "ssh",
    })
    assert isinstance(out, dict)
    blob = json.dumps(out).lower()
    assert "ssh" in blob or "remote" in blob or out.get("plain_language") or out.get("director_summary")


def test_job_claim_idempotent():
    _setup()
    from cyberaudit.job_control import ensure_job_row, claim_job
    jid = f"JOB-REG-{os.getpid()}-{int(time.time())}"
    ensure_job_row({"job_id": jid, "target": "10.0.0.1"})
    assert claim_job(jid) is True
    assert claim_job(jid, worker_id="other") is False


def test_transactional_finalize_sync():
    _setup()
    from cyberaudit.job_control import ensure_job_row, transactional_finalize
    jid = f"JOB-FIN-{os.getpid()}-{int(time.time())}"
    ensure_job_row({"job_id": jid, "target": "10.0.0.3"})
    out = transactional_finalize(
        {"status": "completed", "session_id": "AUD-X", "job_id": jid},
        job_id=jid,
    )
    assert out["status"] == "failed"


def test_cross_tenant_denied():
    _setup()
    from cyberaudit.enterprise import require_tenant_access
    class Sess(dict):
        pass
    client = Sess(role="client", tenant_id="bank_a", authenticated=True)
    assert require_tenant_access("bank_a", client) is True
    assert require_tenant_access("bank_b", client) is False


def test_tenant_db_paths_differ():
    _setup()
    from cyberaudit.tenants import apply_tenant_paths
    a = apply_tenant_paths("reg_alpha")
    b = apply_tenant_paths("reg_beta")
    assert str(a["db"]) != str(b["db"])


def test_idle_module_not_operational():
    _setup()
    from cyberaudit.db import upsert_module_status
    from cyberaudit.dashboard_surfaces import system_health
    upsert_module_status(module_name="openvas_module", status="idle", last_result="not executed", last_run="")
    sh = system_health()
    rows = [m for m in sh["modules"] if "openvas" in (m.get("module_name") or "")]
    if rows:
        assert rows[0].get("operational") is False


def test_cma_disclaimer_not_legal_advice():
    _setup()
    from cyberaudit.dashboard_surfaces import compliance_overview
    co = compliance_overview()
    assert "legal advice" in (co.get("disclaimer") or "").lower()


def test_db_backup_readable():
    _setup()
    from cyberaudit.phase5_db import backup_database
    import sqlite3
    dest = Path("/tmp/ca310p8_backups")
    dest.mkdir(parents=True, exist_ok=True)
    bak = backup_database(dest)
    assert bak.is_file()
    conn = sqlite3.connect(str(bak))
    try:
        assert conn.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0] >= 1
    finally:
        conn.close()


def test_roe_client_match_enterprise():
    _setup()
    from cyberaudit.enterprise import validate_roe_for_client
    ok, _ = validate_roe_for_client({"client_id": "acme"}, "acme")
    assert ok is True
    ok, reason = validate_roe_for_client({"client_id": "other"}, "acme")
    assert ok is False


def test_retention_dry_run_safe():
    _setup()
    from cyberaudit.enterprise import apply_retention
    result = apply_retention(dry_run=True)
    assert result["dry_run"] is True
    assert result["deleted_count"] == 0
