"""CyberAudit 3.10 Phase 4 — report integrity, pack signing, finalization."""

from __future__ import annotations

import json
import os
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "d" * 32)
os.environ.setdefault("CYBERAUDIT_DATA_DIR", "/tmp/ca310p4_data")
os.environ.setdefault("CYBERAUDIT_REPORTS_DIR", "/tmp/ca310p4_reports")


def _setup():
    Path(os.environ["CYBERAUDIT_DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["CYBERAUDIT_REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)
    import importlib
    import cyberaudit.config as cfg
    importlib.reload(cfg)


def test_pdf_magic_required_by_finalization():
    _setup()
    from cyberaudit.finalization import _is_valid_pdf
    from cyberaudit import config
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    fake = config.REPORTS_DIR / "fake.pdf"
    fake.write_bytes(b"not a pdf at all " * 10)
    assert _is_valid_pdf(fake) is False
    real = config.REPORTS_DIR / "real.pdf"
    real.write_bytes(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n" + b"1 0 obj\n<<>>\nendobj\n" * 5)
    assert _is_valid_pdf(real) is True


def test_mandatory_missing_fails_finalization():
    _setup()
    from cyberaudit.finalization import finalize_audit_result
    result = {"session_id": "AUD-TEST-1", "status": "completed", "executive_txt": None, "technical_txt": None}
    out = finalize_audit_result(result)
    assert out["status"] == "failed"
    assert out.get("mandatory_missing")


def test_engagement_pack_refuses_without_mandatory():
    _setup()
    from cyberaudit.engagement_export import build_engagement_pack
    import pytest
    with pytest.raises(RuntimeError, match="mandatory"):
        build_engagement_pack("AUD-EMPTY-XYZ", require_mandatory=True)


def test_engagement_pack_with_artefacts_and_signature():
    _setup()
    from cyberaudit import config
    from cyberaudit.engagement_export import build_engagement_pack
    from cyberaudit.report_signing import verify_pack_zip
    sid = "AUD-PACK-001"
    (config.REPORTS_DIR / f"CyberAudit_Client_{sid}.txt").write_text("Executive summary\n" * 5)
    (config.REPORTS_DIR / f"CyberAudit_Technical_{sid}.txt").write_text("Technical annex\n" * 5)
    (config.REPORTS_DIR / f"CyberAudit_Executive_{sid}.pdf").write_bytes(b"%PDF-1.4\n" + b"% content\n" * 20)
    pack = build_engagement_pack(
        sid, client_name="Acme", target="10.0.0.0/24",
        extra_meta={"roe": {"authorized_by": "CISO", "valid_until": "2027-01-01"}},
        require_mandatory=True,
    )
    assert pack.is_file()
    v = verify_pack_zip(pack)
    assert v["zip_ok"] and v["manifest_ok"] and v["checksums_ok"] and v["signature_ok"] and v["ok"]
    with zipfile.ZipFile(pack, "r") as zf:
        manifest = json.loads(zf.read("MANIFEST.json"))
    assert manifest.get("authorization_reference", {}).get("authorized_by") == "CISO"


def test_fake_pdf_excluded_from_pack():
    _setup()
    from cyberaudit import config
    from cyberaudit.engagement_export import build_engagement_pack
    sid = "AUD-FAKEPDF-1"
    (config.REPORTS_DIR / f"CyberAudit_Client_{sid}.txt").write_text("client\n" * 3)
    (config.REPORTS_DIR / f"CyberAudit_Technical_{sid}.txt").write_text("tech\n" * 3)
    fake = config.REPORTS_DIR / f"CyberAudit_Executive_{sid}.pdf"
    fake.write_bytes(b"plain text disguised as pdf\n" * 10)
    pack = build_engagement_pack(sid, require_mandatory=True)
    with zipfile.ZipFile(pack, "r") as zf:
        names = zf.namelist()
        manifest = json.loads(zf.read("MANIFEST.json"))
    assert fake.name not in names
    assert any(r.get("reason") == "not a genuine PDF" for r in (manifest.get("rejected_files") or []))


def test_sign_manifest_roundtrip():
    from cyberaudit.report_signing import sign_manifest, verify_manifest
    m = sign_manifest({"session_id": "X", "files": []})
    ok, reason = verify_manifest(m)
    assert ok, reason
    m["session_id"] = "tampered"
    assert verify_manifest(m)[0] is False
