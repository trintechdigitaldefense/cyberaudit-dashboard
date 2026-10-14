"""Phase 9 tests."""
from __future__ import annotations
import os, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "test-secret-phase9-32chars-minimum!!")

def test_all():
    from cyberaudit import config
    from cyberaudit.backups import run_backup, test_restore
    from cyberaudit import telemetry
    from cyberaudit.license_mgr import validate_license, save_license
    from cyberaudit.report_archive import list_reports, get_report
    config.DATA_DIR = Path(tempfile.mkdtemp())
    config.REPORTS_DIR = config.DATA_DIR / "reports"
    config.REPORTS_DIR.mkdir(parents=True)
    config.DB_PATH = config.DATA_DIR / "cyber_audit.db"
    config.DB_PATH.write_bytes(b"db")
    (config.REPORTS_DIR / "sample.txt").write_text("x")
    os.environ.pop("CYBERAUDIT_DATA_KEY", None)
    r = run_backup(encrypt=False)
    assert r["status"] == "ok" and test_restore(Path(r["path"]))["status"] == "ok"
    os.environ.pop("CYBERAUDIT_TELEMETRY", None)
    telemetry.track("x", meta={"host": "1.1.1.1"})
    assert telemetry.summary()["events"] == 0
    os.environ["CYBERAUDIT_TELEMETRY"] = "1"
    telemetry.track("scan_complete", meta={"findings": 1, "host": "1.1.1.1"})
    assert telemetry.summary()["events"] >= 1
    os.environ.pop("CYBERAUDIT_TELEMETRY", None)
    assert validate_license()["valid"] is False
    save_license({"key": "k", "tier": "professional", "expires": "2099-01-01"})
    os.environ["CYBERAUDIT_LICENSE_KEY"] = "k"
    assert validate_license()["valid"] is True
    (config.REPORTS_DIR / "CyberAudit_BoardSummary_AUD-1.txt").write_text("b")
    assert list_reports("Board") and get_report("CyberAudit_BoardSummary_AUD-1.txt")
    assert get_report("../etc/passwd") is None
    assert (ROOT / "install.sh").is_file() and (ROOT / "docs" / "OPERATOR_GUIDE.md").is_file()
    os.environ.pop("CYBERAUDIT_LICENSE_KEY", None)

if __name__ == "__main__":
    test_all()
    print("PHASE9 TESTS PASSED")
