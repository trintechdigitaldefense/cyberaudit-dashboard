"""Phase 7 tests."""
from __future__ import annotations
import os, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "test-secret-phase7-32chars-minimum!!")

def test_partner_keys():
    from cyberaudit import config
    from cyberaudit.partner_api import issue_partner_key, verify_api_key, API_VERSION
    config.DATA_DIR = Path(tempfile.mkdtemp())
    entry = issue_partner_key("MSP-Demo", brand="Demo MSP")
    assert entry["key"].startswith("ca_") and verify_api_key(entry["key"])["name"] == "MSP-Demo"
    assert verify_api_key("wrong") is None and API_VERSION == "v1"

def test_airgap_phishing_es_cert():
    from cyberaudit import airgap, config
    from cyberaudit.phishing_sim import create_campaign, ingest_results
    from cyberaudit.i18n_es import translate_board_skeleton
    os.environ["CYBERAUDIT_AIRGAP"] = "1"
    assert airgap.block_egress("t") is True
    os.environ.pop("CYBERAUDIT_AIRGAP", None)
    config.DATA_DIR = Path(tempfile.mkdtemp())
    create_campaign("PH-1", "Test")
    s = ingest_results("PH-1", {"sent": 40, "clicked": 14, "reported": 6, "failed": 0})
    assert s["click_rate_pct"] == 35.0 and s["finding"]["severity"] == "high"
    text = translate_board_skeleton(lang="es", company_name="T", tagline="t", client_name="C",
        session_id="A", date_str="d", target="x", sector="retail", score="42", band="b",
        top_lines=[], money_line="TT$1", fixed=0, still=0, new=0, source_note="s",
        email="e", phone="p", website="w")
    assert "RESUMEN PARA LA JUNTA" in text and "No es monitoreo 24/7" in text
    assert (ROOT / "CERTIFICATION_PATHWAY.md").is_file()

if __name__ == "__main__":
    test_partner_keys(); test_airgap_phishing_es_cert()
    print("PHASE7 TESTS PASSED")
