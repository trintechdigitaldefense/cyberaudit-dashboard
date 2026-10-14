"""Phase 2 unit tests."""
from __future__ import annotations
import os, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "test-secret-not-for-production")

def test_wireless_open_and_wep():
    from cyberaudit.wireless_module import assess_wireless
    findings = assess_wireless([
        {"ssid": "CafeFree", "security": "OPEN", "bssid": "aa:bb"},
        {"ssid": "OldOffice", "security": "WEP", "bssid": "cc:dd"},
        {"ssid": "Corp", "security": "WPA2", "bssid": "ee:ff"},
        {"ssid": "Store-Guest", "security": "WPA2", "bssid": "11:22"},
    ])
    titles = " ".join(f["title"] for f in findings)
    assert "Open Wi-Fi" in titles
    assert "WEP" in titles

def test_auth_no_creds_noop():
    from cyberaudit.auth_scan_module import run_authenticated_checks
    assert run_authenticated_checks([{"host": "10.0.0.1", "port": "22"}], job={}) == []

def test_sector_packs():
    from cyberaudit.sector_templates import get_sector, sector_preamble
    assert "Finance" in get_sector("finance")["label"]
    assert "Island Mart" in sector_preamble("retail", "Island Mart")

def test_translator_rdp():
    from cyberaudit.risk_translator import translate
    t = translate({"service": "rdp", "title": "RDP open"})
    assert "Restrict" in t["do_this_week"] or "week" in t["do_this_week"].lower()

if __name__ == "__main__":
    test_wireless_open_and_wep()
    test_auth_no_creds_noop()
    test_sector_packs()
    test_translator_rdp()
    print("PHASE2 TESTS PASSED")
