"""Phase 5 tests."""
from __future__ import annotations
import os, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "test-secret-phase5-32chars-minimum!!")

def test_director_mode():
    from cyberaudit.director_mode import director_title, enrich_director_mode
    t = director_title({"title": "SMBv1 enabled", "service": "smb"})
    assert "file-sharing" in t.lower() or "ransomware" in t.lower()
    assert enrich_director_mode([{"title": "Open Wi-Fi", "service": "wireless", "severity": "critical"}])[0]["director"]

def test_money_and_board():
    from cyberaudit.money_risk import estimate_cost, enrich_with_money
    from cyberaudit.director_mode import enrich_director_mode
    from cyberaudit.board_summary import build_board_summary_text
    m = estimate_cost({"title": "SMBv1", "service": "smb", "severity": "high"})
    assert m["tt_low"] >= 80_000 and "TT$" in m["tt_display"]
    findings = enrich_with_money(enrich_director_mode([{"title": "RDP network-exposed", "service": "rdp", "severity": "high", "host": "10.0.0.5"}]))
    text = build_board_summary_text(session_id="AUD-T", client_name="Island Mart", target="10.0.0.0/24",
        posture_score=42.0, posture_band="Needs work", findings=findings, sector="retail")
    assert "BOARD SUMMARY" in text and "TT$" in text and "point-in-time" in text.lower()

def test_intel():
    from cyberaudit.caribbean_intel import match_intel
    cards = match_intel([{"title": "SMB null", "service": "smb", "host": "10.0.0.2"}])
    assert cards and "Ransomware" in cards[0]["headline"]

if __name__ == "__main__":
    test_director_mode(); test_money_and_board(); test_intel()
    print("PHASE5 TESTS PASSED")
