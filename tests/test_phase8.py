"""Phase 8 tests."""
from __future__ import annotations
import os, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "test-secret-phase8-32chars-minimum!!")

def test_state_community_workshop():
    from cyberaudit import config
    from cyberaudit.benchmarks import record_anonymous
    from cyberaudit.state_of_cyber import build_state_report, write_state_report
    from cyberaudit.community_tier import apply_community_limits, watermark_report_text, COMMUNITY_MAX_HOSTS
    config.DATA_DIR = Path(tempfile.mkdtemp())
    config.REPORTS_DIR = config.DATA_DIR / "reports"
    record_anonymous(sector="retail", posture_score=51, consent=True)
    record_anonymous(sector="retail", posture_score=78, consent=True)
    text = build_state_report(2026)
    assert "STATE OF CYBERSECURITY IN TRINIDAD & TOBAGO" in text and "point-in-time" in text.lower()
    assert write_state_report(2026).is_file()
    assert apply_community_limits({"tier": "ngo"}, 10)["community"] is True
    try:
        apply_community_limits({"tier": "school"}, COMMUNITY_MAX_HOSTS + 1)
        assert False
    except ValueError:
        pass
    assert "COMMUNITY TIER" in watermark_report_text("X", {"tier": "church"})
    assert (ROOT / "workshop" / "README.md").is_file()
    assert "TT$" in (ROOT / "workshop" / "04_sample_board_summary.txt").read_text()

if __name__ == "__main__":
    test_state_community_workshop()
    print("PHASE8 TESTS PASSED")
