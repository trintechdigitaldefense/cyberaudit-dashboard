"""Phase 1 unit tests — CVSS, posture, retest delta, PDF."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "test-secret-not-for-production")


def test_cvss_scoring():
    from cyberaudit.cvss import score_finding, enrich_findings, severity_from_score

    rdp = score_finding(service="rdp", title="Windows remote desktop", severity="high")
    assert rdp["cvss_version"] == "4.0"
    assert rdp["cvss_base_score"] >= 7.0
    assert "CVSS:4.0/" in rdp["cvss_vector"]

    telnet = score_finding(service="telnet", severity="critical")
    assert telnet["cvss_base_score"] >= 9.0
    assert severity_from_score(9.5) == "Critical"
    assert severity_from_score(5.0) == "Medium"

    items = enrich_findings(
        [{"host": "1.2.3.4", "port": "3389", "service": "rdp", "title": "RDP open", "severity": "high"}]
    )
    assert items[0]["cvss_base_score"] >= 7.0


def test_posture_score():
    from cyberaudit.posture import compute_posture_score, trend_arrow

    empty = compute_posture_score(findings=[], hosts_up=5, open_ports=10)
    assert empty["posture_score"] == 100.0
    assert empty["band"] == "Excellent"

    bad = compute_posture_score(
        findings=[{"severity": "critical"}, {"severity": "high"}, {"severity": "high"}],
        hosts_up=3,
        open_ports=12,
    )
    assert bad["posture_score"] < 70
    assert "↑" in trend_arrow(50, 70)
    assert "↓" in trend_arrow(80, 60)


def test_retest_delta():
    from cyberaudit.retest import compute_delta, fingerprint

    base = [
        {"host": "10.0.0.1", "port": "3389", "title": "RDP open", "service": "rdp", "severity": "high"},
        {"host": "10.0.0.2", "port": "23", "title": "Telnet", "service": "telnet", "severity": "critical"},
    ]
    curr = [
        {"host": "10.0.0.1", "port": "3389", "title": "RDP open", "service": "rdp", "severity": "high"},
        {"host": "10.0.0.3", "port": "445", "title": "SMB", "service": "smb", "severity": "high"},
    ]
    d = compute_delta(base, curr)
    assert d["summary"]["closed_count"] == 1
    assert d["summary"]["still_open_count"] == 1
    assert d["summary"]["new_count"] == 1
    assert fingerprint(base[0]) == fingerprint(curr[0])


def test_executive_pdf(tmp_path=None):
    import tempfile
    from cyberaudit import config
    from cyberaudit.cvss import enrich_findings
    from cyberaudit.exec_pdf import generate_executive_pdf

    td = Path(tempfile.mkdtemp()) if tmp_path is None else Path(tmp_path)
    config.REPORTS_DIR = td
    vulns = enrich_findings([
        {"host": "192.168.1.10", "port": "3389", "service": "rdp", "title": "RDP exposed", "severity": "high"},
        {"host": "192.168.1.11", "port": "23", "service": "telnet", "title": "Telnet", "severity": "critical"},
    ])
    path = generate_executive_pdf(
        session_id="AUD-TEST-001",
        target="192.168.1.0/24",
        vulns=vulns,
        hosts_up=["192.168.1.10", "192.168.1.11"],
        open_ports=[{"host": "192.168.1.10", "port": "3389"}],
        previous_posture=55.0,
        client_name="Demo Client Ltd",
    )
    assert path.exists()
    assert path.stat().st_size > 1000


if __name__ == "__main__":
    test_cvss_scoring()
    test_posture_score()
    test_retest_delta()
    test_executive_pdf()
    print("ALL PHASE1 TESTS PASSED")
