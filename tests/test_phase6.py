"""Phase 6 tests."""
from __future__ import annotations
import json, os, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "test-secret-phase6-32chars-minimum!!")

def test_gvm_xml_ingest():
    from cyberaudit.gvm_ingest import parse_openvas_xml, merge_scanner_findings
    xml = '''<?xml version="1.0"?><report><results>
    <result><host>10.0.0.8</host><port>445/tcp</port><threat>High</threat><severity>7.5</severity>
    <nvt><name>SMB Signing Disabled</name><cve>CVE-2020-TEST</cve></nvt><description>x</description></result>
    <result><host>10.0.0.9</host><port>3389/tcp</port><threat>Critical</threat><severity>9.8</severity>
    <nvt><name>RDP Exposed</name></nvt><description>RDP</description></result>
    </results></report>'''
    p = Path(tempfile.mkdtemp()) / "r.xml"; p.write_text(xml)
    findings = parse_openvas_xml(p)
    assert len(findings) == 2 and findings[1]["severity"] == "critical"
    assert len(merge_scanner_findings([{"host": "10.0.0.8", "title": "SMB Signing Disabled", "port": "445"}], findings)) == 2

def test_credential_and_cloud():
    from cyberaudit.credential_leak import check_emails
    from cyberaudit.cloud_posture import run_cloud_posture
    hits = check_emails(["jane@x.tt"], [{"email": "jane@x.tt", "source": "Demo", "year": "2024"}])
    assert len(hits) == 1 and hits[0]["severity"] == "high"
    f = run_cloud_posture({"cloud_snapshot": {
        "s3_buckets": [{"name": "payroll", "public": True}],
        "security_groups": [{"name": "sg", "inbound": [{"from_port": 3389, "to_port": 3389, "cidrs": ["0.0.0.0/0"]}]}],
        "iam": {"root_mfa": False},
    }})
    assert any("Public" in x["title"] for x in f)

def test_benchmarks():
    from cyberaudit import config
    from cyberaudit.benchmarks import record_anonymous, compare_client
    config.DATA_DIR = Path(tempfile.mkdtemp())
    assert record_anonymous(sector="retail", posture_score=51, consent=False) is False
    for s in (51, 78, 42, 60):
        record_anonymous(sector="retail", posture_score=s, consent=True)
    assert "You: 42" in compare_client("retail", 42)["director_line"]

if __name__ == "__main__":
    test_gvm_xml_ingest(); test_credential_and_cloud(); test_benchmarks()
    print("PHASE6 TESTS PASSED")
