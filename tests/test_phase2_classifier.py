"""CyberAudit 3.10 Phase 2 — finding classification, dedup, CVSS inputs."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "b" * 32)


def test_port_only_is_potential_exposure():
    from cyberaudit.finding_classifier import classify_exposure

    f = classify_exposure(
        {"host": "10.0.0.1", "port": 445, "service": "smb", "banner": ""},
        ("high", "SMB exposed", "Section 6", "smb"),
    )
    assert f["classification"] == "potential_exposure"
    assert f["confidence"] == "low"
    assert f["cve"] == ""


def test_banner_version_raises_confidence():
    from cyberaudit.finding_classifier import classify_exposure

    f = classify_exposure(
        {
            "host": "10.0.0.1",
            "port": 22,
            "service": "ssh",
            "banner": "SSH-2.0-OpenSSH_7.2p2",
        },
        ("low", "SSH open", "", "ssh"),
    )
    assert f["confidence"] in ("medium", "high")
    assert f.get("version")


def test_dedup_keeps_one():
    from cyberaudit.finding_classifier import deduplicate_findings

    a = {
        "host": "10.0.0.1",
        "port": "445",
        "title": "SMB",
        "service": "smb",
        "confidence": "low",
    }
    b = dict(a)
    b["confidence"] = "medium"
    out = deduplicate_findings([a, b])
    assert len(out) == 1
    assert out[0]["confidence"] == "medium"


def test_cvss_documents_inputs():
    from cyberaudit.cvss import score_finding

    s = score_finding(
        service="rdp",
        title="RDP open",
        severity="high",
        classification="potential_exposure",
        confidence="low",
    )
    assert s["cvss_version"] == "4.0"
    assert "cvss_inputs" in s
    assert "not an NVD" in s["cvss_note"]
    assert s["cvss_base_score"] <= 8.5


def test_cvss_telnet_stays_high():
    from cyberaudit.cvss import score_finding

    s = score_finding(
        service="telnet",
        severity="critical",
        classification="potential_exposure",
        confidence="low",
    )
    assert s["cvss_base_score"] >= 9.0


def test_suppression_roundtrip():
    from cyberaudit.false_positive import add_suppression, ensure_fp_table
    from cyberaudit.finding_classifier import apply_suppressions
    from cyberaudit.db import init_db

    init_db()
    ensure_fp_table()
    finding = {
        "host": "10.9.9.9",
        "port": "23",
        "title": "Telnet",
        "service": "telnet",
        "confidence": "low",
    }
    add_suppression(finding=finding, reason="lab noise", created_by="test")
    out = apply_suppressions([finding])
    assert any(x.get("suppressed") or x.get("status") == "false_positive" for x in out)
