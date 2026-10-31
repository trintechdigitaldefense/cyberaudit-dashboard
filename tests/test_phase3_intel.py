"""CyberAudit 3.10 Phase 3 — complete finding intelligence package."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("CYBERAUDIT_SECRET", "c" * 32)


def test_complete_package_fields():
    from cyberaudit.finding_enrichment import enrich_finding_complete

    f = {
        "host": "10.0.0.5",
        "port": "3389",
        "severity": "high",
        "title": "Windows Remote Desktop (RDP) network-exposed",
        "service": "rdp",
        "classification": "potential_exposure",
        "confidence": "low",
        "evidence": '{"host":"10.0.0.5","port":"3389"}',
    }
    out = enrich_finding_complete(f)
    intel = out["intel"]
    assert intel["technical_description"]
    assert intel["evidence"]
    assert intel["plain_language"]
    assert intel["business_impact"]
    assert intel["risk_confidence"] == "low"
    assert intel["remediation"]["priority"].startswith("P2")
    assert intel["remediation"]["suggested_deadline"] == "7 days"
    assert len(intel["verification_steps"]) >= 3
    assert intel["honesty"]["financials_are_estimates"] is True
    assert intel["honesty"]["legal_not_advice"] is True


def test_money_is_estimate():
    from cyberaudit.money_risk import estimate_cost

    m = estimate_cost({"severity": "high", "service": "rdp", "title": "RDP"})
    assert m["is_estimate"] is True
    assert "TT$" in m["tt_display"]
    assert "assumptions" in m


def test_findings_ui_money_uses_finding_dict():
    from cyberaudit.findings_ui import enrich_finding_row
    from cyberaudit.db import init_db

    init_db()
    row = enrich_finding_row(
        {
            "host": "10.0.0.1",
            "port": "23",
            "severity": "high",
            "title": "Telnet service exposed",
            "service": "telnet",
            "status": "open",
        }
    )
    assert row["plain_what"]
    assert row["plain_risk"]
    assert row["plain_action"]


def test_no_legal_advice_claim():
    from cyberaudit.finding_enrichment import enrich_finding_complete

    out = enrich_finding_complete(
        {
            "host": "10.0.0.1",
            "port": "445",
            "severity": "high",
            "title": "SMB exposed",
            "service": "smb",
            "cma_section": "Section 6",
            "cma_rationale": "Informational only",
        }
    )
    assert "not legal advice" in out["intel"]["cma_note"].lower()
