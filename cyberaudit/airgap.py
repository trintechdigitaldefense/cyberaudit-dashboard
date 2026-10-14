"""P7.2 — Offline / air-gapped edition (premium)."""
from __future__ import annotations
import logging, os
from typing import Any
logger = logging.getLogger("CyberAuditDashboard")

def airgap_enabled() -> bool:
    return os.environ.get("CYBERAUDIT_AIRGAP", os.environ.get("AIRGAP_MODE", "0")).strip().lower() in ("1", "true", "yes", "on")

def block_egress(reason: str = "airgap") -> bool:
    if airgap_enabled():
        logger.info("air-gap: blocked egress (%s)", reason)
        return True
    return False

def airgap_status() -> dict[str, Any]:
    on = airgap_enabled()
    return {
        "airgap_mode": on,
        "tier": "premium-airgap" if on else "standard",
        "egress_allowed": not on,
        "features": {
            "local_scan": True, "reports": True, "director_mode": True,
            "webhooks": not on, "email_alerts": not on,
            "external_intel_fetch": not on,
            "usage_telemetry": False if on else "opt-in only",
        },
        "note": "Air-gapped edition never phones home. ROE scan traffic is operational, not telemetry." if on else "Standard mode may send operator-configured alerts only.",
    }
