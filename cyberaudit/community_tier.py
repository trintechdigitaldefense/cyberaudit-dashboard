"""P8.2 — Free community tier (NGO / school / church)."""
from __future__ import annotations
import os
from typing import Any

COMMUNITY_MAX_HOSTS = 32
COMMUNITY_WATERMARK = (
    "COMMUNITY TIER — free for NGOs, schools, and churches in Trinidad & Tobago. "
    "Non-commercial use. Upgrade to a full engagement for larger networks and partner features."
)

def community_mode(job: dict | None = None) -> bool:
    if os.environ.get("CYBERAUDIT_COMMUNITY_TIER", "").strip().lower() in ("1", "true", "yes", "on"):
        return True
    job = job or {}
    tier = str(job.get("tier") or job.get("license_tier") or "").lower()
    return tier in ("community", "free", "ngo", "school", "church")

def apply_community_limits(job: dict, host_count: int = 0) -> dict[str, Any]:
    if not community_mode(job):
        return {"community": False, "max_hosts": None}
    if host_count > COMMUNITY_MAX_HOSTS:
        raise ValueError(
            f"Community tier allows up to {COMMUNITY_MAX_HOSTS} hosts per scan "
            f"(this job has {host_count}). Contact TrinTech for a full engagement."
        )
    return {"community": True, "max_hosts": COMMUNITY_MAX_HOSTS, "watermark": COMMUNITY_WATERMARK,
            "partner_api": False, "commercial": False}

def watermark_report_text(text: str, job: dict | None = None) -> str:
    if not community_mode(job):
        return text
    banner = "\n" + "─" * 72 + f"\n  {COMMUNITY_WATERMARK}\n" + "─" * 72 + "\n"
    return banner + text + banner

def community_status() -> dict[str, Any]:
    return {
        "tier": "community" if community_mode() else "standard",
        "max_hosts": COMMUNITY_MAX_HOSTS if community_mode() else None,
        "eligible": "NGOs, schools, churches in T&T (non-commercial)",
        "includes": ["Point-in-time mapping", "Director mode", "Board summary", "CMA tags"],
        "excludes": ["Partner API", "Unlimited hosts", "Air-gap premium", "Commercial redistribution"],
        "contact": "trintechdigitaldefense@gmail.com",
    }
