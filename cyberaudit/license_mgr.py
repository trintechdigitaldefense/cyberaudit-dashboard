"""C9 — License management."""
from __future__ import annotations
import hashlib, json, logging, os
from datetime import datetime
from pathlib import Path
from typing import Any
from cyberaudit import config
logger = logging.getLogger("CyberAuditDashboard")
_LICENSE_PEPPER = os.environ.get("CYBERAUDIT_LICENSE_PEPPER", "trintech-cyberaudit-2026")

def _license_path() -> Path:
    return config.DATA_DIR / "license.json"

def fingerprint(key: str) -> str:
    return hashlib.sha256(f"{_LICENSE_PEPPER}:{key}".encode()).hexdigest()[:16]

def load_license() -> dict[str, Any] | None:
    env_key = os.environ.get("CYBERAUDIT_LICENSE_KEY", "").strip()
    data = None
    if _license_path().is_file():
        try: data = json.loads(_license_path().read_text(encoding="utf-8"))
        except Exception: data = None
    if env_key:
        data = data or {}
        data["key"] = env_key
    if not data or not data.get("key"): return None
    return data

def validate_license(data: dict | None = None) -> dict[str, Any]:
    data = data if data is not None else load_license()
    if not data or not data.get("key"):
        return {"valid": False, "tier": "community", "reason": "no license"}
    expires = data.get("expires") or data.get("expiry") or ""
    if expires:
        try:
            if datetime.strptime(expires[:10], "%Y-%m-%d") < datetime.utcnow():
                return {"valid": False, "tier": "expired", "reason": f"expired {expires}"}
        except ValueError: pass
    return {"valid": True, "tier": (data.get("tier") or "professional").lower(),
            "seats": data.get("seats") or 1, "partner_name": data.get("partner_name") or "",
            "fingerprint": fingerprint(str(data["key"])), "expires": expires or "none"}

def require_license_or_community(job: dict | None = None) -> dict[str, Any]:
    st = validate_license()
    require = os.environ.get("CYBERAUDIT_REQUIRE_LICENSE", "").strip().lower() in ("1", "true", "yes", "on")
    if st["valid"]: return st
    if require and job is not None:
        job["tier"] = "community"
    return st

def save_license(payload: dict) -> Path:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = _license_path()
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path
