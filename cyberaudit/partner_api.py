"""P7.1 — Partner/MSP API (versioned /api/v1/)."""
from __future__ import annotations
import hmac, json, logging, os, secrets
from functools import wraps
from pathlib import Path
from typing import Any, Callable
from cyberaudit import config
logger = logging.getLogger("CyberAuditDashboard")
API_VERSION = "v1"

def _keys_file() -> Path:
    return config.DATA_DIR / "partner_keys.json"

def load_partner_keys() -> dict[str, dict]:
    keys = {}
    env = os.environ.get("CYBERAUDIT_PARTNER_KEYS", "").strip()
    if env:
        for i, k in enumerate(env.split(",")):
            k = k.strip()
            if k:
                keys[k] = {"name": f"partner-{i+1}", "brand": "TrinTech Digital Defense", "active": True}
    path = _keys_file()
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for row in data if isinstance(data, list) else data.get("keys", []):
                k = (row.get("key") or "").strip()
                if k:
                    keys[k] = {"name": row.get("name") or "partner", "brand": row.get("brand") or config.COMPANY["name"], "active": row.get("active", True) is not False}
        except Exception as exc:
            logger.warning("partner keys: %s", exc)
    return keys

def issue_partner_key(name: str, brand: str = "") -> dict:
    key = "ca_" + secrets.token_urlsafe(24)
    path = _keys_file()
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            rows = data if isinstance(data, list) else data.get("keys", [])
        except Exception:
            rows = []
    entry = {"key": key, "name": name, "brand": brand or config.COMPANY["name"], "active": True}
    rows.append(entry)
    path.write_text(json.dumps({"keys": rows}, indent=2), encoding="utf-8")
    return entry

def verify_api_key(provided: str) -> dict | None:
    if not provided:
        return None
    for k, meta in load_partner_keys().items():
        if meta.get("active") and hmac.compare_digest(k, provided):
            return {"key_prefix": k[:8] + "…", **meta}
    return None

def enqueue_partner_job(payload: dict, partner: dict) -> dict:
    from cyberaudit.hardening import validate_job_payload
    from cyberaudit.schedule_windows import enqueue_scheduled_job
    job = validate_job_payload(payload)
    job["partner_name"] = partner.get("name")
    job["partner_brand"] = partner.get("brand")
    job["source"] = "partner_api"
    path = enqueue_scheduled_job(job)
    return {"api_version": API_VERSION, "status": "queued", "job_id": job.get("job_id"), "path": path, "partner": partner.get("name")}

def partner_status_payload() -> dict:
    return {
        "api_version": API_VERSION,
        "product": config.COMPANY["product"],
        "vendor": config.COMPANY["name"],
        "endpoints": {
            "POST /api/v1/jobs": "Queue audit job",
            "GET /api/v1/health": "Health + capability",
            "GET /api/v1/status": "Status",
        },
        "auth": "X-API-Key or Authorization: Bearer",
    }
