"""Multi-tenant client workspaces — Phase 3 feature #14."""

from __future__ import annotations

import re
import logging
from pathlib import Path
from typing import Optional

from cyberaudit import config

logger = logging.getLogger("CyberAuditDashboard")
_CLIENT_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")


def validate_client_id(client_id: str) -> bool:
    return bool(client_id and _CLIENT_RE.match(client_id))


def tenant_root(client_id: str) -> Path:
    if not validate_client_id(client_id):
        raise ValueError(f"invalid client_id: {client_id!r}")
    root = config.DATA_DIR / "tenants" / client_id
    root.mkdir(parents=True, exist_ok=True)
    return root


def apply_tenant_paths(client_id: str) -> dict[str, Path]:
    root = tenant_root(client_id)
    reports = root / "reports"
    jobs = root / "jobs"
    inbox = root / "inbox"
    for d in (reports, jobs, inbox, inbox / "processed", inbox / "failed"):
        d.mkdir(parents=True, exist_ok=True)
    db_path = root / "cyber_audit.db"
    config.REPORTS_DIR = reports
    config.JOBS_DIR = jobs
    config.INBOX_DIR = inbox
    config.DB_PATH = db_path
    return {"root": root, "reports": reports, "jobs": jobs, "inbox": inbox, "db": db_path}


def list_tenants() -> list[str]:
    base = config.DATA_DIR / "tenants"
    if not base.is_dir():
        return []
    return sorted(p.name for p in base.iterdir() if p.is_dir() and validate_client_id(p.name))


def resolve_tenant_from_request(headers: dict, session_obj: dict | None = None) -> Optional[str]:
    hid = (headers.get("X-CyberAudit-Tenant") or headers.get("x-cyberaudit-tenant") or "").strip()
    if hid and validate_client_id(hid):
        return hid
    if session_obj:
        sid = (session_obj.get("tenant_id") or "").strip()
        if sid and validate_client_id(sid):
            return sid
    return None
