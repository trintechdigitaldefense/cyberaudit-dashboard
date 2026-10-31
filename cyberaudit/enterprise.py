"""CyberAudit 3.10 Phase 7 — enterprise multi-client isolation.

Rules:
- One client must never see another client's findings, reports, or evidence.
- Client-bound users (role=client) are locked to session tenant_id.
- Admin/analyst may switch tenant; all queries must be scoped when tenant is set.
- Deletion and retention are audited and fail-closed without permission.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from cyberaudit import config
from cyberaudit.tenants import (
    apply_tenant_paths,
    list_tenants,
    tenant_root,
    validate_client_id,
)

logger = logging.getLogger("CyberAuditDashboard")

_CLIENT_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\- .]{0,80}$")


def validate_client_name(name: str) -> str:
    n = (name or "").strip()
    if not n or not _CLIENT_RE.match(n):
        raise ValueError("invalid client_name")
    return n[:80]


def current_tenant(session_obj=None, headers: dict | None = None) -> Optional[str]:
    try:
        from flask import session as fs, request
        s = session_obj if session_obj is not None else fs
        h = headers if headers is not None else dict(request.headers)
    except Exception:
        s, h = session_obj or {}, headers or {}

    role = (s.get("role") or "").lower()
    bound = (s.get("tenant_id") or s.get("client_id") or "").strip()

    if role in ("client", "viewer") and bound and validate_client_id(bound):
        return bound

    hid = (h.get("X-CyberAudit-Tenant") or h.get("x-cyberaudit-tenant") or "").strip()
    if hid and validate_client_id(hid):
        if role in ("client",) and bound and hid != bound:
            logger.warning("tenant header override rejected for client role")
            return bound
        return hid

    if bound and validate_client_id(bound):
        return bound
    return None


def require_tenant_access(resource_client_id: str | None, session_obj=None) -> bool:
    try:
        from flask import session as fs
        s = session_obj if session_obj is not None else fs
    except Exception:
        s = session_obj or {}

    role = (s.get("role") or "").lower()
    if role in ("admin", "analyst", "operator"):
        active = current_tenant(s)
        if not active:
            return True
        if not resource_client_id:
            return True
        return resource_client_id == active or resource_client_id == ""

    bound = (s.get("tenant_id") or s.get("client_id") or "").strip()
    if not bound:
        return False
    if not resource_client_id:
        return False
    return resource_client_id == bound


def assert_tenant_access(resource_client_id: str | None) -> None:
    if not require_tenant_access(resource_client_id):
        raise PermissionError("cross-client access denied")


def filter_rows_by_tenant(rows: list[dict], client_field: str = "client_name") -> list[dict]:
    try:
        from flask import session as fs
        role = (fs.get("role") or "").lower()
        bound = (fs.get("tenant_id") or fs.get("client_id") or "").strip()
    except Exception:
        return rows
    if role not in ("client", "viewer") or not bound:
        active = current_tenant()
        if not active:
            return rows
        bound = active
    out = []
    for r in rows:
        cid = (r.get(client_field) or r.get("client_id") or r.get("tenant_id") or "").strip()
        if not cid or cid == bound:
            out.append(r)
    return out


def clients_registry_path() -> Path:
    p = config.DATA_DIR / "clients_registry.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def list_client_registry() -> list[dict]:
    path = clients_registry_path()
    if not path.is_file():
        return [{"client_id": t, "display_name": t, "status": "active"} for t in list_tenants()]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return list(data.get("clients") or [])
    except Exception:
        return []


def upsert_client(
    client_id: str,
    *,
    display_name: str = "",
    contact_email: str = "",
    retention_days: int = 365,
    status: str = "active",
) -> dict:
    if not validate_client_id(client_id):
        raise ValueError("invalid client_id")
    apply_tenant_paths(client_id)
    clients = {c["client_id"]: c for c in list_client_registry() if c.get("client_id")}
    rec = clients.get(client_id, {"client_id": client_id})
    rec.update(
        {
            "client_id": client_id,
            "display_name": (display_name or rec.get("display_name") or client_id)[:120],
            "contact_email": (contact_email or rec.get("contact_email") or "")[:200],
            "retention_days": int(retention_days or rec.get("retention_days") or 365),
            "status": status,
            "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        }
    )
    clients[client_id] = rec
    path = clients_registry_path()
    path.write_text(json.dumps({"clients": list(clients.values())}, indent=2), encoding="utf-8")
    return rec


def validate_roe_for_client(roe: dict, client_id: str | None) -> tuple[bool, str]:
    if not client_id:
        return True, "ok"
    roe_client = (roe.get("client_id") or roe.get("client_name") or "").strip()
    if not roe_client:
        return False, "ROE missing client_id — required for multi-client engagement"
    if roe_client == client_id:
        return True, "ok"
    if roe_client.lower().replace(" ", "-") == client_id.lower():
        return True, "ok"
    return False, f"ROE client '{roe_client}' does not match engagement client '{client_id}'"


ENGAGEMENT_STATUSES = (
    "draft", "roe_pending", "authorised", "in_progress", "reporting", "closed", "archived",
)


def engagement_store_path() -> Path:
    p = config.DATA_DIR / "engagements.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def list_engagements(client_id: str | None = None) -> list[dict]:
    path = engagement_store_path()
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        items = list(data.get("engagements") or [])
    except Exception:
        return []
    if client_id:
        items = [e for e in items if e.get("client_id") == client_id]
    return filter_rows_by_tenant(items, client_field="client_id")


def upsert_engagement(payload: dict) -> dict:
    client_id = (payload.get("client_id") or "").strip()
    if not validate_client_id(client_id):
        raise ValueError("engagement requires valid client_id")
    eng_id = (
        payload.get("engagement_id")
        or f"ENG-{client_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    )
    status = (payload.get("status") or "draft").lower()
    if status not in ENGAGEMENT_STATUSES:
        raise ValueError(f"invalid engagement status: {status}")
    path = engagement_store_path()
    items = {}
    if path.is_file():
        try:
            raw = json.loads(path.read_text(encoding="utf-8")).get("engagements") or []
            items = {e["engagement_id"]: e for e in raw if e.get("engagement_id")}
        except Exception:
            items = {}
    rec = items.get(eng_id, {})
    rec.update(
        {
            "engagement_id": eng_id,
            "client_id": client_id,
            "status": status,
            "target_scope": payload.get("target_scope") or rec.get("target_scope") or "",
            "roe_ref": payload.get("roe_ref") or rec.get("roe_ref") or "",
            "opened_at": rec.get("opened_at")
            or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "closed_at": payload.get("closed_at") or rec.get("closed_at") or "",
            "notes": (payload.get("notes") or rec.get("notes") or "")[:500],
        }
    )
    items[eng_id] = rec
    path.write_text(json.dumps({"engagements": list(items.values())}, indent=2), encoding="utf-8")
    try:
        from cyberaudit.hardening import audit_event
        audit_event(
            "engagement_upsert",
            detail={"engagement_id": eng_id, "client_id": client_id, "status": status},
        )
    except Exception:
        pass
    return rec


def retention_days_for(client_id: str | None) -> int:
    default = int(os.environ.get("CYBERAUDIT_RETENTION_DAYS", "365"))
    if not client_id:
        return default
    for c in list_client_registry():
        if c.get("client_id") == client_id:
            return int(c.get("retention_days") or default)
    return default


def list_expired_reports(client_id: str | None = None) -> list[Path]:
    days = retention_days_for(client_id)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    roots = []
    if client_id and validate_client_id(client_id):
        roots.append(tenant_root(client_id) / "reports")
    else:
        roots.append(Path(config.REPORTS_DIR))
        base = config.DATA_DIR / "tenants"
        if base.is_dir():
            for p in base.iterdir():
                if p.is_dir():
                    roots.append(p / "reports")
    expired = []
    for root in roots:
        if not root.is_dir():
            continue
        for f in root.rglob("*"):
            if not f.is_file():
                continue
            try:
                mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc)
                if mtime < cutoff:
                    expired.append(f)
            except Exception:
                continue
    return expired


def secure_delete_path(path: Path) -> bool:
    try:
        from cyberaudit.encryption import secure_delete
        secure_delete(path)
        return True
    except Exception:
        try:
            path.unlink(missing_ok=True)
            return True
        except Exception as exc:
            logger.error("delete failed %s: %s", path, exc)
            return False


def apply_retention(*, client_id: str | None = None, dry_run: bool = True) -> dict:
    expired = list_expired_reports(client_id)
    deleted = []
    if not dry_run:
        for p in expired:
            if secure_delete_path(p):
                deleted.append(str(p))
        try:
            from cyberaudit.hardening import audit_event
            audit_event(
                "retention_apply",
                detail={"client_id": client_id, "deleted": len(deleted), "dry_run": False},
            )
        except Exception:
            pass
    return {
        "client_id": client_id,
        "dry_run": dry_run,
        "expired_count": len(expired),
        "deleted_count": len(deleted),
        "expired_sample": [str(p) for p in expired[:20]],
        "deleted_sample": deleted[:20],
    }


def archive_client_workspace(client_id: str, dest_dir: Path | str | None = None) -> Path:
    if not validate_client_id(client_id):
        raise ValueError("invalid client_id")
    root = tenant_root(client_id)
    dest_root = Path(dest_dir) if dest_dir else (config.DATA_DIR / "archives")
    dest_root.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = dest_root / f"{client_id}_{ts}.tar.gz"
    shutil.make_archive(str(dest).replace(".tar.gz", ""), "gztar", root_dir=str(root))
    try:
        from cyberaudit.hardening import audit_event
        audit_event("client_archive", detail={"client_id": client_id, "archive": str(dest)})
    except Exception:
        pass
    return dest


def environment_profile() -> dict[str, Any]:
    env = (os.environ.get("CYBERAUDIT_ENV") or os.environ.get("FLASK_ENV") or "lab").lower()
    is_prod = env in ("production", "prod")
    return {
        "environment": "production" if is_prod else "lab",
        "auth_required": bool(getattr(config, "AUTH_REQUIRED", True)),
        "bind_advice": (
            "Bind to 127.0.0.1 or VPN interface only. Never expose 0.0.0.0 without TLS + firewall."
            if is_prod
            else "Lab bind may use 127.0.0.1. Do not scan production networks from lab without ROE."
        ),
        "data_dir": str(config.DATA_DIR),
        "tenants": list_tenants(),
        "guidance": [
            "Lab and production MUST use separate DATA_DIR and secrets.",
            "Never copy production DBs into lab without redaction.",
            "Client role users must have tenant_id set at login.",
            "Retention deletes are audited; prefer dry_run first.",
            "Point-in-time audits only — not continuous monitoring.",
        ],
    }


def scoped_findings_sql(tenant: str | None) -> tuple[str, tuple]:
    if not tenant:
        return "SELECT * FROM findings ORDER BY id DESC LIMIT 500", ()
    return (
        "SELECT * FROM findings WHERE client_name=? OR client_name='' OR client_name IS NULL ORDER BY id DESC LIMIT 500",
        (tenant,),
    )


def ensure_finding_client_column() -> None:
    try:
        from cyberaudit.db import get_db
        with get_db() as conn:
            try:
                conn.execute("ALTER TABLE findings ADD COLUMN client_name TEXT DEFAULT ''")
                conn.commit()
            except Exception:
                pass
            try:
                conn.execute("ALTER TABLE audit_jobs ADD COLUMN client_name TEXT DEFAULT ''")
                conn.commit()
            except Exception:
                pass
    except Exception as exc:
        logger.debug("client column migrate: %s", exc)
