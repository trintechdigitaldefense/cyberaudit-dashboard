"""Thread-local tenant storage context — CyberAudit 3.10.1."""

from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from cyberaudit import config
from cyberaudit.tenants import tenant_root, validate_client_id

logger = logging.getLogger("CyberAuditDashboard")
_local = threading.local()


@dataclass(frozen=True)
class TenantPaths:
    client_id: str
    root: Path
    reports: Path
    jobs: Path
    inbox: Path
    db: Path


def get_active_tenant() -> Optional[TenantPaths]:
    return getattr(_local, "tenant", None)


def resolve_db_path() -> Path:
    t = get_active_tenant()
    if t:
        return t.db
    return Path(config.DB_PATH)


def resolve_reports_dir() -> Path:
    t = get_active_tenant()
    if t:
        return t.reports
    return Path(config.REPORTS_DIR)


def resolve_jobs_dir() -> Path:
    t = get_active_tenant()
    if t:
        return t.jobs
    return Path(config.JOBS_DIR)


def build_tenant_paths(client_id: str) -> TenantPaths:
    if not validate_client_id(client_id):
        raise ValueError(f"invalid client_id: {client_id!r}")
    root = tenant_root(client_id)
    reports = root / "reports"
    jobs = root / "jobs"
    inbox = root / "inbox"
    for d in (reports, jobs, inbox, inbox / "processed", inbox / "failed"):
        d.mkdir(parents=True, exist_ok=True)
    return TenantPaths(
        client_id=client_id,
        root=root,
        reports=reports,
        jobs=jobs,
        inbox=inbox,
        db=root / "cyber_audit.db",
    )


@contextmanager
def tenant_scope(client_id: str | None) -> Iterator[Optional[TenantPaths]]:
    previous = get_active_tenant()
    if not client_id:
        _local.tenant = None
        try:
            yield None
        finally:
            _local.tenant = previous
        return
    paths = build_tenant_paths(client_id)
    _local.tenant = paths
    try:
        yield paths
    finally:
        _local.tenant = previous


def concurrent_isolation_check(client_a: str, client_b: str) -> dict:
    with tenant_scope(client_a) as a:
        db_a = resolve_db_path()
        rep_a = resolve_reports_dir()
        with tenant_scope(client_b) as b:
            db_b = resolve_db_path()
            rep_b = resolve_reports_dir()
            assert b and a
            inner_ok = db_b == b.db and rep_b == b.reports
        restored_ok = resolve_db_path() == a.db
    outer_cleared = get_active_tenant() is None
    return {
        "distinct_db": str(db_a) != str(b.db) if b else False,
        "distinct_reports": str(rep_a) != str(b.reports) if b else False,
        "nested_inner_ok": inner_ok,
        "restored_to_a": restored_ok,
        "outer_cleared": outer_cleared,
        "db_a": str(db_a),
        "db_b": str(b.db) if b else "",
    }
