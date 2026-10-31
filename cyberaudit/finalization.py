"""Transactional audit finalization — CyberAudit 3.10 Phase 4/5.

An audit is completed only when mandatory deliverables exist and validate.
Missing mandatory artefacts → status failed (never silent success).
"""

from __future__ import annotations

import logging
import zipfile
from pathlib import Path
from typing import Any

from cyberaudit import config
from cyberaudit.db import get_db

logger = logging.getLogger("CyberAuditDashboard")

MANDATORY_KEYS = ("executive_txt", "technical_txt")
OPTIONAL_KEYS = ("executive_html", "executive_pdf", "board_summary", "network_map", "engagement_pack")


def _is_valid_file(path: Path | str | None, *, min_bytes: int = 16) -> bool:
    if not path:
        return False
    p = Path(str(path))
    try:
        return p.is_file() and p.stat().st_size >= min_bytes
    except OSError:
        return False


def _is_valid_pdf(path: Path | str | None) -> bool:
    if not _is_valid_file(path, min_bytes=32):
        return False
    try:
        head = Path(str(path)).read_bytes()[:5]
        return head.startswith(b"%PDF-")
    except OSError:
        return False


def _is_valid_zip(path: Path | str | None) -> bool:
    if not _is_valid_file(path, min_bytes=32):
        return False
    try:
        with zipfile.ZipFile(str(path), "r") as zf:
            return zf.testzip() is None
    except Exception:
        return False


def validate_deliverables(result: dict[str, Any]) -> tuple[bool, list[str], list[str]]:
    missing: list[str] = []
    optional_failed: list[str] = []

    if not (_is_valid_file(result.get("executive_txt")) or _is_valid_file(result.get("report"))):
        missing.append("executive_txt")
    if not (_is_valid_file(result.get("technical_txt")) or _is_valid_file(result.get("report_technical"))):
        missing.append("technical_txt")

    pdf = result.get("executive_pdf")
    if pdf:
        if not _is_valid_pdf(pdf):
            optional_failed.append("executive_pdf_invalid")
    elif result.get("pdf_optional_failed") or result.get("pdf_error"):
        optional_failed.append("executive_pdf_missing")

    pack = result.get("engagement_pack")
    if pack and not _is_valid_zip(pack):
        optional_failed.append("engagement_pack_invalid")

    return (len(missing) == 0, missing, optional_failed)


def finalize_audit_result(
    result: dict[str, Any],
    *,
    session_id: str | None = None,
    job_id: str | None = None,
) -> dict[str, Any]:
    sid = session_id or result.get("session_id")
    jid = job_id or result.get("job_id")
    ok, missing, optional_failed = validate_deliverables(result)

    result = dict(result)
    result["optional_failed"] = optional_failed
    result["mandatory_missing"] = missing

    if not ok:
        result["status"] = "failed"
        result["error"] = f"mandatory deliverables missing: {', '.join(missing)}"
        _sync_status(sid, jid, "failed", result.get("error"))
        logger.error("finalization failed session=%s: %s", sid, result["error"])
        return result

    result["status"] = "completed"
    if optional_failed:
        result["completion_notes"] = f"completed with optional failures: {', '.join(optional_failed)}"
    _sync_status(sid, jid, "completed", result.get("completion_notes") or "")
    return result


def _sync_status(session_id: str | None, job_id: str | None, status: str, note: str = "") -> None:
    try:
        with get_db() as conn:
            if session_id:
                conn.execute(
                    "UPDATE audit_sessions SET status=?, notes=COALESCE(notes,'') || ? WHERE session_id=?",
                    (status, f" | finalization:{note}" if note else "", session_id),
                )
            if job_id:
                try:
                    conn.execute("UPDATE audit_jobs SET status=? WHERE job_id=?", (status, job_id))
                except Exception:
                    pass
            conn.commit()
    except Exception as exc:
        logger.error("status sync failed: %s", exc)
