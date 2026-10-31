"""Engagement evidence pack — strengthen existing report set into one portable ZIP.

Packages whatever already exists for a session: board, client, technical,
executive PDF, network map, retest delta. Adds SHA-256 checksums so delivery
is provable. Does not invent new scan capabilities.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cyberaudit import config


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_session_artefacts(session_id: str) -> list[Path]:
    """Find report files that belong to this session under REPORTS_DIR."""
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    sid = (session_id or "").strip()
    if not sid:
        return []
    found: list[Path] = []
    for p in sorted(config.REPORTS_DIR.glob("*")):
        if not p.is_file():
            continue
        if sid in p.name:
            found.append(p)
    return found


def build_engagement_pack(
    session_id: str,
    *,
    client_name: str = "",
    target: str = "",
    extra_meta: dict[str, Any] | None = None,
) -> Path:
    """
    Write a ZIP under REPORTS_DIR:
      CyberAudit_EngagementPack_{session_id}.zip
    Contains all matching artefacts + MANIFEST.json + CHECKSUMS.sha256
    """
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    sid = (session_id or "").strip() or "unknown"
    artefacts = collect_session_artefacts(sid)
    out = config.REPORTS_DIR / f"CyberAudit_EngagementPack_{sid}.zip"

    meta = {
        "product": "CyberAudit",
        "vendor": "TrinTech Digital Defense",
        "session_id": sid,
        "client_name": client_name or "",
        "target": target or "",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "note": (
            "Point-in-time engagement pack. Not continuous monitoring. "
            "AI-assisted wording is intended for human review before client delivery."
        ),
        "files": [],
    }
    if extra_meta:
        meta["extra"] = extra_meta

    checksum_lines: list[str] = []
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in artefacts:
            if path.name.startswith("CyberAudit_EngagementPack_") and path.suffix == ".zip":
                continue
            arc = path.name
            zf.write(path, arcname=arc)
            digest = _sha256(path)
            checksum_lines.append(f"{digest}  {arc}")
            meta["files"].append(
                {
                    "name": arc,
                    "bytes": path.stat().st_size,
                    "sha256": digest,
                }
            )

        manifest_body = json.dumps(meta, indent=2, ensure_ascii=False) + "\n"
        zf.writestr("MANIFEST.json", manifest_body)
        zf.writestr("CHECKSUMS.sha256", "\n".join(checksum_lines) + ("\n" if checksum_lines else ""))

    return out


def ensure_pack_for_result(result: dict[str, Any]) -> dict[str, Any]:
    """Best-effort: attach engagement_pack path onto a completed pipeline result."""
    if not isinstance(result, dict) or result.get("status") != "completed":
        return result
    sid = result.get("session_id") or ""
    if not sid:
        return result
    try:
        pack = build_engagement_pack(
            sid,
            client_name=str(result.get("client_name") or ""),
            target=str(result.get("target") or ""),
            extra_meta={
                "findings": result.get("findings"),
                "posture_score": result.get("posture_score"),
                "posture_band": result.get("band") or result.get("posture_band"),
            },
        )
        result["engagement_pack"] = str(pack)
    except Exception as exc:
        result["engagement_pack_error"] = str(exc)[:300]
    return result
