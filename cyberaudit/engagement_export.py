"""Engagement evidence pack — CyberAudit 3.10 Phase 4.

Mandatory artefact validation before declaring pack ready.
SHA-256 checksums, signed MANIFEST, ZIP integrity verification.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cyberaudit import config

MANDATORY_NAME_PARTS = (
    "CyberAudit_Client_",
    "CyberAudit_Technical_",
)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_session_artefacts(session_id: str) -> list[Path]:
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


def validate_pack_contents(artefacts: list[Path], session_id: str) -> tuple[bool, list[str]]:
    names = [p.name for p in artefacts]
    missing = []
    for part in MANDATORY_NAME_PARTS:
        if not any(part in n and session_id in n for n in names):
            missing.append(f"{part}*{session_id}*")
    return (len(missing) == 0, missing)


def build_engagement_pack(
    session_id: str,
    *,
    client_name: str = "",
    target: str = "",
    extra_meta: dict[str, Any] | None = None,
    require_mandatory: bool = True,
) -> Path:
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    sid = (session_id or "").strip() or "unknown"
    artefacts = collect_session_artefacts(sid)
    out = config.REPORTS_DIR / f"CyberAudit_EngagementPack_{sid}.zip"

    ok, missing = validate_pack_contents(artefacts, sid)
    if require_mandatory and not ok:
        raise RuntimeError(
            f"engagement pack refused — mandatory artefacts missing for {sid}: {missing}"
        )

    version = getattr(config, "VERSION", None) or "3.10.0"

    meta: dict[str, Any] = {
        "product": "CyberAudit",
        "vendor": "TrinTech Digital Defense",
        "version": version,
        "session_id": sid,
        "engagement_id": sid,
        "client_name": client_name or "",
        "target": target or "",
        "scope": target or "",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "mandatory_ok": ok,
        "mandatory_missing": missing,
        "note": (
            "Point-in-time engagement pack. Not continuous monitoring. "
            "AI-assisted wording is intended for human review before client delivery."
        ),
        "files": [],
    }
    if extra_meta:
        meta["extra"] = {
            k: extra_meta[k]
            for k in ("findings", "posture_score", "posture_band", "roe", "tool_version")
            if k in extra_meta
        }
        if extra_meta.get("roe"):
            roe = extra_meta["roe"] or {}
            meta["authorization_reference"] = {
                "authorized_by": roe.get("authorized_by"),
                "valid_from": roe.get("valid_from"),
                "valid_until": roe.get("valid_until"),
                "client_name": roe.get("client_name"),
            }

    checksum_lines: list[str] = []
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in artefacts:
            if path.name.startswith("CyberAudit_EngagementPack_") and path.suffix == ".zip":
                continue
            if path.suffix.lower() == ".pdf":
                head = path.read_bytes()[:5]
                if not head.startswith(b"%PDF-"):
                    meta.setdefault("rejected_files", []).append(
                        {"name": path.name, "reason": "not a genuine PDF"}
                    )
                    continue
            arc = path.name
            zf.write(path, arcname=arc)
            digest = _sha256(path)
            checksum_lines.append(f"{digest}  {arc}")
            meta["files"].append(
                {"name": arc, "bytes": path.stat().st_size, "sha256": digest}
            )

        try:
            from cyberaudit.report_signing import sign_manifest
            meta = sign_manifest(meta)
        except Exception as exc:
            meta["sig_note"] = f"signing skipped: {exc}"[:200]

        zf.writestr("MANIFEST.json", json.dumps(meta, indent=2, ensure_ascii=False) + "\n")
        zf.writestr(
            "CHECKSUMS.sha256",
            "\n".join(checksum_lines) + ("\n" if checksum_lines else ""),
        )

    with zipfile.ZipFile(out, "r") as zf:
        bad = zf.testzip()
        if bad is not None:
            raise RuntimeError(f"engagement pack ZIP integrity failed: {bad}")

    return out


def ensure_pack_for_result(result: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(result, dict):
        return result
    sid = result.get("session_id") or ""
    if not sid:
        return result
    require = result.get("status") in ("completed", None, "")
    try:
        pack = build_engagement_pack(
            sid,
            client_name=str(result.get("client_name") or ""),
            target=str(result.get("target") or ""),
            extra_meta={
                "findings": result.get("findings"),
                "posture_score": result.get("posture_score"),
                "posture_band": result.get("band") or result.get("posture_band"),
                "roe": result.get("roe"),
            },
            require_mandatory=bool(require and result.get("status") == "completed"),
        )
        result["engagement_pack"] = str(pack)
        try:
            from cyberaudit.report_signing import verify_pack_zip
            result["engagement_pack_verify"] = verify_pack_zip(pack)
        except Exception as exc:
            result["engagement_pack_verify_error"] = str(exc)[:200]
    except Exception as exc:
        result["engagement_pack_error"] = str(exc)[:300]
        if result.get("status") == "completed":
            result["optional_failed"] = list(result.get("optional_failed") or []) + [
                "engagement_pack"
            ]
    return result
