"""Report and engagement-pack signing — CyberAudit 3.10 Phase 4.

HMAC-SHA256 signatures over manifest canonical JSON so delivery is verifiable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any


def _secret() -> bytes:
    raw = (
        os.environ.get("CYBERAUDIT_REPORT_SECRET")
        or os.environ.get("CYBERAUDIT_ROE_SECRET")
        or os.environ.get("CYBERAUDIT_SECRET")
        or ""
    ).strip()
    return raw.encode("utf-8") if raw else b""


def canonical_json(data: dict[str, Any]) -> bytes:
    payload = {k: v for k, v in data.items() if k not in ("signature", "sig", "sig_alg")}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sign_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    secret = _secret()
    out = dict(manifest)
    out.pop("signature", None)
    out.pop("sig", None)
    out.pop("sig_alg", None)
    if not secret:
        out["signature"] = ""
        out["sig_alg"] = "none"
        out["sig_note"] = "No CYBERAUDIT_SECRET configured — pack unsigned"
        return out
    sig = hmac.new(secret, canonical_json(out), hashlib.sha256).hexdigest()
    out["signature"] = sig
    out["sig_alg"] = "HMAC-SHA256"
    return out


def verify_manifest(manifest: dict[str, Any]) -> tuple[bool, str]:
    secret = _secret()
    if not secret:
        return False, "no signing secret configured"
    provided = (manifest.get("signature") or "").strip()
    if not provided:
        return False, "signature missing"
    expected = hmac.new(secret, canonical_json(manifest), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, provided):
        return False, "signature invalid"
    return True, "signature ok"


def secret_configured() -> bool:
    return bool(_secret())


def verify_pack_zip(path: Path | str) -> dict[str, Any]:
    import zipfile

    p = Path(str(path))
    result: dict[str, Any] = {
        "path": str(p),
        "ok": False,
        "zip_ok": False,
        "manifest_ok": False,
        "checksums_ok": False,
        "signature_ok": False,
        "errors": [],
    }
    if not p.is_file():
        result["errors"].append("file missing")
        return result
    try:
        with zipfile.ZipFile(p, "r") as zf:
            bad = zf.testzip()
            if bad is not None:
                result["errors"].append(f"corrupt member: {bad}")
                return result
            result["zip_ok"] = True
            names = set(zf.namelist())
            if "MANIFEST.json" not in names:
                result["errors"].append("MANIFEST.json missing")
                return result
            manifest = json.loads(zf.read("MANIFEST.json").decode("utf-8"))
            result["manifest"] = manifest
            result["manifest_ok"] = True

            if "CHECKSUMS.sha256" in names:
                lines = zf.read("CHECKSUMS.sha256").decode("utf-8").strip().splitlines()
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    digest, name = parts[0], parts[-1]
                    if name not in names:
                        result["errors"].append(f"checksum target missing: {name}")
                        continue
                    h = hashlib.sha256(zf.read(name)).hexdigest()
                    if not hmac.compare_digest(h, digest):
                        result["errors"].append(f"checksum mismatch: {name}")
                if not any("checksum mismatch" in e for e in result["errors"]):
                    result["checksums_ok"] = True
            else:
                result["errors"].append("CHECKSUMS.sha256 missing")

            ok_sig, reason = verify_manifest(manifest)
            result["signature_ok"] = ok_sig
            result["signature_reason"] = reason
            if not ok_sig and secret_configured():
                result["errors"].append(f"signature: {reason}")

            result["ok"] = (
                result["zip_ok"]
                and result["manifest_ok"]
                and result["checksums_ok"]
                and (result["signature_ok"] or not secret_configured())
            )
    except Exception as exc:
        result["errors"].append(str(exc)[:300])
    return result
