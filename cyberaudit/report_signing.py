"""Report and engagement-pack signing — CyberAudit 3.10.6.

Uses ONLY CYBERAUDIT_REPORT_SECRET. Never falls back to ROE or app secret.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import zipfile
from pathlib import Path
from typing import Any


def _secret() -> bytes:
    raw = (os.environ.get("CYBERAUDIT_REPORT_SECRET") or "").strip()
    return raw.encode("utf-8") if raw else b""


def production_requires_report_secret() -> bool:
    try:
        from cyberaudit import config
        return not bool(getattr(config, "DEMO_MODE", False))
    except Exception:
        return True


def secret_configured() -> bool:
    return bool(_secret())


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
        if production_requires_report_secret():
            raise RuntimeError(
                "CYBERAUDIT_REPORT_SECRET required to sign production evidence packs"
            )
        out["signature"] = ""
        out["sig_alg"] = "none"
        out["sig_note"] = "No CYBERAUDIT_REPORT_SECRET — pack unsigned (demo only)"
        return out
    sig = hmac.new(secret, canonical_json(out), hashlib.sha256).hexdigest()
    out["signature"] = sig
    out["sig_alg"] = "HMAC-SHA256"
    return out


def verify_manifest(manifest: dict[str, Any]) -> tuple[bool, str]:
    secret = _secret()
    if not secret:
        return False, "no CYBERAUDIT_REPORT_SECRET configured"
    provided = (manifest.get("signature") or "").strip()
    if not provided:
        return False, "signature missing"
    alg = (manifest.get("sig_alg") or "").strip()
    if alg and alg != "HMAC-SHA256":
        return False, f"unexpected sig_alg: {alg}"
    expected = hmac.new(secret, canonical_json(manifest), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, provided):
        return False, "signature invalid"
    return True, "ok"


def verify_pack_zip(path: Path | str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ok": False,
        "zip_ok": False,
        "manifest_ok": False,
        "checksums_ok": False,
        "signature_ok": False,
        "errors": [],
    }
    p = Path(path)
    if not p.is_file():
        result["errors"].append("file missing")
        return result
    try:
        with zipfile.ZipFile(str(p), "r") as zf:
            bad = zf.testzip()
            if bad is not None:
                result["errors"].append(f"corrupt member: {bad}")
                return result
            result["zip_ok"] = True
            names = zf.namelist()
            for n in names:
                if n.startswith("/") or ".." in n.replace("\\\\", "/").split("/"):
                    result["errors"].append(f"path traversal: {n}")
                    return result
            if len(names) != len(set(names)):
                result["errors"].append("duplicate zip member names")
                return result
            if "MANIFEST.json" not in names:
                result["errors"].append("MANIFEST.json missing")
                return result
            meta = json.loads(zf.read("MANIFEST.json").decode("utf-8"))
            result["manifest_ok"] = True
            ok_sig, reason = verify_manifest(meta)
            result["signature_ok"] = ok_sig
            if not ok_sig:
                result["errors"].append(f"signature: {reason}")

            checksums: dict[str, str] = {}
            if "CHECKSUMS.sha256" in names:
                for line in zf.read("CHECKSUMS.sha256").decode("utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) < 2:
                        result["errors"].append(f"malformed checksum line: {line[:80]}")
                        continue
                    digest, fname = parts[0], parts[-1]
                    if fname in checksums:
                        result["errors"].append(f"duplicate checksum: {fname}")
                    checksums[fname] = digest

            payload_names = [n for n in names if n not in ("MANIFEST.json", "CHECKSUMS.sha256")]
            manifest_files = [f.get("name") for f in (meta.get("files") or []) if f.get("name")]

            for n in payload_names:
                if n not in checksums:
                    result["errors"].append(f"missing checksum for {n}")
                else:
                    raw = zf.read(n)
                    digest = hashlib.sha256(raw).hexdigest()
                    if digest != checksums[n]:
                        result["errors"].append(f"checksum mismatch: {n}")
                if n not in manifest_files:
                    result["errors"].append(f"archive member not in manifest: {n}")

            for n in manifest_files:
                if n not in payload_names:
                    result["errors"].append(f"manifest file missing from archive: {n}")
                if n not in checksums:
                    result["errors"].append(f"manifest file missing checksum: {n}")

            result["checksums_ok"] = not any(
                e.startswith("missing checksum")
                or e.startswith("checksum mismatch")
                or e.startswith("duplicate checksum")
                or e.startswith("malformed checksum")
                or e.startswith("manifest file missing")
                or e.startswith("archive member not")
                for e in result["errors"]
            )
            result["ok"] = (
                result["zip_ok"]
                and result["manifest_ok"]
                and result["checksums_ok"]
                and result["signature_ok"]
                and not [e for e in result["errors"] if not e.startswith("signature")]
            )
            if result["signature_ok"]:
                result["errors"] = [e for e in result["errors"] if not e.startswith("signature")]
                result["ok"] = (
                    result["zip_ok"]
                    and result["manifest_ok"]
                    and result["checksums_ok"]
                    and result["signature_ok"]
                    and not result["errors"]
                )
    except zipfile.BadZipFile as exc:
        result["errors"].append(f"bad zip: {exc}")
    except Exception as exc:
        result["errors"].append(str(exc)[:200])
    return result
