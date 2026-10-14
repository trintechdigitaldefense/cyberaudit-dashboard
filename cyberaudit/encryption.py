"""Encrypted data at rest — Phase 3 feature #12. AES-256-GCM."""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from pathlib import Path
from typing import Optional

logger = logging.getLogger("CyberAuditDashboard")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    _HAS_CRYPTO = True
except ImportError:
    AESGCM = None  # type: ignore
    Scrypt = None  # type: ignore
    _HAS_CRYPTO = False


def _derive_key(material: str) -> bytes:
    material = (material or "").strip()
    if not material:
        raise ValueError("CYBERAUDIT_DATA_KEY is empty")
    if len(material) == 64 and all(c in "0123456789abcdefABCDEF" for c in material):
        return bytes.fromhex(material)
    if not _HAS_CRYPTO:
        return hashlib.sha256(material.encode("utf-8")).digest()
    kdf = Scrypt(salt=b"cyberaudit-v1-salt", length=32, n=2**14, r=8, p=1)
    return kdf.derive(material.encode("utf-8"))


def get_data_key() -> Optional[bytes]:
    raw = os.environ.get("CYBERAUDIT_DATA_KEY", "").strip()
    if not raw:
        return None
    try:
        return _derive_key(raw)
    except Exception as exc:
        logger.error("data key derive failed: %s", exc)
        return None


def encrypt_bytes(plaintext: bytes, key: bytes | None = None) -> bytes:
    key = key or get_data_key()
    if not key:
        raise RuntimeError("encryption requested but CYBERAUDIT_DATA_KEY not set")
    if not _HAS_CRYPTO:
        raise RuntimeError("pip install cryptography for AES-256-GCM")
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return b"CAE1" + nonce + ct


def decrypt_bytes(blob: bytes, key: bytes | None = None) -> bytes:
    key = key or get_data_key()
    if not key:
        raise RuntimeError("CYBERAUDIT_DATA_KEY required to decrypt")
    if not _HAS_CRYPTO:
        raise RuntimeError("pip install cryptography for AES-256-GCM")
    if not blob.startswith(b"CAE1") or len(blob) < 16:
        raise ValueError("not a CyberAudit encrypted blob")
    nonce, ct = blob[4:16], blob[16:]
    return AESGCM(key).decrypt(nonce, ct, None)


def encrypt_file(path: Path, *, delete_plaintext: bool = True) -> Path:
    path = Path(path)
    enc = encrypt_bytes(path.read_bytes())
    out = path.with_suffix(path.suffix + ".cae")
    out.write_bytes(enc)
    if delete_plaintext:
        secure_delete(path)
    return out


def decrypt_file(path: Path, dest: Path | None = None) -> Path:
    path = Path(path)
    plain = decrypt_bytes(path.read_bytes())
    dest = dest or Path(str(path).removesuffix(".cae"))
    dest.write_bytes(plain)
    return dest


def secure_delete(path: Path, passes: int = 3) -> None:
    path = Path(path)
    if not path.is_file():
        return
    try:
        size = path.stat().st_size
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        path.unlink(missing_ok=True)
    except Exception as exc:
        logger.warning("secure_delete %s: %s", path, exp if False else exc)
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass


def encryption_status() -> dict:
    key = get_data_key()
    return {
        "crypto_library": _HAS_CRYPTO,
        "key_configured": key is not None,
        "algorithm": "AES-256-GCM" if _HAS_CRYPTO else "unavailable",
        "note": "Set CYBERAUDIT_DATA_KEY to a 64-char hex or passphrase. Encrypted reports use .cae suffix.",
    }
