"""Auth hardening helpers — rate limiting and optional password hashing."""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from collections import defaultdict
from threading import Lock
from typing import Optional

_attempts: dict[str, list[float]] = defaultdict(list)
_lock = Lock()

MAX_ATTEMPTS = int(os.environ.get("CYBERAUDIT_LOGIN_MAX_ATTEMPTS", "8"))
WINDOW_SECONDS = int(os.environ.get("CYBERAUDIT_LOGIN_WINDOW_SECONDS", "300"))


def _prune(key: str, now: float) -> None:
    cutoff = now - WINDOW_SECONDS
    _attempts[key] = [t for t in _attempts[key] if t >= cutoff]


def login_allowed(client_key: str) -> tuple[bool, str]:
    now = time.time()
    with _lock:
        _prune(client_key, now)
        if len(_attempts[client_key]) >= MAX_ATTEMPTS:
            return False, "too many login attempts — try again later"
        return True, "ok"


def record_login_failure(client_key: str) -> None:
    now = time.time()
    with _lock:
        _prune(client_key, now)
        _attempts[client_key].append(now)


def clear_login_failures(client_key: str) -> None:
    with _lock:
        _attempts.pop(client_key, None)


def hash_password(password: str, *, salt: Optional[bytes] = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    iterations = 200_000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, it_s, salt_hex, hash_hex = stored.split("$", 3)
            iterations = int(it_s)
            salt = bytes.fromhex(salt_hex)
            dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
            return hmac.compare_digest(dk.hex(), hash_hex)
        except Exception:
            return False
    return hmac.compare_digest(password.encode("utf-8"), stored.encode("utf-8"))


def configured_password_verifier(password: str) -> bool:
    hashed = (os.environ.get("CYBERAUDIT_PASSWORD_HASH") or "").strip()
    if hashed:
        return verify_password(password, hashed)
    from cyberaudit import config
    return verify_password(password, config.AUTH_PASSWORD or "")
