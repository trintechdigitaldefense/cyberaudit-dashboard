"""Phase 4 — A-class hardening (H1–H10)."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional

from cyberaudit import config

logger = logging.getLogger("CyberAuditDashboard")

_WEAK_PASSWORDS = {
    "admin", "password", "password1", "123456", "12345678", "changeme",
    "cyberaudit", "trintech", "letmein", "default", "root", "toor", "pass",
}


def assert_production_secrets() -> None:
    if config.DEMO_MODE:
        return
    problems: list[str] = []
    sec = os.environ.get("CYBERAUDIT_SECRET", "").strip()
    if not sec:
        problems.append("CYBERAUDIT_SECRET is missing")
    elif len(sec) < 32:
        problems.append("CYBERAUDIT_SECRET must be at least 32 characters")
    pw = (config.AUTH_PASSWORD or "").strip()
    if not pw:
        problems.append("CYBERAUDIT_PASSWORD is empty")
    elif pw.lower() in _WEAK_PASSWORDS:
        problems.append(f"CYBERAUDIT_PASSWORD is a known-weak default ({pw!r}) — refuse to start")
    elif len(pw) < 12:
        problems.append("CYBERAUDIT_PASSWORD must be at least 12 characters in production")
    if (config.AUTH_USER or "").strip().lower() == "admin" and pw.lower() == "admin":
        problems.append("admin/admin is forbidden in production (H5)")
    host = (config.HOST or "").strip()
    if host in ("0.0.0.0", "::") and not os.environ.get("CYBERAUDIT_ALLOW_BIND_ALL"):
        problems.append("Binding 0.0.0.0 without CYBERAUDIT_ALLOW_BIND_ALL=1 is refused")
    if problems:
        raise SystemExit("FATAL: production secrets gate failed:\n  - " + "\n  - ".join(problems))


SESSION_TTL_SECONDS = int(os.environ.get("CYBERAUDIT_SESSION_TTL", "28800"))


def configure_session_security(app) -> None:
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["PERMANENT_SESSION_LIFETIME"] = SESSION_TTL_SECONDS
    app.config["SESSION_REFRESH_EACH_REQUEST"] = True
    if config.COOKIE_SECURE or os.environ.get("CYBERAUDIT_COOKIE_SECURE", "").lower() in ("1", "true", "yes"):
        app.config["SESSION_COOKIE_SECURE"] = True


_rate_lock = threading.Lock()
_rate_buckets: dict[str, list[float]] = defaultdict(list)


def rate_limit(key: str, max_calls: int, window_seconds: float) -> bool:
    now = time.time()
    with _rate_lock:
        bucket = _rate_buckets[key]
        cutoff = now - window_seconds
        _rate_buckets[key] = [t for t in bucket if t >= cutoff]
        if len(_rate_buckets[key]) >= max_calls:
            return False
        _rate_buckets[key].append(now)
        return True


def rate_limited(max_calls: int = 10, window_seconds: float = 60.0):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            from flask import jsonify, request
            ident = request.remote_addr or "unknown"
            if not rate_limit(f"{view.__name__}:{ident}", max_calls, window_seconds):
                return jsonify({"error": "rate_limited", "retry_after": window_seconds}), 429
            return view(*args, **kwargs)
        return wrapped
    return decorator


_TARGET_RE = re.compile(r"^[\w\.\-:/,\[\] ]{1,512}$")
_CLIENT_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9 _\-\.]{0,127}$")
_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


def validate_target(target: str) -> str:
    target = (target or "").strip()
    if not target:
        raise ValueError("target is required")
    if len(target) > 512:
        raise ValueError("target too long")
    if not _TARGET_RE.match(target):
        raise ValueError("target contains invalid characters")
    for bad in ("..", "`", "$(", "|", "&", ";", ">", "<", "\n", "\r", "\x00"):
        if bad in target:
            raise ValueError("target contains forbidden sequence")
    return target


def validate_client_name(name: str) -> str:
    name = (name or "").strip()
    if not name:
        return ""
    if not _CLIENT_RE.match(name):
        raise ValueError("client_name invalid")
    return name


def validate_job_payload(job: dict) -> dict:
    if not isinstance(job, dict):
        raise ValueError("job must be a JSON object")
    out = dict(job)
    out["target"] = validate_target(str(job.get("target") or ""))
    if "client_name" in job or "client" in job:
        out["client_name"] = validate_client_name(str(job.get("client_name") or job.get("client") or ""))
    sector = str(job.get("sector") or job.get("industry") or "general").strip().lower()
    if sector not in ("general", "retail", "finance", "healthcare", "education"):
        raise ValueError("sector must be general|retail|finance|healthcare|education")
    out["sector"] = sector
    if job.get("job_id"):
        jid = str(job["job_id"])
        if not _ID_RE.match(jid):
            raise ValueError("job_id invalid")
        out["job_id"] = jid
    for k in list(out.keys()):
        if k.endswith("_password") or k.endswith("_key"):
            if len(str(out[k] or "")) > 512:
                raise ValueError(f"{k} too long")
    return out


def _audit_db_path() -> Path:
    return config.DATA_DIR / "audit_log.db"


def init_audit_log() -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_audit_db_path()))
    try:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL, username TEXT, role TEXT, action TEXT NOT NULL,
                detail TEXT, ip TEXT, prev_hash TEXT, entry_hash TEXT NOT NULL)"""
        )
        conn.commit()
    finally:
        conn.close()


def _last_hash(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    return row[0] if row else "GENESIS"


def audit_event(action: str, *, username: str = "", role: str = "", detail: str | dict | None = None, ip: str = "") -> str:
    init_audit_log()
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    detail_s = json.dumps(detail, sort_keys=True, default=str)[:2000] if isinstance(detail, dict) else str(detail or "")[:2000]
    conn = sqlite3.connect(str(_audit_db_path()))
    try:
        prev = _last_hash(conn)
        material = f"{prev}|{ts}|{username}|{role}|{action}|{detail_s}|{ip}"
        entry_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()
        conn.execute(
            "INSERT INTO audit_log (ts, username, role, action, detail, ip, prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?,?)",
            (ts, username, role, action, detail_s, ip, prev, entry_hash),
        )
        conn.commit()
        return entry_hash
    finally:
        conn.close()


def verify_audit_chain() -> tuple[bool, str]:
    init_audit_log()
    conn = sqlite3.connect(str(_audit_db_path()))
    try:
        rows = conn.execute(
            "SELECT id, ts, username, role, action, detail, ip, prev_hash, entry_hash FROM audit_log ORDER BY id ASC"
        ).fetchall()
        prev = "GENESIS"
        for row in rows:
            material = f"{prev}|{row[1]}|{row[2]}|{row[3]}|{row[4]}|{row[5]}|{row[6]}"
            expect = hashlib.sha256(material.encode("utf-8")).hexdigest()
            if row[7] != prev:
                return False, f"prev_hash mismatch at id={row[0]}"
            if row[8] != expect:
                return False, f"entry_hash mismatch at id={row[0]}"
            prev = row[8]
        return True, f"ok ({len(rows)} entries)"
    finally:
        conn.close()


CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self' ws: wss:; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)


def apply_security_headers(response):
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["X-XSS-Protection"] = "0"
    if not config.DEMO_MODE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def generate_csrf_token(session_obj) -> str:
    token = session_obj.get("_csrf")
    if not token:
        token = secrets.token_hex(32)
        session_obj["_csrf"] = token
    return token


def validate_csrf(session_obj, token: str | None) -> bool:
    expected = session_obj.get("_csrf") or ""
    provided = (token or "").strip()
    if not expected or not provided:
        return False
    return hmac.compare_digest(expected, provided)


def csrf_protect(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        from flask import jsonify, request, session
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if request.headers.get("X-CyberAudit-Token") or request.headers.get("Authorization", "").lower().startswith("bearer "):
                return view(*args, **kwargs)
            token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
            if not validate_csrf(session, token):
                return jsonify({"error": "csrf_failed"}), 400
        return view(*args, **kwargs)
    return wrapped


def tls_status() -> dict:
    return {
        "cookie_secure": bool(config.COOKIE_SECURE),
        "demo_mode": config.DEMO_MODE,
        "recommendation": "Terminate TLS at nginx/caddy; set CYBERAUDIT_COOKIE_SECURE=1 and HOST=127.0.0.1",
        "bind_host": config.HOST,
    }


def dependency_audit_hint() -> dict:
    return {
        "command": "pip-audit -r requirements.txt",
        "ci_note": "Run pip-audit in CI before merge; pin versions",
    }


def fail_safe_job(fn: Callable, job: dict, *, cleanup: Callable | None = None) -> dict:
    try:
        return fn(job)
    except Exception as exc:
        logger.exception("fail-safe caught job error: %s", exc)
        try:
            if cleanup:
                cleanup(job, exc)
        except Exception as cexc:
            logger.error("cleanup failed: %s", cexc)
        return {
            "status": "failed",
            "error": str(exc)[:500],
            "job_id": job.get("job_id"),
            "target": job.get("target"),
        }
