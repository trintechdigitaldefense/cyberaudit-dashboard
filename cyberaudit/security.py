"""Path safety and auth helpers."""

from __future__ import annotations

import hmac
from functools import wraps
from pathlib import Path
from typing import Optional

from flask import jsonify, redirect, request, session, url_for

from cyberaudit import config


def const_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def current_role() -> str:
    if not config.AUTH_REQUIRED:
        return "operator"
    if session.get("authenticated") is True:
        return session.get("role") or "viewer"
    return "anonymous"


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not config.AUTH_REQUIRED:
            return view(*args, **kwargs)
        if session.get("authenticated") is True:
            return view(*args, **kwargs)
        if request.path.startswith("/api/") or request.path.startswith("/download/"):
            return jsonify({"error": "unauthorized"}), 401
        return redirect(url_for("login", next=request.path))

    return wrapped


def operator_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not config.AUTH_REQUIRED:
            return view(*args, **kwargs)
        if session.get("authenticated") is not True:
            return jsonify({"error": "unauthorized"}), 401
        if current_role() != "operator":
            return jsonify({"error": "forbidden", "detail": "operator role required"}), 403
        return view(*args, **kwargs)

    return wrapped


def socket_authenticated() -> bool:
    if not config.AUTH_REQUIRED:
        return True
    return session.get("authenticated") is True


def ingest_token_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not config.INGEST_TOKEN:
            return (
                jsonify(
                    {
                        "error": "ingest_disabled",
                        "detail": "Set CYBERAUDIT_INGEST_TOKEN to enable pipeline ingest",
                    }
                ),
                503,
            )
        provided = request.headers.get("X-CyberAudit-Token", "")
        if not provided:
            auth = request.headers.get("Authorization", "")
            if auth.lower().startswith("bearer "):
                provided = auth[7:].strip()
        if not provided or not const_eq(provided, config.INGEST_TOKEN):
            return jsonify({"error": "unauthorized"}), 401
        return view(*args, **kwargs)

    return wrapped


def safe_file_under(root: Path, filename: str) -> Optional[Path]:
    if not filename or filename.strip() == "":
        return None
    if "\x00" in filename:
        return None
    candidate = (root / filename).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return candidate
