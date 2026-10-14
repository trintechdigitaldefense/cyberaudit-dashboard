"""Role-based access control — Phase 3 feature #10.

Roles: admin (full), analyst (scan/view/remediate), viewer (read-only).
Junior operators = analyst.
"""

from __future__ import annotations

import hmac
import os
from functools import wraps

from cyberaudit import config


def const_eq(a: str, b: str) -> bool:
    if a is None or b is None:
        return False
    a, b = str(a), str(b)
    if len(a) != len(b):
        return False
    try:
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
    except Exception:
        return False


PERMISSIONS = {
    "admin": {"scan", "view", "download", "ack", "remediate", "config", "tenant", "delete", "schedule", "alerts"},
    "analyst": {"scan", "view", "download", "ack", "remediate", "schedule"},
    "viewer": {"view", "download"},
}


def _env_users() -> list[dict]:
    users = []
    if config.AUTH_USER and config.AUTH_PASSWORD:
        role = os.environ.get("CYBERAUDIT_USER_ROLE", "admin").strip().lower() or "admin"
        if role not in PERMISSIONS:
            role = "admin"
        users.append({"username": config.AUTH_USER, "password": config.AUTH_PASSWORD, "role": role})
    au = os.environ.get("CYBERAUDIT_ANALYST_USER", "").strip()
    ap = os.environ.get("CYBERAUDIT_ANALYST_PASSWORD", "").strip()
    if au and ap:
        users.append({"username": au, "password": ap, "role": "analyst"})
    vu = os.environ.get("CYBERAUDIT_VIEWER_USER", "").strip() or getattr(config, "VIEWER_USER", "")
    vp = os.environ.get("CYBERAUDIT_VIEWER_PASSWORD", "").strip() or getattr(config, "VIEWER_PASSWORD", "")
    if vu and vp:
        users.append({"username": vu, "password": vp, "role": "viewer"})
    return users


def authenticate(username: str, password: str) -> dict | None:
    username = (username or "").strip()
    password = password or ""
    for u in _env_users():
        if const_eq(u["username"], username) and const_eq(u["password"], password):
            return {"username": u["username"], "role": u["role"]}
    return None


def role_of(session_obj=None) -> str:
    if session_obj is None:
        try:
            from flask import session as flask_session
            s = flask_session
        except Exception:
            return "anonymous"
    else:
        s = session_obj
    if not config.AUTH_REQUIRED:
        return "admin"
    if s.get("authenticated") is True:
        return (s.get("role") or "viewer").lower()
    return "anonymous"


def can(permission: str, role: str | None = None) -> bool:
    r = (role or role_of()).lower()
    return permission in PERMISSIONS.get(r, set())


def require_permission(*perms: str):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            from flask import jsonify, redirect, request, session, url_for
            if not config.AUTH_REQUIRED:
                return view(*args, **kwargs)
            if session.get("authenticated") is not True:
                if request.path.startswith("/api/") or request.path.startswith("/download/"):
                    return jsonify({"error": "unauthorized"}), 401
                return redirect(url_for("login", next=request.path))
            missing = [p for p in perms if not can(p)]
            if missing:
                return jsonify({
                    "error": "forbidden",
                    "detail": f"requires permission(s): {', '.join(missing)}",
                    "role": role_of(),
                }), 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


def establish_session(user: dict) -> None:
    from flask import session
    session.clear()
    session["authenticated"] = True
    session["username"] = user["username"]
    session["role"] = user["role"]
    session.permanent = True
