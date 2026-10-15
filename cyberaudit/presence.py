"""Operator / client presence — visibility is defense.

Tracks who is connected to the dashboard, when they connected, and when
they disconnected — down to the second.
"""
from __future__ import annotations
import threading
from datetime import datetime
from typing import Any

_lock = threading.Lock()
_active: dict[str, dict[str, Any]] = {}
_history: list[dict[str, Any]] = []
_HISTORY_MAX = 200

def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def record_connect(*, sid: str, username: str, role: str = "operator", ip: str = "", user_agent: str = "") -> dict[str, Any]:
    ts = _now()
    rec = {
        "sid": sid,
        "username": username or "unknown",
        "role": role or "operator",
        "ip": (ip or "")[:64],
        "user_agent": (user_agent or "")[:120],
        "status": "connected",
        "connected_at": ts,
        "disconnected_at": None,
    }
    with _lock:
        _active[sid] = rec
        _history.insert(0, {**rec, "event": "connected", "at": ts})
        del _history[_HISTORY_MAX:]
    return dict(rec)

def record_disconnect(sid: str) -> dict[str, Any] | None:
    ts = _now()
    with _lock:
        rec = _active.pop(sid, None)
        if not rec:
            return None
        rec = {**rec, "status": "disconnected", "disconnected_at": ts}
        _history.insert(0, {**rec, "event": "disconnected", "at": ts})
        del _history[_HISTORY_MAX:]
        return dict(rec)

def snapshot() -> dict[str, Any]:
    with _lock:
        active = sorted((dict(v) for v in _active.values()), key=lambda r: r.get("connected_at") or "", reverse=True)
        history = list(_history[:50])
    return {
        "active_count": len(active),
        "active": active,
        "history": history,
        "server_time": _now(),
        "note": "Visibility is defense — who is on the console, and when.",
    }
