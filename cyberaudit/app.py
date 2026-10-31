"""CyberAudit Flask application — static import (no exec).

3.10.9: dynamic app_body assembly removed. Implementation lives in app_impl.
"""
from __future__ import annotations

from cyberaudit.app_impl import app, socketio  # noqa: F401

__all__ = ["app", "socketio"]
