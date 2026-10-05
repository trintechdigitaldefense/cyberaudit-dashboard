#!/usr/bin/env python3
"""CyberAudit Dashboard v2.4.0-p3 entrypoint."""
from cyberaudit.app import app, socketio, ensure_workers
from cyberaudit import config

if __name__ == "__main__":
    ensure_workers()
    print("=" * 60)
    print(f"  CyberAudit {config.COMPANY['version']}")
    print(f"  http://{config.HOST}:{config.PORT}")
    print("=" * 60)
    socketio.run(
        app,
        host=config.HOST,
        port=config.PORT,
        debug=False,
        allow_unsafe_werkzeug=True,
    )
else:
    ensure_workers()
