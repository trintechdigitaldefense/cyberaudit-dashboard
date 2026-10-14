"""C8 — Opt-in anonymized usage telemetry. No client data."""
from __future__ import annotations
import json, logging, os, sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any
from cyberaudit import config
logger = logging.getLogger("CyberAuditDashboard")

def telemetry_enabled() -> bool:
    try:
        from cyberaudit.airgap import airgap_enabled
        if airgap_enabled(): return False
    except Exception:
        pass
    return os.environ.get("CYBERAUDIT_TELEMETRY", "").strip().lower() in ("1", "true", "yes", "on")

def _db() -> Path:
    return config.DATA_DIR / "telemetry.db"

def init_telemetry() -> None:
    if not telemetry_enabled(): return
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_db()))
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, event TEXT, module TEXT, meta TEXT)")
        conn.commit()
    finally:
        conn.close()

def track(event: str, module: str = "", meta: dict | None = None) -> None:
    if not telemetry_enabled(): return
    init_telemetry()
    safe = {k: v for k, v in (meta or {}).items() if k.lower() not in ("host", "ip", "email", "target", "client_name", "password")}
    conn = sqlite3.connect(str(_db()))
    try:
        conn.execute("INSERT INTO events (ts, event, module, meta) VALUES (?,?,?,?)",
                     (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), event[:64], module[:64], json.dumps(safe)[:500]))
        conn.commit()
    finally:
        conn.close()

def summary() -> dict[str, Any]:
    if not _db().is_file():
        return {"enabled": telemetry_enabled(), "events": 0}
    conn = sqlite3.connect(str(_db()))
    try:
        n = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        top = conn.execute("SELECT event, COUNT(*) c FROM events GROUP BY event ORDER BY c DESC LIMIT 10").fetchall()
    finally:
        conn.close()
    return {"enabled": telemetry_enabled(), "events": n, "top_events": [{"event": r[0], "count": r[1]} for r in top],
            "note": "Anonymized module usage only — no client data"}
