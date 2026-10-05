#!/usr/bin/env python3
"""
Minimal helper for CyberAudit modules to push status/events into the dashboard.

Usage from nmap_module / openvas_module / etc.:

    from pipeline_client_example import CyberAuditClient
    client = CyberAuditClient()
    client.event("nmap_module", "Scan complete for 192.168.10.0/24", severity="info")
    client.module("nmap_module", status="idle", last_result="22 ports open")
    client.session({...})

Or drop JSON files into CYBERAUDIT_INBOX_DIR (default data/inbox/*.json).
"""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from typing import Any, Optional


class CyberAuditClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        inbox_dir: Optional[str] = None,
    ):
        self.base_url = (
            base_url or os.environ.get("CYBERAUDIT_DASHBOARD_URL", "http://127.0.0.1:1881")
        ).rstrip("/")
        self.token = token or os.environ.get("CYBERAUDIT_INGEST_TOKEN", "")
        self.inbox_dir = Path(
            inbox_dir or os.environ.get("CYBERAUDIT_INBOX_DIR", "data/inbox")
        )

    def _post(self, path: str, payload: dict) -> dict:
        if not self.token:
            return self._drop(path, payload)
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={
                "Content-Type": "application/json",
                "X-CyberAudit-Token": self.token,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _drop(self, path: str, payload: dict) -> dict:
        self.inbox_dir.mkdir(parents=True, exist_ok=True)
        kind = {
            "/api/ingest/event": "event",
            "/api/ingest/module": "module",
            "/api/ingest/session": "session",
        }.get(path, "event")
        body = {"type": kind, **payload}
        name = f"{kind}_{os.getpid()}_{payload.get('module') or payload.get('module_name') or 'x'}.json"
        dest = self.inbox_dir / name.replace(" ", "_")
        dest.write_text(json.dumps(body), encoding="utf-8")
        return {"ok": True, "dropped": str(dest)}

    def event(
        self,
        module: str,
        message: str,
        severity: str = "info",
        event_type: str = "info",
        details: Any = None,
    ) -> dict:
        return self._post(
            "/api/ingest/event",
            {
                "module": module,
                "message": message,
                "severity": severity,
                "event_type": event_type,
                "details": details or {},
            },
        )

    def module(
        self,
        module_name: str,
        status: str = "idle",
        last_result: str = "",
        version: str = "",
    ) -> dict:
        return self._post(
            "/api/ingest/module",
            {
                "module_name": module_name,
                "status": status,
                "last_result": last_result,
                "version": version,
            },
        )

    def session(self, payload: dict) -> dict:
        return self._post("/api/ingest/session", payload)
