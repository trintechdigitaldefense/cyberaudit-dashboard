"""Background workers: demo simulator, inbox poller, retention."""

from __future__ import annotations

import json
import logging
import random
import time
from pathlib import Path

from cyberaudit import config
from cyberaudit.db import (
    insert_live_event,
    prune_old_events,
    upsert_audit_session,
    upsert_module_status,
)

logger = logging.getLogger("CyberAuditDashboard")

_simulator_running = False


def process_inbox_file(path: Path) -> bool:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.error("Inbox parse failed %s: %s", path.name, exc)
        return False
    kind = (data.get("type") or data.get("kind") or "event").lower()
    try:
        if kind in ("event", "live_event", "alert"):
            insert_live_event(
                module=data.get("module") or path.stem,
                message=data.get("message") or data.get("msg") or "",
                severity=data.get("severity") or "info",
                event_type=data.get("event_type") or "info",
                details=data.get("details"),
                timestamp=data.get("timestamp"),
            )
        elif kind in ("module", "module_status"):
            upsert_module_status(
                module_name=data.get("module_name") or data.get("module") or "",
                status=data.get("status") or "idle",
                last_result=data.get("last_result") or data.get("result") or "",
                version=data.get("version") or "",
                last_run=data.get("last_run"),
            )
        elif kind in ("session", "audit_session"):
            upsert_audit_session(data)
        else:
            logger.warning("Unknown inbox type %s in %s", kind, path.name)
            return False
        return True
    except Exception as exc:
        logger.error("Inbox apply failed %s: %s", path.name, exc)
        return False


def live_feed_simulator() -> None:
    global _simulator_running
    _simulator_running = True
    modules = [
        "continuous_ids_module",
        "data_exfiltration_module",
        "regional_threat_intel",
        "nmap_module",
        "openvas_module",
    ]
    severities = ["info", "low", "medium", "high", "critical"]
    messages = [
        "Behavioral baseline deviation detected",
        "New service version fingerprint matched CVE database",
        "Outbound connection to known C2 range blocked",
        "Compliance check against CMA Section 6 completed",
        "TT-CSIRT feed update received",
        "Anomalous DNS query pattern observed",
        "Session archival complete",
    ]
    while _simulator_running:
        time.sleep(random.uniform(4.0, 11.0))
        if not config.DEMO_MODE:
            break
        try:
            insert_live_event(
                module=random.choice(modules),
                message=random.choice(messages),
                severity=random.choices(severities, weights=[40, 25, 20, 10, 5])[0],
                details={"sim": True, "source": "dashboard_simulator"},
            )
        except Exception as exc:
            logger.error("Simulator insert failed: %s", exc)


def inbox_poller() -> None:
    logger.info("Inbox poller watching %s", config.INBOX_DIR)
    while True:
        try:
            for path in sorted(config.INBOX_DIR.glob("*.json")):
                if not path.is_file():
                    continue
                ok = process_inbox_file(path)
                dest_dir = config.INBOX_DIR / ("processed" if ok else "failed")
                dest = dest_dir / f"{path.stem}_{int(time.time())}{path.suffix}"
                try:
                    path.rename(dest)
                except Exception:
                    try:
                        path.unlink()
                    except Exception:
                        pass
        except Exception as exc:
            logger.error("Inbox poller error: %s", exc)
        time.sleep(max(1.0, config.INBOX_POLL_SECONDS))


def retention_worker() -> None:
    while True:
        try:
            n = prune_old_events()
            if n:
                logger.info("Pruned %s live_events", n)
        except Exception as exc:
            logger.error("Retention error: %s", exc)
        time.sleep(max(60, config.RETENTION_INTERVAL_SECONDS))
