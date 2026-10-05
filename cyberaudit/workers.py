"""Background workers: demo simulator, inbox poller, retention."""

from __future__ import annotations

import datetime
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


_ALWAYS_ON = (
    "continuous_ids_module",
    "data_exfiltration_module",
    "regional_threat_intel",
)
_BATCH = (
    "nmap_module",
    "openvas_module",
    "tt_compliance_mapper",
    "patch_verification_module",
    "pdf_report_module",
    "incident_response_module",
    "database_module",
    "diagnostics_module",
)
_ALL_MODULES = _ALWAYS_ON + _BATCH

_MODULE_RESULTS = {
    "nmap_module": [
        "Ports 22,80,443 open - service versions collected",
        "Discovery complete: 24 hosts up on target range",
        "SYN scan finished - 3 unexpected services flagged",
    ],
    "openvas_module": [
        "3 high, 7 medium findings published",
        "GVM scan finished - CVE enrichment complete",
        "Vulnerability scorecard updated for session",
    ],
    "tt_compliance_mapper": [
        "Mapped findings to CMA Sections 3, 6, 7",
        "Statutory risk matrix regenerated",
        "Compliance score recalculated",
    ],
    "regional_threat_intel": [
        "TT-CSIRT advisory ingested",
        "CARICOM IMPACS feed refresh OK",
        "IOC match against regional C2 list",
    ],
    "patch_verification_module": [
        "Baseline drift: 2 packages pending",
        "Patch verification passed for critical hosts",
        "Remediation lag report generated",
    ],
    "pdf_report_module": [
        "Executive PDF report rendered",
        "Report package staged in reports/",
        "Client summary exported",
    ],
    "incident_response_module": [
        "No active containment jobs",
        "Playbook PB-IR-001 staged",
        "IR queue idle - ready",
    ],
    "data_exfiltration_module": [
        "Outbound flow baseline within thresholds",
        "Anomalous DNS tunnel candidate blocked",
        "Monitoring egress on 3 interfaces",
    ],
    "continuous_ids_module": [
        "Log analysis active - 0 critical alerts",
        "Behavioral anomaly score normal",
        "Syslog ingest healthy",
    ],
    "database_module": [
        "Session archived to SQLite",
        "WAL checkpoint complete",
        "Audit history indexed",
    ],
    "diagnostics_module": [
        "All binaries OK",
        "Dependency check passed",
        "Self-heal: no repairs needed",
    ],
}


def activate_demo_pipeline() -> None:
    """Refresh all 11 modules with live timestamps so UI is not stuck idle."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for name in _ALWAYS_ON:
        upsert_module_status(
            module_name=name,
            status="running",
            last_result=random.choice(_MODULE_RESULTS.get(name, ["Active"])),
            last_run=now,
            version="",
        )
    for name in _BATCH:
        upsert_module_status(
            module_name=name,
            status=random.choice(["idle", "ok", "idle"]),
            last_result=random.choice(_MODULE_RESULTS.get(name, ["Ready"])),
            last_run=now,
            version="",
        )
    logger.info("Demo pipeline activated - sensors running, batch modules ready")


def live_feed_simulator() -> None:
    global _simulator_running
    _simulator_running = True
    activate_demo_pipeline()
    severities = ["info", "low", "medium", "high", "critical"]
    messages = [
        "Behavioral baseline deviation detected",
        "New service version fingerprint matched CVE database",
        "Outbound connection to known C2 range blocked",
        "Compliance check against CMA Section 6 completed",
        "TT-CSIRT feed update received",
        "Anomalous DNS query pattern observed",
        "Session archival complete",
        "Patch drift detected on critical host",
        "Playbook trigger acknowledged",
        "GVM socket health check OK",
    ]
    tick = 0
    while _simulator_running:
        time.sleep(random.uniform(3.5, 8.0))
        if not config.DEMO_MODE:
            break
        tick += 1
        try:
            mod = random.choice(_ALL_MODULES)
            sev = random.choices(severities, weights=[35, 25, 22, 12, 6])[0]
            insert_live_event(
                module=mod,
                message=random.choice(messages),
                severity=sev,
                details={"sim": True, "source": "dashboard_simulator"},
            )
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for name in _ALWAYS_ON:
                upsert_module_status(
                    module_name=name,
                    status="running",
                    last_result=random.choice(_MODULE_RESULTS.get(name, ["Active"])),
                    last_run=now,
                )
            if tick % 3 == 0:
                batch = random.choice(_BATCH)
                upsert_module_status(
                    module_name=batch,
                    status="running",
                    last_result=random.choice(_MODULE_RESULTS.get(batch, ["Running"])),
                    last_run=now,
                )
            if tick % 5 == 0:
                batch = random.choice(_BATCH)
                upsert_module_status(
                    module_name=batch,
                    status=random.choice(["ok", "idle"]),
                    last_result=random.choice(_MODULE_RESULTS.get(batch, ["Complete"])),
                    last_run=now,
                )
        except Exception as exp:
            logger.error("Simulator insert failed: %s", exp)


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
        except Exception as exp:
            logger.error("Inbox poller error: %s", exp)
        time.sleep(max(1.0, config.INBOX_POLL_SECONDS))


def retention_worker() -> None:
    while True:
        try:
            n = prune_old_events()
            if n:
                logger.info("Pruned %s live_events", n)
        except Exception as exp:
            logger.error("Retention error: %s", exp)
        time.sleep(max(60, config.RETENTION_INTERVAL_SECONDS))
