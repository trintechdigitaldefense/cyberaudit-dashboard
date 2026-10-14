"""Webhook / email alerts — Phase 3 feature #13."""

from __future__ import annotations

import json
import logging
import os
import smtplib
import ssl
import urllib.request
from email.message import EmailMessage

logger = logging.getLogger("CyberAuditDashboard")


def _operator_webhook() -> str:
    return os.environ.get("CYBERAUDIT_ALERT_WEBHOOK", "").strip()


def _smtp_config() -> dict[str, str]:
    return {
        "host": os.environ.get("CYBERAUDIT_SMTP_HOST", "").strip(),
        "port": os.environ.get("CYBERAUDIT_SMTP_PORT", "587").strip(),
        "user": os.environ.get("CYBERAUDIT_SMTP_USER", "").strip(),
        "password": os.environ.get("CYBERAUDIT_SMTP_PASSWORD", "").strip(),
        "from_addr": os.environ.get("CYBERAUDIT_SMTP_FROM", "").strip(),
        "to_addr": os.environ.get("CYBERAUDIT_ALERT_EMAIL", "").strip(),
    }


def post_webhook(url: str, payload: dict) -> bool:
    if not url:
        return False
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json", "User-Agent": "CyberAudit/3.3-alerts"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:
        logger.warning("webhook failed %s: %s", url[:60], exp if False else exc)
        return False


def send_email(subject: str, body: str) -> bool:
    cfg = _smtp_config()
    if not (cfg["host"] and cfg["to_addr"] and cfg["from_addr"]):
        return False
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = cfg["from_addr"]
        msg["To"] = cfg["to_addr"]
        msg.set_content(body)
        port = int(cfg["port"] or 587)
        context = ssl.create_default_context()
        with smtplib.SMTP(cfg["host"], port, timeout=20) as server:
            server.ehlo()
            try:
                server.starttls(context=context)
            except Exception:
                pass
            if cfg["user"] and cfg["password"]:
                server.login(cfg["user"], cfg["password"])
            server.send_message(msg)
        return True
    except Exception as exc:
        logger.warning("email alert failed: %s", exp if False else exc)
        return False


def notify_scan_complete(result: dict, job: dict | None = None) -> dict[str, bool]:
    job = job or {}
    payload = {
        "event": "scan_complete",
        "session_id": result.get("session_id"),
        "target": result.get("target"),
        "findings": result.get("findings"),
        "posture_score": result.get("posture_score"),
        "posture_band": result.get("posture_band"),
        "status": result.get("status"),
        "sector": result.get("sector"),
    }
    subject = f"[CyberAudit] Scan complete {result.get('session_id')} posture={result.get('posture_score')}"
    body = json.dumps(payload, indent=2)
    out = {
        "operator_webhook": post_webhook(_operator_webhook(), payload),
        "operator_email": send_email(subject, body),
        "client_webhook": False,
    }
    client_url = (job.get("client_webhook") or "").strip()
    if client_url and job.get("client_alerts_opt_in"):
        client_payload = {
            "event": "scan_complete",
            "session_id": result.get("session_id"),
            "posture_score": result.get("posture_score"),
            "findings_count": result.get("findings"),
            "status": result.get("status"),
        }
        out["client_webhook"] = post_webhook(client_url, client_payload)
    return out


def notify_critical_findings(findings: list[dict], session_id: str) -> dict[str, bool]:
    critical = [f for f in findings if (f.get("severity") or "").lower() in ("critical", "high")]
    if not critical:
        return {"operator_webhook": False, "operator_email": False}
    payload = {
        "event": "critical_findings",
        "session_id": session_id,
        "count": len(critical),
        "items": [{
            "host": f.get("host"), "port": f.get("port"),
            "severity": f.get("severity"), "title": f.get("title"),
            "cvss": f.get("cvss_base_score"),
        } for f in critical[:20]],
    }
    subject = f"[CyberAudit] {len(critical)} high/critical finding(s) — {session_id}"
    body = json.dumps(payload, indent=2)
    return {
        "operator_webhook": post_webhook(_operator_webhook(), payload),
        "operator_email": send_email(subject, body),
    }
