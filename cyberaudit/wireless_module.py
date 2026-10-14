"""Wireless audit module — Phase 2 feature #7.

Supports operator-supplied survey JSON (preferred under ROE) and optional
local radio survey via nmcli. Does not crack passwords.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any

from cyberaudit import config

logger = logging.getLogger("CyberAuditDashboard")


def _parse_survey(raw: Any) -> list[dict]:
    if raw is None:
        return []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return []
    if isinstance(raw, dict):
        raw = raw.get("networks") or raw.get("aps") or [raw]
    out = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        out.append({
            "ssid": str(item.get("ssid") or item.get("SSID") or "").strip(),
            "bssid": str(item.get("bssid") or item.get("BSSID") or "").strip(),
            "security": str(item.get("security") or item.get("encryption") or item.get("akm") or "").upper(),
            "signal": item.get("signal") or item.get("signal_dbm"),
            "band": str(item.get("band") or item.get("frequency") or ""),
            "guest": bool(item.get("guest") or item.get("is_guest")),
            "vendor": str(item.get("vendor") or ""),
        })
    return out


def local_radio_survey() -> list[dict]:
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY,BSSID,FREQ", "dev", "wifi", "list"],
            capture_output=True, text=True, timeout=20,
        )
        if r.returncode != 0:
            return []
        nets = []
        for line in (r.stdout or "").splitlines():
            parts = line.split(":")
            if len(parts) < 4:
                continue
            ssid, signal, security = parts[0], parts[1], parts[2]
            bssid = parts[3] if len(parts) > 3 else ""
            freq = parts[4] if len(parts) > 4 else ""
            nets.append({
                "ssid": ssid, "signal": signal, "security": security.upper(),
                "bssid": bssid.replace("\\:", ":"), "band": freq,
                "guest": "guest" in ssid.lower(),
            })
        return nets
    except FileNotFoundError:
        return []
    except Exception as exc:
        logger.debug("nmcli survey failed: %s", exc)
        return []


def assess_wireless(networks: list[dict]) -> list[dict]:
    findings: list[dict] = []
    if not networks:
        return findings
    ssids: dict = {}
    for n in networks:
        ssid = n.get("ssid") or "(hidden)"
        ssids.setdefault(ssid, []).append(n)

    for ssid, rows in ssids.items():
        sec = " ".join((r.get("security") or "") for r in rows)
        host_label = ssid[:64] or "wireless"
        if any(x in sec for x in ("--", "OPEN", "NONE", "OPN")) or sec.strip() in ("", "OPEN"):
            if not any(k in sec for k in ("WPA", "WEP", "RSN", "IEEE")):
                findings.append({
                    "host": host_label, "port": "wifi", "severity": "critical",
                    "title": f"Open Wi-Fi network: {ssid or '(hidden)'}",
                    "cve": "", "cma_section": "Section 3", "service": "wireless",
                    "evidence": str(rows[0]),
                })
        if "WEP" in sec:
            findings.append({
                "host": host_label, "port": "wifi", "severity": "critical",
                "title": f"WEP encryption in use: {ssid}",
                "cve": "", "cma_section": "Section 3", "service": "wireless", "evidence": sec,
            })
        if "WPA1" in sec or ("WPA" in sec and "WPA2" not in sec and "WPA3" not in sec and "RSN" not in sec):
            findings.append({
                "host": host_label, "port": "wifi", "severity": "high",
                "title": f"Legacy WPA (not WPA2/WPA3): {ssid}",
                "cve": "", "cma_section": "Section 6", "service": "wireless", "evidence": sec,
            })
        if "WPA2" in sec and "WPA3" not in sec:
            findings.append({
                "host": host_label, "port": "wifi", "severity": "low",
                "title": f"WPA2 without WPA3 transition: {ssid}",
                "cve": "", "cma_section": "Section 7", "service": "wireless", "evidence": sec,
            })
        if "guest" in ssid.lower():
            findings.append({
                "host": host_label, "port": "wifi", "severity": "medium",
                "title": f"Guest SSID detected — confirm isolation from LAN: {ssid}",
                "cve": "", "cma_section": "Section 6", "service": "wireless",
                "evidence": "Guest network should not reach POS, servers, or cameras",
            })

    for ssid, rows in ssids.items():
        secs = {(r.get("security") or "").upper() for r in rows}
        if len(secs) > 1:
            findings.append({
                "host": ssid[:64], "port": "wifi", "severity": "medium",
                "title": f"Same SSID advertises mixed security modes: {ssid}",
                "cve": "", "cma_section": "Section 6", "service": "wireless", "evidence": str(secs),
            })
    return findings


def load_survey_from_job(job: dict | None) -> list[dict]:
    job = job or {}
    nets = _parse_survey(job.get("wireless_survey") or job.get("wifi_survey"))
    if nets:
        return nets
    path = job.get("wireless_survey_file") or ""
    if path:
        p = Path(path)
        if not p.is_absolute():
            p = config.DATA_DIR / p
        if p.is_file():
            try:
                return _parse_survey(p.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.warning("wireless survey file: %s", exc)
    return []


def run_wireless_audit(job: dict | None = None, *, use_local_radio: bool = False) -> list[dict]:
    nets = load_survey_from_job(job)
    if not nets and use_local_radio:
        nets = local_radio_survey()
    if not nets:
        return []
    return assess_wireless(nets)
