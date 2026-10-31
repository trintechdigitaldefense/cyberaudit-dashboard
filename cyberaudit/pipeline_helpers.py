"""Pipeline helpers — CyberAudit 3.10.4.

Static module extracted from former pipeline_body_*.txt sources.
No runtime exec(). Imported by pipeline_authorized.
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import logging
import secrets
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Optional

from cyberaudit import config
from cyberaudit.db import insert_finding, insert_live_event, upsert_audit_session, upsert_module_status

logger = logging.getLogger("CyberAuditDashboard")

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379,
    8000, 8080, 8443, 8888, 9200, 27017,
]
SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
    5985: "winrm-http", 5986: "winrm-https", 6379: "redis", 8000: "http-alt",
    8080: "http-alt", 8443: "https-alt", 8888: "http-alt", 9200: "elasticsearch",
    27017: "mongodb",
}
RISK_RULES = {
    23: ("high", "Telnet service exposed (cleartext remote access)", "Section 6", "telnet"),
    21: ("medium", "FTP service exposed", "Section 6", "ftp"),
    445: ("high", "SMB service exposed", "Section 6", "smb"),
    3389: ("high", "RDP exposed", "Section 6", "rdp"),
    5900: ("medium", "VNC exposed", "Section 6", "vnc"),
    1433: ("high", "MSSQL exposed", "Section 6", "mssql"),
    3306: ("high", "MySQL exposed", "Section 6", "mysql"),
    5432: ("high", "PostgreSQL exposed", "Section 6", "postgres"),
    27017: ("high", "MongoDB exposed", "Section 6", "mongodb"),
    6379: ("high", "Redis exposed", "Section 6", "redis"),
}


def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _mod(name: str, status: str, result: str = "") -> None:
    upsert_module_status(module_name=name, status=status, last_result=result[:500] if result else "")


def _ev(module: str, message: str, severity: str = "info", **kw: Any) -> None:
    details = kw.get("details") if isinstance(kw.get("details"), dict) else kw
    insert_live_event(module=module, message=message, severity=severity, event_type="pipeline", details=details or {})


def _parse_targets(target: str, max_hosts: int = 256) -> list[str]:
    out: list[str] = []
    for part in (target or "").replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "/" in part:
                net = ipaddress.ip_network(part, strict=False)
                for i, host in enumerate(net.hosts()):
                    if i >= max_hosts:
                        break
                    out.append(str(host))
            else:
                out.append(str(ipaddress.ip_address(part)))
        except ValueError:
            out.append(part)
    return out[:max_hosts]


def _nmap_available() -> bool:
    try:
        subprocess.run(["nmap", "-V"], capture_output=True, timeout=5, check=False)
        return True
    except Exception:
        return False


def discover_live_hosts(hosts: list[str]) -> list[str]:
    """Return only hosts that respond. Never invent live hosts from candidates."""
    live: list[str] = []
    for h in hosts:
        try:
            # TCP connect probe on common ports
            ok = False
            for port in (80, 443, 22, 445, 3389):
                try:
                    with socket.create_connection((h, port), timeout=0.6):
                        ok = True
                        break
                except OSError:
                    continue
            if ok:
                live.append(h)
        except Exception:
            continue
    return live


def recon_scan(hosts: list[str]) -> list[dict]:
    open_ports: list[dict] = []
    ports = list(DEFAULT_PORTS)

    def _scan_host(host: str) -> list[dict]:
        found = []
        for port in ports:
            try:
                with socket.create_connection((host, port), timeout=0.5):
                    found.append({
                        "host": host,
                        "port": port,
                        "service": SERVICE_HINTS.get(port, "unknown"),
                        "state": "open",
                    })
            except OSError:
                continue
        return found

    with ThreadPoolExecutor(max_workers=min(16, max(1, len(hosts)))) as ex:
        futs = {ex.submit(_scan_host, h): h for h in hosts}
        for fut in as_completed(futs):
            try:
                open_ports.extend(fut.result())
            except Exception:
                continue
    return open_ports


def vulnerability_heuristics(open_ports: list[dict]) -> list[dict]:
    vulns: list[dict] = []
    for p in open_ports:
        port = int(p.get("port") or 0)
        if port in RISK_RULES:
            sev, title, cma, key = RISK_RULES[port]
            vulns.append({
                "host": p.get("host"),
                "port": port,
                "severity": sev,
                "title": title,
                "cve": "",
                "cma_section": cma,
                "evidence": f"Open port {port}/{p.get('service')}",
                "service_key": key,
                "confidence": "heuristic",
                "finding_type": "heuristic_indicator",
            })
    return vulns


def map_tt_compliance(vulns: list[dict]) -> list[dict]:
    for v in vulns:
        if not v.get("cma_section"):
            sev = (v.get("severity") or "").lower()
            if sev in ("critical", "high"):
                v["cma_section"] = "Section 6"
            else:
                v["cma_section"] = "Section 3"
        v["cma_disclaimer"] = (
            "Informational mapping to the Trinidad and Tobago Computer Misuse Act "
            "for awareness only — not legal advice; human review required."
        )
    return vulns


def write_network_map(session_id: str, target: str, hosts_up: list[str], open_ports: list[dict]) -> Path:
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = config.REPORTS_DIR / f"network_map_{session_id}.json"
    data = {
        "session_id": session_id,
        "target": target,
        "host_count": len(hosts_up),
        "hosts_up": hosts_up[:256],
        "open_ports": open_ports[:2000],
        "generated_at": _now(),
        "note": "Point-in-time map — not continuous monitoring.",
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path
