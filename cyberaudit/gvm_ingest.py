"""P6.1 — GVM/OpenVAS report ingestion. Complements enterprise scanners."""
from __future__ import annotations
import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

logger = logging.getLogger("CyberAuditDashboard")
_SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "log": "info", "info": "info"}

def _sev_from_threat(threat: str, score: str = "") -> str:
    t = (threat or "").strip().lower()
    if t in _SEVERITY_MAP:
        return _SEVERITY_MAP[t]
    try:
        s = float(score or 0)
        if s >= 9.0: return "critical"
        if s >= 7.0: return "high"
        if s >= 4.0: return "medium"
        if s > 0: return "low"
    except ValueError:
        pass
    return "info"

def parse_openvas_xml(path: Path | str) -> list[dict]:
    path = Path(path)
    root = ET.parse(path).getroot()
    findings = []
    for res in root.findall(".//result"):
        host = (res.findtext("host") or "").strip()
        port = (res.findtext("port") or "").strip()
        port_num = port.split("/")[0] if port else ""
        nvt = res.find("nvt")
        name = (nvt.get("name") or nvt.findtext("name") or "").strip() if nvt is not None else ""
        cve = (nvt.findtext("cve") or "").strip() if nvt is not None else ""
        if cve == "NOCVE": cve = ""
        threat = (res.findtext("threat") or res.findtext("severity") or "").strip()
        severity_score = (res.findtext("severity") or "").strip()
        desc = (res.findtext("description") or "")[:1500]
        if not name and not desc:
            continue
        findings.append({
            "host": host or "unknown", "port": port_num, "severity": _sev_from_threat(threat, severity_score),
            "title": name or "OpenVAS finding", "cve": cve, "cma_section": "", "service": "openvas",
            "evidence": desc, "source": "gvm_openvas", "scanner_score": severity_score,
        })
    return findings

def parse_openvas_json(path: Path | str) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = data.get("results") or data.get("vulnerabilities") or data if isinstance(data, list) else data.get("findings") or []
    findings = []
    for r in rows:
        if not isinstance(r, dict): continue
        findings.append({
            "host": str(r.get("host") or r.get("ip") or "unknown"),
            "port": str(r.get("port") or "").split("/")[0],
            "severity": _sev_from_threat(str(r.get("threat") or r.get("severity") or ""), str(r.get("severity") or r.get("cvss") or "")),
            "title": str(r.get("name") or r.get("title") or "Scanner finding"),
            "cve": str(r.get("cve") or ""), "cma_section": "", "service": "openvas",
            "evidence": str(r.get("description") or r.get("summary") or "")[:1500],
            "source": "gvm_openvas",
        })
    return findings

def ingest_scanner_file(path: Path | str) -> list[dict]:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(str(path))
    if path.suffix.lower() in (".xml", ".omp") or path.read_bytes()[:100].strip().startswith(b"<"):
        return parse_openvas_xml(path)
    return parse_openvas_json(path)

def merge_scanner_findings(local_findings: list[dict], scanner_findings: list[dict]) -> list[dict]:
    seen, out = set(), []
    for f in list(local_findings) + list(scanner_findings):
        key = (str(f.get("host") or "").lower(), str(f.get("title") or "").lower()[:80], str(f.get("port") or ""))
        if key in seen: continue
        seen.add(key)
        out.append(f)
    return out
