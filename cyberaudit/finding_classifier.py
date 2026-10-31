"""Evidence-based finding classification — CyberAudit 3.10 Phase 2.

Never report a vulnerability as confirmed merely because a port is open.
Separates: potential_exposure | version_suspect | confirmed_weakness
Attaches confidence, evidence, and optional CVE hints from verified banners.
"""

from __future__ import annotations

import json
import re
from typing import Any

_VERSION_RE = re.compile(
    r"(?:version[\s:/]*|v)(\d+\.\d+(?:\.\d+)?)",
    re.IGNORECASE,
)

_CVE_HINTS: dict[str, list[tuple[str, str, str]]] = {
    "smb": [
        ("1.0", "CVE-2017-0144", "SMBv1-era exposure associated with EternalBlue-class risk — verify patch level"),
    ],
    "openssl": [
        ("1.0.1", "CVE-2014-0160", "OpenSSL 1.0.1* historically linked to Heartbleed — confirm build"),
    ],
    "apache": [
        ("2.2.", "CVE-2017-9798", "Legacy Apache 2.2.x — review for known issues and end-of-life"),
    ],
    "openssh": [
        ("7.2", "CVE-2016-6210", "Older OpenSSH builds — verify current vendor advisories"),
    ],
}


def extract_version(banner: str, service: str = "") -> str | None:
    if not banner:
        return None
    m = _VERSION_RE.search(banner)
    if m:
        return m.group(1)
    low = banner.lower()
    for token in ("openssh_", "apache/", "openssl/", "mysql/", "postgres/", "microsoft-iis/"):
        if token in low:
            try:
                part = low.split(token, 1)[1]
                ver = re.match(r"([\d.]+)", part)
                if ver:
                    return ver.group(1)
            except Exception:
                pass
    return None


def classify_exposure(row: dict[str, Any], risk_rule: tuple | None = None) -> dict[str, Any]:
    host = row.get("host")
    port = row.get("port")
    banner = (row.get("banner") or "").strip()
    service = (row.get("service") or "").strip().lower()
    if risk_rule:
        severity, title, cma, skey = risk_rule
        service = service or skey
    else:
        severity, title, cma, skey = "medium", f"Exposed service on port {port}", "", service

    version = extract_version(banner, service)
    evidence = {
        "host": host,
        "port": port,
        "service": service or skey,
        "banner": banner,
        "version_extracted": version,
        "probe": {k: row.get(k) for k in ("host", "port", "service", "banner") if row.get(k) is not None},
    }

    cve = ""
    cve_note = ""
    classification = "potential_exposure"
    confidence = "low"
    confidence_note = "Port open only — not a confirmed vulnerability"

    if banner and version:
        confidence = "medium"
        confidence_note = "Service banner and version observed; still requires validation against patch state"
        classification = "version_suspect"
        for key, hints in _CVE_HINTS.items():
            if key in (service or skey or "") or key in banner.lower():
                for prefix, cve_id, note in hints:
                    if version.startswith(prefix) or prefix in version:
                        cve = cve_id
                        cve_note = note
                        classification = "version_suspect"
                        confidence = "medium"
                        confidence_note = (
                            f"Version evidence suggests review for {cve_id}. "
                            "Not confirmed exploited — verify with vendor advisory and patch status."
                        )
                        break

    finding = {
        "host": host,
        "port": port,
        "severity": severity,
        "title": title,
        "cve": cve,
        "cve_note": cve_note,
        "cma_section": cma,
        "cma_rationale": (
            f"Informational mapping for exposure class '{skey or service}'. "
            "Not legal advice; requires human review."
        ),
        "cma_review_status": "needs_human_review",
        "service": skey or service,
        "classification": classification,
        "confidence": confidence,
        "confidence_note": confidence_note,
        "version": version or "",
        "evidence": json.dumps(evidence, ensure_ascii=False),
        "evidence_obj": evidence,
    }
    return finding


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    from cyberaudit.retest import fingerprint

    seen: dict[str, dict] = {}
    order: list[str] = []
    for f in findings:
        fp = fingerprint(f)
        if fp not in seen:
            seen[fp] = dict(f)
            seen[fp]["fingerprint"] = fp
            order.append(fp)
        else:
            rank = {"low": 0, "medium": 1, "high": 2}
            old = seen[fp]
            if rank.get(str(f.get("confidence") or "low"), 0) > rank.get(
                str(old.get("confidence") or "low"), 0
            ):
                merged = dict(f)
                merged["fingerprint"] = fp
                merged["dedup_merged"] = True
                seen[fp] = merged
            else:
                old["dedup_count"] = int(old.get("dedup_count") or 1) + 1
    return [seen[k] for k in order]


def apply_suppressions(
    findings: list[dict],
    suppressions: list[dict] | None = None,
) -> list[dict]:
    from cyberaudit.retest import fingerprint

    if not suppressions:
        try:
            from cyberaudit.false_positive import load_suppressions
            suppressions = load_suppressions()
        except Exception:
            suppressions = []

    active = [s for s in (suppressions or []) if s.get("active", True)]
    if not active:
        return findings

    out = []
    for f in findings:
        fp = f.get("fingerprint") or fingerprint(f)
        suppressed = False
        for s in active:
            if s.get("fingerprint") and s["fingerprint"] == fp:
                suppressed = True
                break
            if (
                s.get("host")
                and str(s.get("host")) == str(f.get("host"))
                and str(s.get("port") or "") == str(f.get("port") or "")
                and (not s.get("service") or s.get("service") == f.get("service"))
            ):
                suppressed = True
                break
        if suppressed:
            row = dict(f)
            row["status"] = "false_positive"
            row["suppressed"] = True
            out.append(row)
        else:
            out.append(f)
    return out
