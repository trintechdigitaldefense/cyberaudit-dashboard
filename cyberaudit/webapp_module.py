"""Web application checks — TLS, security headers, default pages, certs.

Phase 2 feature #6. Non-destructive HTTP/HTTPS probes on in-scope open web ports.
"""

from __future__ import annotations

import datetime
import logging
import socket
import ssl
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError

logger = logging.getLogger("CyberAuditDashboard")

SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)

DEFAULT_PATHS = (
    "/admin",
    "/administrator",
    "/login",
    "/wp-admin",
    "/phpmyadmin",
    "/manager/html",
    "/.env",
    "/server-status",
)


def _http_get(url: str, timeout: float = 5.0) -> tuple[int | None, dict[str, str], bytes]:
    req = Request(url, headers={"User-Agent": "CyberAudit/3.1 TrinTechDigitalDefense"})
    try:
        with urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
            headers = {k: v for k, v in resp.headers.items()}
            body = resp.read(8192)
            return resp.status, headers, body
    except HTTPError as e:
        headers = {k: v for k, v in (e.headers.items() if e.headers else [])}
        return e.code, headers, b""
    except Exception:
        return None, {}, b""


def grade_tls(host: str, port: int = 443) -> dict[str, Any]:
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "tls_version": None,
        "cipher": None,
        "cert_subject": None,
        "cert_issuer": None,
        "not_after": None,
        "days_remaining": None,
        "expired": False,
        "errors": [],
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["tls_version"] = ssock.version()
                result["cipher"] = (ssock.cipher() or (None,))[0]
                cert = ssock.getpeercert()
                if cert:
                    result["cert_subject"] = str(cert.get("subject") or ())
                    result["cert_issuer"] = str(cert.get("issuer") or ())
                    na = cert.get("notAfter")
                    result["not_after"] = na
                    if na:
                        try:
                            exp = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                            days = (exp - datetime.datetime.utcnow()).days
                            result["days_remaining"] = days
                            result["expired"] = days < 0
                        except Exception as exc:
                            result["errors"].append(str(exc))
    except Exception as exc:
        result["errors"].append(str(exc))
    return result


def check_security_headers(host: str, port: int, use_tls: bool) -> dict[str, Any]:
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}:{port}/"
    status, headers, _ = _http_get(url)
    lower_map = {k.lower(): v for k, v in headers.items()}
    present = {h: lower_map.get(h.lower()) for h in SECURITY_HEADERS if h.lower() in lower_map}
    missing = [h for h in SECURITY_HEADERS if h not in present]
    return {
        "url": url,
        "status": status,
        "present": present,
        "missing": missing,
        "cleartext": not use_tls,
    }


def check_default_paths(host: str, port: int, use_tls: bool) -> list[dict]:
    scheme = "https" if use_tls else "http"
    hits = []
    for path in DEFAULT_PATHS:
        url = f"{scheme}://{host}:{port}{path}"
        status, _, _ = _http_get(url, timeout=3.0)
        if status and status < 400:
            hits.append({"url": url, "status": status, "path": path})
    return hits


def assess_web_services(open_ports: list[dict]) -> list[dict]:
    findings: list[dict] = []
    web_ports = []
    for row in open_ports:
        p = int(row["port"]) if str(row.get("port", "")).isdigit() else 0
        svc = (row.get("service") or "").lower()
        if p in (80, 443, 8080, 8443, 8000, 8888) or "http" in svc:
            web_ports.append(row)

    for row in web_ports:
        host = row["host"]
        port = int(row["port"])
        use_tls = port in (443, 8443) or "https" in (row.get("service") or "").lower()

        if use_tls:
            tls = grade_tls(host, port)
            if tls.get("expired"):
                findings.append({
                    "host": host, "port": str(port), "severity": "high",
                    "title": "TLS certificate expired", "cve": "", "cma_section": "Section 6",
                    "service": "https", "evidence": str(tls),
                })
            elif tls.get("days_remaining") is not None and tls["days_remaining"] < 30:
                findings.append({
                    "host": host, "port": str(port), "severity": "medium",
                    "title": f"TLS certificate expires in {tls['days_remaining']} days",
                    "cve": "", "cma_section": "Section 7", "service": "https", "evidence": str(tls),
                })
            ver = (tls.get("tls_version") or "").upper()
            if ver in ("TLSv1", "TLSv1.0", "TLSv1.1", "SSLV3"):
                findings.append({
                    "host": host, "port": str(port), "severity": "high",
                    "title": f"Outdated TLS protocol ({tls.get('tls_version')})",
                    "cve": "", "cma_section": "Section 6", "service": "https", "evidence": str(tls),
                })

        headers = check_security_headers(host, port, use_tls)
        if headers.get("cleartext"):
            findings.append({
                "host": host, "port": str(port), "severity": "medium",
                "title": "Web service served over cleartext HTTP", "cve": "",
                "cma_section": "Section 6", "service": "http", "evidence": str(headers),
            })
        if headers.get("status") and len(headers.get("missing") or []) >= 4:
            findings.append({
                "host": host, "port": str(port), "severity": "low",
                "title": "Multiple security headers missing", "cve": "",
                "cma_section": "Section 7",
                "service": "http" if not use_tls else "https",
                "evidence": str(headers.get("missing")),
            })

        hits = check_default_paths(host, port, use_tls)
        for hit in hits:
            sev = "high" if hit["path"] in ("/admin", "/administrator", "/phpmyadmin", "/.env") else "medium"
            findings.append({
                "host": host, "port": str(port), "severity": sev,
                "title": f"Default/admin path reachable: {hit['path']}", "cve": "",
                "cma_section": "Section 3" if sev == "high" else "Section 6",
                "service": "http" if not use_tls else "https", "evidence": str(hit),
            })

    return findings
