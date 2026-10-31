"""Signed Rules of Engagement — CyberAudit 3.10 Phase 1.

Fail closed: missing, expired, out-of-scope, or malformed authorization rejects the job.
HMAC signature binds the ROE payload so operators can prove what was authorised.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("CyberAuditDashboard")

REQUIRED_ROE_FIELDS = (
    "client_name",
    "authorized_by",
    "targets",
    "valid_from",
    "valid_until",
)


def _roe_secret() -> bytes:
    raw = (
        os.environ.get("CYBERAUDIT_ROE_SECRET")
        or os.environ.get("CYBERAUDIT_SECRET")
        or ""
    ).strip()
    if not raw:
        return b""
    return raw.encode("utf-8")


def _canonical_payload(roe: dict[str, Any]) -> bytes:
    data = {
        k: v
        for k, v in roe.items()
        if k not in ("signature", "sig", "sig_alg")
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sign_roe(roe: dict[str, Any]) -> dict[str, Any]:
    secret = _roe_secret()
    if not secret:
        raise ValueError("Cannot sign ROE: CYBERAUDIT_SECRET / CYBERAUDIT_ROE_SECRET not set")
    out = dict(roe)
    out.pop("signature", None)
    out.pop("sig", None)
    out.pop("sig_alg", None)
    sig = hmac.new(secret, _canonical_payload(out), hashlib.sha256).hexdigest()
    out["signature"] = sig
    out["sig_alg"] = "HMAC-SHA256"
    return out


def verify_roe_signature(roe: dict[str, Any]) -> tuple[bool, str]:
    secret = _roe_secret()
    if not secret:
        return False, "no ROE signing secret configured"
    provided = (roe.get("signature") or roe.get("sig") or "").strip()
    if not provided:
        return False, "ROE signature missing"
    expected = hmac.new(secret, _canonical_payload(roe), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, provided):
        return False, "ROE signature invalid"
    return True, "signature ok"


def _parse_dt(value: str) -> datetime | None:
    value = (value or "").strip()
    if not value:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(value.replace("Z", "+0000"), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _normalize_targets(targets: Any) -> list[str]:
    if targets is None:
        return []
    if isinstance(targets, str):
        return [p.strip() for p in targets.replace(";", ",").split(",") if p.strip()]
    if isinstance(targets, (list, tuple)):
        return [str(t).strip() for t in targets if str(t).strip()]
    return []


def _ip_in_scope(addr: str, allowed: list[str]) -> bool:
    addr = addr.strip()
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return any(addr.lower() == a.lower() for a in allowed if "/" not in a)

    for entry in allowed:
        entry = entry.strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                net = ipaddress.ip_network(entry, strict=False)
                if ip in net:
                    return True
            else:
                if ip == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            if addr.lower() == entry.lower():
                return True
    return False


def extract_roe(job: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("roe", "authorization", "rules_of_engagement", "roe_record"):
        val = job.get(key)
        if isinstance(val, dict):
            return val
        if isinstance(val, str) and val.strip().startswith("{"):
            try:
                parsed = json.loads(val)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass
    return None


def validate_roe(
    job: dict[str, Any],
    *,
    require_signature: bool | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    from cyberaudit import config

    demo = bool(getattr(config, "DEMO_MODE", False))
    roe = extract_roe(job)

    if roe is None:
        if demo and job.get("lab_unauthenticated") is True:
            logger.warning("DEMO lab job without ROE — lab_unauthenticated=1")
            return {
                "client_name": job.get("client_name") or "lab",
                "authorized_by": "demo",
                "targets": [job.get("target") or ""],
                "valid_from": "1970-01-01",
                "valid_until": "2099-12-31",
                "demo": True,
            }
        raise PermissionError(
            "ROE required: missing authorization record. "
            "Provide job['roe'] with signed Rules of Engagement."
        )

    missing = [f for f in REQUIRED_ROE_FIELDS if not str(roe.get(f) or "").strip()]
    if missing:
        raise ValueError(f"ROE malformed — missing mandatory fields: {', '.join(missing)}")

    if require_signature is None:
        require_signature = not demo
    if require_signature:
        ok, reason = verify_roe_signature(roe)
        if not ok:
            raise PermissionError(f"ROE authorization failed: {reason}")

    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    valid_from = _parse_dt(str(roe.get("valid_from") or ""))
    valid_until = _parse_dt(str(roe.get("valid_until") or ""))
    if not valid_from or not valid_until:
        raise ValueError("ROE malformed — valid_from/valid_until must be parseable datetimes")
    if now < valid_from:
        raise PermissionError(
            f"ROE not yet valid (valid_from={roe.get('valid_from')}, now={now.isoformat()})"
        )
    if now > valid_until:
        raise PermissionError(
            f"ROE expired (valid_until={roe.get('valid_until')}, now={now.isoformat()})"
        )

    allowed = _normalize_targets(roe.get("targets"))
    if not allowed:
        raise ValueError("ROE malformed — targets list is empty")

    job_target = (job.get("target") or "").strip()
    if not job_target:
        raise ValueError("job target is required")

    job_targets = _normalize_targets(job_target) or [job_target]

    for jt in job_targets:
        if "/" in jt:
            try:
                job_net = ipaddress.ip_network(jt, strict=False)
                contained = False
                for entry in allowed:
                    try:
                        if "/" in entry:
                            if job_net.subnet_of(ipaddress.ip_network(entry, strict=False)):
                                contained = True
                                break
                        else:
                            if job_net == ipaddress.ip_network(entry + "/32", strict=False) or \
                               job_net == ipaddress.ip_network(entry + "/128", strict=False):
                                contained = True
                                break
                    except ValueError:
                        continue
                if not contained:
                    raise PermissionError(
                        f"ROE scope violation: target {jt} is outside authorized targets {allowed}"
                    )
            except ValueError as exc:
                raise ValueError(f"ROE target parse error: {jt}") from exc
        else:
            if not _ip_in_scope(jt, allowed):
                raise PermissionError(
                    f"ROE scope violation: target {jt} is outside authorized targets {allowed}"
                )

    ports = roe.get("ports") or roe.get("authorized_ports")
    if ports is not None:
        try:
            allowed_ports = {int(p) for p in ports}
        except (TypeError, ValueError) as exc:
            raise ValueError("ROE ports must be a list of integers") from exc
        job_ports = job.get("ports")
        if job_ports:
            for p in job_ports:
                if int(p) not in allowed_ports:
                    raise PermissionError(f"ROE scope violation: port {p} not authorized")

    if roe.get("window") or roe.get("roe_window"):
        from cyberaudit.schedule_windows import window_allows_now

        allowed_w, reason = window_allows_now(
            roe.get("window") or roe.get("roe_window"),
            now=now.replace(tzinfo=None) if now.tzinfo else now,
            fail_closed=True,
        )
        if not allowed_w:
            raise PermissionError(f"ROE window enforced: {reason}")

    return roe


def assert_authorized(job: dict[str, Any]) -> dict[str, Any]:
    return validate_roe(job)
