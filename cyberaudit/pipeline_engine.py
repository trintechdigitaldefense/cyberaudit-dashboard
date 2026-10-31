"""CyberAudit pipeline engine — 3.10.2 single entry.

Authorized run_audit_job lives in pipeline_authorized.py so imports of
`from cyberaudit.pipeline_engine import run_audit_job` always use the ROE-gated
path, regardless of any stale pipeline_body_2.txt on disk or GitHub.
"""
from __future__ import annotations

from cyberaudit.pipeline_authorized import run_audit_job  # noqa: F401

__all__ = ["run_audit_job"]
