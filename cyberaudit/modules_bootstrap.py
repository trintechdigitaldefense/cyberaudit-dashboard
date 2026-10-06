"""Register and update pipeline module statuses for the dashboard UI."""
from __future__ import annotations

from cyberaudit.db import upsert_module_status, get_db

_PIPELINE_MODULES = (
    ("nmap_module", "idle", "Ready — queue a target to start recon"),
    ("openvas_module", "idle", "Ready — waits for recon results"),
    ("tt_compliance_mapper", "idle", "Ready — TT Computer Misuse Act mapper"),
    ("regional_threat_intel", "idle", "Ready — TT-CSIRT / CARICOM enrichment"),
    ("patch_verification_module", "idle", "Ready — baseline compare"),
    ("pdf_report_module", "idle", "Ready — report generation"),
    ("incident_response_module", "idle", "Ready — playbooks available"),
    ("data_exfiltration_module", "ok", "Standby — feed via inbox/ingest"),
    ("continuous_ids_module", "ok", "Standby — feed via inbox/ingest"),
    ("database_module", "ok", "SQLite archive ready"),
    ("diagnostics_module", "ok", "Runtime checks OK"),
)


def ensure_modules_ready() -> None:
    for name, status, result in _PIPELINE_MODULES:
        with get_db() as conn:
            exists = conn.execute(
                "SELECT 1 FROM module_status WHERE module_name=?", (name,)
            ).fetchone()
        if not exists:
            upsert_module_status(module_name=name, status=status, last_result=result)


def mark_modules_for_job(target: str) -> None:
    upsert_module_status("nmap_module", "running", f"Queued recon for {target}")
    upsert_module_status("openvas_module", "queued", "Waiting for recon")
    upsert_module_status("tt_compliance_mapper", "queued", "Waiting for findings")
    upsert_module_status("pdf_report_module", "queued", "Waiting for assessment")
    upsert_module_status("database_module", "queued", "Waiting for session archive")
    upsert_module_status("diagnostics_module", "running", "Pre-job health check")
