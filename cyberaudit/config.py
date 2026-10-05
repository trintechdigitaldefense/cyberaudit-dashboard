"""Environment-driven configuration."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DEMO_MODE = os.environ.get("DEMO_MODE", "0").strip().lower() in ("1", "true", "yes", "on")

DATA_DIR = Path(os.environ.get("CYBERAUDIT_DATA_DIR", BASE_DIR / "data")).resolve()
REPORTS_DIR = Path(os.environ.get("CYBERAUDIT_REPORTS_DIR", BASE_DIR / "reports")).resolve()
PLAYBOOKS_DIR = Path(os.environ.get("CYBERAUDIT_PLAYBOOKS_DIR", BASE_DIR / "playbooks")).resolve()
DB_PATH = Path(os.environ.get("CYBERAUDIT_DB_PATH", DATA_DIR / "cyber_audit.db")).resolve()
INBOX_DIR = Path(os.environ.get("CYBERAUDIT_INBOX_DIR", DATA_DIR / "inbox")).resolve()
JOBS_DIR = Path(os.environ.get("CYBERAUDIT_JOBS_DIR", DATA_DIR / "jobs")).resolve()

HOST = os.environ.get("CYBERAUDIT_HOST", "127.0.0.1")
PORT = int(os.environ.get("CYBERAUDIT_PORT", "1881"))

AUTH_USER = os.environ.get("CYBERAUDIT_USER", "").strip()
AUTH_PASSWORD = os.environ.get("CYBERAUDIT_PASSWORD", "").strip()
VIEWER_USER = os.environ.get("CYBERAUDIT_VIEWER_USER", "").strip()
VIEWER_PASSWORD = os.environ.get("CYBERAUDIT_VIEWER_PASSWORD", "").strip()
AUTH_REQUIRED = bool(AUTH_USER and AUTH_PASSWORD) or bool(VIEWER_USER and VIEWER_PASSWORD)

INGEST_TOKEN = os.environ.get("CYBERAUDIT_INGEST_TOKEN", "").strip()
AUDIT_TRIGGER_CMD = os.environ.get("CYBERAUDIT_AUDIT_TRIGGER_CMD", "").strip()
EVENT_RETENTION_DAYS = int(os.environ.get("CYBERAUDIT_EVENT_RETENTION_DAYS", "30"))
INBOX_POLL_SECONDS = float(os.environ.get("CYBERAUDIT_INBOX_POLL_SECONDS", "5"))
RETENTION_INTERVAL_SECONDS = int(os.environ.get("CYBERAUDIT_RETENTION_INTERVAL_SECONDS", "3600"))

_secret = os.environ.get("CYBERAUDIT_SECRET", "").strip()
if not _secret:
    if DEMO_MODE:
        SECRET_KEY = secrets.token_hex(32)
    else:
        raise SystemExit(
            "FATAL: CYBERAUDIT_SECRET is required when DEMO_MODE is off. "
            "export CYBERAUDIT_SECRET=$(openssl rand -hex 32)"
        )
else:
    SECRET_KEY = _secret

_allowed = os.environ.get("CYBERAUDIT_ALLOWED_ORIGINS", "").strip()
if _allowed:
    ALLOWED_ORIGINS = [o.strip() for o in _allowed.split(",") if o.strip()]
else:
    ALLOWED_ORIGINS = [
        f"http://{HOST}:{PORT}",
        f"http://127.0.0.1:{PORT}",
        f"http://localhost:{PORT}",
    ]

COOKIE_SECURE = os.environ.get("CYBERAUDIT_COOKIE_SECURE", "").strip().lower() in (
    "1", "true", "yes",
)

COMPANY = {
    "name": "TrinTech Digital Defense",
    "short_name": "TrinTech DD",
    "tagline": "Caribbean Cyber Resilience • Trinidad & Tobago",
    "product": "CyberAudit",
    "version": "2.4.0-p3",
    "address": "Level 3, Maritime Centre, 29 Tenth Avenue, Barataria, Trinidad and Tobago",
    "phone": "+1 (868) 555-0142",
    "email": "ops@trintech.digital",
    "support": "support@trintech.digital",
    "website": "https://trintech.digital",
    "reg_number": "TT-C-2023-88421",
    "compliance": [
        "Trinidad and Tobago Computer Misuse Act, Chap. 11:17 (Sections 3, 6, 7)",
        "CARICOM IMPACS Cyber Security Framework",
        "TT-CSIRT Operational Guidelines",
        "Data Protection Act 2011 (Trinidad & Tobago)",
    ],
    "mission": (
        "To deliver sovereign, modular, and legally aligned cybersecurity "
        "orchestration for Caribbean critical infrastructure and enterprise networks."
    ),
}


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    PLAYBOOKS_DIR.mkdir(parents=True, exist_ok=True)
    INBOX_DIR.mkdir(parents=True, exist_ok=True)
    (INBOX_DIR / "processed").mkdir(parents=True, exist_ok=True)
    (INBOX_DIR / "failed").mkdir(parents=True, exist_ok=True)
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
