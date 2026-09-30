#!/usr/bin/env python3
"""
CyberAudit Live Operations Dashboard
TrinTech Digital Defense
Port: 1881
"""

import os
import json
import sqlite3
import datetime
import threading
import time
import random
from pathlib import Path
from flask import (
    Flask, render_template, jsonify, send_file, request,
    redirect, url_for, flash, Response
)
from flask_socketio import SocketIO, emit
import logging

BASE_DIR = Path(__file__).parent.resolve()
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
PLAYBOOKS_DIR = BASE_DIR / "playbooks"
DB_PATH = DATA_DIR / "cyber_audit.db"

DATA_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)
PLAYBOOKS_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = "trin-tech-cyberaudit-1881-secure-key"
app.config["TEMPLATES_AUTO_RELOAD"] = True

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CyberAuditDashboard")

COMPANY = {
    "name": "TrinTech Digital Defense",
    "short_name": "TrinTech DD",
    "tagline": "Caribbean Cyber Resilience - Trinidad & Tobago",
    "product": "CyberAudit",
    "version": "2.1.0",
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

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE,
            start_time TEXT,
            end_time TEXT,
            target TEXT,
            status TEXT,
            findings_count INTEGER DEFAULT 0,
            high_severity INTEGER DEFAULT 0,
            medium_severity INTEGER DEFAULT 0,
            low_severity INTEGER DEFAULT 0,
            compliance_score REAL,
            report_path TEXT,
            notes TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS live_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            module TEXT,
            event_type TEXT,
            severity TEXT,
            message TEXT,
            details TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS module_status (
            module_name TEXT PRIMARY KEY,
            status TEXT,
            last_run TEXT,
            last_result TEXT,
            version TEXT
        )
    """)
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def seed_sample_data():
    conn = get_db()
    c = conn.cursor()
    modules = [
        ("nmap_module", "idle", "2026-08-29 18:12:00", "Ports 22,80,443 open", "1.4.2"),
        ("openvas_module", "idle", "2026-08-29 18:15:30", "3 high, 7 medium findings", "2.0.1"),
        ("tt_compliance_mapper", "idle", "2026-08-29 18:16:00", "Mapped to CMA s.3,6,7", "1.2.0"),
        ("regional_threat_intel", "running", "2026-08-29 21:40:00", "Pulling TT-CSIRT feed", "1.1.3"),
        ("patch_verification_module", "idle", "2026-08-29 17:55:00", "Baseline matched", "1.0.8"),
        ("pdf_report_module", "idle", "2026-08-29 18:20:00", "Report generated", "1.3.0"),
        ("incident_response_module", "idle", "2026-08-28 14:00:00", "No active IR", "1.1.0"),
        ("data_exfiltration_module", "running", "2026-08-29 21:45:00", "Monitoring outbound flows", "1.0.5"),
        ("continuous_ids_module", "running", "2026-08-29 21:50:00", "Log analysis active", "1.2.1"),
        ("database_module", "idle", "2026-08-29 18:21:00", "Session archived", "1.0.2"),
        ("diagnostics_module", "idle", "2026-08-29 16:00:00", "All binaries OK", "1.0.0"),
    ]
    for m in modules:
        c.execute("INSERT OR REPLACE INTO module_status VALUES (?,?,?,?,?)", m)
    sessions = [
        ("AUD-20260829-001", "2026-08-29 17:30:00", "2026-08-29 18:22:00", "192.168.10.0/24", "completed", 14, 3, 7, 4, 78.5, "reports/CyberAudit_Report_AUD-20260829-001.pdf", "Full internal subnet scan."),
        ("AUD-20260828-003", "2026-08-28 09:00:00", "2026-08-28 10:15:00", "10.50.0.12", "completed", 5, 1, 2, 2, 91.0, "reports/CyberAudit_Report_AUD-20260828-003.pdf", "External perimeter check."),
        ("AUD-20260827-002", "2026-08-27 14:00:00", "2026-08-27 15:40:00", "mail.example.tt", "completed", 8, 0, 4, 4, 85.2, "reports/CyberAudit_Report_AUD-20260827-002.pdf", "Mail gateway compliance scan."),
    ]
    for s in sessions:
        c.execute("""INSERT OR IGNORE INTO audit_sessions
               (session_id, start_time, end_time, target, status,
                findings_count, high_severity, medium_severity, low_severity,
                compliance_score, report_path, notes)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", s)
    events = [
        ("2026-08-29 21:48:12", "continuous_ids_module", "anomaly", "medium", "Unusual process spawn detected on host 192.168.10.45", json.dumps({"pid": 88421})),
        ("2026-08-29 21:49:03", "data_exfiltration_module", "alert", "high", "Outbound volume spike to external host", json.dumps({"bytes": 2400000000})),
        ("2026-08-29 21:50:17", "regional_threat_intel", "info", "info", "New TT-CSIRT advisory ingested", json.dumps({"advisory": "TT-ADV-2026-084"})),
    ]
    for e in events:
        c.execute("INSERT INTO live_events (timestamp, module, event_type, severity, message, details) VALUES (?,?,?,?,?,?)", e)
    conn.commit()
    conn.close()

_simulator_running = False

def live_feed_simulator():
    global _simulator_running
    _simulator_running = True
    modules = ["continuous_ids_module", "data_exfiltration_module", "regional_threat_intel", "nmap_module"]
    severities = ["info", "low", "medium", "high", "critical"]
    messages = [
        "Behavioral baseline deviation detected",
        "New service version fingerprint matched CVE database",
        "Outbound connection to known C2 range blocked",
        "Compliance check against CMA Section 6 completed",
        "TT-CSIRT feed update received",
        "Anomalous DNS query pattern observed",
        "Session archival complete",
    ]
    while _simulator_running:
        time.sleep(random.uniform(4.0, 11.0))
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        module = random.choice(modules)
        severity = random.choices(severities, weights=[40, 25, 20, 10, 5])[0]
        msg = random.choice(messages)
        event = {
            "timestamp": now, "module": module,
            "event_type": "alert" if severity in ("high", "critical") else "info",
            "severity": severity, "message": msg,
            "details": json.dumps({"sim": True}),
        }
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("INSERT INTO live_events (timestamp, module, event_type, severity, message, details) VALUES (?,?,?,?,?,?)",
                (event["timestamp"], event["module"], event["event_type"], event["severity"], event["message"], event["details"]))
            conn.commit()
            conn.close()
            socketio.emit("live_event", event)
        except Exception as exc:
            logger.error("Simulator insert failed: %s", exc)

def ensure_sample_reports():
    for fname in ["CyberAudit_Report_AUD-20260829-001.pdf", "CyberAudit_Report_AUD-20260828-003.pdf", "CyberAudit_Report_AUD-20260827-002.pdf"]:
        path = REPORTS_DIR / fname
        if not path.exists():
            path.write_bytes(b"%PDF-1.4 placeholder CyberAudit report - TrinTech Digital Defense\n")

def ensure_sample_playbooks():
    pass  # playbooks already on disk / in repo

@app.route("/")
def index():
    return render_template("index.html", company=COMPANY)

@app.route("/api/status")
def api_status():
    conn = get_db()
    modules = [dict(r) for r in conn.execute("SELECT * FROM module_status ORDER BY module_name").fetchall()]
    recent = [dict(r) for r in conn.execute("SELECT * FROM live_events ORDER BY id DESC LIMIT 30").fetchall()]
    sessions = [dict(r) for r in conn.execute("SELECT * FROM audit_sessions ORDER BY start_time DESC LIMIT 10").fetchall()]
    conn.close()
    return jsonify({"modules": modules, "recent_events": recent, "sessions": sessions,
                    "server_time": datetime.datetime.now().isoformat(), "company": COMPANY})

@app.route("/api/events")
def api_events():
    limit = request.args.get("limit", 50, type=int)
    conn = get_db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM live_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/api/sessions")
def api_sessions():
    conn = get_db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM audit_sessions ORDER BY start_time DESC").fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/api/modules")
def api_modules():
    conn = get_db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM module_status").fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/reports")
def reports_page():
    files = sorted(REPORTS_DIR.glob("*.pdf"), key=lambda p: p.stat().st_mtime, reverse=True)
    report_list = [{"name": f.name, "size": f.stat().st_size,
                   "mtime": datetime.datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")} for f in files]
    return render_template("reports.html", company=COMPANY, reports=report_list)

@app.route("/download/report/<path:filename>")
def download_report(filename):
    path = REPORTS_DIR / filename
    if not path.exists() or not path.is_file():
        return "Report not found", 404
    return send_file(path, as_attachment=True, download_name=filename)

@app.route("/playbooks")
def playbooks_page():
    files = sorted(PLAYBOOKS_DIR.glob("*.md"))
    pb_list = []
    for f in files:
        content = f.read_text(encoding="utf-8")[:400] + "..."
        pb_list.append({"name": f.name, "preview": content, "size": f.stat().st_size})
    return render_template("playbooks.html", company=COMPANY, playbooks=pb_list)

@app.route("/playbook/<path:filename>")
def view_playbook(filename):
    path = PLAYBOOKS_DIR / filename
    if not path.exists():
        return "Playbook not found", 404
    content = path.read_text(encoding="utf-8")
    return render_template("playbook_view.html", company=COMPANY, name=filename, content=content)

@app.route("/download/playbook/<path:filename>")
def download_playbook(filename):
    path = PLAYBOOKS_DIR / filename
    if not path.exists():
        return "Not found", 404
    return send_file(path, as_attachment=True, download_name=filename)

@app.route("/live")
def live_page():
    return render_template("live.html", company=COMPANY)

@app.route("/about")
def about_page():
    return render_template("about.html", company=COMPANY)

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "CyberAudit Dashboard", "port": 1881})

@socketio.on("connect")
def on_connect():
    emit("status", {"msg": "Connected to CyberAudit live feed", "time": datetime.datetime.now().isoformat()})

@socketio.on("request_snapshot")
def on_snapshot():
    conn = get_db()
    events = [dict(r) for r in conn.execute("SELECT * FROM live_events ORDER BY id DESC LIMIT 25").fetchall()]
    conn.close()
    emit("snapshot", events)

if __name__ == "__main__":
    init_db()
    seed_sample_data()
    ensure_sample_reports()
    t = threading.Thread(target=live_feed_simulator, daemon=True)
    t.start()
    print("=" * 60)
    print(f"  {COMPANY['name']} - {COMPANY['product']} Dashboard")
    print(f"  Listening on http://0.0.0.0:1881")
    print("=" * 60)
    socketio.run(app, host="0.0.0.0", port=1881, debug=False, allow_unsafe_werkzeug=True)
