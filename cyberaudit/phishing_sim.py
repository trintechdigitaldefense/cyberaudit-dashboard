"""P7.3 — Phishing simulation add-on (results ingest + director narrative)."""
from __future__ import annotations
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any
from cyberaudit import config

def _db() -> Path:
    return config.DATA_DIR / "phishing_sim.db"

def init_phishing_db() -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_db()))
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS campaigns (
            id TEXT PRIMARY KEY, name TEXT, sector TEXT,
            sent INTEGER DEFAULT 0, clicked INTEGER DEFAULT 0, reported INTEGER DEFAULT 0,
            failed INTEGER DEFAULT 0, created_at TEXT, notes TEXT)""")
        conn.commit()
    finally:
        conn.close()

def create_campaign(campaign_id: str, name: str, sector: str = "general", notes: str = "") -> dict:
    init_phishing_db()
    conn = sqlite3.connect(str(_db()))
    try:
        conn.execute("INSERT OR REPLACE INTO campaigns (id, name, sector, sent, clicked, reported, failed, created_at, notes) VALUES (?,?,?,0,0,0,0,?,?)",
                     (campaign_id, name, sector, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), notes))
        conn.commit()
    finally:
        conn.close()
    return {"id": campaign_id, "name": name, "status": "created"}

def ingest_results(campaign_id: str, results: dict) -> dict:
    init_phishing_db()
    if "sent" in results:
        sent, clicked, reported, failed = int(results.get("sent") or 0), int(results.get("clicked") or 0), int(results.get("reported") or 0), int(results.get("failed") or 0)
    else:
        rows = results.get("events") or results.get("results") or []
        sent = len(rows)
        clicked = sum(1 for r in rows if (r.get("action") or "").lower() in ("click", "clicked", "opened"))
        reported = sum(1 for r in rows if (r.get("action") or "").lower() in ("report", "reported"))
        failed = sum(1 for r in rows if (r.get("action") or "").lower() in ("fail", "failed", "bounce"))
    conn = sqlite3.connect(str(_db()))
    try:
        conn.execute("UPDATE campaigns SET sent=?, clicked=?, reported=?, failed=? WHERE id=?", (sent, clicked, reported, failed, campaign_id))
        if conn.total_changes == 0:
            conn.execute("INSERT INTO campaigns (id, name, sector, sent, clicked, reported, failed, created_at, notes) VALUES (?,?,?,?,?,?,?,?,?)",
                         (campaign_id, campaign_id, "general", sent, clicked, reported, failed, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), ""))
        conn.commit()
    finally:
        conn.close()
    return summarize_campaign(campaign_id)

def summarize_campaign(campaign_id: str) -> dict[str, Any]:
    init_phishing_db()
    conn = sqlite3.connect(str(_db()))
    try:
        row = conn.execute("SELECT id, name, sector, sent, clicked, reported, failed, created_at FROM campaigns WHERE id=?", (campaign_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return {"error": "not_found", "id": campaign_id}
    sent, clicked, reported = row[3], row[4], row[5]
    click_rate = (clicked / sent * 100) if sent else 0.0
    report_rate = (reported / sent * 100) if sent else 0.0
    if sent == 0:
        narrative = "No simulation results loaded yet."
    elif click_rate >= 30:
        narrative = f"About {click_rate:.0f}% of staff clicked a simulated phishing message. That is high — schedule awareness this month."
    elif click_rate >= 15:
        narrative = f"About {click_rate:.0f}% of staff clicked. Common for first simulations — retest in 90 days."
    else:
        narrative = f"Click rate was {click_rate:.0f}%. Encourage the {report_rate:.0f}% who reported suspicious mail."
    finding = None
    if sent:
        finding = {
            "host": "people", "port": "awareness",
            "severity": "high" if click_rate >= 30 else "medium" if click_rate >= 15 else "low",
            "title": f"Phishing simulation click rate {click_rate:.0f}%", "cve": "", "cma_section": "Section 7",
            "service": "phishing_sim", "evidence": narrative, "source": "phishing_sim",
            "plain": {"what": "Staff were tested with a safe simulated phishing message.",
                       "happen": "Real phishing is how many Caribbean businesses lose email and banking access.",
                       "do_this_week": "Share results with managers; thank people who reported.",
                       "do_this_month": "Run a 30-minute awareness session and schedule a retest."},
        }
    return {"id": row[0], "name": row[1], "sent": sent, "clicked": clicked, "reported": reported,
            "click_rate_pct": round(click_rate, 1), "report_rate_pct": round(report_rate, 1),
            "director_line": narrative, "finding": finding}
