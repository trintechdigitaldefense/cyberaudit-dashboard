"""P6.4 — Anonymized sector benchmark database. Consent required. No PII."""
from __future__ import annotations
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any
from cyberaudit import config

SECTORS = ("general", "retail", "finance", "healthcare", "education")

def _db_path() -> Path:
    return config.DATA_DIR / "benchmarks.db"

def init_benchmarks() -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_db_path()))
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS sector_baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT, sector TEXT NOT NULL,
            posture_score REAL NOT NULL, findings_total INTEGER,
            findings_critical INTEGER, findings_high INTEGER,
            year_month TEXT NOT NULL, created_at TEXT NOT NULL)""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_bench_sector ON sector_baselines(sector)")
        conn.commit()
    finally:
        conn.close()

def record_anonymous(*, sector: str, posture_score: float, findings_total: int = 0,
                     findings_critical: int = 0, findings_high: int = 0, consent: bool = False) -> bool:
    if not consent:
        return False
    sector = (sector or "general").lower().strip()
    if sector not in SECTORS: sector = "general"
    init_benchmarks()
    now = datetime.utcnow()
    conn = sqlite3.connect(str(_db_path()))
    try:
        conn.execute(
            "INSERT INTO sector_baselines (sector, posture_score, findings_total, findings_critical, findings_high, year_month, created_at) VALUES (?,?,?,?,?,?,?)",
            (sector, float(posture_score), int(findings_total), int(findings_critical), int(findings_high),
             now.strftime("%Y-%m"), now.strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()
        return True
    finally:
        conn.close()

def sector_stats(sector: str) -> dict[str, Any]:
    sector = (sector or "general").lower().strip()
    init_benchmarks()
    conn = sqlite3.connect(str(_db_path()))
    try:
        rows = conn.execute("SELECT posture_score FROM sector_baselines WHERE sector=? ORDER BY posture_score", (sector,)).fetchall()
    finally:
        conn.close()
    scores = [float(r[0]) for r in rows]
    if not scores:
        return {"sector": sector, "sample_size": 0, "average": None, "top_quartile": None,
                "message": f"No anonymized samples yet for sector '{sector}'."}
    n = len(scores)
    avg = sum(scores) / n
    top_q = scores[int(n * 0.75)] if n >= 4 else scores[-1]
    return {"sector": sector, "sample_size": n, "average": round(avg, 1), "top_quartile": round(top_q, 1),
            "min": round(scores[0], 1), "max": round(scores[-1], 1)}

def compare_client(sector: str, client_score: float) -> dict[str, Any]:
    stats = sector_stats(sector)
    if not stats["sample_size"]:
        return {**stats, "client_score": client_score,
                "director_line": f"Your posture score is {client_score:.0f}/100. Not enough anonymized {sector} samples yet to benchmark."}
    return {**stats, "client_score": client_score,
            "director_line": (
                f"{sector.title()} in our anonymized Caribbean sample averages {stats['average']}/100 "
                f"(n={stats['sample_size']}). Top performers sit near {stats['top_quartile']}/100. "
                f"You: {client_score:.0f}/100."
            )}
