"""C7 — Report archive & retrieval."""
from __future__ import annotations
import shutil
from pathlib import Path
from typing import Any
from cyberaudit import config

def list_reports(query: str = "", limit: int = 100) -> list[dict[str, Any]]:
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    q = (query or "").lower().strip()
    rows = []
    for p in sorted(config.REPORTS_DIR.glob("*"), key=lambda x: x.stat().st_mtime, reverse=True):
        if not p.is_file(): continue
        if q and q not in p.name.lower(): continue
        st = p.stat()
        rows.append({"name": p.name, "path": str(p), "bytes": st.st_size, "mtime": st.st_mtime, "kind": _kind(p.name)})
        if len(rows) >= limit: break
    return rows

def _kind(name: str) -> str:
    n = name.lower()
    if "board" in n: return "board_summary"
    if "executive" in n or n.endswith(".pdf"): return "executive"
    if "retest" in n or "delta" in n: return "retest_delta"
    if "state_of_cyber" in n: return "state_report"
    return "other"

def get_report(filename: str) -> Path | None:
    if not filename or ".." in filename or "/" in filename or "\\" in filename:
        return None
    candidate = (config.REPORTS_DIR / filename).resolve()
    try:
        candidate.relative_to(config.REPORTS_DIR.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None

def export_report(filename: str, dest_dir: Path) -> Path | None:
    src = get_report(filename)
    if not src: return None
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name
    shutil.copy2(src, dest)
    return dest
