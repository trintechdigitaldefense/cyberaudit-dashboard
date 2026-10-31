"""Structural PDF validation for CyberAudit deliverables."""
from __future__ import annotations

from pathlib import Path
from typing import Any


def validate_pdf(path: Path | str, *, min_pages: int = 1) -> dict[str, Any]:
    """Return {ok, pages, error}. Uses pypdf when available; rejects header-only fakes."""
    p = Path(path)
    result: dict[str, Any] = {"ok": False, "pages": 0, "error": ""}
    if not p.is_file() or p.stat().st_size < 16:
        result["error"] = "missing or empty"
        return result
    raw = p.read_bytes()[:8]
    if not raw.startswith(b"%PDF-"):
        result["error"] = "not a PDF header"
        return result
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(p))
        if getattr(reader, "is_encrypted", False):
            try:
                reader.decrypt("")
            except Exception:
                result["error"] = "encrypted"
                return result
        n = len(reader.pages)
        result["pages"] = n
        if n < min_pages:
            result["error"] = f"page_count={n} < {min_pages}"
            return result
        result["ok"] = True
        return result
    except ImportError:
        data = p.read_bytes()
        if b"%%EOF" not in data[-1024:] and b"%%EOF" not in data:
            result["error"] = "missing %%EOF (install pypdf for full validation)"
            return result
        if len(data) < 200:
            result["error"] = "suspiciously small PDF"
            return result
        result["ok"] = True
        result["pages"] = -1
        result["error"] = "pypdf not installed; header+EOF only"
        return result
    except Exception as exc:
        result["error"] = f"parse failed: {exc}"[:200]
        return result
