"""Structural PDF validation for CyberAudit deliverables."""
from __future__ import annotations

from pathlib import Path
from typing import Any


def validate_pdf(path: Path | str, *, min_pages: int = 1, require_parser: bool | None = None) -> dict[str, Any]:
    p = Path(path)
    result: dict[str, Any] = {"ok": False, "pages": 0, "error": ""}
    if require_parser is None:
        try:
            from cyberaudit import config
            require_parser = not bool(getattr(config, "DEMO_MODE", False))
        except Exception:
            require_parser = True
    if not p.is_file() or p.stat().st_size < 16:
        result["error"] = "missing or empty"
        return result
    if not p.read_bytes()[:8].startswith(b"%PDF-"):
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
        if require_parser:
            result["error"] = "pypdf required in production"
            return result
        data = p.read_bytes()
        if b"%%EOF" not in data or len(data) < 200:
            result["error"] = "pypdf unavailable and weak fallback failed"
            return result
        result["ok"] = True
        result["pages"] = -1
        result["error"] = "demo fallback: header+EOF only"
        return result
    except Exception as exc:
        result["error"] = f"parse failed: {exc}"[:200]
        return result
