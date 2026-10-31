"""CyberAudit pipeline engine — loads implementation parts.

3.10.1: body_1 provides recon/heuristics helpers; its legacy run_audit_job
(without ROE) is stripped so body_2's authorized pipeline is the only entry.
"""
from pathlib import Path
import re

_dir = Path(__file__).parent

def _load_part(path: Path, *, strip_run_audit: bool = False) -> str:
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8")
    if strip_run_audit:
        m = re.search(r"^def run_audit_job\(", text, flags=re.M)
        if m:
            text = text[: m.start()]
    return text

_code = "".join(
    [
        _load_part(_dir / "pipeline_body_0.txt"),
        _load_part(_dir / "pipeline_body_1.txt", strip_run_audit=True),
        _load_part(_dir / "pipeline_body_2.txt"),
    ]
)
exec(compile(_code, str(_dir / "pipeline_engine_impl.py"), "exec"), globals())
