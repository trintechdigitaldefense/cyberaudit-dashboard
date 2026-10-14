"""CyberAudit 3.1 — client network mapping pipeline."""
from pathlib import Path
_dir = Path(__file__).parent
_parts = [
    _dir / "pipeline_body_0.txt",
    _dir / "pipeline_body_1.txt",
    _dir / "pipeline_body_2.txt",
]
_code = "".join(p.read_text(encoding="utf-8") for p in _parts if p.exists())
exec(compile(_code, str(_dir / "pipeline_engine_impl.py"), "exec"), globals())
