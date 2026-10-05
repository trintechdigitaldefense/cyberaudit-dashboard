"""Real CyberAudit pipeline execution."""
from pathlib import Path
_dir = Path(__file__).parent
_code = (_dir / "pipeline_body_0.txt").read_text(encoding="utf-8") + (_dir / "pipeline_body_1.txt").read_text(encoding="utf-8")
exec(compile(_code, str(_dir / "pipeline_engine_impl.py"), "exec"), globals())
