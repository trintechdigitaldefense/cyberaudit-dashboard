"""Client-facing CyberAudit reports — plain language for non-technical readers."""
from pathlib import Path
_dir = Path(__file__).parent
_code = (_dir / "report_body_0.txt").read_text(encoding="utf-8") + (_dir / "report_body_1.txt").read_text(encoding="utf-8")
exec(compile(_code, str(_dir / "report_generator_impl.py"), "exec"), globals())
