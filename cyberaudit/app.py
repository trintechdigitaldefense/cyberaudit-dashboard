"""CyberAudit Flask application."""
from pathlib import Path
_dir = Path(__file__).parent
_code = "".join((_dir / f"app_body_{i}.txt").read_text(encoding="utf-8") for i in range(8))
exec(compile(_code, str(Path(__file__).with_name("app_impl.py")), "exec"), globals())
