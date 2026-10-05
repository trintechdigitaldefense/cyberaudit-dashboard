"""CyberAudit Flask application."""
from cyberaudit.app_src_0 import SRC as S0
from cyberaudit.app_src_1 import SRC as S1
from cyberaudit.app_src_2 import SRC as S2
_code = S0 + S1 + S2
_g = {"__name__": __name__, "__file__": __file__}
exec(compile(_code, __file__, "exec"), _g)
for _k, _v in _g.items():
    if not _k.startswith("_"):
        globals()[_k] = _v
