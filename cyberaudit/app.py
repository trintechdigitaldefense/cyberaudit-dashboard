"""CyberAudit Flask app loader."""
from __future__ import annotations
import base64
import zlib
from cyberaudit.app_b64_a import PARTS as A
from cyberaudit.app_b64_b import PARTS as B

_code = zlib.decompress(base64.b64decode("".join(A + B))).decode("utf-8")
_g = {"__name__": __name__, "__file__": __file__}
exec(compile(_code, __file__, "exec"), _g)
for _k, _v in _g.items():
    if not _k.startswith("_"):
        globals()[_k] = _v
