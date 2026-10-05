"""CyberAudit Flask app (source stored compressed for transport)."""
from __future__ import annotations
import base64
import sys
import types
import zlib

_B64 = (
    "eNrNPO1y4zaS//0UKGypQiayLHsmczlVdInH1sxoY1teSZPslONiUSJkcU2RGpLyx7pctQ+xT3hP"
    "ct34IkCRsuyZXDapGpNAA+hu9DdAUUrfRX52TfzlMgqnfh4mMZn50zxJ74kfByRNVjnLWpTSnVma"
    "LIjnzVb5KmWeR8LFMklzgIqTnA/MdmRT4OcsDxdMvf8jS2L1HCVXV2F8pV4TPShj05TlxetqskyT"
    "Kct0Sz5PmR8YY/kSHKsZp0E2OzsE/uNkNfmjP4Fm8YiYhLN78ZKyIEzZNFdvccBSL2eLZQT4q8bP"
    "K5ZJiAwgvFkYMfWaZUC1eFmlkTdL0uaOa2DkZcn0GjiRKNRG/L0/aJIgzKZJHOPqhC3CXIya3k9Y"
    "6q+CMFcjAGgWXpV7W6JZAbE4wy0BarI1yGBi8yWYeGHmAZG55MIVy71gIp7DODRfMpbmQHCMTLfa"
    "ovCGeeyGxZozLPAyHzgHWPi5r1pzzQHJpSUfzjHzbP6JnkUSrGCODARqlWlmGuSAlKzSML+3iQJ2"
    "ZLnHPou5AAI2M/fSRG0V4A+76OXJNYs93FPY90B0gTyG5bZkCcuBCpSaM3/G+P57KxQV2cgJBJLy"
    "OayJKoTg64jfJuk1SzOFdxhPkjtvmUQRTEQ4P2ecieFiFeHaTZC9HGdMYk+M3TG22XF3QGNJV4i5"
    "43mxvwCd5K1SOC7oqHc07I29X3qf6CWAiuZW0WoBj3un5yeH497IO/w4HnjD3sng8JiPG6crVpp3"
    "NOoPzryjweCXfs/7MB6fD85OPm0FPDo87Y364x4Hpif+Hd0JZwo1BdM7+jjsdYTubpiKgxWramXr"
    "aj1z1BxNWCLNPD+KklvgcpKGsOtZV657eHIy+K137A2G/ff9s1GT+Nl9PEVhZF2qzQ6FXTVF2lEP"
)
_code = zlib.decompress(base64.b64decode("".join(_B64))).decode("utf-8")
_g = {"__name__": __name__, "__file__": __file__}
exec(compile(_code, __file__, "exec"), _g)
for _k, _v in _g.items():
    if not _k.startswith("_"):
        globals()[_k] = _v
