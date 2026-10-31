"""CyberAudit 3.10 Phase 9 — docs and version presence."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def test_release_notes_exist():
    p = ROOT / "docs" / "RELEASE_NOTES_3.10.md"
    assert p.is_file()
    text = p.read_text(encoding="utf-8")
    assert "3.10" in text
    assert "point-in-time" in text.lower()
    assert "24/7" in text.lower()


def test_dod_checklist_exist():
    p = ROOT / "docs" / "DOD_CHECKLIST_3.10.md"
    assert p.is_file()
    text = p.read_text(encoding="utf-8")
    assert "ROE" in text
    assert "mandatory" in text.lower()
    assert "idle" in text.lower()


def test_changelog_has_all_phases():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    for n in range(1, 10):
        assert f"Phase {n}" in text, f"missing Phase {n}"


def test_version_is_310():
    from cyberaudit import config
    ver = str(getattr(config, "VERSION", "") or config.COMPANY.get("version", ""))
    assert ver.startswith("3.10"), f"unexpected version: {ver}"


def test_readme_version_line():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "3.10.0" in text
