"""Unit tests that do not require a running server."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path


def safe_file_under(root: Path, filename: str):
    if not filename or filename.strip() == "":
        return None
    if "\x00" in filename:
        return None
    candidate = (root / filename).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return candidate


class PathSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "ok.pdf").write_text("x", encoding="utf-8")
        (self.root / "sub").mkdir()
        (self.root / "sub" / "nested.md").write_text("y", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid(self):
        self.assertIsNotNone(safe_file_under(self.root, "ok.pdf"))

    def test_nested(self):
        self.assertIsNotNone(safe_file_under(self.root, "sub/nested.md"))

    def test_traversal(self):
        self.assertIsNone(safe_file_under(self.root, "../etc/passwd"))
        self.assertIsNone(safe_file_under(self.root, "/etc/passwd"))
        self.assertIsNone(safe_file_under(self.root, ".."))

    def test_null(self):
        self.assertIsNone(safe_file_under(self.root, "ok.pdf\x00"))


if __name__ == "__main__":
    unittest.main()
