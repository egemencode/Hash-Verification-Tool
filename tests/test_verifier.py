"""Unit tests for core.verifier."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.support import DiagnosticTempDir
from core.manifest_manager import build_manifest_for_folder  # noqa: E402
from core.verifier import Verifier  # noqa: E402


class VerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.root = Path(self.tmp.name)
        (self.root / "stable.txt").write_text("stable content")
        (self.root / "will_change.txt").write_text("original content")
        (self.root / "will_disappear.txt").write_text("temporary content")
        self.manifest = build_manifest_for_folder(self.root).manifest

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_clean_run_reports_only_unchanged(self) -> None:
        result = Verifier(self.manifest).verify(self.root)
        self.assertTrue(result.is_clean)
        self.assertEqual(len(result.unchanged), 3)
        self.assertEqual(result.summary()["modified"], 0)

    def test_modifications_new_and_missing_are_classified(self) -> None:
        # Mutate the live folder.
        (self.root / "will_change.txt").write_text("MODIFIED CONTENT")
        (self.root / "will_disappear.txt").unlink()
        (self.root / "brand_new.txt").write_text("hello")

        result = Verifier(self.manifest).verify(self.root)
        summary = result.summary()

        self.assertEqual(summary["unchanged"], 1)
        self.assertEqual(summary["modified"], 1)
        self.assertEqual(summary["new"], 1)
        self.assertEqual(summary["missing"], 1)
        self.assertFalse(result.is_clean)

        self.assertEqual(result.modified[0].path, "will_change.txt")
        self.assertEqual(result.missing[0], "will_disappear.txt")
        self.assertEqual(result.new[0], "brand_new.txt")

    def test_serialisable_to_dict(self) -> None:
        result = Verifier(self.manifest).verify(self.root)
        data = result.to_dict()
        self.assertIn("summary", data)
        self.assertIn("details", data)
        self.assertIn("unchanged", data["details"])

    def test_progress_callback_fires_for_every_file(self) -> None:
        events: list = []
        Verifier(self.manifest).verify(self.root, on_progress=events.append)
        # setUp created 3 files: one event each, then the terminal event.
        per_file = [e for e in events if not e.is_terminal]
        self.assertEqual(len(per_file), 3)
        self.assertEqual(per_file[-1].done, 3)
        self.assertEqual(per_file[-1].total, 3)

        self.assertTrue(events[-1].is_terminal)


if __name__ == "__main__":
    unittest.main()
