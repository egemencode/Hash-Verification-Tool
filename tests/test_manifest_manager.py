"""Unit tests for core.manifest_manager."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.support import DiagnosticTempDir
from core.manifest_manager import (  # noqa: E402
    FileEntry,
    Manifest,
    ManifestError,
    build_manifest_for_folder,
)


class ManifestRoundtripTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.root = Path(self.tmp.name)
        (self.root / "a.txt").write_text("alpha")
        (self.root / "sub").mkdir()
        (self.root / "sub" / "b.txt").write_text("bravo")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_build_and_save_roundtrip(self) -> None:
        manifest = build_manifest_for_folder(self.root, algorithm="sha256").manifest
        self.assertEqual(len(manifest.entries), 2)

        target = self.root / "manifest.json"
        manifest.save(target)
        self.assertTrue(target.exists())

        loaded = Manifest.load(target)
        self.assertEqual(loaded.algorithm, "sha256")
        self.assertEqual(set(loaded.entries.keys()), set(manifest.entries.keys()))
        for key, original in manifest.entries.items():
            self.assertEqual(loaded.entries[key].hash, original.hash)

    def test_save_creates_parent_directories(self) -> None:
        manifest = build_manifest_for_folder(self.root).manifest
        nested_target = self.root / "out" / "nested" / "manifest.json"
        manifest.save(nested_target)
        self.assertTrue(nested_target.exists())

    def test_load_missing_manifest_raises(self) -> None:
        with self.assertRaises(ManifestError):
            Manifest.load(self.root / "missing.json")

    def test_load_invalid_json_raises(self) -> None:
        bad = self.root / "bad.json"
        bad.write_text("{not valid json")
        with self.assertRaises(ManifestError):
            Manifest.load(bad)

    def test_load_missing_sections_raises(self) -> None:
        bad = self.root / "incomplete.json"
        bad.write_text(json.dumps({"hello": "world"}))
        with self.assertRaises(ManifestError):
            Manifest.load(bad)

    def test_invalid_entry_raises(self) -> None:
        with self.assertRaises(ManifestError):
            FileEntry.from_dict({"hash": "abc"})  # missing fields

    def test_progress_callback_fires_for_every_file(self) -> None:
        events: list = []
        build_manifest_for_folder(self.root, on_progress=events.append)
        # setUp created 2 files
        self.assertEqual(len(events), 2)
        self.assertEqual(events[-1].done, 2)
        self.assertEqual(events[-1].total, 2)
        self.assertGreater(events[-1].percent, 99.0)


if __name__ == "__main__":
    unittest.main()
