"""Tests for atomic JSON/text persistence."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.support import DiagnosticTempDir
from core.atomic_io import write_json_atomic, write_text_atomic


class AtomicIOTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_writes_and_reads_back(self) -> None:
        target = self.root / "sub" / "data.json"
        write_json_atomic(target, {"a": 1, "b": "ç"})
        self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {"a": 1, "b": "ç"})

    def test_overwrite_replaces_content(self) -> None:
        target = self.root / "data.json"
        write_json_atomic(target, {"v": 1})
        write_json_atomic(target, {"v": 2})
        self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["v"], 2)

    def test_no_temp_files_left_behind(self) -> None:
        target = self.root / "data.json"
        write_json_atomic(target, {"v": 1})
        leftovers = [p.name for p in self.root.iterdir() if p.name != "data.json"]
        self.assertEqual(leftovers, [])

    def test_text_atomic(self) -> None:
        target = self.root / "note.txt"
        write_text_atomic(target, "merhaba ü")
        self.assertEqual(target.read_text(encoding="utf-8"), "merhaba ü")


class NoLeakedHandlesTests(unittest.TestCase):
    """
    Regression for the intermittent WinError 145 ("directory not empty"):
    a leaked file descriptor makes the temp file undeletable on Windows, so
    the write must never leave a descriptor open — on any path.
    """

    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        # If a handle leaked, THIS is what previously blew up.
        self.tmp.cleanup()

    def _stray(self) -> list[str]:
        return [p.name for p in self.root.iterdir() if p.name != "data.json"]

    def test_repeated_writes_leave_no_temp_files(self) -> None:
        target = self.root / "data.json"
        for i in range(200):
            write_json_atomic(target, {"i": i})
        self.assertEqual(self._stray(), [])
        self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["i"], 199)

    def test_replace_failure_removes_temp_file(self) -> None:
        target = self.root / "data.json"
        write_json_atomic(target, {"v": 0})
        with mock.patch("core.atomic_io.os.replace", side_effect=OSError("boom")):
            with self.assertRaises(OSError):
                write_json_atomic(target, {"v": 1})
        # Failed write: original intact, no leftovers to break directory removal.
        self.assertEqual(self._stray(), [])
        self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["v"], 0)

    def test_write_failure_leaves_directory_empty(self) -> None:
        # Previously this test deleted the leftovers itself, which hid the
        # very defect it was supposed to catch. Assert instead.
        target = self.root / "data.json"
        with mock.patch("core.atomic_io.os.write", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                write_json_atomic(target, {"v": 1})
        self.assertEqual(list(self.root.iterdir()), [])

    def test_fsync_failure_leaves_directory_empty(self) -> None:
        target = self.root / "data.json"
        with mock.patch("core.atomic_io.os.fsync", side_effect=OSError("no fsync")):
            with self.assertRaises(OSError):
                write_json_atomic(target, {"v": 1})
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
