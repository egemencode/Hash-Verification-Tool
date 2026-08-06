"""
Local-store / history persistence: writes are atomic and failures are
raised (never silently swallowed), with in-memory rollback on failure.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.support import DiagnosticTempDir
from core import history_manager, local_verify
from core.history_manager import HistoryManager, HistoryStoreError, make_entry
from core.local_verify import LocalStoreError, LocalVerifyStore, LocalVerifyStatus


class LocalStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.path = Path(self.tmp.name) / "known_files.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_remember_then_compare_same(self) -> None:
        store = LocalVerifyStore(self.path)
        store.remember("C:/x/file.bin", "a" * 64, 10)
        result = store.compare("C:/x/file.bin", "a" * 64)
        self.assertEqual(result.status, LocalVerifyStatus.SAME)

    def test_write_failure_raises_and_rolls_back(self) -> None:
        store = LocalVerifyStore(self.path)
        with mock.patch.object(
            local_verify, "write_json_atomic", side_effect=OSError("disk full")
        ):
            with self.assertRaises(LocalStoreError):
                store.remember("C:/x/file.bin", "a" * 64, 10)
        # Rolled back: the record must not appear to exist.
        self.assertIsNone(store.get("C:/x/file.bin"))

    def test_forget_write_failure_rolls_back(self) -> None:
        store = LocalVerifyStore(self.path)
        store.remember("C:/x/file.bin", "a" * 64, 10)
        with mock.patch.object(
            local_verify, "write_json_atomic", side_effect=OSError("readonly")
        ):
            with self.assertRaises(LocalStoreError):
                store.forget("C:/x/file.bin")
        self.assertIsNotNone(store.get("C:/x/file.bin"))


class HistoryStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.path = Path(self.tmp.name) / "history.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _entry(self, name: str = "f.exe"):
        return make_entry(
            file_name=name,
            file_path=f"C:/x/{name}",
            sha256="a" * 64,
            risk_level="unknown",
            headline="test",
        )

    def test_add_and_read_back(self) -> None:
        hm = HistoryManager(self.path)
        hm.add(self._entry())
        self.assertEqual(len(hm.all()), 1)

    def test_add_write_failure_rolls_back(self) -> None:
        hm = HistoryManager(self.path)
        hm.add(self._entry("first.exe"))
        with mock.patch.object(
            history_manager, "write_json_atomic", side_effect=OSError("disk full")
        ):
            with self.assertRaises(HistoryStoreError):
                hm.add(self._entry("second.exe"))
        # The failed add must not remain in memory.
        names = [e.file_name for e in hm.all()]
        self.assertEqual(names, ["first.exe"])

    def test_clear_write_failure_keeps_entries(self) -> None:
        hm = HistoryManager(self.path)
        hm.add(self._entry())
        with mock.patch.object(
            history_manager, "write_json_atomic", side_effect=OSError("readonly")
        ):
            with self.assertRaises(HistoryStoreError):
                hm.clear()
        self.assertEqual(len(hm.all()), 1)


if __name__ == "__main__":
    unittest.main()
