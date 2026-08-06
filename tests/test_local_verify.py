"""Round-trip tests for the local fingerprint store."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.support import DiagnosticTempDir
from core.local_verify import LocalVerifyStatus, LocalVerifyStore


class LocalVerifyStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.store_path = Path(self.tmp.name) / "known.json"
        self.file_path = Path(self.tmp.name) / "sample.txt"
        self.file_path.write_text("hello", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_not_tracked_initially(self) -> None:
        store = LocalVerifyStore(self.store_path)
        result = store.compare(self.file_path, "abc123")
        self.assertEqual(result.status, LocalVerifyStatus.NOT_TRACKED)

    def test_remember_then_same(self) -> None:
        store = LocalVerifyStore(self.store_path)
        store.remember(self.file_path, "abc", size=5)
        result = store.compare(self.file_path, "abc")
        self.assertEqual(result.status, LocalVerifyStatus.SAME)

    def test_remember_then_changed(self) -> None:
        store = LocalVerifyStore(self.store_path)
        store.remember(self.file_path, "abc", size=5)
        result = store.compare(self.file_path, "xyz")
        self.assertEqual(result.status, LocalVerifyStatus.CHANGED)
        self.assertEqual(result.previous_hash, "abc")
        self.assertEqual(result.current_hash, "xyz")

    def test_persistence_across_instances(self) -> None:
        first = LocalVerifyStore(self.store_path)
        first.remember(self.file_path, "abc", size=5)

        second = LocalVerifyStore(self.store_path)
        result = second.compare(self.file_path, "abc")
        self.assertEqual(result.status, LocalVerifyStatus.SAME)

    def test_forget_removes_record(self) -> None:
        store = LocalVerifyStore(self.store_path)
        store.remember(self.file_path, "abc", size=5)
        self.assertTrue(store.forget(self.file_path))
        result = store.compare(self.file_path, "abc")
        self.assertEqual(result.status, LocalVerifyStatus.NOT_TRACKED)


if __name__ == "__main__":
    unittest.main()
