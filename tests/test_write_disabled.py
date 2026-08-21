"""
When a corrupt store cannot be preserved, the tool must refuse to write.

The property these tests assert is user-observable and destructive if wrong:
the **original bytes on disk stay byte-for-byte unchanged**, so the data can
still be recovered by hand.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.support import DiagnosticTempDir, same_path
from core import atomic_io, history_manager, local_verify
from utils import settings as settings_mod
from core.history_manager import HistoryManager, HistoryStoreError, make_entry
from core.local_verify import LocalStoreError, LocalVerifyStore
from utils.settings import AppSettings, SettingsError

CORRUPT = b"{ this is definitely not json \x00\xff"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class _QuarantineFails:
    """Context manager forcing quarantine_corrupt_file to fail."""

    def __init__(self, *modules):
        self._patches = [
            mock.patch.object(m, "quarantine_corrupt_file", return_value=None)
            for m in modules
        ]

    def __enter__(self):
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *a):
        for p in self._patches:
            p.stop()


class HistoryWriteDisabledTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.path = Path(self.tmp.name) / "history.json"
        self.path.write_bytes(CORRUPT)
        self.before = _digest(self.path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_add_refuses_and_leaves_bytes_untouched(self) -> None:
        with _QuarantineFails(history_manager):
            hm = HistoryManager(self.path)
            hm.all()  # triggers the load + failed quarantine
            self.assertTrue(hm.write_disabled)
            with self.assertRaises(HistoryStoreError):
                hm.add(
                    make_entry(
                        file_name="f", file_path="C:/f", sha256="a" * 64,
                        risk_level="unknown", headline="h",
                    )
                )
        self.assertEqual(_digest(self.path), self.before)
        self.assertEqual(self.path.read_bytes(), CORRUPT)

    def test_clear_refuses_and_leaves_bytes_untouched(self) -> None:
        with _QuarantineFails(history_manager):
            hm = HistoryManager(self.path)
            hm.all()
            with self.assertRaises(HistoryStoreError):
                hm.clear()
        self.assertEqual(self.path.read_bytes(), CORRUPT)

    def test_successful_quarantine_allows_writing(self) -> None:
        # Control: when the corrupt file CAN be preserved, we may start fresh.
        hm = HistoryManager(self.path)
        hm.all()
        self.assertFalse(hm.write_disabled)
        hm.add(
            make_entry(
                file_name="f", file_path="C:/f", sha256="a" * 64,
                risk_level="unknown", headline="h",
            )
        )
        self.assertEqual(len(hm.all()), 1)
        quarantined = list(self.path.parent.glob("history.json.corrupt*"))
        self.assertTrue(quarantined)
        self.assertEqual(quarantined[0].read_bytes(), CORRUPT)


class LocalStoreWriteDisabledTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.path = Path(self.tmp.name) / "known_files.json"
        self.path.write_bytes(CORRUPT)
        self.before = _digest(self.path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_remember_refuses_and_leaves_bytes_untouched(self) -> None:
        with _QuarantineFails(local_verify):
            store = LocalVerifyStore(self.path)
            store.all()
            self.assertTrue(store.write_disabled)
            with self.assertRaises(LocalStoreError):
                store.remember("C:/x/file.bin", "a" * 64, 10)
        self.assertEqual(_digest(self.path), self.before)

    def test_forget_refuses_when_write_disabled(self) -> None:
        with _QuarantineFails(local_verify):
            store = LocalVerifyStore(self.path)
            store.all()
            # Nothing tracked, so forget() returns False without writing;
            # a tracked entry would raise. Either way the file is untouched.
            store.forget("C:/x/file.bin")
        self.assertEqual(self.path.read_bytes(), CORRUPT)

    def test_successful_quarantine_allows_writing(self) -> None:
        store = LocalVerifyStore(self.path)
        store.all()
        self.assertFalse(store.write_disabled)
        store.remember("C:/x/file.bin", "a" * 64, 10)
        quarantined = list(self.path.parent.glob("known_files.json.corrupt*"))
        self.assertTrue(quarantined)
        self.assertEqual(quarantined[0].read_bytes(), CORRUPT)


class SettingsCorruptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.base = Path(self.tmp.name)
        self.path = self.base / "hashtool_settings.json"
        settings_mod.clear_migration_warnings()
        settings_mod._reset_write_disabled_for_tests()

    def tearDown(self) -> None:
        settings_mod._reset_write_disabled_for_tests()
        settings_mod.clear_migration_warnings()
        self.tmp.cleanup()

    def test_corrupt_settings_are_quarantined_with_warning(self) -> None:
        self.path.write_bytes(CORRUPT)
        with mock.patch.object(settings_mod, "_base_dir", return_value=self.base):
            data = settings_mod.load_settings()
            warnings = settings_mod.pending_migration_warnings()
        self.assertEqual(data, {})
        self.assertTrue(warnings, "a corrupt settings file must be reported")
        quarantined = list(self.base.glob("hashtool_settings.json.corrupt*"))
        self.assertTrue(quarantined, "corrupt settings were not preserved")
        self.assertEqual(quarantined[0].read_bytes(), CORRUPT)

    def test_quarantine_failure_disables_saving(self) -> None:
        self.path.write_bytes(CORRUPT)
        with mock.patch.object(settings_mod, "_base_dir", return_value=self.base), \
             mock.patch.object(settings_mod, "quarantine_corrupt_file", return_value=None):
            settings_mod.load_settings()
            disabled, reason = settings_mod.settings_write_disabled()
            self.assertTrue(disabled)
            self.assertTrue(reason)
            with self.assertRaises(SettingsError):
                settings_mod.save_settings({"language": "en"})
        # Original bytes must survive untouched.
        self.assertEqual(self.path.read_bytes(), CORRUPT)

    def test_appsettings_save_surfaces_the_error(self) -> None:
        self.path.write_bytes(CORRUPT)
        with mock.patch.object(settings_mod, "_base_dir", return_value=self.base), \
             mock.patch.object(settings_mod, "quarantine_corrupt_file", return_value=None):
            settings = AppSettings()
            settings.language = "en"
            with self.assertRaises(SettingsError):
                settings.save()
        self.assertEqual(self.path.read_bytes(), CORRUPT)

    def test_locked_file_is_not_quarantined(self) -> None:
        # An OSError (locked / permission) does NOT mean the content is bad —
        # moving it could destroy good data, so it must stay put.
        self.path.write_text(json.dumps({"language": "en"}), encoding="utf-8")
        before = self.path.read_bytes()

        real_open = Path.open

        def locked(self_path, *args, **kwargs):
            if same_path(self_path, self.path):
                raise PermissionError("locked by another process")
            return real_open(self_path, *args, **kwargs)

        with mock.patch.object(settings_mod, "_base_dir", return_value=self.base), \
             mock.patch.object(Path, "open", locked):
            data = settings_mod.load_settings()
            disabled, _reason = settings_mod.settings_write_disabled()

        self.assertEqual(data, {})
        self.assertTrue(disabled, "writing must be refused while the file is unreadable")
        self.assertEqual(list(self.base.glob("*.corrupt*")), [])
        self.assertEqual(self.path.read_bytes(), before)

    def test_valid_settings_untouched(self) -> None:
        self.path.write_text(json.dumps({"language": "en"}), encoding="utf-8")
        with mock.patch.object(settings_mod, "_base_dir", return_value=self.base):
            data = settings_mod.load_settings()
            disabled, _ = settings_mod.settings_write_disabled()
        self.assertEqual(data["language"], "en")
        self.assertFalse(disabled)
        self.assertEqual(list(self.base.glob("*.corrupt*")), [])


if __name__ == "__main__":
    unittest.main()
