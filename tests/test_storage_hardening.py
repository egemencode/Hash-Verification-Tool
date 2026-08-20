"""
P0.7 — storage, secret migration and PowerShell resolution.

Behaviour under test:
  * A legacy plaintext key must be migrated and scrubbed even when the new
    settings file already exists (the "already migrated once" path).
  * A crash between "protected copy written" and "plaintext scrubbed" must
    heal on the next launch.
  * A store that cannot be *read* (PermissionError) must fail closed: it may
    not later overwrite the file it could not read.
  * PowerShell must be located through the OS, not through an environment
    variable an attacker can set.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

from tests.support import DiagnosticTempDir
from core import secret_store, signature_checker as sc
from core.history_manager import HistoryManager, HistoryStoreError, make_entry
from core.local_verify import LocalStoreError, LocalVerifyStore
from utils import settings as S
from utils.settings import (
    KEY_VT_API_KEY,
    KEY_VT_API_KEY_ENC,
    SETTINGS_FILENAME,
    AppSettings,
)

_HAVE_DPAPI = secret_store.is_available()
IS_WINDOWS = sys.platform.startswith("win")
SECRET = "VT-KEY-THAT-MUST-NOT-SURVIVE"


class _Layout:
    def __init__(self, root: Path, *, new_settings: dict | None = None,
                 legacy: dict | None = None):
        self.exe = root / "app"
        self.user = root / "user"
        self.exe.mkdir(parents=True)
        self.user.mkdir(parents=True)
        if legacy is not None:
            (self.exe / SETTINGS_FILENAME).write_text(
                json.dumps(legacy), encoding="utf-8"
            )
        if new_settings is not None:
            d = self.user / "HashTool"
            d.mkdir(parents=True, exist_ok=True)
            (d / SETTINGS_FILENAME).write_text(
                json.dumps(new_settings), encoding="utf-8"
            )

    def patches(self):
        return (
            mock.patch.object(S, "_executable_dir", return_value=self.exe),
            mock.patch.dict(os.environ, {"LOCALAPPDATA": str(self.user)}),
        )

    @property
    def legacy_file(self) -> Path:
        return self.exe / SETTINGS_FILENAME

    @property
    def new_file(self) -> Path:
        return self.user / "HashTool" / SETTINGS_FILENAME


@unittest.skipUnless(_HAVE_DPAPI, "DPAPI (Windows) not available")
class LegacyKeyWithExistingProfileTests(unittest.TestCase):
    """The reported hole: new profile exists, legacy plaintext still there."""

    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        S.clear_migration_warnings()
        S._reset_write_disabled_for_tests()

    def tearDown(self) -> None:
        S.clear_migration_warnings()
        S._reset_write_disabled_for_tests()
        self._tmp.cleanup()

    def test_plaintext_is_migrated_even_when_new_profile_exists(self) -> None:
        layout = _Layout(
            self.root,
            new_settings={"language": "tr"},          # profile already migrated once
            legacy={KEY_VT_API_KEY: SECRET, "language": "en"},
        )
        p1, p2 = layout.patches()
        with p1, p2:
            loaded = AppSettings.load()
            new_text = layout.new_file.read_text(encoding="utf-8")
            legacy_text = layout.legacy_file.read_text(encoding="utf-8")

        self.assertEqual(loaded.virustotal_api_key, SECRET, "key was not recovered")
        self.assertNotIn(SECRET, new_text)
        self.assertNotIn(SECRET, legacy_text)
        self.assertIn(KEY_VT_API_KEY_ENC, json.loads(new_text))

    def test_crash_between_encrypt_and_scrub_heals_next_launch(self) -> None:
        # Simulate the interrupted state: protected slot already written,
        # plaintext still sitting in the legacy file.
        token = secret_store.protect(SECRET)
        layout = _Layout(
            self.root,
            new_settings={KEY_VT_API_KEY_ENC: token, "language": "tr"},
            legacy={KEY_VT_API_KEY: SECRET, "keep": "me"},
        )
        p1, p2 = layout.patches()
        with p1, p2:
            loaded = AppSettings.load()
            legacy_raw = json.loads(layout.legacy_file.read_text(encoding="utf-8"))

        self.assertEqual(loaded.virustotal_api_key, SECRET)
        self.assertNotIn(KEY_VT_API_KEY, legacy_raw, "plaintext was not scrubbed")
        self.assertEqual(legacy_raw.get("keep"), "me", "unrelated settings lost")


class UnreadableStoreFailsClosedTests(unittest.TestCase):
    """A store we could not read must never be overwritten."""

    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _deny(self, target: Path):
        real_open = Path.open

        def denied(self_path, *a, **kw):
            if str(self_path) == str(target):
                raise PermissionError("locked by another process")
            return real_open(self_path, *a, **kw)

        return mock.patch.object(Path, "open", denied)

    def test_history_permission_error_disables_writes(self) -> None:
        path = self.root / "history.json"
        payload = json.dumps({"schema": "trust-history/1.0", "entries": [{"file_name": "keep"}]})
        path.write_text(payload, encoding="utf-8")
        before = path.read_bytes()

        with self._deny(path):
            hm = HistoryManager(path)
            hm.all()
            self.assertTrue(hm.write_disabled, "unreadable history must fail closed")
            with self.assertRaises(HistoryStoreError):
                hm.add(
                    make_entry(
                        file_name="new", file_path="C:/n", sha256="a" * 64,
                        risk_level="unknown", headline="h",
                    )
                )
        self.assertEqual(path.read_bytes(), before, "unreadable file was overwritten")

    def test_local_store_permission_error_disables_writes(self) -> None:
        path = self.root / "known_files.json"
        payload = json.dumps({"schema": "trust-store/1.0", "records": {"x": {}}})
        path.write_text(payload, encoding="utf-8")
        before = path.read_bytes()

        with self._deny(path):
            store = LocalVerifyStore(path)
            store.all()
            self.assertTrue(store.write_disabled)
            with self.assertRaises(LocalStoreError):
                store.remember("C:/x/f.bin", "a" * 64, 1)
        self.assertEqual(path.read_bytes(), before)

    def test_permission_error_does_not_quarantine(self) -> None:
        # A locked file may hold perfectly good data — moving it would be
        # destructive.
        path = self.root / "history.json"
        path.write_text(json.dumps({"entries": []}), encoding="utf-8")
        with self._deny(path):
            HistoryManager(path).all()
        self.assertEqual(list(self.root.glob("*.corrupt*")), [])


class PowerShellResolutionTests(unittest.TestCase):
    """The interpreter path must not come from a spoofable env var."""

    def test_spoofed_systemroot_is_not_trusted(self) -> None:
        with DiagnosticTempDir() as d:
            fake = Path(d) / "System32" / "WindowsPowerShell" / "v1.0"
            fake.mkdir(parents=True)
            planted = fake / "powershell.exe"
            planted.write_bytes(b"MZ evil")

            with mock.patch.dict(os.environ, {"SystemRoot": d, "windir": d}):
                if IS_WINDOWS:
                    resolved = sc._powershell_executable()
                    self.assertNotEqual(
                        Path(resolved).resolve(), planted.resolve(),
                        "a planted powershell.exe under a spoofed SystemRoot was used",
                    )
                else:
                    with self.assertRaises(FileNotFoundError):
                        sc._powershell_executable()

    @unittest.skipUnless(IS_WINDOWS, "Windows-only")
    def test_resolves_under_real_windows_directory(self) -> None:
        resolved = Path(sc._powershell_executable())
        self.assertTrue(resolved.is_file())
        real_windows = Path(sc._windows_directory())
        self.assertTrue(
            str(resolved).lower().startswith(str(real_windows).lower()),
            f"{resolved} is not under {real_windows}",
        )

    @unittest.skipUnless(IS_WINDOWS, "Windows-only")
    def test_fails_closed_when_the_winapi_call_fails(self) -> None:
        # If the OS cannot tell us where Windows is, we must refuse — not fall
        # back to an environment variable an attacker may control.
        with DiagnosticTempDir() as d:
            with mock.patch.dict(os.environ, {"SystemRoot": d, "windir": d}), \
                 mock.patch.object(sc, "_system_directory", return_value=None), \
                 mock.patch(
                     "ctypes.windll.kernel32.GetWindowsDirectoryW", return_value=0
                 ):
                self.assertIsNone(sc._windows_directory())
                with self.assertRaises(FileNotFoundError):
                    sc._powershell_executable()

    @unittest.skipUnless(IS_WINDOWS, "Windows-only")
    def test_windows_directory_ignores_env(self) -> None:
        with DiagnosticTempDir() as d:
            with mock.patch.dict(os.environ, {"SystemRoot": d, "windir": d}):
                self.assertNotEqual(
                    Path(sc._windows_directory()).resolve(), Path(d).resolve()
                )


if __name__ == "__main__":
    unittest.main()
