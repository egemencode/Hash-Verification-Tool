"""
Settings storage: secure API-key handling (P1.3) + location/validation (P1.4).
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.support import DiagnosticTempDir
from core import secret_store
from utils import settings as settings_mod
from utils.settings import (
    KEY_VT_API_KEY,
    KEY_VT_API_KEY_ENC,
    AppSettings,
    SettingsError,
    _valid_history_limit,
    _valid_language,
)

_HAVE_DPAPI = secret_store.is_available()


class ValidationTests(unittest.TestCase):
    def test_history_limit_coerces_bad_values(self) -> None:
        self.assertEqual(_valid_history_limit("abc"), 50)
        self.assertEqual(_valid_history_limit(-5), 1)
        self.assertEqual(_valid_history_limit(10 ** 9), 10_000)
        self.assertEqual(_valid_history_limit(123), 123)

    def test_language_falls_back(self) -> None:
        self.assertEqual(_valid_language("de"), "tr")
        self.assertEqual(_valid_language("en"), "en")
        self.assertEqual(_valid_language(None), "tr")


class _RedirectedBaseDir:
    """Context manager pointing settings at a temp base dir."""

    def __init__(self, base: Path) -> None:
        self.base = base
        self._patch = mock.patch.object(settings_mod, "_base_dir", return_value=base)

    def __enter__(self):
        self._patch.start()
        return self

    def __exit__(self, *a):
        self._patch.stop()


@unittest.skipUnless(_HAVE_DPAPI, "DPAPI (Windows) not available")
class SecretStoreTests(unittest.TestCase):
    def test_protect_unprotect_round_trip(self) -> None:
        token = secret_store.protect("super-secret-key")
        self.assertNotIn("super-secret-key", token)
        self.assertEqual(secret_store.unprotect(token), "super-secret-key")

    def test_redact(self) -> None:
        line = "using key abc123 now"
        self.assertNotIn("abc123", secret_store.redact("abc123", line))


@unittest.skipUnless(_HAVE_DPAPI, "DPAPI (Windows) not available")
class ApiKeyStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.base = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_key_saved_encrypted_not_plaintext(self) -> None:
        with _RedirectedBaseDir(self.base):
            s = AppSettings.load()
            s.virustotal_api_key = "MY-VT-KEY-123"
            s.save()
            raw = json.loads((self.base / "hashtool_settings.json").read_text(encoding="utf-8"))
        self.assertNotIn(KEY_VT_API_KEY, raw)          # no plaintext slot
        self.assertIn(KEY_VT_API_KEY_ENC, raw)         # encrypted slot present
        self.assertNotIn("MY-VT-KEY-123", json.dumps(raw))  # value never in the file

    def test_key_round_trips_through_load(self) -> None:
        with _RedirectedBaseDir(self.base):
            s = AppSettings.load()
            s.virustotal_api_key = "round-trip-key"
            s.save()
            reloaded = AppSettings.load()
        self.assertEqual(reloaded.virustotal_api_key, "round-trip-key")

    def test_legacy_plaintext_is_migrated(self) -> None:
        with _RedirectedBaseDir(self.base):
            # Simulate an old settings file with a plaintext key.
            (self.base).mkdir(parents=True, exist_ok=True)
            (self.base / "hashtool_settings.json").write_text(
                json.dumps({KEY_VT_API_KEY: "old-plain-key"}), encoding="utf-8"
            )
            loaded = AppSettings.load()  # triggers migration
            raw = json.loads((self.base / "hashtool_settings.json").read_text(encoding="utf-8"))
        self.assertEqual(loaded.virustotal_api_key, "old-plain-key")
        self.assertNotIn(KEY_VT_API_KEY, raw)      # plaintext removed
        self.assertIn(KEY_VT_API_KEY_ENC, raw)     # now protected

    def test_clearing_key_removes_encrypted_slot(self) -> None:
        with _RedirectedBaseDir(self.base):
            s = AppSettings.load()
            s.virustotal_api_key = "temp"
            s.save()
            s.virustotal_api_key = ""
            s.save()
            raw = json.loads((self.base / "hashtool_settings.json").read_text(encoding="utf-8"))
        self.assertNotIn(KEY_VT_API_KEY_ENC, raw)


class LocationTests(unittest.TestCase):
    def test_portable_marker_switches_base_dir(self) -> None:
        with DiagnosticTempDir() as d:
            exe_dir = Path(d)
            with mock.patch.object(settings_mod, "_executable_dir", return_value=exe_dir):
                # No marker -> LOCALAPPDATA-based (not the exe dir).
                self.assertNotEqual(settings_mod._base_dir(), exe_dir)
                # Marker present -> exe-adjacent (portable).
                (exe_dir / settings_mod.PORTABLE_MARKER).write_text("", encoding="utf-8")
                self.assertTrue(settings_mod.is_portable())
                self.assertEqual(settings_mod._base_dir(), exe_dir)

    def test_default_base_uses_localappdata(self) -> None:
        with DiagnosticTempDir() as d:
            exe_dir = Path(d) / "exe"
            local = Path(d) / "local"
            exe_dir.mkdir()
            with mock.patch.object(settings_mod, "_executable_dir", return_value=exe_dir), \
                 mock.patch.dict(os.environ, {"LOCALAPPDATA": str(local)}):
                self.assertEqual(settings_mod._base_dir(), local / "HashTool")


if __name__ == "__main__":
    unittest.main()
