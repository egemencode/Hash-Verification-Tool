"""
Blocker 4 regression suite: after migrating a legacy plaintext API key into
DPAPI-protected storage, **no plaintext copy may survive** — neither in the
new per-user file nor in the original exe-adjacent one.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core import secret_store
from tests.support import DiagnosticTempDir
from utils import settings as settings_mod
from utils.settings import (
    KEY_VT_API_KEY,
    KEY_VT_API_KEY_ENC,
    SETTINGS_FILENAME,
    AppSettings,
)

_HAVE_DPAPI = secret_store.is_available()
SECRET = "VT-LEGACY-PLAINTEXT-KEY-9931"


class _LegacyLayout:
    """An old install: settings + data sitting next to the executable."""

    def __init__(self, tmp: Path, *, with_settings: bool = True, with_data: bool = True):
        self.exe_dir = tmp / "app"
        self.user_dir = tmp / "user"
        self.exe_dir.mkdir(parents=True)
        self.user_dir.mkdir(parents=True)
        if with_settings:
            (self.exe_dir / SETTINGS_FILENAME).write_text(
                json.dumps(
                    {
                        KEY_VT_API_KEY: SECRET,
                        "language": "en",
                        "some_unknown_setting": "keep-me",
                    }
                ),
                encoding="utf-8",
            )
        if with_data:
            data = self.exe_dir / "data"
            data.mkdir()
            (data / "history.json").write_text(
                json.dumps({"schema": "trust-history/1.0", "entries": []}), encoding="utf-8"
            )
            (data / "known_files.json").write_text(
                json.dumps({"schema": "trust-store/1.0", "records": {}}), encoding="utf-8"
            )

    def patches(self):
        return (
            mock.patch.object(settings_mod, "_executable_dir", return_value=self.exe_dir),
            mock.patch.dict(os.environ, {"LOCALAPPDATA": str(self.user_dir)}),
        )

    @property
    def legacy_settings(self) -> Path:
        return self.exe_dir / SETTINGS_FILENAME

    @property
    def new_settings(self) -> Path:
        return self.user_dir / "HashTool" / SETTINGS_FILENAME


class MigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        # DiagnosticTempDir fails loudly *with a file listing* if anything is
        # left behind, so an intermittent "directory not empty" names the file
        # instead of being masked by ignore_cleanup_errors/retries.
        self.tmp = DiagnosticTempDir(prefix="hvt-migration-")
        self.root = self.tmp.path
        settings_mod.clear_migration_warnings()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @unittest.skipUnless(_HAVE_DPAPI, "DPAPI (Windows) not available")
    def test_no_plaintext_survives_in_either_file(self) -> None:
        """The mandated test for this blocker."""
        layout = _LegacyLayout(self.root)
        p1, p2 = layout.patches()
        with p1, p2:
            loaded = AppSettings.load()
            self.assertEqual(loaded.virustotal_api_key, SECRET)
            self.assertTrue(loaded.key_migrated)

            new_text = layout.new_settings.read_text(encoding="utf-8")
            old_text = layout.legacy_settings.read_text(encoding="utf-8")

        # Neither file may contain the secret in any form.
        self.assertNotIn(SECRET, new_text)
        self.assertNotIn(SECRET, old_text)
        # The new file holds only the protected token.
        self.assertIn(KEY_VT_API_KEY_ENC, json.loads(new_text))
        self.assertNotIn(KEY_VT_API_KEY, json.loads(new_text))
        self.assertNotIn(KEY_VT_API_KEY, json.loads(old_text))

    @unittest.skipUnless(_HAVE_DPAPI, "DPAPI (Windows) not available")
    def test_other_legacy_settings_are_preserved(self) -> None:
        layout = _LegacyLayout(self.root)
        p1, p2 = layout.patches()
        with p1, p2:
            AppSettings.load()
            old_raw = json.loads(layout.legacy_settings.read_text(encoding="utf-8"))
        # Only the secret is scrubbed; unrelated keys stay untouched.
        self.assertEqual(old_raw.get("some_unknown_setting"), "keep-me")
        self.assertEqual(old_raw.get("language"), "en")

    @unittest.skipUnless(_HAVE_DPAPI, "DPAPI (Windows) not available")
    def test_migration_is_idempotent(self) -> None:
        layout = _LegacyLayout(self.root)
        p1, p2 = layout.patches()
        with p1, p2:
            first = AppSettings.load()
            second = AppSettings.load()
            third = AppSettings.load()
            new_raw = json.loads(layout.new_settings.read_text(encoding="utf-8"))
        self.assertEqual(first.virustotal_api_key, SECRET)
        self.assertEqual(second.virustotal_api_key, SECRET)
        self.assertEqual(third.virustotal_api_key, SECRET)
        self.assertNotIn(KEY_VT_API_KEY, new_raw)

    @unittest.skipUnless(_HAVE_DPAPI, "DPAPI (Windows) not available")
    def test_scrub_failure_is_reported_and_redacted(self) -> None:
        layout = _LegacyLayout(self.root)
        p1, p2 = layout.patches()
        real_write = settings_mod.write_json_atomic

        def failing_write(path, data, **kw):
            # Fail only when writing the legacy file (the scrub step).
            if Path(path).resolve() == layout.legacy_settings.resolve():
                raise OSError("access denied")
            return real_write(path, data, **kw)

        with p1, p2, mock.patch.object(settings_mod, "write_json_atomic", failing_write):
            AppSettings.load()
            warnings = settings_mod.pending_migration_warnings()

        self.assertTrue(warnings, "a failed scrub must produce a visible warning")
        joined = " ".join(warnings)
        self.assertNotIn(SECRET, joined)  # never leak the key in an error

    def test_portable_mode_does_not_scrub_its_own_file(self) -> None:
        layout = _LegacyLayout(self.root)
        (layout.exe_dir / settings_mod.PORTABLE_MARKER).write_text("", encoding="utf-8")
        p1, p2 = layout.patches()
        with p1, p2:
            self.assertTrue(settings_mod.is_portable())
            AppSettings.load()
            raw = json.loads(layout.legacy_settings.read_text(encoding="utf-8"))
        # In portable mode this IS the live settings file — it must not be
        # treated as a stale legacy copy and gutted.
        self.assertEqual(raw.get("some_unknown_setting"), "keep-me")

    def test_data_only_legacy_install_is_migrated(self) -> None:
        # No legacy settings file at all — history/fingerprints must still move.
        layout = _LegacyLayout(self.root, with_settings=False, with_data=True)
        p1, p2 = layout.patches()
        with p1, p2:
            AppSettings.load()
            new_history = settings_mod.history_path()
            new_store = settings_mod.trust_store_path()
            self.assertTrue(new_history.exists(), "history.json was not migrated")
            self.assertTrue(new_store.exists(), "known_files.json was not migrated")

    def test_data_migrated_even_when_new_settings_already_exist(self) -> None:
        layout = _LegacyLayout(self.root, with_settings=True, with_data=True)
        p1, p2 = layout.patches()
        with p1, p2:
            # Simulate a profile whose settings were migrated in an earlier run
            # but whose data files never made it across.
            new_dir = layout.user_dir / "HashTool"
            new_dir.mkdir(parents=True, exist_ok=True)
            (new_dir / SETTINGS_FILENAME).write_text(
                json.dumps({"language": "tr"}), encoding="utf-8"
            )
            AppSettings.load()
            self.assertTrue(settings_mod.history_path().exists())


if __name__ == "__main__":
    unittest.main()
