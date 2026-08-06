"""
RT#3 — saving settings must not resurrect a stale copy.

The reported defect: the Settings view saved the draft correctly, then
``_on_settings_changed`` wrote the parent's *old* raw dict back over it, so a
privacy preference the user had just switched off reverted to on.

Also covers the parsing fail-safe: only a real JSON ``true`` may enable
online checks. ``"false"``, ``"true"``, numbers, ``null``, objects and lists
must all read as disabled.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.support import DiagnosticTempDir
from utils import settings as S
from utils.settings import KEY_VT_AUTOQUERY, KEY_VT_API_KEY_ENC, AppSettings


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.base = Path(self._tmp.name)
        self.file = self.base / "hashtool_settings.json"
        S.clear_migration_warnings()
        S._reset_write_disabled_for_tests()

    def tearDown(self) -> None:
        S.clear_migration_warnings()
        S._reset_write_disabled_for_tests()
        self._tmp.cleanup()

    def _raw(self) -> dict:
        return json.loads(self.file.read_text(encoding="utf-8"))


class NoStaleOverwriteTests(_Base):
    def test_disabling_online_checks_survives_the_parent_callback(self) -> None:
        self.file.write_text(json.dumps({KEY_VT_AUTOQUERY: True}), encoding="utf-8")

        with mock.patch.object(S, "_base_dir", return_value=self.base):
            live = AppSettings.load()
            self.assertTrue(live.virustotal_autoquery)

            # The Settings view edits a draft and saves it.
            draft = live.copy_for_edit()
            draft.virustotal_autoquery = False
            draft.save()
            after_draft = self._raw().get(KEY_VT_AUTOQUERY)

            # Whatever the parent does afterwards must not undo it.
            S.save_settings({"language": "tr"})
            after_secondary = self._raw().get(KEY_VT_AUTOQUERY)

        self.assertIs(after_draft, False)
        self.assertIs(
            after_secondary, False,
            "a later settings write resurrected the old privacy preference",
        )

    def test_parent_holding_a_stale_dict_cannot_overwrite_the_draft(self) -> None:
        """
        Faithful reproduction of the reported defect: the parent kept the raw
        dict it loaded at startup (autoquery=True) and wrote it back after the
        draft was saved.
        """
        self.file.write_text(json.dumps({KEY_VT_AUTOQUERY: True}), encoding="utf-8")

        with mock.patch.object(S, "_base_dir", return_value=self.base):
            stale_raw = S.load_settings()          # parent's startup snapshot
            self.assertIs(stale_raw.get(KEY_VT_AUTOQUERY), True)

            draft = AppSettings.load().copy_for_edit()
            draft.virustotal_autoquery = False
            draft.save()
            after_draft = self._raw().get(KEY_VT_AUTOQUERY)

            # The parent's post-save callback writes its stale copy back.
            stale_raw["language"] = "tr"
            try:
                S.save_settings(stale_raw)
            except S.SettingsError:
                pass
            after_secondary = self._raw().get(KEY_VT_AUTOQUERY)

        self.assertIs(after_draft, False)
        self.assertIs(
            after_secondary, False,
            "a stale raw dict re-enabled online checks the user had turned off",
        )

    def test_reload_after_save_keeps_the_choice(self) -> None:
        self.file.write_text(json.dumps({KEY_VT_AUTOQUERY: True}), encoding="utf-8")
        with mock.patch.object(S, "_base_dir", return_value=self.base):
            draft = AppSettings.load().copy_for_edit()
            draft.virustotal_autoquery = False
            draft.save()
            reloaded = AppSettings.load()
        self.assertFalse(reloaded.virustotal_autoquery)

    def test_language_change_does_not_touch_privacy(self) -> None:
        self.file.write_text(json.dumps({KEY_VT_AUTOQUERY: False}), encoding="utf-8")
        with mock.patch.object(S, "_base_dir", return_value=self.base):
            S.save_settings({"language": "en"})
            reloaded = AppSettings.load()
        self.assertFalse(reloaded.virustotal_autoquery)
        self.assertEqual(reloaded.language, "en")


class AutoqueryParsingTests(_Base):
    """Only a genuine boolean true may enable sending hashes to a third party."""

    def _load_with(self, value) -> bool:
        self.file.write_text(json.dumps({KEY_VT_AUTOQUERY: value}), encoding="utf-8")
        with mock.patch.object(S, "_base_dir", return_value=self.base):
            return AppSettings.load().virustotal_autoquery

    def test_string_false_is_disabled(self) -> None:
        self.assertFalse(self._load_with("false"))

    def test_string_true_is_disabled(self) -> None:
        # A string is not a boolean; refuse to guess about a privacy setting.
        self.assertFalse(self._load_with("true"))

    def test_numbers_are_disabled(self) -> None:
        self.assertFalse(self._load_with(1))
        self.assertFalse(self._load_with(0))

    def test_null_object_list_are_disabled(self) -> None:
        self.assertFalse(self._load_with(None))
        self.assertFalse(self._load_with({"on": True}))
        self.assertFalse(self._load_with(["yes"]))

    def test_real_boolean_true_enables(self) -> None:
        self.assertTrue(self._load_with(True))

    def test_real_boolean_false_disables(self) -> None:
        self.assertFalse(self._load_with(False))


class ApiKeyTransactionTests(_Base):
    """Changing/removing the key must be one transaction, with no rollback."""

    def setUp(self) -> None:
        super().setUp()
        from core import secret_store

        if not secret_store.is_available():
            self.skipTest("DPAPI (Windows) not available")

    def test_setting_a_key_survives_a_later_unrelated_save(self) -> None:
        with mock.patch.object(S, "_base_dir", return_value=self.base):
            draft = AppSettings.load().copy_for_edit()
            draft.virustotal_api_key = "KEY-ONE"
            draft.save()
            S.save_settings({"language": "en"})
            reloaded = AppSettings.load()
        self.assertEqual(reloaded.virustotal_api_key, "KEY-ONE")

    def test_removing_the_key_is_not_undone(self) -> None:
        with mock.patch.object(S, "_base_dir", return_value=self.base):
            draft = AppSettings.load().copy_for_edit()
            draft.virustotal_api_key = "KEY-ONE"
            draft.save()

            draft2 = AppSettings.load().copy_for_edit()
            draft2.virustotal_api_key = ""      # explicit removal
            draft2.save()
            after_removal = self._raw()

            S.save_settings({"language": "tr"})
            after_secondary = self._raw()

        self.assertNotIn(KEY_VT_API_KEY_ENC, after_removal)
        self.assertNotIn(
            KEY_VT_API_KEY_ENC, after_secondary,
            "an unrelated save brought the removed key back",
        )


if __name__ == "__main__":
    unittest.main()
