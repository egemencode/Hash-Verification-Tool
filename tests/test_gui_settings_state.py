"""
Settings must not undo a choice the user already made, and must be able to
remove the key it stores.

Two independent defects, both in how the Settings tab relates to state that
lives somewhere else:

* The language is held in three places — the i18n module, the raw settings
  dict, and ``AppSettings``. Switching from the menu updated two of them, so
  the Settings tab was rebuilt holding the *previous* language and the next
  save wrote it back and switched the UI to it.

* An API key token that cannot be decrypted is deliberately never deleted by
  an ordinary save, because that once destroyed a user's only copy. The escape
  hatch is ``AppSettings.clear_api_key()`` — and nothing in the UI called it.
  The warning the application itself raises says "you can choose 'Anahtarı
  Kaldır'", naming a control that did not exist.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    import tkinter as tk

    _probe = tk.Tk()
    _probe.destroy()
    TK_AVAILABLE = True
    TK_SKIP = ""
except Exception as exc:  # pragma: no cover
    TK_AVAILABLE = False
    TK_SKIP = f"Tk unavailable: {exc}"


class _AppCase(unittest.TestCase):
    """Builds a real app against an isolated profile."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.profile = self.root / "profile"
        (self.profile / "HashTool").mkdir(parents=True)
        self.settings_file = self.profile / "HashTool" / "hashtool_settings.json"
        self._env = mock.patch.dict(os.environ, {"LOCALAPPDATA": str(self.profile)})
        self._env.start()
        self._write_settings()

        import utils.settings as settings_mod
        from gui.i18n import set_language

        settings_mod._reset_write_disabled_for_tests()
        settings_mod.clear_migration_warnings()
        set_language("tr")

        from gui.app import HashToolApp

        self.app = HashToolApp()
        self.app.update_idletasks()

    def _write_settings(self) -> None:
        """Override to seed the profile before the app starts."""

    def tearDown(self) -> None:
        try:
            self.app.destroy()
        finally:
            self._env.stop()
            self._tmp.cleanup()
            from gui.i18n import set_language

            set_language("tr")

    def _stored(self) -> dict:
        if not self.settings_file.exists():
            return {}
        return json.loads(self.settings_file.read_text(encoding="utf-8"))


@unittest.skipUnless(TK_AVAILABLE, TK_SKIP or "Tk unavailable")
class LanguageStateTests(_AppCase):
    def test_saving_settings_keeps_the_language_chosen_from_the_menu(self) -> None:
        from gui.i18n import get_language

        self.assertEqual(get_language(), "tr")
        self.app._switch_language("en")                  # noqa: SLF001
        self.assertEqual(get_language(), "en", "the menu switch did not take")

        # The tab was rebuilt by the switch, so take it fresh — this is the
        # object the user is now looking at.
        view = self.app.settings_view
        with mock.patch("gui.views.settings_view.messagebox.showinfo"):
            view._on_save()                              # noqa: SLF001

        self.assertEqual(
            get_language(), "en",
            "saving settings reverted the language the user had just chosen",
        )
        self.assertEqual(
            self._stored().get("language"), "en",
            "the reverted language was written to disk as well",
        )

    def test_the_settings_tab_shows_the_language_actually_in_use(self) -> None:
        self.app._switch_language("en")                  # noqa: SLF001
        self.assertEqual(
            self.app.settings_view.language_var.get(), "en",
            "the language radio still shows the language the app is no longer in",
        )


@unittest.skipUnless(TK_AVAILABLE, TK_SKIP or "Tk unavailable")
class UnreadableKeyRemovalTests(_AppCase):
    def _write_settings(self) -> None:
        # A token this user cannot decrypt: another Windows account's DPAPI
        # blob looks exactly like this from here.
        self.settings_file.write_text(
            json.dumps(
                {"language": "tr", "virustotal_api_key_enc": "not-a-real-dpapi-blob"}
            ),
            encoding="utf-8",
        )

    def test_an_undecryptable_key_can_be_removed(self) -> None:
        from utils.settings import SecretState

        self.assertIs(
            self.app._app_settings.secret_state,            # noqa: SLF001
            SecretState.UNREADABLE,
            "test setup: the seeded token was not treated as undecryptable",
        )
        self.assertEqual(
            self._stored().get("virustotal_api_key_enc"), "not-a-real-dpapi-blob",
            "test setup: the token is not on disk",
        )

        view = self.app.settings_view
        with mock.patch("gui.views.settings_view.messagebox.askyesno",
                        return_value=True), \
             mock.patch("gui.views.settings_view.messagebox.showinfo"):
            view.remove_key_button.invoke()

        self.assertNotIn(
            "virustotal_api_key_enc", self._stored(),
            "the key the user asked to remove is still stored",
        )

    def test_removal_is_abandoned_when_the_user_declines(self) -> None:
        view = self.app.settings_view
        with mock.patch("gui.views.settings_view.messagebox.askyesno",
                        return_value=False), \
             mock.patch("gui.views.settings_view.messagebox.showinfo"):
            view.remove_key_button.invoke()

        self.assertEqual(
            self._stored().get("virustotal_api_key_enc"), "not-a-real-dpapi-blob",
            "declining the confirmation still removed the key",
        )


if __name__ == "__main__":
    unittest.main()
