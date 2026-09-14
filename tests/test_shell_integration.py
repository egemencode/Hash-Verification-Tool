"""
The Explorer context-menu entry: what gets written, and what it says.

Everything here writes under a *test* registry base rather than the real
``Software\\Classes\\*\\shell``. A test suite that edits the shell's own keys
would change the machine it runs on — and leave the change behind when it
fails half way.

The command string is where a mistake costs most: it is handed to the shell
as one line, so a path that is not quoted turns "C:\\Program Files\\..." into
two arguments and the menu entry silently does nothing.
"""

from __future__ import annotations

import sys
import unittest

WINDOWS = sys.platform == "win32"
SKIP = "Explorer integration is Windows-only"


@unittest.skipUnless(WINDOWS, SKIP)
class BuildCommandTests(unittest.TestCase):
    def test_the_executable_path_is_quoted_so_spaces_survive(self) -> None:
        from utils.shell_integration import build_command

        command = build_command(r"C:\Program Files\HashTool\HashToolGUI.exe")

        self.assertEqual(
            '"C:\\Program Files\\HashTool\\HashToolGUI.exe" --verify "%1"',
            command,
        )

    def test_the_clicked_file_is_passed_as_a_quoted_placeholder(self) -> None:
        from utils.shell_integration import build_command

        command = build_command(r"C:\tools\HashToolGUI.exe")

        # "%1" unquoted is the same bug as an unquoted exe path, one argument
        # further along: it breaks on every file whose name has a space.
        self.assertIn('"%1"', command)
        self.assertNotIn(' %1', command.replace('"%1"', ""))

    def test_running_from_source_launches_the_interpreter_with_the_script(self) -> None:
        from utils.shell_integration import build_command

        command = build_command(
            r"C:\Python\pythonw.exe", script=r"C:\dev\Hash Tool\gui_main.py"
        )

        self.assertEqual(
            '"C:\\Python\\pythonw.exe" "C:\\dev\\Hash Tool\\gui_main.py" '
            '--verify "%1"',
            command,
        )


@unittest.skipUnless(WINDOWS, SKIP)
class RegistryTests(unittest.TestCase):
    """
    Writes under a private base, never the shell's own key.

    Each test cleans up after itself; a leftover key here would be a leftover
    key on the developer's machine.
    """

    TEST_ROOT = r"Software\HashToolTests"
    BASE = TEST_ROOT + r"\shell\VerifyWithHashTool"
    EXE = r"C:\Program Files\HashTool\HashToolGUI.exe"

    def tearDown(self) -> None:
        # The whole private tree, not just the entry: unregister() deliberately
        # leaves parent keys alone (in real use they are Windows' own), so the
        # intermediate keys this test invented are ours to remove.
        _delete_tree(self.TEST_ROOT)

    def test_nothing_is_registered_before_anything_is_written(self) -> None:
        from utils.shell_integration import is_registered, registered_command

        self.assertFalse(is_registered(base=self.BASE))
        self.assertIsNone(registered_command(base=self.BASE))

    def test_registering_stores_the_command_and_the_menu_label(self) -> None:
        from utils.shell_integration import (
            build_command, is_registered, registered_command, registered_label,
            register,
        )

        register(self.EXE, "Bu dosyayı doğrula", base=self.BASE)

        self.assertTrue(is_registered(base=self.BASE))
        self.assertEqual(build_command(self.EXE), registered_command(base=self.BASE))
        self.assertEqual("Bu dosyayı doğrula", registered_label(base=self.BASE))

    def test_registering_again_from_a_new_location_replaces_the_command(self) -> None:
        from utils.shell_integration import build_command, register, registered_command

        register(self.EXE, "Bu dosyayı doğrula", base=self.BASE)
        moved = r"D:\Tools\HashTool\HashToolGUI.exe"
        register(moved, "Bu dosyayı doğrula", base=self.BASE)

        # The whole point: the exe moved, and the menu must not keep calling
        # the place it used to be.
        self.assertEqual(build_command(moved), registered_command(base=self.BASE))

    def test_unregistering_leaves_no_key_behind(self) -> None:
        from utils.shell_integration import is_registered, register, unregister

        register(self.EXE, "Bu dosyayı doğrula", base=self.BASE)
        unregister(base=self.BASE)

        self.assertFalse(is_registered(base=self.BASE))
        # Not just the value — the command subkey too, or Explorer keeps an
        # empty entry in the menu.
        self.assertIsNone(_raw_subkey(self.BASE + r"\command"))

    def test_unregistering_something_never_registered_is_not_an_error(self) -> None:
        from utils.shell_integration import unregister

        unregister(base=self.BASE)   # must not raise


def _raw_subkey(path: str):
    """Read a key straight from HKCU, bypassing the module under test."""
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path):
            return path
    except FileNotFoundError:
        return None

@unittest.skipUnless(WINDOWS, SKIP)
class LaunchTargetTests(unittest.TestCase):
    def test_a_frozen_build_launches_the_executable_alone(self) -> None:
        from unittest import mock
        from utils.shell_integration import launch_target

        with mock.patch.object(sys, "frozen", True, create=True):
            executable, script = launch_target()

        self.assertEqual(sys.executable, executable)
        self.assertIsNone(script, "a frozen exe has no script to pass")

    def test_running_from_source_points_at_a_gui_entry_point_that_exists(self) -> None:
        from pathlib import Path
        from utils.shell_integration import launch_target

        executable, script = launch_target()

        self.assertIsNotNone(script)
        # A path that is merely plausible is the failure mode here: the menu
        # entry would be written, look right, and do nothing.
        self.assertTrue(Path(script).is_file(), f"no entry point at {script}")
        self.assertTrue(Path(executable).is_file(), f"no interpreter at {executable}")

    def test_running_from_source_picks_the_console_less_interpreter(self) -> None:
        from pathlib import Path
        from utils.shell_integration import launch_target

        executable, _script = launch_target()

        # python.exe would flash a console window behind the GUI on every
        # right-click. pythonw.exe is the same interpreter without one.
        if Path(sys.executable).with_name("pythonw.exe").is_file():
            self.assertEqual("pythonw.exe", Path(executable).name)


@unittest.skipUnless(WINDOWS, SKIP)
class SyncTests(unittest.TestCase):
    """sync() is the one call the app makes: make the registry match the setting."""

    TEST_ROOT = r"Software\HashToolTests"
    BASE = TEST_ROOT + r"\shell\VerifyWithHashTool"
    EXE = r"C:\Program Files\HashTool\HashToolGUI.exe"
    LABEL = "Bu dosyayı doğrula"

    def tearDown(self) -> None:
        _delete_tree(self.TEST_ROOT)

    def test_turning_the_setting_on_creates_the_entry(self) -> None:
        from utils.shell_integration import build_command, registered_command, sync

        sync(True, self.LABEL, executable=self.EXE, base=self.BASE)

        self.assertEqual(build_command(self.EXE), registered_command(base=self.BASE))

    def test_turning_the_setting_off_removes_the_entry(self) -> None:
        from utils.shell_integration import is_registered, sync

        sync(True, self.LABEL, executable=self.EXE, base=self.BASE)
        sync(False, self.LABEL, executable=self.EXE, base=self.BASE)

        self.assertFalse(is_registered(base=self.BASE))

    def test_an_entry_pointing_at_the_old_location_is_repaired(self) -> None:
        from utils.shell_integration import build_command, registered_command, sync

        sync(True, self.LABEL, executable=self.EXE, base=self.BASE)
        moved = r"D:\Portable\HashToolGUI.exe"
        sync(True, self.LABEL, executable=moved, base=self.BASE)

        # Moving the exe is the ordinary way this breaks, and the app calls
        # sync() at startup precisely to catch it.
        self.assertEqual(build_command(moved), registered_command(base=self.BASE))

    def test_switching_language_rewrites_the_menu_text(self) -> None:
        from utils.shell_integration import registered_label, sync

        sync(True, self.LABEL, executable=self.EXE, base=self.BASE)
        sync(True, "Verify this file", executable=self.EXE, base=self.BASE)

        self.assertEqual("Verify this file", registered_label(base=self.BASE))

    def test_turning_it_off_when_it_was_never_on_is_harmless(self) -> None:
        from utils.shell_integration import is_registered, sync

        sync(False, self.LABEL, executable=self.EXE, base=self.BASE)

        self.assertFalse(is_registered(base=self.BASE))


class ShellMenuSettingTests(unittest.TestCase):
    """The setting itself — stored like any other, and off until asked for."""

    def setUp(self) -> None:
        import os
        from pathlib import Path
        from unittest import mock
        from tests.support import DiagnosticTempDir

        self._tmp = DiagnosticTempDir()
        self._env = mock.patch.dict(
            os.environ, {"LOCALAPPDATA": str(Path(self._tmp.name) / "profile")}
        )
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        self._tmp.cleanup()

    def test_the_menu_entry_is_off_on_a_fresh_install(self) -> None:
        from utils.settings import AppSettings

        # Writing to the shell is a change to the user's system. A tool does
        # not make one because it was installed.
        self.assertFalse(AppSettings.load().shell_context_menu)

    def test_the_choice_survives_a_save_and_reload(self) -> None:
        from utils.settings import AppSettings

        settings = AppSettings.load()
        settings.shell_context_menu = True
        settings.save()

        self.assertTrue(AppSettings.load().shell_context_menu)


try:
    import tkinter as tk

    _probe = tk.Tk()
    _probe.destroy()
    TK_AVAILABLE = True
    TK_SKIP = ""
except Exception as exc:  # pragma: no cover
    TK_AVAILABLE = False
    TK_SKIP = f"Tk unavailable: {exc}"


@unittest.skipUnless(TK_AVAILABLE and WINDOWS, TK_SKIP or SKIP)
class SettingsWiringTests(unittest.TestCase):
    """
    The toggle, and who acts on it.

    The Settings screen only records the choice; the application is what
    touches the registry. sync() is patched here rather than exercised: this
    test must not write a verb into the machine running it.
    """

    def setUp(self) -> None:
        import os
        from pathlib import Path
        from unittest import mock
        from tests.support import DiagnosticTempDir

        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self._env = mock.patch.dict(
            os.environ, {"LOCALAPPDATA": str(self.root / "profile")}
        )
        self._env.start()

        from gui.app import HashToolApp

        self.app = HashToolApp()
        self.app.update_idletasks()

    def tearDown(self) -> None:
        try:
            self.app.destroy()
        finally:
            self._env.stop()
            self._tmp.cleanup()

    def _settings_view(self):
        view = self.app.settings_view
        self.assertIsNotNone(view, "the Settings window was never built")
        return view

    def test_the_settings_screen_offers_the_toggle(self) -> None:
        view = self._settings_view()

        self.assertFalse(
            view.shell_menu_var.get(), "the toggle should start off"
        )

    def test_saving_with_the_box_ticked_records_the_choice(self) -> None:
        from unittest import mock
        from utils.settings import AppSettings

        view = self._settings_view()
        view.shell_menu_var.set(True)
        with mock.patch("utils.shell_integration.sync"),              mock.patch("tkinter.messagebox.showinfo"):
            view._on_save()                                  # noqa: SLF001

        self.assertTrue(AppSettings.load().shell_context_menu)

    def test_saving_asks_the_shell_to_match_the_new_choice(self) -> None:
        from unittest import mock
        from gui.i18n import t

        view = self._settings_view()
        view.shell_menu_var.set(True)
        with mock.patch("utils.shell_integration.sync") as sync,              mock.patch("tkinter.messagebox.showinfo"):
            view._on_save()                                  # noqa: SLF001

        sync.assert_called_once_with(True, t("shell.menu.label"))

    def test_a_shell_that_refuses_the_write_does_not_pass_for_success(self) -> None:
        from unittest import mock

        view = self._settings_view()
        view.shell_menu_var.set(True)
        with mock.patch(
            "utils.shell_integration.sync", side_effect=OSError("access denied")
        ), mock.patch("tkinter.messagebox.showinfo"),            mock.patch("tkinter.messagebox.showerror") as shown:
            view._on_save()                                  # noqa: SLF001

        # Silently leaving a ticked box that does nothing is the failure this
        # guards: the user would right-click and find no menu entry.
        self.assertTrue(shown.called)


def _delete_tree(path: str) -> None:
    """Delete a key and everything under it (winreg deletes only leaves)."""
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            while True:
                try:
                    child = winreg.EnumKey(key, 0)
                except OSError:
                    break
                _delete_tree(path + "\\" + child)
    except FileNotFoundError:
        return
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
    except FileNotFoundError:
        pass


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
