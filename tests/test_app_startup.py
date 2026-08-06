"""
The application must actually start.

This builds the real ``HashToolApp`` — real Tk widgets, real TrustCheckView —
against an isolated LOCALAPPDATA so it cannot touch the developer's profile.
Import-only or stubbed tests do not catch geometry-manager conflicts, missing
widget wiring, or anything else that happens during ``_build()``.

Skipped only when no display/Tk is available (headless CI).
"""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

try:
    import tkinter as tk

    _root = tk.Tk()
    _root.destroy()
    TK_AVAILABLE = True
    TK_SKIP_REASON = ""
except Exception as exc:  # pragma: no cover - depends on the environment
    TK_AVAILABLE = False
    TK_SKIP_REASON = f"Tk unavailable: {exc}"


@unittest.skipUnless(TK_AVAILABLE, TK_SKIP_REASON or "Tk unavailable")
class AppStartupTests(unittest.TestCase):
    """A smoke test that would have caught 'the app does not open'."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(
            os.environ, {"LOCALAPPDATA": self._tmp.name}
        )
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        self._tmp.cleanup()

    def _make_app(self):
        from gui.app import HashToolApp

        return HashToolApp()

    def test_app_constructs_updates_and_destroys(self) -> None:
        app = self._make_app()
        try:
            app.update_idletasks()
        finally:
            app.destroy()

    def test_trust_view_widgets_really_exist(self) -> None:
        app = self._make_app()
        try:
            app.update_idletasks()
            view = app.trust_view
            self.assertIsNotNone(view, "the trust-check view was not built")
            # Real widgets, not stubs.
            self.assertTrue(view.winfo_exists())
            self.assertTrue(view.scan_button.winfo_exists())
            # Every child of the drop-zone frame must use ONE geometry manager.
            for child in view.winfo_children():
                self._assert_single_geometry_manager(child)
        finally:
            app.destroy()

    def _assert_single_geometry_manager(self, widget) -> None:
        managers = set()
        for child in widget.winfo_children():
            manager = child.winfo_manager()
            if manager:
                managers.add(manager)
            self._assert_single_geometry_manager(child)
        self.assertLessEqual(
            len(managers), 1,
            f"{widget} mixes geometry managers: {sorted(managers)}",
        )

    def test_second_construction_after_destroy(self) -> None:
        # Rebuilding (e.g. after a language switch) must not leave Tk in a
        # broken state.
        app = self._make_app()
        app.update_idletasks()
        app.destroy()
        app2 = self._make_app()
        try:
            app2.update_idletasks()
        finally:
            app2.destroy()

    def test_close_protocol_is_registered(self) -> None:
        app = self._make_app()
        try:
            handler = app.protocol("WM_DELETE_WINDOW")
            self.assertTrue(
                handler, "no WM_DELETE_WINDOW handler: closing the window is unhandled"
            )
        finally:
            app.destroy()


if __name__ == "__main__":
    unittest.main()
