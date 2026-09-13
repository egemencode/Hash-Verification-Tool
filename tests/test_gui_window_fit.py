"""
The window's two heights match the layouts they are for.

TrustCheckView sizes the window with two constants rather than measuring at
runtime: resizing a window from inside a callback that Tk's update() is
running kills the interpreter, so the measurement cannot live in the product.
It lives here instead.

The constants it replaced were guesses, and had drifted — 470 for a screen
asking 347, 880 for one asking 691, so a quarter of the opening window was
empty grey below the last control. Reported as "there is a big gap at the
bottom", which is what a stale constant looks like once a row moves.

These tests fail when the layout changes and the constants do not. Read the
number out of the failure message and update the constant.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from tests.support import DiagnosticTempDir

try:
    import tkinter as tk

    _probe = tk.Tk()
    _probe.destroy()
    TK_AVAILABLE = True
    TK_SKIP = ""
except Exception as exc:  # pragma: no cover
    TK_AVAILABLE = False
    TK_SKIP = f"Tk unavailable: {exc}"


@unittest.skipUnless(TK_AVAILABLE, TK_SKIP or "Tk unavailable")
class WindowHeightConstantsTests(unittest.TestCase):
    def setUp(self) -> None:
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

    # ------------------------------------------------------------------
    def _wanted(self) -> int:
        """What the current layout asks the window to be."""
        self.app.update_idletasks()
        return self.app.winfo_reqheight()

    def test_the_collapsed_constant_is_what_the_simple_screen_asks_for(self) -> None:
        from gui.views.trust_check_view import TrustCheckView

        self.assertEqual(
            self._wanted(),
            TrustCheckView.COLLAPSED_HEIGHT,
            "the simple screen's layout moved; update COLLAPSED_HEIGHT",
        )

    def test_the_expanded_constant_is_what_the_details_screen_asks_for(self) -> None:
        from gui.views.trust_check_view import TrustCheckView

        self.app.trust_view._toggle_details()          # noqa: SLF001

        self.assertEqual(
            self._wanted(),
            TrustCheckView.EXPANDED_HEIGHT,
            "the details screen's layout moved; update EXPANDED_HEIGHT",
        )

    def test_the_opening_window_is_no_taller_than_its_content(self) -> None:
        height = int(self.app.winfo_geometry().split("x")[1].split("+")[0])

        self.assertEqual(self._wanted(), height, "dead space under the content")

    def test_showing_the_details_asks_for_a_taller_window(self) -> None:
        from gui.views.trust_check_view import TrustCheckView

        self.assertGreater(
            TrustCheckView.EXPANDED_HEIGHT, TrustCheckView.COLLAPSED_HEIGHT
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
