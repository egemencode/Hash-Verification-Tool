"""
The result card must not claim a scan is running when none is.

Reported from the field: the user drops a file, the card says "Scanning the
file, please wait…", and it stays that way for good. Nothing is stuck — no
scan was ever started. ``_clear_summary`` was resetting the card *into* the
in-progress state, so merely choosing a file painted a scan that did not
exist, while the status bar honestly read "Ready."

A screen that reports work nobody is doing is worse than a blank one: it
tells the user to wait, and waiting is the one thing that cannot help.
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
class SelectionStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self._env = mock.patch.dict(
            os.environ, {"LOCALAPPDATA": str(self.root / "profile")}
        )
        self._env.start()

        self.sample = self.root / "sample.bin"
        self.sample.write_bytes(b"hello")

        from gui.app import HashToolApp

        self.app = HashToolApp()
        self.app.update_idletasks()
        self.view = self.app.trust_view

    def tearDown(self) -> None:
        try:
            self.view.shutdown()
            self.app.destroy()
        finally:
            self._env.stop()
            self._tmp.cleanup()

    # ------------------------------------------------------------------
    def _badge_text(self) -> str:
        c = self.view.badge_canvas
        return " ".join(
            c.itemcget(item, "text")
            for item in c.find_all()
            if c.type(item) == "text"
        )

    def _scanning_words(self) -> tuple[str, str]:
        from gui.i18n import t

        return t("trust.badge.scanning"), t("trust.summary.scanning")

    def _drain(self) -> None:
        """Let any scan we started finish, so tearDown is not racing it."""
        worker = getattr(self.view, "_worker_thread", None)
        if worker is not None:
            worker.join(timeout=60)
        for _ in range(20):
            self.view._poll_queue()               # noqa: SLF001
            self.app.update()
            if not self.view.is_busy:
                break

    # --- the reported bug ----------------------------------------------
    def test_choosing_a_file_does_not_claim_a_scan_is_running(self) -> None:
        badge_word, summary_word = self._scanning_words()

        self.view._set_selected_path(str(self.sample))   # noqa: SLF001
        self._drain()

        self.assertNotEqual(
            summary_word,
            self.view.headline_var.get(),
            "choosing a file said a scan was in progress",
        )
        self.assertNotIn(
            badge_word,
            self._badge_text(),
            "the badge said Scanning… with no scan running",
        )

    def test_a_missing_history_file_does_not_claim_a_scan_is_running(self) -> None:
        badge_word, summary_word = self._scanning_words()

        started = self.view.rescan_path(str(self.root / "gone.bin"))

        self.assertFalse(started)
        self.assertNotEqual(summary_word, self.view.headline_var.get())
        self.assertNotIn(badge_word, self._badge_text())

    # --- the state that IS true must survive the fix ---------------------
    # --- choosing a file IS the request ----------------------------------
    def test_dropping_a_file_starts_the_scan(self) -> None:
        self.view._on_files_dropped([os.fsencode(str(self.sample))])  # noqa: SLF001

        self.assertTrue(self.view.is_busy, "the drop did not start a scan")
        self._drain()
        self.assertIsNotNone(self.view._controller.last_result)       # noqa: SLF001

    def test_the_file_picker_starts_the_scan(self) -> None:
        with mock.patch(
            "tkinter.filedialog.askopenfilename", return_value=str(self.sample)
        ):
            self.view._pick_file()                                    # noqa: SLF001

        self.assertTrue(self.view.is_busy, "the picker did not start a scan")
        self._drain()

    def test_dropping_something_that_is_not_a_file_starts_nothing(self) -> None:
        with mock.patch("tkinter.messagebox.showwarning") as warned:
            self.view._on_files_dropped(                              # noqa: SLF001
                [os.fsencode(str(self.root / "gone.bin"))]
            )

        self.assertTrue(warned.called)
        self.assertFalse(self.view.is_busy)

    def test_starting_a_scan_does_say_a_scan_is_running(self) -> None:
        badge_word, summary_word = self._scanning_words()

        self.view._set_selected_path(str(self.sample))   # noqa: SLF001
        self.view._on_scan()                             # noqa: SLF001
        # Deliberately no pumping: _on_scan paints the card before it starts
        # the worker, so this is what the user sees the instant they press it.
        self.assertEqual(summary_word, self.view.headline_var.get())
        self.assertIn(badge_word, self._badge_text())

        self._drain()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
