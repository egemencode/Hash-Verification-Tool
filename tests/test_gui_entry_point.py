"""
What the GUI does with a command line.

Explorer launches the app with ``--verify "<file>"`` when someone uses the
context-menu entry. Everything here is about that hand-off: the path arrives
intact, and a command line the app does not understand still opens a window
rather than dying silently — a double-clicked GUI has nowhere to print an
argument-parsing error.
"""

from __future__ import annotations

import unittest


class EntryPointArgumentTests(unittest.TestCase):
    def test_the_verify_flag_carries_the_path(self) -> None:
        from gui_main import parse_args

        self.assertEqual(
            r"C:\Users\me\Downloads\setup.exe",
            parse_args(["--verify", r"C:\Users\me\Downloads\setup.exe"]),
        )

    def test_a_path_with_spaces_arrives_in_one_piece(self) -> None:
        from gui_main import parse_args

        self.assertEqual(
            r"C:\Program Files\App\my report.pdf",
            parse_args(["--verify", r"C:\Program Files\App\my report.pdf"]),
        )

    def test_no_arguments_means_no_file_to_scan(self) -> None:
        from gui_main import parse_args

        self.assertIsNone(parse_args([]))

    def test_a_command_line_it_cannot_parse_still_opens_the_window(self) -> None:
        from gui_main import parse_args

        # argparse's default is to print usage and raise SystemExit. In a
        # windowed build there is no console to print to, so the user would
        # double-click and watch nothing happen.
        self.assertIsNone(parse_args(["--nonsense", "whatever"]))

    def test_the_flag_without_a_path_is_ignored_rather_than_fatal(self) -> None:
        from gui_main import parse_args

        self.assertIsNone(parse_args(["--verify"]))


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
class StartupScanTests(unittest.TestCase):
    """A right-click should produce a verdict, not a window to click again in."""

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
        self.sample = self.root / "clicked.bin"
        self.sample.write_bytes(b"right-clicked")

    def tearDown(self) -> None:
        app = getattr(self, "app", None)
        try:
            if app is not None:
                app.trust_view.shutdown()
                app.destroy()
        finally:
            self._env.stop()
            self._tmp.cleanup()

    def _drain(self) -> None:
        worker = getattr(self.app.trust_view, "_worker_thread", None)
        if worker is not None:
            worker.join(timeout=60)
        for _ in range(20):
            self.app.trust_view._poll_queue()      # noqa: SLF001
            self.app.update()
            if not self.app.trust_view.is_busy:
                break

    def test_a_file_passed_on_the_command_line_is_scanned_without_a_click(self) -> None:
        from gui.app import HashToolApp

        self.app = HashToolApp(initial_path=str(self.sample))
        self._drain()

        self.assertIsNotNone(self.app.trust_view._controller.last_result)  # noqa: SLF001
        self.assertIn("clicked.bin", self.app.trust_view.file_label_var.get())

    def test_a_file_that_no_longer_exists_opens_the_window_anyway(self) -> None:
        from unittest import mock
        from gui.app import HashToolApp

        # Explorer can hand over a path that was deleted between the
        # right-click and the launch. Refusing to open is the wrong answer.
        with mock.patch("tkinter.messagebox.showwarning"):
            self.app = HashToolApp(initial_path=str(self.root / "gone.bin"))
            self.app.update()

        self.assertFalse(self.app.trust_view.is_busy)

    def test_no_path_opens_the_ordinary_empty_window(self) -> None:
        from gui.app import HashToolApp

        self.app = HashToolApp()
        self.app.update()

        self.assertIsNone(self.app.trust_view._controller.last_result)  # noqa: SLF001


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
