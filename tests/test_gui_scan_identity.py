"""
RT#2 — the four mandated acceptance scenarios, against real Tk widgets.

These build an actual ``HashToolApp`` (isolated LOCALAPPDATA), drive the real
``TrustCheckView``, and assert on what is on screen and which buttons are
usable. Controller-only tests do not close this gate: the defects were in the
wiring between the view and the controller.
"""

from __future__ import annotations

import os
import threading
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
class GuiScanIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self._env = mock.patch.dict(os.environ, {"LOCALAPPDATA": str(self.root / "profile")})
        self._env.start()

        self.a = self.root / "a.bin"
        self.b = self.root / "b.bin"
        self.a.write_bytes(b"AAAA")
        self.b.write_bytes(b"BBBB")

        from gui.app import HashToolApp

        self.app = HashToolApp()
        self.app.update_idletasks()
        self.view = self.app.trust_view

    def tearDown(self) -> None:
        try:
            self.app.destroy()
        finally:
            self._env.stop()
            self._tmp.cleanup()

    # ------------------------------------------------------------------
    def _pump(self, rounds: int = 40) -> None:
        """Let queued Tk callbacks run without a real event loop."""
        for _ in range(rounds):
            self.app.update()
            self.app.update_idletasks()

    def _summary_text(self) -> str:
        """Everything the result panel is currently showing."""
        return " ".join(
            (
                self.view.headline_var.get(),
                self.view.bullets_text.get("1.0", "end"),
                self.view.advice_var.get(),
                self.view.file_label_var.get(),
            )
        )

    def _enabled(self, button) -> bool:
        return "disabled" not in button.state()

    def _scan_and_wait(self, path: Path) -> None:
        self.view._set_selected_path(str(path))   # noqa: SLF001
        self.view._on_scan()                      # noqa: SLF001
        # Wait for the worker itself, then drain the queue directly: the
        # view's own polling is scheduled with after(120ms), which a tight
        # update() loop would not reach.
        worker = getattr(self.view, "_worker_thread", None)
        if worker is not None:
            worker.join(timeout=60)
        for _ in range(20):
            self.view._poll_queue()               # noqa: SLF001
            self._pump(1)
            if not self.view.is_busy:
                break
        self._pump(3)

    # --- 1 -------------------------------------------------------------
    def test_1_error_on_b_leaves_no_trace_or_action_from_a(self) -> None:
        self._scan_and_wait(self.a)
        self.assertTrue(self._enabled(self.view.export_json_btn))
        self.assertIn("a.bin", self._summary_text())

        # B fails.
        from core import trust_pipeline

        with mock.patch.object(
            trust_pipeline, "collect_file_info", side_effect=RuntimeError("unreadable")
        ):
            with mock.patch("tkinter.messagebox.showerror"):
                self._scan_and_wait(self.b)

        self.assertIsNone(self.view._controller.last_result)  # noqa: SLF001
        for button in (self.view.export_json_btn, self.view.export_html_btn,
                       self.view.remember_btn):
            self.assertFalse(
                self._enabled(button), f"{button} stayed usable after B failed"
            )
        self.assertNotIn("a.bin", self._summary_text())

    # --- 2 -------------------------------------------------------------
    def test_2_stale_status_and_result_cannot_touch_the_new_session(self) -> None:
        self.view._set_selected_path(str(self.a))     # noqa: SLF001
        stale = self.view._controller.begin_scan()    # noqa: SLF001
        self.assertIsNotNone(stale)

        # The user drops B in while A is "running".
        self.view._set_selected_path(str(self.b))     # noqa: SLF001
        self.assertEqual(
            Path(self.view._controller.selected_path), self.b.resolve()  # noqa: SLF001
        )

        # A's worker now reports progress and a result, late.
        self.view._msg_queue.put(("status", (stale, "A ilerliyor…")))   # noqa: SLF001
        self.view._msg_queue.put(("done", (stale, object())))           # noqa: SLF001
        self.view._poll_queue()                                          # noqa: SLF001
        self._pump(3)

        self.assertIsNone(self.view._controller.last_result)  # noqa: SLF001
        self.assertFalse(self._enabled(self.view.export_json_btn))
        self.assertEqual(
            Path(self.view._controller.selected_path), self.b.resolve()  # noqa: SLF001
        )

    # --- 3 -------------------------------------------------------------
    def test_3_missing_history_entry_scans_nothing(self) -> None:
        self._scan_and_wait(self.a)
        gone = self.root / "deleted.bin"

        from core import trust_pipeline

        with mock.patch.object(trust_pipeline, "run_trust_check") as pipeline:
            started = self.view.rescan_path(str(gone))
            self._pump(3)

        self.assertFalse(started, "a scan was started for a missing file")
        self.assertEqual(
            pipeline.call_count, 0,
            "the pipeline ran even though the history file was gone",
        )
        self.assertIsNone(self.view._controller.selected_path)  # noqa: SLF001
        self.assertFalse(self._enabled(self.view.scan_button))

    # --- 4 -------------------------------------------------------------
    def test_4_shutdown_cancels_and_no_callback_hits_dead_widgets(self) -> None:
        self.view._set_selected_path(str(self.a))     # noqa: SLF001
        session = self.view._controller.begin_scan()  # noqa: SLF001

        started = threading.Event()
        release = threading.Event()

        def slow_worker():
            started.set()
            release.wait(timeout=5)

        worker = threading.Thread(target=slow_worker, daemon=True)
        self.view._worker_thread = worker             # noqa: SLF001
        worker.start()
        started.wait(timeout=5)

        self.view.shutdown()
        release.set()
        worker.join(timeout=5)

        self.assertTrue(session.cancelled)
        self.assertFalse(worker.is_alive(), "the worker did not finish in time")

        # A late callback after shutdown must be dropped, not rendered.
        self.view._msg_queue.put(("done", (session, object())))   # noqa: SLF001
        self.view._poll_queue()                                    # noqa: SLF001
        self.assertIsNone(self.view._controller.last_result)       # noqa: SLF001

    def test_new_selection_clears_the_technical_tabs(self) -> None:
        self._scan_and_wait(self.a)
        self.view._set_selected_path(str(self.b))     # noqa: SLF001
        self._pump(2)
        for entry in self.view.hash_rows.values():
            self.assertEqual(entry.get(), "", "a previous file's hash stayed on screen")

    def test_second_scan_while_busy_is_ignored(self) -> None:
        self.view._set_selected_path(str(self.a))     # noqa: SLF001
        first = self.view._controller.begin_scan()    # noqa: SLF001
        second = self.view._controller.begin_scan()   # noqa: SLF001
        self.assertIsNotNone(first)
        self.assertIsNone(second, "a second worker could be started while busy")


if __name__ == "__main__":
    unittest.main()
