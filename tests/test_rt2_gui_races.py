"""
Red-team round 2 — GUI races (#1 #2 #4), against real Tk widgets.

The defects here are in the wiring between the view and the controller, so
the tests drive a real ``HashToolApp``: they queue genuinely stale messages,
inspect the widgets, and assert on what the user would see.
"""

from __future__ import annotations

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


@unittest.skipUnless(TK_AVAILABLE, TK_SKIP or "Tk unavailable")
class _GuiCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self._env = mock.patch.dict(
            os.environ, {"LOCALAPPDATA": str(self.root / "profile")}
        )
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

    def _enabled(self, button) -> bool:
        return "disabled" not in button.state()

    def _start(self, path: Path):
        """Begin a scan session without launching a real worker."""
        self.view._set_selected_path(str(path))     # noqa: SLF001
        session = self.view._controller.begin_scan()  # noqa: SLF001
        self.view._set_busy(True)                    # noqa: SLF001
        return session


class StaleTerminalMessageTests(_GuiCase):
    """#1 — a stale terminal message must not disturb the live scan."""

    def test_stale_terminal_messages_do_not_disturb_the_active_scan(self) -> None:
        for kind in ("cancelled", "done", "error"):
            with self.subTest(message=kind):
                session_a = self._start(self.a)
                session_b = self._start(self.b)   # supersedes A
                self.assertIsNotNone(session_b)

                busy_before = self.view.is_busy
                status_before = self.view.status_text
                scan_enabled_before = self._enabled(self.view.scan_button)
                self.assertTrue(busy_before)

                payload = RuntimeError("late") if kind == "error" else object()
                self.view._msg_queue.put((kind, (session_a, payload)))  # noqa: SLF001
                self.view._poll_queue()                                  # noqa: SLF001

                self.assertTrue(self.view.is_busy, "stale message cleared busy")
                self.assertEqual(
                    self.view.status_text, status_before,
                    "stale message changed the status line",
                )
                self.assertEqual(
                    self._enabled(self.view.scan_button), scan_enabled_before,
                    "stale message re-enabled the scan button",
                )
                self.assertTrue(
                    self.view._controller.is_current(session_b),  # noqa: SLF001
                    "B stopped being the current session",
                )

    def test_b_still_completes_after_a_stale_message(self) -> None:
        from core.scan_controller import ScanState

        session_a = self._start(self.a)
        session_b = self._start(self.b)

        self.view._msg_queue.put(("cancelled", (session_a, None)))  # noqa: SLF001
        self.view._msg_queue.put(("done", (session_b, self._fake_result())))  # noqa: SLF001
        self.view._poll_queue()                                      # noqa: SLF001

        self.assertTrue(
            self.view._msg_queue.empty(),                            # noqa: SLF001
            "the poll loop stopped at the stale message",
        )
        self.assertEqual(
            self.view._controller.state, ScanState.SUCCESS,          # noqa: SLF001
        )
        self.assertIsNotNone(self.view._controller.last_result)      # noqa: SLF001

    def _fake_result(self):
        from core.trust_pipeline import run_trust_check
        from core.vt_client import VirusTotalClient

        return run_trust_check(
            str(self.b),
            vt_client=VirusTotalClient(api_key=None),
            local_store=None,
            check_signature_flag=False,
            query_virustotal=False,
        )


class MissingHistoryCancelsActiveScanTests(_GuiCase):
    """#2 — a missing history entry must cancel whatever is running."""

    def test_active_session_is_cancelled_and_cannot_deliver(self) -> None:
        session_a = self._start(self.a)
        gone = self.root / "deleted.bin"

        started = self.view.rescan_path(str(gone))
        self.assertFalse(started)

        controller = self.view._controller                   # noqa: SLF001
        self.assertTrue(session_a.cancelled, "the running session was not cancelled")
        self.assertFalse(controller.is_current(session_a))
        self.assertFalse(controller.deliver_result(session_a, object()))
        self.assertFalse(controller.deliver_error(session_a, RuntimeError("x")))
        self.assertFalse(controller.deliver_cancelled(session_a))
        self.assertIsNone(controller.selected_path)
        self.assertFalse(self.view.is_busy, "the view stayed busy after the failure")

    def test_late_result_from_a_leaves_no_evidence_on_screen(self) -> None:
        session_a = self._start(self.a)
        gone = self.root / "deleted.bin"
        self.view.rescan_path(str(gone))

        self.view._msg_queue.put(("done", (session_a, object())))  # noqa: SLF001
        self.view._poll_queue()                                    # noqa: SLF001

        self.assertIsNone(self.view._controller.last_result)       # noqa: SLF001
        for button in (self.view.export_json_btn, self.view.export_html_btn,
                       self.view.remember_btn):
            self.assertFalse(self._enabled(button))


class FailedRescanClearsEvidenceTests(_GuiCase):
    """#4 — a failed scan must not leave the previous result on screen."""

    def _run_real_scan(self, path: Path) -> None:
        self.view._set_selected_path(str(path))   # noqa: SLF001
        self.view._on_scan()                      # noqa: SLF001
        worker = getattr(self.view, "_worker_thread", None)
        if worker is not None:
            worker.join(timeout=60)
        for _ in range(20):
            self.view._poll_queue()               # noqa: SLF001
            self.app.update()
            if not self.view.is_busy:
                break

    def test_error_replaces_the_previous_result_with_a_terminal_card(self) -> None:
        self._run_real_scan(self.a)
        self.assertTrue(self._enabled(self.view.export_json_btn))
        first_hashes = {k: e.get() for k, e in self.view.hash_rows.items()}
        self.assertTrue(any(first_hashes.values()), "the first scan produced no hashes")

        from core import trust_pipeline

        with mock.patch.object(
            trust_pipeline, "collect_file_info", side_effect=RuntimeError("okunamadı")
        ), mock.patch("tkinter.messagebox.showerror"):
            self._run_real_scan(self.a)

        headline = self.view.headline_var.get()
        self.assertNotIn("bekleyin", headline.lower(), "the spinner text survived")
        self.assertIn("tamamlanamadı", headline.lower())
        for entry in self.view.hash_rows.values():
            self.assertEqual(entry.get(), "", "a previous hash stayed on screen")
        for button in (self.view.export_json_btn, self.view.export_html_btn,
                       self.view.remember_btn):
            self.assertFalse(self._enabled(button))


if __name__ == "__main__":
    unittest.main()
