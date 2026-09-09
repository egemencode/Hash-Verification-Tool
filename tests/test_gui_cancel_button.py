"""
A running scan must be stoppable by the user.

The cancellation machinery has been in place for several rounds: a session
carries a cancel token, the pipeline polls it at every stage boundary, and the
view already renders a CANCELLED outcome. The part the user can actually reach
was missing. Until then the only way to stop a scan was to close the window, so
someone who started a scan of the wrong file — or pointed the tool at a large
file over a slow network share — had to sit through it.

These tests drive the real widget with ``invoke()``, which runs exactly the
command a mouse click runs, and assert on the outcome: the controller's
terminal state, what the card says, and which actions are offered afterwards.
Asserting that a widget merely *exists* would pass against a button wired to
nothing.

Cancellation is cooperative — the worker only notices at the next stage
boundary — so the scan is parked inside a stage, cancelled, and then released.
That is the real sequence a user produces, and it is the one where a naive
implementation races.
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
class CancelButtonTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self._env = mock.patch.dict(
            os.environ, {"LOCALAPPDATA": str(self.root / "profile")}
        )
        self._env.start()

        self.target = self.root / "target.bin"
        self.target.write_bytes(b"X" * 4096)

        from gui.app import HashToolApp

        self.app = HashToolApp()
        self.app.update_idletasks()
        self.view = self.app.trust_view

        # Released in tearDown as well, so a failed assertion cannot leave the
        # worker parked forever and the temp tree undeletable.
        self._release = threading.Event()

    def tearDown(self) -> None:
        self._release.set()
        worker = getattr(self.view, "_worker_thread", None)
        if worker is not None:
            worker.join(timeout=30)
        try:
            self.app.destroy()
        finally:
            self._env.stop()
            self._tmp.cleanup()

    # ------------------------------------------------------------------
    def _pump(self, rounds: int = 3) -> None:
        for _ in range(rounds):
            self.app.update()
            self.app.update_idletasks()

    def _enabled(self, button) -> bool:
        return "disabled" not in button.state()

    def _park_in_a_stage(self):
        """
        Freeze the scan inside the signature stage.

        Returns an Event that is set once the worker is genuinely parked, so a
        test never cancels a scan that has not started — which would prove
        nothing about cancelling a *running* one.
        """
        from core import trust_pipeline

        entered = threading.Event()
        real = trust_pipeline.check_signature

        def parked(path):
            entered.set()
            self._release.wait(timeout=30)
            return real(path)

        patcher = mock.patch.object(trust_pipeline, "check_signature", parked)
        patcher.start()
        self.addCleanup(patcher.stop)
        return entered

    def _drain_until_idle(self) -> None:
        worker = getattr(self.view, "_worker_thread", None)
        if worker is not None:
            worker.join(timeout=30)
        # The view polls with after(120ms), which a tight update() loop would
        # not reach, so the queue is drained directly.
        for _ in range(40):
            self.view._poll_queue()               # noqa: SLF001
            self._pump(1)
            if not self.view.is_busy:
                break

    # ------------------------------------------------------------------
    def test_pressing_cancel_stops_a_running_scan(self) -> None:
        from core.scan_controller import ControllerState

        entered = self._park_in_a_stage()
        self.view._set_selected_path(str(self.target))   # noqa: SLF001
        self.view._on_scan()                             # noqa: SLF001
        self.assertTrue(entered.wait(timeout=30), "the scan never reached a stage")
        self.assertTrue(self.view.is_busy, "the scan is not actually running")

        # The affordance must be reachable exactly when it is needed.
        self.assertTrue(
            self._enabled(self.view.cancel_button),
            "there is no usable way to stop a scan that is running",
        )
        self.view.cancel_button.invoke()
        self._release.set()
        self._drain_until_idle()

        self.assertIs(
            self.view._controller.state, ControllerState.CANCELLED,  # noqa: SLF001
            "the scan did not end as cancelled",
        )
        self.assertFalse(self.view.is_busy)
        self.assertIsNone(
            self.view._controller.last_result,                # noqa: SLF001
            "a cancelled scan produced a verdict",
        )

        shown = (self.view.headline_var.get() + " " + self.view.advice_var.get()).lower()
        self.assertIn("iptal", shown, f"the card does not say it was cancelled: {shown!r}")

        # A verdict was never reached, so nothing may be exportable or
        # recordable as a baseline.
        for button in (
            self.view.export_json_btn,
            self.view.export_html_btn,
            self.view.remember_btn,
        ):
            self.assertFalse(
                self._enabled(button),
                "a cancelled scan still offers a result action",
            )

    def test_a_scan_that_finishes_just_after_cancel_still_ends_the_screen(self) -> None:
        # The worker can reach its last stage boundary before the user clicks,
        # then deliver a perfectly good result a moment later. The controller
        # is right to discard it — the user asked to stop — but the screen has
        # to end somewhere. Before the Cancel button existed nothing could set
        # the token mid-scan, so this ordering was unreachable; adding the
        # button is what makes it possible.
        from core.scan_controller import ControllerState

        self.view._set_selected_path(str(self.target))    # noqa: SLF001
        session = self.view._controller.begin_scan()      # noqa: SLF001
        self.assertIsNotNone(session)
        self.view._set_busy(True)                         # noqa: SLF001

        self.view.cancel_button.invoke()
        # The worker had already finished; its result arrives after the click.
        self.view._msg_queue.put(("done", (session, object())))   # noqa: SLF001
        self.view._poll_queue()                           # noqa: SLF001
        self._pump(2)

        self.assertIs(
            self.view._controller.state, ControllerState.CANCELLED,   # noqa: SLF001
        )
        self.assertIsNone(
            self.view._controller.last_result,                  # noqa: SLF001
            "a scan the user cancelled still published its verdict",
        )
        shown = (self.view.headline_var.get() + " " + self.view.advice_var.get()).lower()
        self.assertIn(
            "iptal", shown,
            f"the screen never said the scan ended; it still shows: {shown!r}",
        )
        self.assertTrue(
            self._enabled(self.view.scan_button),
            "the scan button is stuck disabled, so the screen cannot be used again",
        )
        self.assertFalse(self._enabled(self.view.cancel_button))

    def test_cancel_is_only_usable_while_a_scan_is_running(self) -> None:
        self.assertFalse(
            self._enabled(self.view.cancel_button),
            "cancel is usable with no scan running",
        )

        entered = self._park_in_a_stage()
        self.view._set_selected_path(str(self.target))   # noqa: SLF001
        self.view._on_scan()                             # noqa: SLF001
        self.assertTrue(entered.wait(timeout=30), "the scan never reached a stage")
        self.assertTrue(self._enabled(self.view.cancel_button))

        self._release.set()
        self._drain_until_idle()
        self.assertFalse(
            self._enabled(self.view.cancel_button),
            "cancel is still usable after the scan finished",
        )


if __name__ == "__main__":
    unittest.main()
