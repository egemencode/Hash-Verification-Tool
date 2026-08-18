"""
The Advanced tabs must be stoppable, and closing the window must stop them.

The Trust Check screen got a session, a cancel token and a bounded join several
rounds ago. The Gelişmiş Hash / Verify / Report tabs never did: they share one
bare daemon thread (``HashToolApp._Worker``) that nothing can cancel and nobody
joins. ``destroy()`` shuts the trust view down and cancels scheduled callbacks,
then returns — the folder-hash worker keeps running.

That is not merely an untidy thread. The worker is the code that *writes the
manifest*: it calls ``build.save(...)`` itself, after the window is gone. So a
user who closes the window to abandon a scan still gets a reference file on
disk that they stopped asking for — and a manifest is exactly the artefact that
later verifies as an authoritative baseline.

These tests therefore assert on the artefact and on the user-visible controls,
not on thread bookkeeping.
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
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
class AdvancedTabCancelTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self._env = mock.patch.dict(
            os.environ, {"LOCALAPPDATA": str(self.root / "profile")}
        )
        self._env.start()

        # Enough files that the scan is still running when we act on it.
        self.data = self.root / "data"
        self.data.mkdir()
        for index in range(12):
            (self.data / f"f{index:02d}.bin").write_bytes(bytes([index]) * 2048)
        # Outside the scanned folder: keeps the policy gate quiet so no modal
        # dialog blocks the run.
        self.manifest = self.root / "m.json"

        from gui.app import HashToolApp

        self.app = HashToolApp()
        self.app.update_idletasks()
        self.tab = self.app.hash_tab

        self._release = threading.Event()
        self._destroyed = False

    def tearDown(self) -> None:
        self._release.set()
        worker = getattr(self.app, "_worker", None)
        thread = getattr(worker, "_thread", None) if worker is not None else None
        if thread is not None:
            thread.join(timeout=30)
        try:
            if not self._destroyed:
                self.app.destroy()
        except tk.TclError:  # pragma: no cover - already gone
            pass
        finally:
            self._env.stop()
            self._tmp.cleanup()

    # ------------------------------------------------------------------
    def _pump(self, rounds: int = 3) -> None:
        for _ in range(rounds):
            try:
                self.app.update()
                self.app.update_idletasks()
            except tk.TclError:  # pragma: no cover - window already destroyed
                return

    def _enabled(self, button) -> bool:
        return "disabled" not in button.state()

    def _park_after_first_file(self):
        """
        Let one file hash, then hold the scan open.

        Returns an Event set once the scan is genuinely mid-folder, so a test
        never acts on a scan that has not started.
        """
        from core import manifest_manager

        entered = threading.Event()
        real = manifest_manager.hash_file_with_snapshot
        seen: list[int] = []

        def parked(*args, **kwargs):
            seen.append(1)
            if len(seen) >= 2:
                entered.set()
                self._release.wait(timeout=30)
            return real(*args, **kwargs)

        patcher = mock.patch.object(
            manifest_manager, "hash_file_with_snapshot", parked
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        return entered

    def _start_folder_hash(self) -> None:
        self.tab.mode_var.set("folder")
        self.tab.target_var.set(str(self.data))
        self.tab.output_var.set(str(self.manifest))
        self.tab._on_run()                                # noqa: SLF001

    def _join_worker(self) -> None:
        worker = getattr(self.app, "_worker", None)
        thread = getattr(worker, "_thread", None) if worker is not None else None
        if thread is not None:
            thread.join(timeout=30)

    def _pump_until_idle(self, timeout: float = 30.0) -> None:
        """
        Run the event loop until the app has processed the terminal message.

        The result is delivered by a callback scheduled with after(100ms), so a
        fixed number of update() calls can return before it has ever run — and
        then every assertion about the end state is really an assertion about
        the moment the button was pressed. This waits for the app to actually
        clear its worker slot and fails loudly if that never happens, so a test
        can never pass by outrunning the callback it is testing.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self.app.update()
                self.app.update_idletasks()
            except tk.TclError:  # pragma: no cover - window already destroyed
                return
            if getattr(self.app, "_worker", None) is None:
                return
        raise AssertionError(
            "the app never finished the operation: the terminal message was "
            "not delivered within the timeout"
        )

    # ------------------------------------------------------------------
    def test_closing_the_window_does_not_leave_a_manifest_behind(self) -> None:
        entered = self._park_after_first_file()
        self._start_folder_hash()
        self.assertTrue(entered.wait(timeout=30), "the scan never started")

        self.app.destroy()
        self._destroyed = True
        self._release.set()
        self._join_worker()

        self.assertFalse(
            self.manifest.exists(),
            "the window was closed mid-scan and the tool still wrote a "
            "manifest — an abandoned scan became a reference file",
        )

    def test_pressing_cancel_stops_a_folder_hash(self) -> None:
        entered = self._park_after_first_file()
        self._start_folder_hash()
        self.assertTrue(entered.wait(timeout=30), "the scan never started")

        self.assertTrue(
            self._enabled(self.app.cancel_button),
            "a running folder scan offers no way to stop it",
        )
        self.app.cancel_button.invoke()
        self._release.set()
        self._join_worker()
        self._pump_until_idle()

        self.assertFalse(
            self.manifest.exists(),
            "a cancelled scan still wrote its manifest",
        )
        self.assertFalse(
            self._enabled(self.app.cancel_button),
            "cancel is still usable after the scan ended",
        )

    def test_cancelling_is_not_reported_as_a_failed_scan(self) -> None:
        # A cancelled build is incomplete by definition, and the completion
        # handler treats an incomplete build as something that went wrong —
        # "TARAMA TAMAMLANAMADI" plus a modal warning. Telling someone who
        # pressed Cancel that the scan failed describes a fault that does not
        # exist and invites them to go looking for it.
        warnings: list[tuple] = []
        errors: list[tuple] = []
        with mock.patch("gui.app.messagebox.showwarning",
                        lambda *a, **k: warnings.append(a)), \
             mock.patch("gui.app.messagebox.showerror",
                        lambda *a, **k: errors.append(a)):
            entered = self._park_after_first_file()
            self._start_folder_hash()
            self.assertTrue(entered.wait(timeout=30), "the scan never started")

            self.app.cancel_button.invoke()
            self._release.set()
            self._join_worker()
            self._pump_until_idle()

        self.assertEqual(
            warnings, [], f"cancelling raised a failure dialog: {warnings!r}"
        )
        self.assertEqual(errors, [], f"cancelling raised an error dialog: {errors!r}")
        # The settled end state, not the transitional "İptal ediliyor…" the
        # click sets — that one also contains "iptal" and would let this pass
        # without the terminal message ever being delivered.
        from gui.i18n import t

        self.assertEqual(
            self.app.status_var.get(), t("status.cancelled"),
            "the status line does not report the scan as cancelled",
        )

    def test_cancel_is_idle_when_nothing_is_running(self) -> None:
        self.assertFalse(
            self._enabled(self.app.cancel_button),
            "cancel is usable with no operation running",
        )


if __name__ == "__main__":
    unittest.main()
