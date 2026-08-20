"""
"Test Key" runs on a thread nobody owns.

Every other background job in this application goes through one of two
mechanisms. Trust Check has :class:`core.scan_controller.ScanController` — a
session identity, a cancel token, a bounded join, a single scheduler. The
Advanced tabs have ``_Worker`` in ``gui/app.py``, which has the same token,
join and scheduler discipline under a different name.

``SettingsView._on_test`` has neither. It calls ``threading.Thread(...)``
directly and hands the answer back with a bare ``self.after(0, ...)``. So:

* nothing knows which request is current, and a stale answer overwrites a
  fresh one — the same "a late result is attached to the wrong subject"
  failure that ScanSession was written to prevent, here about which *key* the
  verdict belongs to;
* nothing waits for it at teardown, and the callback it schedules lands on a
  destroyed widget.

Both are demonstrated below against a client that is held open on purpose, so
the ordering is decided by the test rather than by the network.
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
except Exception as exc:  # pragma: no cover - depends on the machine
    TK_AVAILABLE = False
    TK_SKIP = f"Tk unavailable: {exc}"


class _HeldClient:
    """
    A VirusTotal client whose lookup blocks until the test releases it.

    One instance per key, registered in a shared registry so the test can
    release them in whatever order it wants to reproduce.

    Each key answers with a *different* verdict. Two identical answers would
    make "the stale one overwrote the current one" unobservable — the screen
    would read the same either way, and the test would pass without deciding
    anything.
    """

    registry: dict[str, "_HeldClient"] = {}
    verdicts: dict[str, str] = {}

    def __init__(self, api_key: str = "", timeout: float = 0.0) -> None:
        self.api_key = api_key
        self.released = threading.Event()
        self.entered = threading.Event()
        type(self).registry[api_key] = self

    @property
    def has_key(self) -> bool:
        return bool(self.api_key)

    def lookup_hash(self, digest: str):
        self.entered.set()
        # Bounded so a broken test fails instead of hanging the suite.
        if not self.released.wait(timeout=10.0):
            raise AssertionError("the test never released this lookup")
        from core.vt_client import VTStatus

        status = type(self).verdicts.get(self.api_key, VTStatus.OK)
        return mock.Mock(status=status, message=f"verdict for {self.api_key}")


@unittest.skipUnless(TK_AVAILABLE, TK_SKIP or "Tk unavailable")
class KeyTestTaskTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        profile = Path(self._tmp.name) / "profile"
        (profile / "HashTool").mkdir(parents=True)
        self._env = mock.patch.dict(os.environ, {"LOCALAPPDATA": str(profile)})
        self._env.start()

        import utils.settings as settings_mod
        from gui.i18n import set_language

        settings_mod._reset_write_disabled_for_tests()      # noqa: SLF001
        set_language("tr")

        _HeldClient.registry.clear()
        _HeldClient.verdicts = {}
        self._patch = mock.patch(
            "gui.views.settings_view.VirusTotalClient", _HeldClient
        )
        self._patch.start()

        from gui.app import HashToolApp

        self.app = HashToolApp()
        self.app.update()
        self.view = self.app.settings_view

    def tearDown(self) -> None:
        for client in list(_HeldClient.registry.values()):
            client.released.set()
        try:
            if self.app.winfo_exists():
                self.app.destroy()
        except tk.TclError:
            pass
        finally:
            self._patch.stop()
            self._env.stop()
            self._tmp.cleanup()

    # ------------------------------------------------------------------
    def _start_test_for(self, key: str) -> _HeldClient:
        self.view.api_key_var.set(key)
        self.view._on_test()                                # noqa: SLF001
        self.app.update()
        client = _HeldClient.registry.get(key)
        self.assertIsNotNone(client, f"no lookup was started for {key!r}")
        self.assertTrue(
            client.entered.wait(timeout=5.0),
            f"the worker for {key!r} never reached the lookup",
        )
        return client

    def _run_loop(self, ms: int = 400) -> None:
        """
        Run the real event loop for a moment.

        ``update()`` is not enough here. Tkinter refuses an ``after()`` issued
        from a secondary thread unless the main loop is actually running, and
        the delivery under test is exactly that call — so a test that only
        pumps ``update()`` never sees either verdict arrive and passes while
        asserting nothing. This one starts the loop and stops it again with
        ``quit()``, which leaves the window intact.
        """
        self.app.after(ms, self.app.quit)
        self.app.mainloop()

    def test_a_stale_verdict_cannot_overwrite_the_current_one(self) -> None:
        """
        Press Test, edit the key, press Test again, then let the *first*
        lookup finish last.

        The status line must keep talking about the key that is in the field.
        Without an identity check the older answer lands second and wins, and
        the user reads a verdict about a key they have already replaced.
        """
        from core.vt_client import VTStatus
        from gui.i18n import t

        # The realistic shape of this: a key that was rejected, then corrected.
        _HeldClient.verdicts = {
            "OLD-KEY": VTStatus.UNAUTHORIZED,
            "NEW-KEY": VTStatus.OK,
        }
        first = self._start_test_for("OLD-KEY")
        second = self._start_test_for("NEW-KEY")
        pending = self.view.test_status_var.get()
        self.assertEqual(pending, t("settings.test.running"))

        # The stale one answers FIRST, which is both the realistic order — it
        # started earlier — and the only order that tests anything. Letting
        # the current one answer first stops the poll chain (nothing is busy
        # any more), so the stale answer is never even drained and the screen
        # is protected by an accident rather than by a decision.
        #
        # Released from inside the loop: a worker that calls after() while the
        # loop is stopped raises instead of delivering.
        self.app.after(50, first.released.set)
        self._run_loop()

        self.assertEqual(
            self.view.test_status_var.get(), pending,
            "the superseded lookup wrote the screen: the user is told a key "
            "was rejected after they already replaced it",
        )

        self.app.after(50, second.released.set)
        self._run_loop()

        self.assertEqual(
            self.view.test_status_var.get(), t("settings.test.ok"),
            "the current lookup's verdict never reached the screen",
        )

    def test_switching_language_stops_the_lookup_it_throws_away(self) -> None:
        """
        The Settings tab is destroyed more often than the window is.

        A language switch rebuilds the whole notebook, so this view goes away
        while the application keeps running — and with it goes the only thing
        that was ever going to read the answer. The request must be told to
        stop, not left running against a screen that no longer exists. That is
        the same obligation ``_switch_language`` already honours for the trust
        view; Settings simply had nothing to honour it with.

        What this does *not* claim: that leaving it would raise. It would not.
        Destroying a widget deletes its Tcl commands, so a pending ``after``
        aimed at it fires into nothing — no callback, no error, no report. The
        first version of this test asserted that an exception was reported and
        passed against the broken code for exactly that reason;
        ``tools/verify_fix_coverage.py`` refused it as toothless, which is
        what that harness is for.
        """
        self._start_test_for("SOME-KEY")
        runner = self.view._key_test                        # noqa: SLF001
        task = runner.current
        self.assertIsNotNone(task)
        self.assertFalse(task.cancelled)

        self.app._switch_language("en")                     # noqa: SLF001

        self.assertTrue(
            task.cancelled,
            "the discarded view left its lookup running",
        )
        self.assertIsNone(
            runner.submit(lambda t: "should not run"),
            "the discarded view's runner still accepts work nobody will read",
        )

    def test_the_lookup_never_calls_into_tk_from_its_own_thread(self) -> None:
        """
        The original defect, stated as the rule that prevents it.

        ``_on_test`` used to hand its answer back with ``self.after(0, ...)``
        from inside the worker. Tkinter rejects that unless the main loop
        happens to be running, and on a window that has already been destroyed
        it raises on the worker thread.

        This does not assert "no exception was raised": the runner catches
        whatever its job throws and reports it as a result, so the crash is
        now contained and an exception-shaped test would pass against the
        broken code. What still bites is *which thread* touches Tk. Delivery
        must happen on the one that owns the widgets.
        """
        from gui.i18n import t

        main = threading.current_thread()
        callers: list[threading.Thread] = []
        original_after = self.view.after

        def recording_after(*args, **kwargs):
            callers.append(threading.current_thread())
            return original_after(*args, **kwargs)

        self.view.after = recording_after                   # type: ignore[method-assign]

        client = self._start_test_for("SOME-KEY")
        self.app.after(50, client.released.set)
        self._run_loop()

        self.assertTrue(callers, "nothing scheduled anything — the probe is blind")
        offenders = sorted({c.name for c in callers if c is not main})
        self.assertEqual(
            offenders, [],
            "the lookup reached into Tk from a worker thread",
        )
        self.assertNotEqual(
            self.view.test_status_var.get(), t("settings.test.running"),
            "the verdict never arrived, so the delivery path was not exercised",
        )


if __name__ == "__main__":
    unittest.main()
