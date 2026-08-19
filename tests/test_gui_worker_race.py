"""
A finished operation must not be discarded because of when we looked.

``HashToolApp._poll`` drains the worker's queue and then asks whether the
thread is still alive. Between those two statements the worker can finish:
:meth:`_Worker._run` puts its terminal message and *then* returns, so there is
a window in which the drain saw an empty queue and the liveness check sees a
dead thread. The old code treated that as "nothing to report", called
``_finish`` — which also drops the reference to the worker — and the message
was gone for good.

What the user sees: a hash or verify run that completes, writes its manifest,
and reports nothing. The status line reads "Hazır." and the tab stays empty.
Nothing is *wrong* on disk, which is what makes it easy to miss; the tool has
simply stopped telling the truth about what it did.

The window is microseconds wide, so this is reproduced by construction rather
than by racing. The fake below finishes at exactly the moment the real one
can: after the drain, before the liveness check.
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
except Exception as exc:  # pragma: no cover - depends on the machine
    TK_AVAILABLE = False
    TK_SKIP = f"Tk unavailable: {exc}"


class _WorkerFinishingBetweenTheChecks:
    """
    Queues its terminal message after the first drain and before the first
    liveness check — the one interleaving the real worker can produce.
    """

    def __init__(self, message) -> None:
        self._message = message
        self._drains = 0
        self._alive = True

    def drain(self) -> list:
        self._drains += 1
        if self._drains == 1:
            # The thread finishes here: its message is now queued, and it is
            # about to be reported as dead.
            self._alive = False
            return []
        message, self._message = self._message, None
        return [message] if message is not None else []

    def is_alive(self) -> bool:
        return self._alive

    def cancel(self) -> None:
        pass

    def join(self, timeout: float) -> None:
        pass


@unittest.skipUnless(TK_AVAILABLE, TK_SKIP or "Tk unavailable")
class WorkerHandoverTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        profile = Path(self._tmp.name) / "profile"
        (profile / "HashTool").mkdir(parents=True)
        self._env = mock.patch.dict(os.environ, {"LOCALAPPDATA": str(profile)})
        self._env.start()

        import utils.settings as settings_mod
        from gui.i18n import set_language

        settings_mod._reset_write_disabled_for_tests()      # noqa: SLF001
        set_language("tr")

        from gui.app import HashToolApp

        self.app = HashToolApp()
        self.app.update_idletasks()

    def tearDown(self) -> None:
        try:
            self.app.destroy()
        finally:
            self._env.stop()
            self._tmp.cleanup()

    def _poll_with(self, kind: str, payload):
        from gui.app import _Message

        worker = _WorkerFinishingBetweenTheChecks(_Message(kind, payload))
        self.app._worker = worker                           # noqa: SLF001
        seen: list = []
        errors: list = []
        self.app._poll(seen.append, errors.append, None)    # noqa: SLF001
        return seen, errors

    def test_a_result_queued_as_the_thread_exits_still_reaches_the_tab(self) -> None:
        seen, _ = self._poll_with("done", {"manifest": "written"})
        self.assertEqual(
            seen, [{"manifest": "written"}],
            "the completed operation was discarded: the run finished, the "
            "manifest was written, and nothing was reported",
        )

    def test_a_failure_queued_as_the_thread_exits_is_still_reported(self) -> None:
        """
        The worse half of the same window.

        Dropping a "done" costs the user a result they can recompute. Dropping
        an "error" replaces a failure with ``status.ready`` — the tool reports
        success for something that did not happen.
        """
        from gui.i18n import t

        seen, errors = self._poll_with("error", RuntimeError("disk full"))
        self.assertEqual(seen, [], "a failure was delivered as a result")
        self.assertEqual(
            [str(e) for e in errors], ["disk full"],
            "the failure was swallowed and the run reported as finished",
        )
        self.assertNotEqual(
            self.app.status_var.get(), t("status.ready"),
            "the status line claims the run ended normally",
        )

    def test_a_cancel_queued_as_the_thread_exits_is_still_announced(self) -> None:
        from gui.i18n import t

        seen, errors = self._poll_with("cancelled", None)
        self.assertEqual(seen, [], "a cancelled run was rendered as a result")
        self.assertEqual(errors, [])
        self.assertEqual(
            self.app.status_var.get(), t("status.cancelled"),
            "the cancelled run was reported as an ordinary finish",
        )


if __name__ == "__main__":
    unittest.main()
