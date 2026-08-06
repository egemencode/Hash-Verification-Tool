"""
RT2#3 — destroying the window must not leave a scheduled Tk callback behind.

A pending ``after()`` script keeps firing after its widget is gone and Tk
reports ``invalid command name "..._poll_queue"`` on stderr. The process
still exits 0, so only stderr reveals it — which is why this test runs the
scenario in a **child process** and fails on any Tcl noise.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Any of these in stderr means a callback outlived its widget.
_FORBIDDEN = (
    "invalid command name",
    "bgerror",
    "TclError",
    "main thread is not in main loop",
)

_SCENARIO = textwrap.dedent(
    """
    import os, sys, tempfile, time

    profile = tempfile.mkdtemp()
    os.environ["LOCALAPPDATA"] = profile

    import tkinter as tk
    try:
        tk.Tk().destroy()
    except Exception as exc:
        print("SKIP:no-tk", exc)
        raise SystemExit(0)

    from gui.app import HashToolApp

    workdir = tempfile.mkdtemp()
    sample = os.path.join(workdir, "sample.bin")
    with open(sample, "wb") as fh:
        fh.write(b"A" * 4096)

    app = HashToolApp()
    app.update_idletasks()
    view = app.trust_view

    # Start a real scan so a poll callback is genuinely scheduled.
    view._set_selected_path(sample)
    view._on_scan()
    app.update()

    {teardown}

    # Run the event loop long enough for any surviving after() script to fire.
    deadline = time.time() + 2.0
    while time.time() < deadline:
        try:
            root.update()
        except tk.TclError:
            break
        time.sleep(0.02)

    print("SCENARIO OK")
    """
)


def _run_scenario(teardown: str) -> subprocess.CompletedProcess:
    code = _SCENARIO.format(teardown=teardown)
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(_PROJECT_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
    )


class TkShutdownIsSilentTests(unittest.TestCase):
    def _assert_clean(self, proc: subprocess.CompletedProcess) -> None:
        if "SKIP:no-tk" in proc.stdout:
            self.skipTest("Tk unavailable in the child process")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        for needle in _FORBIDDEN:
            self.assertNotIn(
                needle, proc.stderr,
                f"Tcl noise after teardown ({needle}):\n{proc.stderr}",
            )

    def test_destroying_the_app_leaves_no_callback(self) -> None:
        self._assert_clean(
            _run_scenario("root = app\napp.destroy()")
        )

    def test_destroying_only_the_view_leaves_no_callback(self) -> None:
        # The view can be torn down on its own (notebook rebuild).
        self._assert_clean(
            _run_scenario("view.shutdown()\nview.destroy()\nroot = app")
        )

    def test_language_rebuild_leaves_no_callback(self) -> None:
        self._assert_clean(
            _run_scenario(
                "app._shutdown_active_scans()\n"
                "app._switch_language('en')\n"
                "root = app"
            )
        )

    def test_scenario_actually_scheduled_a_poll(self) -> None:
        # Guard against the test passing because nothing was ever scheduled.
        proc = _run_scenario(
            "print('POLL_ID', view._poll_after_id is not None)\n"
            "root = app\napp.destroy()"
        )
        if "SKIP:no-tk" in proc.stdout:
            self.skipTest("Tk unavailable in the child process")
        self.assertIn(
            "POLL_ID True", proc.stdout,
            "no poll callback was pending, so the test proves nothing",
        )


if __name__ == "__main__":
    unittest.main()
