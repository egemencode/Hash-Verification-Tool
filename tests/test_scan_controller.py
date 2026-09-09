"""
P0.2 — a result must never be shown under the wrong file.

These are behaviour tests against the Tk-free ``ScanController``: they drive
real state transitions, deliver real (and deliberately stale) worker
callbacks, and assert on the controller's observable state. Nothing here
inspects source text.
"""

from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from tests.support import DiagnosticTempDir, same_path
from core.scan_controller import ScanController, ControllerState


class _Recorder:
    """Captures what the view layer would have been told to render."""

    def __init__(self) -> None:
        self.rendered: list[tuple[str, str]] = []   # (path, kind)
        self.cleared = 0

    def on_result(self, session, result) -> None:
        self.rendered.append((session.path, "result"))

    def on_error(self, session, exc) -> None:
        self.rendered.append((session.path, "error"))

    def on_cleared(self) -> None:
        self.cleared += 1


class _Tree(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.a = self.root / "a.bin"
        self.b = self.root / "b.bin"
        self.a.write_bytes(b"AAAA")
        self.b.write_bytes(b"BBBB")
        self.rec = _Recorder()
        self.ctl = ScanController(
            on_result=self.rec.on_result,
            on_error=self.rec.on_error,
            on_cleared=self.rec.on_cleared,
        )

    def tearDown(self) -> None:
        self.ctl.shutdown()
        self._tmp.cleanup()


class StateMachineTests(_Tree):
    def test_starts_idle(self) -> None:
        self.assertEqual(self.ctl.state, ControllerState.IDLE)
        self.assertIsNone(self.ctl.last_result)

    def test_select_moves_to_selected(self) -> None:
        self.ctl.select(str(self.a))
        self.assertEqual(self.ctl.state, ControllerState.SELECTED)

    def test_scan_requires_a_selection(self) -> None:
        self.assertFalse(self.ctl.begin_scan())
        self.assertEqual(self.ctl.state, ControllerState.IDLE)

    def test_successful_scan_reaches_success(self) -> None:
        self.ctl.select(str(self.a))
        session = self.ctl.begin_scan()
        self.assertEqual(self.ctl.state, ControllerState.SCANNING)
        self.ctl.deliver_result(session, {"ok": True})
        self.assertEqual(self.ctl.state, ControllerState.SUCCESS)
        self.assertIsNotNone(self.ctl.last_result)

    def test_error_reaches_error_state(self) -> None:
        self.ctl.select(str(self.a))
        session = self.ctl.begin_scan()
        self.ctl.deliver_error(session, RuntimeError("boom"))
        self.assertEqual(self.ctl.state, ControllerState.ERROR)
        self.assertIsNone(self.ctl.last_result)

    def test_cancel_reaches_cancelled(self) -> None:
        self.ctl.select(str(self.a))
        session = self.ctl.begin_scan()
        self.ctl.cancel()
        self.assertTrue(session.cancelled)
        self.ctl.deliver_result(session, {"ok": True})
        self.assertEqual(self.ctl.state, ControllerState.CANCELLED)
        self.assertIsNone(self.ctl.last_result)

    def test_busy_blocks_a_second_scan(self) -> None:
        self.ctl.select(str(self.a))
        self.ctl.begin_scan()
        self.assertTrue(self.ctl.is_busy)
        self.assertFalse(self.ctl.begin_scan())


class ResultIdentityTests(_Tree):
    """The scenarios from the audit, one test each."""

    def test_1_error_on_b_does_not_leave_a_actionable(self) -> None:
        # A succeeds…
        self.ctl.select(str(self.a))
        s_a = self.ctl.begin_scan()
        self.ctl.deliver_result(s_a, {"file": "a"})
        self.assertTrue(self.ctl.can_export)
        self.assertTrue(self.ctl.can_save_baseline)

        # …then B is selected and fails.
        self.ctl.select(str(self.b))
        s_b = self.ctl.begin_scan()
        self.ctl.deliver_error(s_b, RuntimeError("unreadable"))

        self.assertIsNone(self.ctl.last_result)
        self.assertFalse(self.ctl.can_export, "A's result stayed actionable")
        self.assertFalse(self.ctl.can_save_baseline)

    def test_2_stale_callback_from_a_cannot_render_under_b(self) -> None:
        self.ctl.select(str(self.a))
        s_a = self.ctl.begin_scan()
        # B is dropped in while A is still running.
        self.ctl.select(str(self.b))
        # A's worker finishes late.
        self.ctl.deliver_result(s_a, {"file": "a"})

        self.assertEqual(self.rec.rendered, [], "a stale result was rendered")
        self.assertIsNone(self.ctl.last_result)
        self.assertEqual(self.ctl.state, ControllerState.SELECTED)
        # same_path, not assertEqual: select() stores Path(p).resolve(), so
        # comparing against the raw spelling only holds while the raw spelling
        # happens to be canonical.
        self.assertTrue(
            same_path(self.ctl.selected_path, self.b),
            f"selection is {self.ctl.selected_path}, expected {self.b}",
        )

    def test_3_rescan_of_a_missing_file_does_not_scan_the_old_one(self) -> None:
        self.ctl.select(str(self.a))
        s_a = self.ctl.begin_scan()
        self.ctl.deliver_result(s_a, {"file": "a"})

        gone = self.root / "deleted.bin"
        started = self.ctl.rescan(str(gone))
        self.assertIsNone(started, "a rescan of a missing file started a scan")
        # The negative form is the one that quietly rots: assertNotEqual
        # against a raw spelling passes on any spelling difference, so on a
        # machine that normalises the path differently it would keep passing
        # even if the controller really had fallen back to A.
        self.assertFalse(
            same_path(self.ctl.selected_path, self.a),
            "the previously selected file would have been scanned instead",
        )
        self.assertEqual(self.ctl.state, ControllerState.ERROR)

    def test_selecting_a_new_file_clears_the_previous_result(self) -> None:
        self.ctl.select(str(self.a))
        s_a = self.ctl.begin_scan()
        self.ctl.deliver_result(s_a, {"file": "a"})
        self.assertIsNotNone(self.ctl.last_result)

        self.ctl.select(str(self.b))
        self.assertIsNone(self.ctl.last_result)
        self.assertGreaterEqual(self.rec.cleared, 1)

    def test_actions_bind_to_the_scanned_identity_not_the_selection(self) -> None:
        self.ctl.select(str(self.a))
        s_a = self.ctl.begin_scan()
        self.ctl.deliver_result(s_a, {"file": "a"})
        # The user picks another file but does not scan it.
        self.ctl.select(str(self.b))
        # Nothing is exportable now — and certainly not under B's name.
        self.assertFalse(self.ctl.can_export)
        self.assertIsNone(self.ctl.result_path)

    def test_result_path_is_the_immutable_scanned_path(self) -> None:
        self.ctl.select(str(self.a))
        s_a = self.ctl.begin_scan()
        self.ctl.deliver_result(s_a, {"file": "a"})
        self.assertEqual(Path(self.ctl.result_path), self.a.resolve())

    def test_cancelled_scan_does_not_revive_previous_result(self) -> None:
        self.ctl.select(str(self.a))
        s_a = self.ctl.begin_scan()
        self.ctl.deliver_result(s_a, {"file": "a"})

        self.ctl.select(str(self.b))
        s_b = self.ctl.begin_scan()
        self.ctl.cancel()
        self.ctl.deliver_result(s_b, {"file": "b"})
        self.assertIsNone(self.ctl.last_result)
        self.assertFalse(self.ctl.can_export)


class ShutdownTests(_Tree):
    def test_4_shutdown_cancels_and_discards_late_callbacks(self) -> None:
        self.ctl.select(str(self.a))
        session = self.ctl.begin_scan()
        self.ctl.shutdown()
        self.assertTrue(session.cancelled)

        # A worker finishing after shutdown must not call back into the view.
        before = len(self.rec.rendered)
        self.ctl.deliver_result(session, {"file": "a"})
        self.ctl.deliver_error(session, RuntimeError("late"))
        self.assertEqual(len(self.rec.rendered), before)

    def test_shutdown_is_idempotent(self) -> None:
        self.ctl.shutdown()
        self.ctl.shutdown()
        self.assertTrue(self.ctl.is_shut_down)

    def test_no_new_scan_after_shutdown(self) -> None:
        self.ctl.select(str(self.a))
        self.ctl.shutdown()
        self.assertFalse(self.ctl.begin_scan())


class ConcurrencyTests(_Tree):
    def test_session_ids_are_unique_under_threads(self) -> None:
        ids: list[str] = []
        lock = threading.Lock()

        def worker() -> None:
            for _ in range(25):
                self.ctl.select(str(self.a))
                session = self.ctl.begin_scan()
                if session is not None:
                    with lock:
                        ids.append(session.session_id)
                    self.ctl.deliver_result(session, {"x": 1})

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(ids), len(set(ids)), "session ids collided")


if __name__ == "__main__":
    unittest.main()
