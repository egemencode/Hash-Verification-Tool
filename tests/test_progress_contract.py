"""
The ProgressEvent contract.

Progress is a promise to the UI: the denominator does not move, the numerator
only goes up, and exactly one final event says how the run ended. Today the
folder scanners break the first promise — they enumerate the tree once to
count and a second time to process, so a file created in between makes
``done`` overshoot ``total`` — and they break the third: an empty folder emits
no event at all, leaving a progress bar stuck at 0% with nothing to clear it.

Every assertion below is on the events a caller actually receives.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import core.manifest_manager as mm
from core.hash_utils import ProgressEvent, ScanState
from core.manifest_manager import build_manifest_for_folder
from core.verifier import Verifier
from tests.support import DiagnosticTempDir


class _Recorder:
    """Collects progress events and answers the invariants we care about."""

    def __init__(self) -> None:
        self.events: list[ProgressEvent] = []

    def __call__(self, event: ProgressEvent) -> None:
        self.events.append(event)

    @property
    def terminal(self) -> list[ProgressEvent]:
        return [e for e in self.events if e.is_terminal]

    def assert_contract(self, case: unittest.TestCase) -> ProgressEvent:
        case.assertTrue(self.events, "no progress events were emitted at all")
        for event in self.events:
            case.assertGreaterEqual(event.percent, 0.0)
            case.assertLessEqual(event.percent, 100.0)
            case.assertLessEqual(
                event.done,
                event.total,
                f"done overshot total: {event.done}/{event.total} at {event.path!r}",
            )
        progressed = [e for e in self.events if not e.is_terminal]
        for previous, current in zip(progressed, progressed[1:]):
            case.assertGreaterEqual(
                current.done, previous.done, "progress went backwards"
            )
        case.assertEqual(
            len(self.terminal), 1,
            f"expected exactly one terminal event, got {len(self.terminal)}",
        )
        case.assertIs(
            self.events[-1], self.terminal[0], "the terminal event was not last"
        )
        return self.terminal[0]


class _ScanCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _populate(self, count: int = 3) -> None:
        for i in range(count):
            (self.data / f"f{i}.txt").write_text(f"content {i}", encoding="utf-8")


class BuildProgressTests(_ScanCase):
    def test_done_never_exceeds_total_when_a_file_appears_mid_scan(self) -> None:
        # No mocking: the file is created from inside the progress callback, in
        # a directory the walk has not opened yet. A scanner that counts with
        # one walk and processes with a second, lazily-consumed one picks it up
        # during the loop while the denominator was fixed before it.
        (self.data / "sub1").mkdir()
        (self.data / "sub2").mkdir()
        (self.data / "sub1" / "a.txt").write_text("a", encoding="utf-8")
        (self.data / "sub2" / "b.txt").write_text("b", encoding="utf-8")

        rec = _Recorder()
        state = {"fired": False}

        def watch(event: ProgressEvent) -> None:
            rec(event)
            if not state["fired"] and event.path.startswith("sub1/"):
                state["fired"] = True
                (self.data / "sub2" / "late.txt").write_text("late", encoding="utf-8")

        build_manifest_for_folder(self.data, on_progress=watch)

        self.assertTrue(state["fired"], "the injection point was never reached")
        self.assertTrue((self.data / "sub2" / "late.txt").exists())
        rec.assert_contract(self)
        per_file = [e for e in rec.events if not e.is_terminal]
        self.assertEqual(
            len(per_file), rec.events[-1].total,
            "the loop processed a different number of files than it counted",
        )

    def test_empty_folder_still_reports_a_terminal_event(self) -> None:
        rec = _Recorder()
        build_manifest_for_folder(self.data, on_progress=rec)
        terminal = rec.assert_contract(self)
        self.assertIs(terminal.state, ScanState.COMPLETED)
        self.assertEqual(
            terminal.percent, 100.0,
            "a finished scan must not leave the bar below 100%",
        )

    def test_normal_scan_ends_completed(self) -> None:
        self._populate(4)
        rec = _Recorder()
        result = build_manifest_for_folder(self.data, on_progress=rec)
        terminal = rec.assert_contract(self)
        self.assertIs(terminal.state, ScanState.COMPLETED)
        self.assertEqual(terminal.done, terminal.total)
        self.assertTrue(result.complete)

    def test_unreadable_file_does_not_break_the_sequence(self) -> None:
        self._populate(3)
        real = mm.hash_file_with_snapshot

        def fail_on_one(path, *a, **kw):
            if Path(path).name == "f1.txt":
                raise mm.HashError("simulated read failure")
            return real(path, *a, **kw)

        rec = _Recorder()
        mm.hash_file_with_snapshot = fail_on_one
        try:
            result = build_manifest_for_folder(self.data, on_progress=rec)
        finally:
            mm.hash_file_with_snapshot = real

        terminal = rec.assert_contract(self)
        self.assertIs(terminal.state, ScanState.COMPLETED)
        self.assertFalse(result.complete)
        self.assertIn("f1.txt", result.skipped)

    def test_cancelled_scan_has_its_own_state_and_is_not_complete(self) -> None:
        self._populate(6)
        rec = _Recorder()
        seen: list[str] = []

        def cancel_after_two() -> bool:
            return len(seen) >= 2

        def watch(event: ProgressEvent) -> None:
            if not event.is_terminal:
                seen.append(event.path)
            rec(event)

        result = build_manifest_for_folder(
            self.data, on_progress=watch, cancel=cancel_after_two
        )

        terminal = rec.assert_contract(self)
        self.assertIs(terminal.state, ScanState.CANCELLED)
        self.assertTrue(result.cancelled)
        self.assertFalse(
            result.complete,
            "a cancelled scan described the folder as fully covered",
        )
        self.assertLess(result.file_count, 6, "cancellation did not stop the work")

    def test_cancelled_build_refuses_to_write_a_manifest(self) -> None:
        # Two separate guards can raise ManifestError here, so assert the one
        # that only cancellation triggers: even with allow_partial=True — the
        # escape hatch an incomplete scan does have — a cancelled scan writes
        # nothing. It stopped at an arbitrary file, so the artefact would be a
        # prefix of the folder with no marker saying where it stops.
        self._populate(6)
        cancelled = build_manifest_for_folder(self.data, cancel=lambda: True)
        target = self.root / "m.json"

        with self.assertRaises(mm.ManifestError):
            cancelled.save(target)
        with self.assertRaises(mm.ManifestError):
            cancelled.save(target, allow_partial=True)
        self.assertFalse(target.exists())
        self.assertFalse((self.root / "m.partial.json").exists())

        # Contrast: a merely *incomplete* scan does get the escape hatch, so
        # the assertion above is about cancellation and not about incompleteness.
        real = mm.hash_file_with_snapshot

        def fail_on_one(path, *a, **kw):
            if Path(path).name == "f1.txt":
                raise mm.HashError("simulated read failure")
            return real(path, *a, **kw)

        mm.hash_file_with_snapshot = fail_on_one
        try:
            incomplete = build_manifest_for_folder(self.data)
        finally:
            mm.hash_file_with_snapshot = real

        self.assertFalse(incomplete.complete)
        self.assertFalse(incomplete.cancelled)
        written = incomplete.save(target, allow_partial=True)
        self.assertTrue(Path(written).exists())

    def test_a_scan_that_raises_still_reports_a_terminal_event(self) -> None:
        # The contract promised to callers is "exactly one terminal event,
        # always last". A UI that stops its spinner on is_terminal hangs
        # forever if an exception can escape without one — and the tree
        # vanishing mid-scan (removable media, a temp dir another process
        # cleans up) does exactly that, from the post-loop re-walk.
        self._populate(3)
        rec = _Recorder()
        real_inventory = mm.snapshot_inventory

        def blow_up(*args, **kwargs):
            raise mm.HashError("Folder not found: simulated")

        mm.snapshot_inventory = blow_up
        try:
            with self.assertRaises(mm.HashError):
                build_manifest_for_folder(self.data, on_progress=rec)
        finally:
            mm.snapshot_inventory = real_inventory

        terminal = rec.assert_contract(self)
        self.assertIs(terminal.state, ScanState.FAILED)

    def test_a_verify_that_raises_still_reports_a_terminal_event(self) -> None:
        self._populate(3)
        manifest = build_manifest_for_folder(self.data).manifest
        import core.verifier as verifier_mod

        rec = _Recorder()
        real_inventory = verifier_mod.snapshot_inventory

        def blow_up(*args, **kwargs):
            raise verifier_mod.HashError("Cannot list: simulated")

        verifier_mod.snapshot_inventory = blow_up
        try:
            with self.assertRaises(verifier_mod.HashError):
                Verifier(manifest).verify(self.data, on_progress=rec)
        finally:
            verifier_mod.snapshot_inventory = real_inventory

        terminal = rec.assert_contract(self)
        self.assertIs(terminal.state, ScanState.FAILED)


class VerifyProgressTests(_ScanCase):
    def _manifest(self):
        return build_manifest_for_folder(self.data).manifest

    def test_done_never_exceeds_total_when_a_file_appears_mid_verify(self) -> None:
        # No mocking: create the file from inside the progress callback, in a
        # directory the walk has not reached yet. A scanner that counts with
        # one walk and then processes with a second, lazily-consumed one picks
        # the new file up during the loop while the denominator was fixed
        # before it — the bar goes past its own maximum. One shared enumeration
        # cannot.
        (self.data / "sub1").mkdir()
        (self.data / "sub2").mkdir()
        (self.data / "sub1" / "a.txt").write_text("a", encoding="utf-8")
        (self.data / "sub2" / "b.txt").write_text("b", encoding="utf-8")
        manifest = self._manifest()

        rec = _Recorder()
        state = {"fired": False}

        def watch(event: ProgressEvent) -> None:
            rec(event)
            if not state["fired"] and event.path.startswith("sub1/"):
                state["fired"] = True
                (self.data / "sub2" / "late.txt").write_text("late", encoding="utf-8")

        Verifier(manifest).verify(self.data, on_progress=watch)

        self.assertTrue(state["fired"], "the injection point was never reached")
        self.assertTrue((self.data / "sub2" / "late.txt").exists())
        rec.assert_contract(self)
        per_file = [e for e in rec.events if not e.is_terminal]
        self.assertEqual(
            len(per_file), rec.events[-1].total,
            "the loop processed a different number of files than it counted",
        )

    def test_empty_folder_verify_reports_terminal(self) -> None:
        manifest = self._manifest()
        rec = _Recorder()
        Verifier(manifest).verify(self.data, on_progress=rec)
        terminal = rec.assert_contract(self)
        self.assertIs(terminal.state, ScanState.COMPLETED)

    def test_cancelled_verify_is_not_a_clean_result(self) -> None:
        self._populate(6)
        manifest = self._manifest()
        rec = _Recorder()
        calls = {"n": 0}

        def cancel_after_two() -> bool:
            calls["n"] += 1
            return calls["n"] > 3

        result = Verifier(manifest).verify(
            self.data, on_progress=rec, cancel=cancel_after_two
        )
        terminal = rec.assert_contract(self)
        self.assertIs(terminal.state, ScanState.CANCELLED)
        self.assertTrue(result.cancelled)
        self.assertFalse(
            result.scan_complete,
            "a cancelled verify claimed it had observed the whole folder",
        )
        self.assertFalse(result.trusted_match)
        self.assertFalse(result.is_clean)


if __name__ == "__main__":
    unittest.main()
