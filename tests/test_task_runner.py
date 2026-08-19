"""
The ordering rules a background job has to obey, without a display.

:mod:`core.task_runner` exists because "which answer is current?" was decided
by whichever thread happened to finish last. These tests pin the answer to
identity instead of timing, so a future change that makes the runner faster or
slower cannot quietly make it wrong.
"""

from __future__ import annotations

import threading
import unittest

from core.task_runner import (
    CANCELLED,
    DONE,
    ERROR,
    TaskCancelled,
    TaskRunner,
)


class _Gate:
    """
    A job that waits until the test lets it finish, and never looks at its
    cancellation token.

    That is the realistic shape, not a shortcut: the job this module was
    written for is a blocking HTTP request, which cannot be interrupted and
    will hand back a perfectly good answer to a question nobody is asking any
    more. A gate that checked the token would only exercise the easy path.
    """

    def __init__(self, value: str) -> None:
        self.value = value
        self.entered = threading.Event()
        self.release = threading.Event()
        self.done = threading.Event()

    def __call__(self, task) -> str:
        self.entered.set()
        if not self.release.wait(timeout=10.0):
            raise AssertionError("the test never released this job")
        self.done.set()
        return self.value


def _collect(runner, count: int, timeout: float = 5.0) -> list:
    """
    Drain until *count* results have arrived.

    Not "wait until the runner is idle": ``busy`` describes the current task
    only, and a superseded worker can still be running behind it — which is
    the very thing these tests are about.
    """
    deadline = threading.Event()
    timer = threading.Timer(timeout, deadline.set)
    timer.daemon = True
    timer.start()
    try:
        out: list = []
        while len(out) < count and not deadline.is_set():
            out.extend(runner.drain())
            if len(out) < count:
                threading.Event().wait(0.02)
        return out
    finally:
        timer.cancel()


class SupersessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = TaskRunner(label="test")

    def tearDown(self) -> None:
        self.runner.shutdown(timeout=2.0)

    def test_the_current_task_is_the_one_submitted_last(self) -> None:
        first_gate, second_gate = _Gate("first"), _Gate("second")
        first = self.runner.submit(first_gate)
        self.assertTrue(first_gate.entered.wait(timeout=5.0))
        second = self.runner.submit(second_gate)

        self.assertFalse(self.runner.is_current(first))
        self.assertTrue(self.runner.is_current(second))
        self.assertTrue(first.cancelled, "the superseded task was not cancelled")

        first_gate.release.set()
        second_gate.release.set()

    def test_a_superseded_answer_is_refused_even_when_it_arrives_first(self) -> None:
        """
        The point of the whole module.

        Cancellation cannot interrupt a blocking call, so the old job finishes
        and posts something. Ordering by arrival would let it win.
        """
        first_gate, second_gate = _Gate("stale"), _Gate("fresh")
        self.runner.submit(first_gate)
        self.assertTrue(first_gate.entered.wait(timeout=5.0))
        self.runner.submit(second_gate)
        self.assertTrue(second_gate.entered.wait(timeout=5.0))

        # The stale one finishes first, on purpose.
        first_gate.release.set()
        second_gate.release.set()
        results = _collect(self.runner, 2)
        self.assertEqual(len(results), 2, "not both jobs reported back")
        kinds = {r.payload: r.kind for r in results}
        self.assertEqual(
            kinds.get("stale"), CANCELLED,
            "a superseded job reported its answer as a live result",
        )
        self.assertEqual(kinds.get("fresh"), DONE)

    def test_drain_current_returns_only_the_live_answer(self) -> None:
        """
        Released in two phases, so the queue holds *only* the stale answer
        while the first phase runs.

        An earlier version released both at once and then polled until
        something came back. That version passed against a ``drain_current``
        that returned whatever it drained last — which answer surfaced was
        decided by thread scheduling, so the test agreed with either
        behaviour. ``tools/verify_fix_coverage.py`` refused it, correctly.
        """
        first_gate, second_gate = _Gate("stale"), _Gate("fresh")
        self.runner.submit(first_gate)
        self.assertTrue(first_gate.entered.wait(timeout=5.0))
        self.runner.submit(second_gate)
        self.assertTrue(second_gate.entered.wait(timeout=5.0))

        seen: list[str] = []

        def collect(window: float) -> None:
            end = threading.Event()
            timer = threading.Timer(window, end.set)
            timer.daemon = True
            timer.start()
            try:
                while not end.is_set():
                    result = self.runner.drain_current()
                    if result is not None:
                        seen.append(result.payload)
                    threading.Event().wait(0.01)
            finally:
                timer.cancel()

        # Phase one: only the superseded job can answer. The window is short
        # and bounded, and it exists to give the wrong behaviour a chance to
        # appear rather than to wait out a right one.
        first_gate.release.set()
        self.assertTrue(first_gate.done.wait(timeout=5.0))
        collect(0.4)
        self.assertEqual(
            seen, [],
            "a superseded answer was handed to the caller as the live one",
        )

        second_gate.release.set()
        self.assertTrue(second_gate.done.wait(timeout=5.0))
        collect(0.4)
        self.assertEqual(seen, ["fresh"], "the live answer was dropped")


class OutcomeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = TaskRunner(label="test")

    def tearDown(self) -> None:
        self.runner.shutdown(timeout=2.0)

    def _settle(self):
        return _collect(self.runner, 1)

    def test_a_raising_job_reports_the_exception_rather_than_losing_it(self) -> None:
        def boom(task):
            raise ValueError("no network")

        self.runner.submit(boom)
        results = self._settle()
        self.assertEqual([r.kind for r in results], [ERROR])
        self.assertIsInstance(results[0].payload, ValueError)

    def test_a_job_that_honours_its_token_reports_cancelled(self) -> None:
        started = threading.Event()

        def cooperative(task):
            started.set()
            for _ in range(500):
                task.raise_if_cancelled()
                threading.Event().wait(0.01)
            return "finished anyway"

        self.runner.submit(cooperative)
        self.assertTrue(started.wait(timeout=5.0))
        self.runner.cancel()
        results = self._settle()
        self.assertEqual([r.kind for r in results], [CANCELLED])

    def test_the_token_raises_the_runners_own_exception(self) -> None:
        runner = TaskRunner(label="probe")
        task = runner.submit(lambda t: None)
        self.assertIsNotNone(task)
        task.cancel()
        with self.assertRaises(TaskCancelled):
            task.raise_if_cancelled()
        runner.shutdown(timeout=2.0)


class ShutdownTests(unittest.TestCase):
    def test_a_closed_runner_refuses_new_work(self) -> None:
        """
        Not tidiness: a job submitted after teardown has nobody left to drain
        it, so it would run, finish, and post into a queue nothing reads —
        while the caller believes it was started.
        """
        runner = TaskRunner(label="test")
        runner.shutdown(timeout=2.0)
        self.assertIsNone(runner.submit(lambda task: "should not run"))

    def test_shutdown_cancels_the_job_in_flight(self) -> None:
        runner = TaskRunner(label="test")
        gate = _Gate("value")
        task = runner.submit(gate)
        self.assertTrue(gate.entered.wait(timeout=5.0))

        # Bounded: the job ignores its token, and the window may not be held
        # open by a worker that will not stop.
        gate.release.set()
        runner.shutdown(timeout=2.0)
        self.assertTrue(task.cancelled)


if __name__ == "__main__":
    unittest.main()
