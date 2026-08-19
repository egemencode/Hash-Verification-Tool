"""
One background job at a time, with an identity and a way to stop it.

Why this exists
---------------
Three surfaces in this application run work off the UI thread, and until now
each answered the same four questions differently — or not at all:

* Trust Check has :class:`core.scan_controller.ScanController`: a session id,
  a cancel token, a bounded join, a single scheduler.
* The Advanced tabs have ``_Worker`` in ``gui/app.py``: the same token, join
  and scheduler under different names, but no identity.
* Settings' "Test Key" had none of it. A bare ``threading.Thread`` and a bare
  cross-thread ``after()``.

The missing identity is not a tidiness complaint. Press Test, notice the key
is wrong, paste the right one, press Test again: two lookups are now in
flight, and whichever finishes *last* writes the screen. The user reads
"the key was rejected" about a key they already replaced. That is the same
failure ScanSession was written to prevent — a late answer attached to the
wrong subject — and it was reachable in Settings because nothing there knew
what "current" meant.

The shape
---------
Results are delivered through a queue that the UI thread drains, never by
calling back into Tk from the worker. That is deliberate: Tkinter rejects an
``after()`` issued from another thread unless the main loop happens to be
running, and when the window has already been destroyed the call raises on the
worker thread, where the exception is printed and otherwise ignored. Handing
back a queue makes delivery the caller's business, on the caller's thread, at
a moment the caller chooses.

Free of Tk, so the ordering rules are testable without a display.
"""

from __future__ import annotations

import itertools
import queue
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from utils.logger import get_logger

log = get_logger("core.tasks")

_task_counter = itertools.count(1)

# Terminal outcomes a task can report.
DONE = "done"
ERROR = "error"
CANCELLED = "cancelled"


class TaskCancelled(Exception):
    """Raised inside a worker whose task was superseded or cancelled."""


@dataclass(frozen=True)
class Task:
    """One submission. Immutable except for its cancellation flag."""

    task_id: str
    label: str
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def cancel(self) -> None:
        self._cancel.set()

    def raise_if_cancelled(self) -> None:
        """Worker-side cooperative cancellation check."""
        if self.cancelled:
            raise TaskCancelled(self.task_id)


@dataclass(frozen=True)
class TaskResult:
    """What a finished task hands back, with the task that produced it."""

    task: Task
    kind: str           # DONE | ERROR | CANCELLED
    payload: Any


class TaskRunner:
    """
    Runs one job at a time and remembers which one is current.

    Submitting again supersedes the job in flight: the old task is cancelled
    and — this is the part that matters — its result is refused even if it
    arrives first, because the runner compares identities rather than timing.
    Cancellation is cooperative and cannot interrupt a blocking call, so
    "refused on arrival" is the only guarantee available and the one the
    caller can rely on.
    """

    def __init__(self, *, label: str = "task") -> None:
        self._label = label
        self._lock = threading.Lock()
        self._current: Optional[Task] = None
        self._thread: Optional[threading.Thread] = None
        self._queue: "queue.Queue[TaskResult]" = queue.Queue()
        self._shut_down = False

    # --- submitting ---------------------------------------------------
    def submit(self, target: Callable[[Task], Any]) -> Optional[Task]:
        """
        Start *target* on a daemon thread, superseding anything in flight.

        Returns the new task, or ``None`` once :meth:`shutdown` has run — a
        runner that has been torn down must not start work whose results
        nobody will ever drain.
        """
        with self._lock:
            if self._shut_down:
                return None
            if self._current is not None:
                self._current.cancel()
            task = Task(task_id=f"{self._label}-{next(_task_counter)}",
                        label=self._label)
            self._current = task
            thread = threading.Thread(
                target=self._run, args=(target, task), daemon=True,
                name=f"{self._label}-worker",
            )
            self._thread = thread
        thread.start()
        return task

    def _run(self, target: Callable[[Task], Any], task: Task) -> None:
        try:
            result = target(task)
        except TaskCancelled:
            self._queue.put(TaskResult(task, CANCELLED, None))
            return
        except Exception as exc:  # noqa: BLE001 - reported, never swallowed
            log.exception("%s failed", task.task_id)
            self._queue.put(TaskResult(task, ERROR, exc))
            return
        # A task that was superseded while it worked did not produce the
        # answer anybody is still waiting for. Say so rather than letting the
        # caller decide from a bare result whether it is stale.
        if task.cancelled:
            self._queue.put(TaskResult(task, CANCELLED, result))
        else:
            self._queue.put(TaskResult(task, DONE, result))

    # --- consuming ----------------------------------------------------
    def is_current(self, task: Optional[Task]) -> bool:
        return task is not None and self._current is task

    @property
    def current(self) -> Optional[Task]:
        return self._current

    @property
    def busy(self) -> bool:
        """
        Whether the *current* task is still running.

        Not "whether any thread is running". A superseded worker can outlive
        the one that replaced it — that is the whole reason this class exists
        — and reporting it as busy would keep a caller polling for an answer
        it has already decided to refuse.
        """
        thread = self._thread
        return thread is not None and thread.is_alive()

    def drain(self) -> list[TaskResult]:
        """Every result posted since the last call, oldest first."""
        out: list[TaskResult] = []
        try:
            while True:
                out.append(self._queue.get_nowait())
        except queue.Empty:
            pass
        return out

    def drain_current(self) -> Optional[TaskResult]:
        """
        The result of the task that is still current, if one has arrived.

        Results from superseded tasks are dropped here rather than at each
        call site, which is where forgetting to check has consequences.
        """
        latest: Optional[TaskResult] = None
        for result in self.drain():
            if self.is_current(result.task):
                latest = result
        return latest

    # --- stopping -----------------------------------------------------
    def cancel(self) -> None:
        """Ask the job in flight to stop; its result will be refused."""
        with self._lock:
            if self._current is not None:
                self._current.cancel()

    def shutdown(self, timeout: float = 5.0) -> None:
        """
        Cancel and wait, then refuse further submissions.

        The join is bounded because a worker that ignores its token — a
        blocking network read, say — must not be able to hold the window open.
        What the bound buys is not a stopped thread but a stopped *delivery*:
        after this the runner is closed, so nothing the straggler posts is
        ever read.

        Only the current worker is joined. Anything it superseded was already
        being refused on arrival, and waiting for it would trade a guarantee
        nobody needs for a window that closes more slowly.
        """
        with self._lock:
            self._shut_down = True
            if self._current is not None:
                self._current.cancel()
            thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
