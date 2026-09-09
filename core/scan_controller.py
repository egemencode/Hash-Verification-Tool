"""
Scan session state machine.

    IDLE -> SELECTED -> SCANNING -> SUCCESS | ERROR | CANCELLED

The problem this solves: a scan runs on a worker thread, but the user can
select another file, cancel, or close the window while it is in flight. Any
result that arrives afterwards belongs to a *different* file than the one now
on screen, and rendering it there would attach a verdict to the wrong bytes.

Every scan therefore gets an immutable :class:`ScanSession` — a unique id, the
canonical path resolved at start, the snapshot taken then, and its own
cancellation flag. Results are only accepted from the session that is still
current; everything else is dropped silently.

Deliberately free of Tk so the transitions are testable without a display.
"""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

from core.hash_utils import FileSnapshot, HashError, snapshot_file


class ControllerState(str, Enum):
    IDLE = "idle"
    SELECTED = "selected"
    SCANNING = "scanning"
    SUCCESS = "success"
    ERROR = "error"
    CANCELLED = "cancelled"


_session_counter = itertools.count(1)


@dataclass(frozen=True)
class ScanSession:
    """One scan attempt. Immutable except for its cancellation flag."""

    session_id: str
    path: str                    # canonical, resolved at start
    snapshot: Optional[FileSnapshot]
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def cancel(self) -> None:
        self._cancel.set()

    def raise_if_cancelled(self) -> None:
        """Worker-side cooperative cancellation check."""
        if self.cancelled:
            raise ScanCancelled(self.session_id)


class ScanCancelled(Exception):
    """Raised inside a worker when its session was cancelled."""


class ScanController:
    """
    Owns the current selection, the in-flight session and the last result.

    The view renders whatever this object says; it never keeps its own copy of
    a result, so there is only one place where "which file is this about?" is
    answered.
    """

    def __init__(
        self,
        *,
        on_result: Optional[Callable[[ScanSession, Any], None]] = None,
        on_error: Optional[Callable[[ScanSession, BaseException], None]] = None,
        on_cleared: Optional[Callable[[], None]] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._state = ControllerState.IDLE
        self._selected: Optional[str] = None
        self._active: Optional[ScanSession] = None
        self._result: Optional[Any] = None
        self._result_session: Optional[ScanSession] = None
        self._shut_down = False
        self._on_result = on_result
        self._on_error = on_error
        self._on_cleared = on_cleared

    # ------------------------------------------------------------------
    # Observable state
    # ------------------------------------------------------------------
    @property
    def state(self) -> ControllerState:
        with self._lock:
            return self._state

    @property
    def selected_path(self) -> Optional[str]:
        with self._lock:
            return self._selected

    @property
    def last_result(self) -> Optional[Any]:
        with self._lock:
            return self._result

    @property
    def result_path(self) -> Optional[str]:
        """
        The path the current result actually belongs to.

        Export / "save fingerprint" must use this, never the on-screen
        selection: the two can differ the moment the user picks another file.
        """
        with self._lock:
            return self._result_session.path if self._result_session else None

    @property
    def is_busy(self) -> bool:
        with self._lock:
            return self._state is ControllerState.SCANNING

    @property
    def is_shut_down(self) -> bool:
        with self._lock:
            return self._shut_down

    @property
    def can_export(self) -> bool:
        with self._lock:
            return self._result is not None and self._state is ControllerState.SUCCESS

    @property
    def can_save_baseline(self) -> bool:
        return self.can_export

    # ------------------------------------------------------------------
    # Transitions
    # ------------------------------------------------------------------
    def select(self, path: str) -> None:
        """Choose a file. Any previous result stops being current at once."""
        with self._lock:
            if self._shut_down:
                return
            canonical = _canonical(path)
            if self._active is not None:
                # The in-flight scan is no longer what the user is looking at.
                self._active.cancel()
                self._active = None
            self._selected = canonical
            self._clear_result_locked()
            self._state = ControllerState.SELECTED
        self._notify_cleared()

    def begin_scan(self) -> Optional[ScanSession]:
        """Start a scan of the selected file. Returns the session, or None."""
        with self._lock:
            if self._shut_down or self._selected is None:
                return None
            if self._state is ControllerState.SCANNING:
                return None  # busy: ignore repeat presses / drops
            try:
                snapshot = snapshot_file(self._selected)
            except HashError:
                snapshot = None
            session = ScanSession(
                session_id=f"scan-{next(_session_counter)}",
                path=self._selected,
                snapshot=snapshot,
            )
            self._active = session
            self._clear_result_locked()
            self._state = ControllerState.SCANNING
            return session

    def rescan(self, path: str) -> Optional[ScanSession]:
        """
        Re-scan a specific file (e.g. a history row).

        If it no longer exists we move to ERROR instead of falling back to
        whatever was selected before — silently scanning a different file
        would attach the history entry's identity to unrelated bytes.
        """
        with self._lock:
            if self._shut_down:
                return None
            if not Path(path).is_file():
                # Whatever is running is now irrelevant — and if we left it
                # active it could still deliver a result that would be
                # rendered under a selection the user no longer has.
                if self._active is not None:
                    self._active.cancel()
                    self._active = None
                self._selected = None
                self._clear_result_locked()
                self._state = ControllerState.ERROR
                return None
        self.select(path)
        return self.begin_scan()

    def cancel(self) -> None:
        with self._lock:
            if self._active is not None:
                self._active.cancel()

    def shutdown(self) -> None:
        """
        Cancel in-flight work and refuse further callbacks.

        Afterwards the controller no longer reports itself busy: there is
        nothing left to wait for, and a caller that keeps asking (e.g. a
        language switch that refuses to rebuild while a scan runs) would
        otherwise block forever on a scan that has already been abandoned.
        """
        with self._lock:
            self._shut_down = True
            if self._active is not None:
                self._active.cancel()
                self._active = None
                self._clear_result_locked()
                self._state = ControllerState.CANCELLED

    # ------------------------------------------------------------------
    # Worker callbacks
    # ------------------------------------------------------------------
    def is_current(self, session: ScanSession) -> bool:
        """True when *session* is still the scan the UI is showing."""
        with self._lock:
            return self._is_current_locked(session)

    def deliver_cancelled(self, session: ScanSession) -> bool:
        """A worker reported that it stopped because it was cancelled."""
        with self._lock:
            if self._active is not session:
                return False
            self._active = None
            self._clear_result_locked()
            self._state = ControllerState.CANCELLED
            return True

    def deliver_result(self, session: ScanSession, result: Any) -> bool:
        """Accept a worker result. Returns False when it was discarded."""
        with self._lock:
            if not self._is_current_locked(session):
                if session.cancelled and self._active is session:
                    self._active = None
                    self._state = ControllerState.CANCELLED
                return False
            self._active = None
            self._result = result
            self._result_session = session
            self._state = ControllerState.SUCCESS
        if self._on_result is not None:
            self._on_result(session, result)
        return True

    def deliver_error(self, session: ScanSession, exc: BaseException) -> bool:
        with self._lock:
            if not self._is_current_locked(session):
                if session.cancelled and self._active is session:
                    self._active = None
                    self._state = ControllerState.CANCELLED
                return False
            self._active = None
            self._clear_result_locked()
            self._state = ControllerState.ERROR
        if self._on_error is not None:
            self._on_error(session, exc)
        return True

    # ------------------------------------------------------------------
    def _is_current_locked(self, session: ScanSession) -> bool:
        if self._shut_down or session.cancelled:
            return False
        return self._active is session

    def _clear_result_locked(self) -> None:
        self._result = None
        self._result_session = None

    def _notify_cleared(self) -> None:
        if self._on_cleared is not None:
            self._on_cleared()


def _canonical(path: str) -> str:
    try:
        return str(Path(path).resolve())
    except OSError:
        return str(Path(path))
