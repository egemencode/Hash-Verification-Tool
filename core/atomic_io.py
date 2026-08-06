"""
Atomic file persistence helpers.

Writing JSON/text with ``open(path, "w")`` truncates the destination
*before* the new content is written, so a crash (or a second process
writing at the same time) can leave a half-written or empty file. These
helpers write to a temporary file in the **same directory**, flush + fsync
it, then ``os.replace`` it over the destination — an atomic rename on the
same filesystem. Failures raise :class:`OSError` so callers can surface a
real error instead of silently losing data.
"""

from __future__ import annotations

import json
import os
import secrets
import traceback
from pathlib import Path
from typing import Any, Optional


class AtomicWriteError(OSError):
    """Raised when an atomic write cannot be completed safely."""


# Diagnostic ring buffer: records every temp file this module creates and how
# it ended, so a test can prove *which* code path left a stray file behind.
# Off by default — production has no use for it, and building a stack summary
# on every settings write is pure overhead. Enable with
# HASHTOOL_ATOMIC_AUDIT=1 or via enable_write_audit().
_AUDIT_LIMIT = 200
_audit: list[dict[str, Any]] = []
_audit_enabled = os.environ.get("HASHTOOL_ATOMIC_AUDIT") == "1"


def enable_write_audit(enabled: bool = True) -> None:
    """Turn the diagnostic audit trail on/off (tests and debugging only)."""
    global _audit_enabled
    _audit_enabled = enabled
    if not enabled:
        _audit.clear()


def write_audit() -> list[dict[str, Any]]:
    """Snapshot of recent atomic-write outcomes (newest last)."""
    return list(_audit)


def clear_write_audit() -> None:
    _audit.clear()


def _record(tmp_name: str, target: Path, outcome: str) -> None:
    if not _audit_enabled:
        return
    if len(_audit) >= _AUDIT_LIMIT:
        del _audit[0]
    _audit.append(
        {
            "tmp": tmp_name,
            "target": str(target),
            "outcome": outcome,
            "caller": _caller_summary(),
        }
    )


def _caller_summary() -> str:
    """Two frames of context, enough to name the code path."""
    frames = []
    for frame in traceback.extract_stack()[:-3][-3:]:
        frames.append(f"{Path(frame.filename).name}:{frame.lineno} {frame.name}")
    return " <- ".join(reversed(frames))


def _atomic_write(path: Path, data: str, encoding: str = "utf-8") -> Path:
    """
    Write *data* to *path* atomically.

    Every stage — encode, create, write, fsync, close, replace — runs inside a
    single cleanup scope, so **no failure path can leave a temporary file
    behind**. Splitting the stages across separate try blocks was the defect
    this replaces: an error in encode/write/fsync closed the descriptor but
    left the temp file on disk, which later surfaced as a stray
    ``.<name>.<rand>.tmp`` next to the real store.

    Raises :class:`AtomicWriteError` (an ``OSError``) if the temp file itself
    could not be removed after a failure — that leftover is reported, never
    swallowed.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    # Encode before creating anything: an encoding error then cannot leave a
    # file behind at all.
    payload = data.encode(encoding)

    # Same-directory temp file guarantees os.replace stays on one filesystem.
    fd, tmp_name = _make_temp(path.parent)
    fd_open = True
    replaced = False
    try:
        written = 0
        total = len(payload)
        while written < total:
            chunk = os.write(fd, payload[written:])
            if chunk <= 0:
                # A non-positive result means no forward progress; looping
                # would spin forever.
                raise AtomicWriteError(
                    f"os.write made no progress writing {tmp_name} "
                    f"({written}/{total} bytes written)"
                )
            written += chunk
        os.fsync(fd)
        os.close(fd)
        fd_open = False
        os.replace(tmp_name, path)
        replaced = True
    finally:
        if fd_open:
            # Release the descriptor before touching the file: on Windows an
            # open handle makes the temp file undeletable.
            try:
                os.close(fd)
            except OSError:
                pass
        if replaced:
            _record(tmp_name, path, "replaced")
        else:
            _remove_temp_or_raise(tmp_name)
            _record(tmp_name, path, "removed-after-failure")
    return path


def _make_temp(directory: Path) -> tuple[int, str]:
    """
    Create an exclusive temp file with a short, fixed-shape name.

    The name stays within 8.3 limits (<=8 character stem, <=3 character
    extension, single dot, no leading dot). This is defensive hygiene, not a
    fix for a diagnosed problem: it keeps our temp files out of any
    short-name-alias machinery and makes them trivially recognisable as ours
    when something unexpected turns up in a data directory. We have not
    established that alias generation ever caused a stray file here.
    """
    directory.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    last_error: Optional[OSError] = None
    for _ in range(64):
        # "hvt" + 5 hex chars = 8-character stem.
        candidate = directory / f"hvt{secrets.token_hex(3)[:5]}.tmp"
        try:
            fd = os.open(candidate, flags, 0o600)
        except FileExistsError:
            continue
        except OSError as exc:
            last_error = exc
            break
        return fd, str(candidate)
    raise AtomicWriteError(
        f"could not create a temporary file in {directory}"
        + (f": {last_error}" if last_error else "")
    )


def _remove_temp_or_raise(name: str) -> None:
    """
    Delete the abandoned temp file. If it cannot be removed, raise so the
    leftover is visible instead of silently polluting the data directory.
    """
    try:
        os.unlink(name)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AtomicWriteError(
            f"temp file could not be removed after a failed write: {name} ({exc})"
        ) from exc


def write_json_atomic(
    path: str | Path, data: Any, *, indent: int | None = 2
) -> Path:
    """Serialise *data* to JSON and write it atomically. Raises OSError."""
    payload = json.dumps(data, indent=indent, ensure_ascii=False)
    return _atomic_write(Path(path), payload)


def write_text_atomic(path: str | Path, text: str, *, encoding: str = "utf-8") -> Path:
    """Write *text* atomically. Raises OSError on failure."""
    return _atomic_write(Path(path), text, encoding)


def corrupt_reason(exc: BaseException) -> str:
    """
    Short, user-facing description of why a JSON store could not be read.

    Handles both malformed JSON and non-UTF-8 binary content — the latter
    raises ``UnicodeDecodeError``, which is *not* a ``json.JSONDecodeError``
    and would otherwise escape a naive handler.
    """
    if isinstance(exc, UnicodeDecodeError):
        return "dosya metin olarak okunamıyor (bozuk/ikili veri)"
    msg = getattr(exc, "msg", None) or str(exc)
    return f"bozuk JSON: {msg}"


def quarantine_corrupt_file(path: str | Path) -> Path | None:
    """
    Move an unreadable/corrupt data file aside instead of overwriting it.

    Returns the quarantine path, or ``None`` if the file could not be moved
    (in which case the caller must not claim the data was preserved). This
    turns "corrupt store silently reset to empty" into a recoverable event:
    the original bytes stay on disk under a ``.corrupt`` name.
    """
    src = Path(path)
    if not src.exists():
        return None
    for index in range(1, 100):
        suffix = ".corrupt" if index == 1 else f".corrupt{index}"
        candidate = src.with_name(src.name + suffix)
        if candidate.exists():
            continue
        try:
            os.replace(src, candidate)
            return candidate
        except OSError:
            return None
    return None
