"""
File metadata helpers.

Collects user-facing information (size, extension, timestamps) about
a single file so the GUI can show it without re-stat'ing the path on
every refresh.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class FileInfoError(Exception):
    """Raised when a file's metadata cannot be collected."""


@dataclass(frozen=True)
class FileInfo:
    """User-friendly snapshot of a file's metadata."""

    name: str
    path: str
    extension: str
    size_bytes: int
    size_human: str
    created_at: str
    modified_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def human_readable_size(num_bytes: int) -> str:
    """Convert *num_bytes* into '12.3 MB' style text."""
    if num_bytes < 0:
        return "0 B"
    units = ("B", "KB", "MB", "GB", "TB")
    size = float(num_bytes)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def _to_iso(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().isoformat(
            timespec="seconds"
        )
    except (OSError, OverflowError, ValueError):
        return ""


def collect_file_info(file_path: str | Path) -> FileInfo:
    """Return a :class:`FileInfo` for *file_path*.

    Raises :class:`FileInfoError` for missing files, broken symlinks or
    permission problems so the caller has a single exception type to
    catch.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileInfoError(f"Dosya bulunamadı: {path}")
    if not path.is_file():
        raise FileInfoError(f"Bir dosya değil: {path}")

    try:
        stat = path.stat()
    except OSError as exc:
        raise FileInfoError(f"Dosya bilgileri okunamadı: {exc}") from exc

    # st_ctime is creation time on Windows, status-change on POSIX. Good
    # enough for our user-facing label — both are "when did this file
    # first appear on disk" from the user's perspective.
    return FileInfo(
        name=path.name,
        path=str(path.resolve()),
        extension=path.suffix.lower() or "(yok)",
        size_bytes=stat.st_size,
        size_human=human_readable_size(stat.st_size),
        created_at=_to_iso(stat.st_ctime),
        modified_at=_to_iso(stat.st_mtime),
    )
