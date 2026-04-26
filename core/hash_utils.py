"""
Hash computation utilities.

Streams files in fixed-size chunks so that very large files do not
have to be loaded into memory all at once.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

# Algorithms we expose to the CLI. Mapping kept explicit so that an
# unsupported value fails fast instead of relying on hashlib's full set.
SUPPORTED_ALGORITHMS: tuple[str, ...] = ("md5", "sha1", "sha256", "sha512")
DEFAULT_ALGORITHM: str = "sha256"

# 64 KiB is a good default: large enough to amortise syscall overhead,
# small enough to stay friendly to constrained environments.
DEFAULT_CHUNK_SIZE: int = 64 * 1024


class HashError(Exception):
    """Raised when a file cannot be hashed."""


@dataclass(frozen=True)
class ProgressEvent:
    """Emitted by long-running hash / verify loops for UI updates.

    ``done`` is 1-based, so ``done == total`` signals completion of the
    final file. ``total`` is 0 when it is not known ahead of time.
    """

    done: int
    total: int
    path: str

    @property
    def percent(self) -> float:
        return (self.done / self.total * 100.0) if self.total else 0.0


def get_supported_algorithms() -> tuple[str, ...]:
    """Return the tuple of algorithm names accepted by the CLI."""
    return SUPPORTED_ALGORITHMS


def _validate_algorithm(algorithm: str) -> str:
    algo = algorithm.lower().strip()
    if algo not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. "
            f"Supported: {', '.join(SUPPORTED_ALGORITHMS)}"
        )
    return algo


def compute_file_hash(
    file_path: str | Path,
    algorithm: str = DEFAULT_ALGORITHM,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    """
    Compute the hex digest of a single file.

    Raises HashError for missing files, permission issues or read failures
    so that callers have a single exception type to handle.
    """
    algo = _validate_algorithm(algorithm)
    path = Path(file_path)

    if not path.exists():
        raise HashError(f"File not found: {path}")
    if not path.is_file():
        raise HashError(f"Path is not a regular file: {path}")

    hasher = hashlib.new(algo)
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(chunk_size), b""):
                hasher.update(chunk)
    except PermissionError as exc:
        raise HashError(f"Permission denied: {path}") from exc
    except OSError as exc:
        raise HashError(f"I/O error while reading {path}: {exc}") from exc

    return hasher.hexdigest()


def iter_files(folder: str | Path) -> Iterable[Path]:
    """Yield every regular file under *folder* recursively."""
    root = Path(folder)
    if not root.exists():
        raise HashError(f"Folder not found: {root}")
    if not root.is_dir():
        raise HashError(f"Path is not a directory: {root}")

    for entry in root.rglob("*"):
        if entry.is_file():
            yield entry


def count_files(folder: str | Path) -> int:
    """
    Return the number of regular files under *folder*.

    Used by progress reporting to know the denominator before the main
    hashing loop starts. The walk is stat-only, so it is cheap even on
    very large trees.
    """
    return sum(1 for _ in iter_files(folder))
