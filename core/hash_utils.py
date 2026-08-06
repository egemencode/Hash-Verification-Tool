"""
Hash computation utilities.

Streams files in fixed-size chunks so that very large files do not
have to be loaded into memory all at once.

Beyond the original single-digest :func:`compute_file_hash`, this module
now offers :func:`compute_file_hashes` which computes several digests in a
**single pass** over the file (open once, feed each chunk to every hasher).
Both single- and multi-hash paths capture a :class:`FileSnapshot` from the
*same* open handle before and after reading, so a file that is modified
mid-read can be detected instead of producing a hash for a file that no
longer matches its recorded size/mtime.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence

# Algorithms we expose to the CLI. Mapping kept explicit so that an
# unsupported value fails fast instead of relying on hashlib's full set.
SUPPORTED_ALGORITHMS: tuple[str, ...] = ("md5", "sha1", "sha256", "sha512")
DEFAULT_ALGORITHM: str = "sha256"

# 64 KiB is a good default: large enough to amortise syscall overhead,
# small enough to stay friendly to constrained environments.
DEFAULT_CHUNK_SIZE: int = 64 * 1024


class HashError(Exception):
    """Raised when a file cannot be hashed."""


class FileChangedDuringScanError(HashError):
    """
    Raised when a file's identity/size/mtime changed while we were reading
    it. A hash produced under these conditions cannot be trusted, so callers
    that care about consistency should treat this as a hard failure rather
    than silently returning a digest.
    """


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
        if self.total <= 0:
            return 0.0
        # Clamp so a late-arriving file (total under-counted) never shows
        # 103% and a stale event never shows a negative value.
        return max(0.0, min(100.0, self.done / self.total * 100.0))


@dataclass(frozen=True)
class FileSnapshot:
    """
    Cheap identity fingerprint of a file used to detect mid-scan changes.

    ``ino`` / ``dev`` may be ``0`` on some platforms (older Windows stat
    results); in that case they are ignored and only size + mtime are
    compared.
    """

    size: int
    mtime_ns: int
    ino: int = 0
    dev: int = 0

    @classmethod
    def from_stat(cls, st: os.stat_result) -> "FileSnapshot":
        return cls(
            size=st.st_size,
            mtime_ns=getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000)),
            ino=getattr(st, "st_ino", 0) or 0,
            dev=getattr(st, "st_dev", 0) or 0,
        )

    @property
    def mtime(self) -> float:
        """Modification time in seconds (manifest-compatible float)."""
        return self.mtime_ns / 1_000_000_000

    def is_same(self, other: "FileSnapshot") -> bool:
        if self.size != other.size or self.mtime_ns != other.mtime_ns:
            return False
        # Only trust inode/device when both snapshots reported them.
        if self.ino and other.ino and (self.ino != other.ino or self.dev != other.dev):
            return False
        return True


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


def _validate_chunk_size(chunk_size: int) -> int:
    if chunk_size <= 0:
        raise ValueError(f"chunk_size must be a positive integer, got {chunk_size!r}")
    return chunk_size


def _ensure_regular_file(path: Path) -> None:
    if not path.exists():
        raise HashError(f"File not found: {path}")
    if not path.is_file():
        raise HashError(f"Path is not a regular file: {path}")


def _guarded_hash_stream(
    path: Path, algos: Sequence[str], chunk_size: int
) -> tuple[dict[str, str], FileSnapshot, FileSnapshot]:
    """
    Hash *path* under every algorithm in *algos* in a single pass.

    Returns ``(digests, before, after)`` where *before*/*after* are the
    :class:`FileSnapshot`s taken from the same file descriptor immediately
    before and after the read loop.
    """
    hashers = {algo: hashlib.new(algo) for algo in algos}
    try:
        with path.open("rb") as fh:
            before = FileSnapshot.from_stat(os.fstat(fh.fileno()))
            for chunk in iter(lambda: fh.read(chunk_size), b""):
                for hasher in hashers.values():
                    hasher.update(chunk)
            after = FileSnapshot.from_stat(os.fstat(fh.fileno()))
    except PermissionError as exc:
        raise HashError(f"Permission denied: {path}") from exc
    except OSError as exc:
        raise HashError(f"I/O error while reading {path}: {exc}") from exc

    digests = {algo: hashers[algo].hexdigest() for algo in algos}
    return digests, before, after


def compute_file_hashes_with_snapshot(
    file_path: str | Path,
    algorithms: Sequence[str] = (DEFAULT_ALGORITHM,),
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    *,
    ensure_stable: bool = True,
) -> tuple[dict[str, str], FileSnapshot]:
    """
    Compute several digests in one pass and return ``(digests, snapshot)``.

    The returned :class:`FileSnapshot` is **handle-bound**: it is read with
    ``fstat()`` from the very file descriptor the bytes were hashed from,
    immediately after the final chunk. Callers must use this snapshot rather
    than a separate ``stat()`` call — an independent stat leaves a window in
    which the file can be swapped, which would attribute the hashes to one
    file and the metadata to another.
    """
    if not algorithms:
        raise ValueError("At least one algorithm is required.")
    algos = [_validate_algorithm(a) for a in algorithms]
    _validate_chunk_size(chunk_size)

    path = Path(file_path)
    _ensure_regular_file(path)

    digests, before, after = _guarded_hash_stream(path, algos, chunk_size)
    if ensure_stable and not before.is_same(after):
        raise FileChangedDuringScanError(
            f"File changed while it was being read: {path}"
        )
    return digests, after


def compute_file_hashes(
    file_path: str | Path,
    algorithms: Sequence[str] = (DEFAULT_ALGORITHM,),
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    *,
    ensure_stable: bool = True,
) -> dict[str, str]:
    """
    Compute several digests of a single file in **one pass**.

    The file is opened once and every chunk is fed to all requested hashers,
    so MD5/SHA-1/SHA-256 come from the exact same bytes (and the same
    point-in-time snapshot).

    When *ensure_stable* is true (the default) a
    :class:`FileChangedDuringScanError` is raised if the file's
    size/mtime/identity changed between the start and end of the read.

    Raises :class:`ValueError` for an unknown algorithm, an empty
    algorithm list or a non-positive *chunk_size*; :class:`HashError`
    for missing files, permission issues or read failures.
    """
    digests, _snapshot = compute_file_hashes_with_snapshot(
        file_path, algorithms, chunk_size, ensure_stable=ensure_stable
    )
    return digests


def compute_file_hash(
    file_path: str | Path,
    algorithm: str = DEFAULT_ALGORITHM,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    """
    Compute the hex digest of a single file (backwards-compatible API).

    This is a thin wrapper over :func:`compute_file_hashes`. It keeps the
    original lenient behaviour (``ensure_stable=False``) so existing callers
    such as the recursive folder walk tolerate a file changing underneath
    them without raising; use :func:`compute_file_hashes` or
    :func:`hash_file_with_snapshot` when strict consistency is required.
    """
    algo = _validate_algorithm(algorithm)
    return compute_file_hashes(
        file_path, (algo,), chunk_size, ensure_stable=False
    )[algo]


def hash_file_with_snapshot(
    file_path: str | Path,
    algorithm: str = DEFAULT_ALGORITHM,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    *,
    ensure_stable: bool = True,
) -> tuple[str, FileSnapshot]:
    """
    Hash a file and return ``(digest, snapshot)`` where *snapshot* records
    the size/mtime/identity captured from the same handle used to hash.

    This lets manifest building record a file's metadata that is consistent
    with the exact bytes hashed (no separate ``stat()`` race). *ensure_stable*
    defaults to True so a file mutated mid-read is reported as an error
    rather than silently recorded with an untrustworthy digest.
    """
    algo = _validate_algorithm(algorithm)
    digests, snapshot = compute_file_hashes_with_snapshot(
        file_path, [algo], chunk_size, ensure_stable=ensure_stable
    )
    return digests[algo], snapshot


def snapshot_file(file_path: str | Path) -> FileSnapshot:
    """Return a :class:`FileSnapshot` for *file_path* (raises HashError)."""
    path = Path(file_path)
    try:
        return FileSnapshot.from_stat(path.stat())
    except OSError as exc:
        raise HashError(f"Cannot stat {path}: {exc}") from exc


def _file_identity(path: Path) -> Optional[tuple[int, int]]:
    """(device, inode) pair used for loop detection; None when unavailable."""
    try:
        st = path.stat()
    except OSError:
        return None
    dev, ino = getattr(st, "st_dev", 0), getattr(st, "st_ino", 0)
    return (dev, ino) if ino else None


def iter_files(
    folder: str | Path,
    *,
    follow_symlinks: bool = False,
    exclude: Optional[Iterable[str | Path]] = None,
) -> Iterable[Path]:
    """
    Yield every regular file under *folder*, deterministically.

    Security-relevant defaults:

    * **Reparse points are not followed.** A symlink or Windows junction
      inside the tree would otherwise let content from anywhere on the disk
      appear as if it belonged to the scanned folder.
    * When ``follow_symlinks`` is enabled the resolved target must still live
      under the root (containment check), and a device/inode ``visited`` set
      stops junction cycles from recursing forever.
    * Entries are walked with :func:`os.scandir` in sorted order so two runs
      over an unchanged tree produce identical output.
    """
    root = Path(folder)
    if not root.exists():
        raise HashError(f"Folder not found: {root}")
    if not root.is_dir():
        raise HashError(f"Path is not a directory: {root}")

    root_resolved = root.resolve()
    excluded = {Path(p).resolve() for p in (exclude or ())}
    visited: set[tuple[int, int]] = set()

    def _contained(path: Path) -> bool:
        try:
            return path.resolve().is_relative_to(root_resolved)
        except (OSError, ValueError):
            return False

    def _walk(directory: Path):
        try:
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            raise HashError(f"Cannot list {directory}: {exc}") from exc

        for entry in entries:
            path = Path(entry.path)
            if excluded:
                try:
                    if path.resolve() in excluded:
                        continue
                except OSError:
                    pass
            try:
                is_link = entry.is_symlink() or _is_reparse_point(entry)
            except OSError:
                is_link = False

            if entry.is_dir(follow_symlinks=False):
                if is_link and not follow_symlinks:
                    continue  # never traverse a junction/symlink by default
                if is_link and not _contained(path):
                    continue  # escapes the root
                identity = _file_identity(path)
                if identity is not None:
                    if identity in visited:
                        continue  # cycle
                    visited.add(identity)
                yield from _walk(path)
            elif entry.is_file(follow_symlinks=False):
                if is_link and not follow_symlinks:
                    continue
                yield path

    yield from _walk(root)


def _is_reparse_point(entry: "os.DirEntry[str]") -> bool:
    """True for a Windows reparse point (junction) as well as a symlink."""
    if entry.is_symlink():
        return True
    try:
        attrs = entry.stat(follow_symlinks=False).st_file_attributes  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return False
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def count_files(
    folder: str | Path,
    *,
    follow_symlinks: bool = False,
    exclude: Optional[Iterable[str | Path]] = None,
) -> int:
    """
    Return the number of regular files under *folder*.

    Uses the same traversal rules as :func:`iter_files` so the progress
    denominator matches what will actually be processed.
    """
    return sum(1 for _ in iter_files(folder, follow_symlinks=follow_symlinks, exclude=exclude))


def snapshot_inventory(
    folder: str | Path,
    *,
    follow_symlinks: bool = False,
    exclude: Optional[Iterable[str | Path]] = None,
) -> dict[str, FileSnapshot]:
    """
    Take a deterministic inventory of the tree: relative path -> snapshot.

    Comparing the inventory taken before a scan with one taken after tells us
    whether files were added, removed or modified *while we were scanning* —
    which is what makes an "incomplete" verdict possible instead of quietly
    reporting a manifest that never matched any single point in time.
    """
    root = Path(folder).resolve()
    out: dict[str, FileSnapshot] = {}
    for path in iter_files(root, follow_symlinks=follow_symlinks, exclude=exclude):
        try:
            rel = path.resolve().relative_to(root).as_posix()
            out[rel] = FileSnapshot.from_stat(path.stat())
        except (OSError, ValueError):
            continue
    return out
