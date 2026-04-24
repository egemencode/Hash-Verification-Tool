"""
Manifest read/write layer.

A manifest is a JSON document that records, for every scanned file,
its relative path, hash, algorithm, size and last-modified timestamp.
Keeping the format explicit (rather than pickling a dataclass) makes
the file portable and easily diffable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from core import __version__
from core.hash_utils import (
    DEFAULT_ALGORITHM,
    HashError,
    ProgressEvent,
    compute_file_hash,
    count_files,
    iter_files,
)

MANIFEST_SCHEMA_VERSION: str = "1.0"


class ManifestError(Exception):
    """Raised for manifest serialisation / parsing problems."""


@dataclass
class FileEntry:
    """Single file record stored inside a manifest."""

    hash: str
    algorithm: str
    size: int
    mtime: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FileEntry":
        try:
            return cls(
                hash=str(data["hash"]),
                algorithm=str(data["algorithm"]),
                size=int(data["size"]),
                mtime=float(data["mtime"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ManifestError(f"Invalid file entry: {data!r}") from exc


@dataclass
class Manifest:
    """In-memory representation of a manifest file."""

    root_path: str
    algorithm: str = DEFAULT_ALGORITHM
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    schema_version: str = MANIFEST_SCHEMA_VERSION
    tool_version: str = __version__
    entries: dict[str, FileEntry] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------
    def add(self, relative_path: str, entry: FileEntry) -> None:
        # Always store with forward slashes so manifests are portable
        # between Windows and POSIX.
        self.entries[relative_path.replace("\\", "/")] = entry

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": {
                "schema_version": self.schema_version,
                "tool_version": self.tool_version,
                "created_at": self.created_at,
                "algorithm": self.algorithm,
                "root_path": self.root_path,
                "file_count": len(self.entries),
            },
            "entries": {
                path: entry.to_dict() for path, entry in self.entries.items()
            },
        }

    def save(self, output_path: str | Path) -> Path:
        """Write the manifest to *output_path* as pretty-printed JSON."""
        path = Path(output_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", encoding="utf-8") as fh:
                json.dump(self.to_dict(), fh, indent=2, ensure_ascii=False)
        except OSError as exc:
            raise ManifestError(f"Cannot write manifest to {path}: {exc}") from exc
        return path

    @classmethod
    def load(cls, manifest_path: str | Path) -> "Manifest":
        """Read a manifest from disk and rehydrate it."""
        path = Path(manifest_path)
        if not path.exists():
            raise ManifestError(f"Manifest not found: {path}")
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ManifestError(f"Manifest is not valid JSON: {exc}") from exc
        except OSError as exc:
            raise ManifestError(f"Cannot read manifest {path}: {exc}") from exc

        if not isinstance(data, dict) or "metadata" not in data or "entries" not in data:
            raise ManifestError("Manifest is missing required sections")

        metadata = data["metadata"]
        entries_raw = data["entries"]
        if not isinstance(entries_raw, dict):
            raise ManifestError("Manifest 'entries' must be an object")

        manifest = cls(
            root_path=str(metadata.get("root_path", "")),
            algorithm=str(metadata.get("algorithm", DEFAULT_ALGORITHM)),
            created_at=str(metadata.get("created_at", "")),
            schema_version=str(metadata.get("schema_version", MANIFEST_SCHEMA_VERSION)),
            tool_version=str(metadata.get("tool_version", __version__)),
        )
        for rel_path, raw_entry in entries_raw.items():
            if not isinstance(raw_entry, dict):
                raise ManifestError(f"Invalid entry for {rel_path!r}")
            manifest.add(rel_path, FileEntry.from_dict(raw_entry))
        return manifest


# ----------------------------------------------------------------------
# High-level builder used by the CLI
# ----------------------------------------------------------------------
def build_manifest_for_file(
    file_path: str | Path,
    algorithm: str = DEFAULT_ALGORITHM,
) -> Manifest:
    """Build a manifest containing just one file."""
    path = Path(file_path).resolve()
    manifest = Manifest(root_path=str(path.parent), algorithm=algorithm)
    digest = compute_file_hash(path, algorithm=algorithm)
    stat = path.stat()
    manifest.add(
        path.name,
        FileEntry(
            hash=digest,
            algorithm=algorithm,
            size=stat.st_size,
            mtime=stat.st_mtime,
        ),
    )
    return manifest


def build_manifest_for_folder(
    folder_path: str | Path,
    algorithm: str = DEFAULT_ALGORITHM,
    on_error: Optional[Callable[[str, Exception], None]] = None,
    on_progress: Optional[Callable[[ProgressEvent], None]] = None,
) -> Manifest:
    """
    Build a manifest for every file under *folder_path*.

    *on_error*    receives ``(relative_path, exception)`` and lets
                  callers decide whether to swallow or re-raise.
    *on_progress* receives a :class:`ProgressEvent` after each file is
                  processed (succeeded or errored). Used by the GUI to
                  drive a live progress bar + status line.
    """
    root = Path(folder_path).resolve()
    manifest = Manifest(root_path=str(root), algorithm=algorithm)

    # First pass: cheap stat-only walk to know the denominator.
    total = count_files(root) if on_progress is not None else 0

    for index, file_path in enumerate(iter_files(root), start=1):
        rel = file_path.relative_to(root).as_posix()
        try:
            digest = compute_file_hash(file_path, algorithm=algorithm)
            stat = file_path.stat()
            manifest.add(
                rel,
                FileEntry(
                    hash=digest,
                    algorithm=algorithm,
                    size=stat.st_size,
                    mtime=stat.st_mtime,
                ),
            )
        except (HashError, OSError) as exc:
            if on_error is not None:
                on_error(rel, exc)
        if on_progress is not None:
            on_progress(ProgressEvent(done=index, total=total, path=rel))
    return manifest
