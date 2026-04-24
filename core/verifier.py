"""
Verification engine.

Takes a previously-produced manifest plus the current state of a folder
and classifies every file as one of:

    unchanged | modified | new | missing | error
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Optional

from core.hash_utils import (
    HashError,
    ProgressEvent,
    compute_file_hash,
    count_files,
    iter_files,
)
from core.manifest_manager import Manifest


@dataclass
class ModifiedEntry:
    path: str
    old_hash: str
    new_hash: str
    old_size: int
    new_size: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ErrorEntry:
    path: str
    error: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    """Aggregated verification outcome ready for reporting."""

    folder: str
    algorithm: str
    unchanged: list[str] = field(default_factory=list)
    modified: list[ModifiedEntry] = field(default_factory=list)
    new: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    errors: list[ErrorEntry] = field(default_factory=list)

    # ------------------------------------------------------------------
    @property
    def total_scanned(self) -> int:
        return (
            len(self.unchanged)
            + len(self.modified)
            + len(self.new)
            + len(self.errors)
        )

    @property
    def is_clean(self) -> bool:
        """True when nothing changed and nothing failed."""
        return not (self.modified or self.new or self.missing or self.errors)

    def summary(self) -> dict[str, int]:
        return {
            "total_scanned": self.total_scanned,
            "unchanged": len(self.unchanged),
            "modified": len(self.modified),
            "new": len(self.new),
            "missing": len(self.missing),
            "errors": len(self.errors),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "folder": self.folder,
            "algorithm": self.algorithm,
            "summary": self.summary(),
            "details": {
                "unchanged": list(self.unchanged),
                "modified": [m.to_dict() for m in self.modified],
                "new": list(self.new),
                "missing": list(self.missing),
                "errors": [e.to_dict() for e in self.errors],
            },
        }


# ----------------------------------------------------------------------
# Verifier
# ----------------------------------------------------------------------
class Verifier:
    """Compare the live state of a folder against a stored manifest."""

    def __init__(self, manifest: Manifest):
        self.manifest = manifest

    def verify(
        self,
        folder: str | Path,
        on_progress: Optional[Callable[[ProgressEvent], None]] = None,
    ) -> VerificationResult:
        root = Path(folder).resolve()
        if not root.exists() or not root.is_dir():
            raise FileNotFoundError(f"Folder not found or not a directory: {root}")

        algorithm = self.manifest.algorithm
        result = VerificationResult(folder=str(root), algorithm=algorithm)

        # Pre-count so the UI can render a real progress bar instead of
        # an indeterminate spinner.
        total = count_files(root) if on_progress is not None else 0

        # We always re-check using the manifest's algorithm so that the
        # comparison is apples-to-apples even if the user changes their
        # default later on.
        seen_relative_paths: set[str] = set()

        for index, file_path in enumerate(iter_files(root), start=1):
            rel = file_path.relative_to(root).as_posix()
            seen_relative_paths.add(rel)

            try:
                current_hash = compute_file_hash(file_path, algorithm=algorithm)
                current_size = file_path.stat().st_size
            except (HashError, OSError) as exc:
                result.errors.append(ErrorEntry(path=rel, error=str(exc)))
                if on_progress is not None:
                    on_progress(ProgressEvent(done=index, total=total, path=rel))
                continue

            previous = self.manifest.entries.get(rel)
            if previous is None:
                result.new.append(rel)
            elif previous.hash == current_hash:
                result.unchanged.append(rel)
            else:
                result.modified.append(
                    ModifiedEntry(
                        path=rel,
                        old_hash=previous.hash,
                        new_hash=current_hash,
                        old_size=previous.size,
                        new_size=current_size,
                    )
                )

            if on_progress is not None:
                on_progress(ProgressEvent(done=index, total=total, path=rel))

        # Anything in the manifest we did not encounter is missing.
        for rel in self.manifest.entries.keys():
            if rel not in seen_relative_paths:
                result.missing.append(rel)

        # Stable, sorted output makes diffs and tests deterministic.
        result.unchanged.sort()
        result.modified.sort(key=lambda m: m.path)
        result.new.sort()
        result.missing.sort()
        result.errors.sort(key=lambda e: e.path)
        return result
