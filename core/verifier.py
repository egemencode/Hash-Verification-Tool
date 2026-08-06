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

from typing import Sequence

from core.hash_utils import (
    HashError,
    ProgressEvent,
    count_files,
    hash_file_with_snapshot,
    iter_files,
    snapshot_inventory,
)
from core.manifest_manager import Manifest, ManifestError, SignatureState


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
    # Trust level of the manifest the comparison was made against.
    signature_state: SignatureState = SignatureState.UNSIGNED
    # Paths that appeared, vanished or changed *while* we were scanning.
    changed_during_scan: list[str] = field(default_factory=list)
    # True when the caller explicitly accepted an unverifiable reference.
    policy_accepted: bool = False

    # ------------------------------------------------------------------
    # Typed outcome fields. These replace the ambiguous `is_clean`, which
    # conflated "the bytes match the reference" with "the reference can be
    # trusted" and "the scan actually covered everything".
    # ------------------------------------------------------------------
    @property
    def files_match(self) -> bool:
        """Every file present matched the manifest. Says nothing about trust."""
        return not (self.modified or self.new or self.missing or self.errors)

    @property
    def scan_complete(self) -> bool:
        """The tree did not shift underneath us during the scan."""
        return not self.changed_during_scan

    @property
    def reference_trusted(self) -> bool:
        """The manifest was verified against an out-of-band trusted key."""
        return self.signature_state is SignatureState.TRUSTED

    @property
    def trusted_match(self) -> bool:
        """The only combination that means "verified against a trusted reference"."""
        return self.files_match and self.scan_complete and self.reference_trusted

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
        """
        Deprecated compatibility alias — prefer the typed fields.

        Kept only so existing callers keep working. It means "the files
        matched, the scan was complete, and the manifest's signature was not
        broken" — it does **not** mean the reference was trusted. Use
        :attr:`trusted_match` for that.
        """
        if not self.signature_state.is_usable:
            return False
        return self.files_match and self.scan_complete

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
            "manifest_signature": self.signature_state.value,
            # Typed outcome: consumers must be able to distinguish "the bytes
            # matched" from "the reference was trustworthy" without parsing
            # prose or relying on the deprecated is_clean flag.
            "files_match": self.files_match,
            "scan_complete": self.scan_complete,
            "reference_trusted": self.reference_trusted,
            "trusted_match": self.trusted_match,
            "policy_accepted": self.policy_accepted,
            "changed_during_scan": list(self.changed_during_scan),
            # Deprecated; kept for existing readers. Never means "trusted".
            "is_clean": self.is_clean,
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

    def __init__(self, manifest: Manifest, trusted_public_hex: Optional[str] = None):
        self.manifest = manifest
        self._trusted_public_hex = trusted_public_hex

    def verify(
        self,
        folder: str | Path,
        on_progress: Optional[Callable[[ProgressEvent], None]] = None,
        *,
        follow_symlinks: bool = False,
        exclude: Optional[Sequence[str | Path]] = None,
        recheck: bool = True,
    ) -> VerificationResult:
        """
        Compare *folder* against the manifest.

        Threat-model note — this is **not** an atomic snapshot of the folder.
        Three layers narrow the window, none closes it:

        * each file is hashed with a handle-bound snapshot, so a mutation
          *during* a single read is detected;
        * the whole tree is inventoried before and after, so files added,
          removed or visibly altered mid-scan are reported;
        * with ``recheck=True`` (default) every "unchanged" file is hashed a
          second time, which also catches a swap that forged size and mtime.

        An attacker who can write to the tree while the scan runs can still
        change a file after its final re-hash. Treat the result as evidence
        about a *window in time*, not a proof about the folder's state now.
        Pass ``recheck=False`` to halve the I/O on trees you control, at the
        cost of the third layer.
        """
        root = Path(folder).resolve()
        if not root.exists() or not root.is_dir():
            raise FileNotFoundError(f"Folder not found or not a directory: {root}")

        # A manifest that never covered the whole folder cannot be a reference:
        # every file it missed would silently verify as unchanged.
        if not getattr(self.manifest, "complete", True):
            raise ManifestError(
                f"Referans manifest eksik (kısmi): {len(self.manifest.skipped)} "
                "dosya taranmamış. Doğrulama yapılmadı."
            )

        # Defence in depth: Manifest.load() already gates on the signature,
        # but a Manifest built or mutated in memory reaches us ungated. Never
        # compare against a manifest whose signature does not hold up.
        signature_state = self.manifest.check_integrity(self._trusted_public_hex)

        algorithm = self.manifest.algorithm
        result = VerificationResult(
            folder=str(root), algorithm=algorithm, signature_state=signature_state
        )

        walk_kwargs = {"follow_symlinks": follow_symlinks, "exclude": list(exclude or ())}

        # Inventory the tree before and after. Hashing a file tells us what it
        # contained *at that moment*; only comparing the whole tree's state
        # across the scan reveals a file that was swapped, added or deleted
        # after we had already read it.
        before_inventory = snapshot_inventory(root, **walk_kwargs)

        # Pre-count so the UI can render a real progress bar instead of
        # an indeterminate spinner.
        total = count_files(root, **walk_kwargs) if on_progress is not None else 0

        # We always re-check using the manifest's algorithm so that the
        # comparison is apples-to-apples even if the user changes their
        # default later on.
        seen_relative_paths: set[str] = set()

        for index, file_path in enumerate(iter_files(root, **walk_kwargs), start=1):
            rel = file_path.relative_to(root).as_posix()
            seen_relative_paths.add(rel)

            try:
                # Strict, handle-bound: the size we compare comes from the same
                # descriptor as the digest, and a file mutated mid-read is an
                # error rather than a hash attributable to neither version.
                current_hash, snap = hash_file_with_snapshot(
                    file_path, algorithm=algorithm, ensure_stable=True
                )
                current_size = snap.size
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

        # Second inventory: anything that appeared, vanished or changed while
        # we were working means the per-file digests above do not all describe
        # the same point in time, so the run cannot be called clean.
        after_inventory = snapshot_inventory(root, **walk_kwargs)
        drifted = set(before_inventory) ^ set(after_inventory)
        for rel in set(before_inventory) & set(after_inventory):
            if not before_inventory[rel].is_same(after_inventory[rel]):
                drifted.add(rel)

        if recheck:
            # Metadata can be forged: an attacker can rewrite a file after we
            # hashed it and restore both its size and its mtime, which no
            # inventory comparison can see. Re-hashing every file we called
            # unchanged is the only check that reads the actual bytes again.
            # It costs a second pass; see the docstring for how to skip it.
            still_unchanged: list[str] = []
            for rel in result.unchanged:
                file_path = root / rel
                try:
                    digest, snap = hash_file_with_snapshot(
                        file_path, algorithm=algorithm, ensure_stable=True
                    )
                except (HashError, OSError) as exc:
                    result.errors.append(ErrorEntry(path=rel, error=str(exc)))
                    drifted.add(rel)
                    continue
                previous = self.manifest.entries.get(rel)
                if previous is not None and previous.hash != digest:
                    result.modified.append(
                        ModifiedEntry(
                            path=rel,
                            old_hash=previous.hash,
                            new_hash=digest,
                            old_size=previous.size,
                            new_size=snap.size,
                        )
                    )
                    drifted.add(rel)
                else:
                    still_unchanged.append(rel)
            result.unchanged = still_unchanged

            # A third inventory, taken *after* the re-hash pass. Without it the
            # whole duration of that pass is an unobserved window: a file added
            # once the mid-scan inventory had been taken would never be seen.
            final_inventory = snapshot_inventory(root, **walk_kwargs)
            drifted |= set(after_inventory) ^ set(final_inventory)
            for rel in set(after_inventory) & set(final_inventory):
                if not after_inventory[rel].is_same(final_inventory[rel]):
                    drifted.add(rel)

        result.changed_during_scan = sorted(drifted)

        # Stable, sorted output makes diffs and tests deterministic.
        result.unchanged.sort()
        result.modified.sort(key=lambda m: m.path)
        result.new.sort()
        result.missing.sort()
        result.errors.sort(key=lambda e: e.path)
        return result
