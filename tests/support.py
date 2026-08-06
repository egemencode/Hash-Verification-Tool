"""
Shared test helpers.

``DiagnosticTempDir`` replaces a bare ``tempfile.TemporaryDirectory`` in tests
that exercise code which writes files. If the directory cannot be removed, the
failure is **not** suppressed — instead it is re-raised with a listing of what
is still inside, so an intermittent "directory not empty" names the offending
file instead of leaving us guessing.
"""

from __future__ import annotations

import atexit
import errno
import os
import shutil
import tempfile
from pathlib import Path

# The only rmdir failures we may tolerate, and then only for a directory we
# have verified is empty. ERROR_DIR_NOT_EMPTY(145) is what Windows reports
# when a directory entry outlives the file that was deleted from it.
# Access-denied / sharing violations are NOT in this list on purpose.
_TOLERATED_RMDIR_WINERRORS = frozenset({145})
_TOLERATED_RMDIR_ERRNOS = frozenset({errno.ENOTEMPTY, errno.EEXIST})


class LeftoverFilesError(AssertionError):
    """Raised when a temp dir still holds files after the test finished."""


class InconclusiveCleanupError(AssertionError):
    """
    Raised when files we cannot attribute survived cleanup.

    Distinct from :class:`LeftoverFilesError` (which means *we* leaked), but
    still a failure: without process-level evidence we cannot claim the file
    belongs to another program, and a run that leaves unexplained files is
    not a clean run.
    """


class DiagnosticTempDir:
    """A temp directory whose cleanup failure reports the leftover entries."""

    def __init__(self, prefix: str = "hvt-test-") -> None:
        self._dir = tempfile.mkdtemp(prefix=prefix)
        self.path = Path(self._dir)
        # Empty directories Windows would not let us remove yet (see cleanup).
        self.pending_delete_dirs: list[str] = []
        # Unattributable files that were still present on re-check.
        self.foreign_leftovers: list[str] = []
        # Unattributable entries that had already vanished on re-check. Nothing
        # of ours survived, so these do not fail the run — but they are worth
        # surfacing, because they are the only trace of whatever produced them.
        self.transient_leftovers: list[str] = []
        # The attribution above is only sound while the audit is recording,
        # so make sure it is on for every test that uses this harness.
        from core.atomic_io import enable_write_audit

        enable_write_audit(True)

    @property
    def name(self) -> str:
        """Drop-in compatibility with ``tempfile.TemporaryDirectory``."""
        return self._dir

    # Make the object usable anywhere a path is expected, so it can replace
    # tempfile.TemporaryDirectory in `with ... as d:` blocks unchanged.
    def __fspath__(self) -> str:
        return self._dir

    def __str__(self) -> str:
        return self._dir

    # ------------------------------------------------------------------
    def listing(self) -> list[str]:
        """Every entry currently under the temp root, relative + sized."""
        out: list[str] = []
        for entry in sorted(_walk_no_follow(self.path)):
            try:
                rel = entry.relative_to(self.path)
                if entry.is_dir():
                    out.append(f"{rel}/  (dir)")
                else:
                    out.append(f"{rel}  ({entry.stat().st_size} bytes)")
            except OSError as exc:
                out.append(f"{entry}  <stat failed: {exc}>")
        return out

    def cleanup(self) -> None:
        """
        Tear the tree down and assert the invariant that actually matters:
        **no file may be left behind**.

        A file we cannot delete (or did not expect) is a real defect — a
        leaked handle or a stray temp file — and raises
        :class:`LeftoverFilesError` with the full listing.

        A *directory* that refuses to be removed while being verifiably empty
        is not a defect: on Windows ``unlink`` only marks a file for deletion,
        and the directory entry survives until the last handle closes — an
        external scanner (Defender / Search indexer) touching a file we just
        wrote is enough. The product never removes these directories, so
        asserting on it would test the antivirus, not the code. We record it
        instead of failing, and we still fail loudly if the directory is
        non-empty.
        """
        snapshot = self.listing()

        # Step 1 — delete every file. A failure here is a real defect.
        _unlink_all_files(self.path)

        # Step 2 — the invariant that matters: nothing may survive as a file.
        remaining_files = (
            [
                str(p.relative_to(self.path))
                for p in _walk_no_follow(self.path)
                if p.is_file() and not _is_reparse(p)
            ]
            if self.path.exists()
            else []
        )
        if remaining_files:
            from core.atomic_io import write_audit

            relevant = [
                entry for entry in write_audit()
                if str(self.path) in entry["tmp"] or str(self.path) in entry["target"]
            ]
            audit_lines = [
                f"{e['outcome']:>22}  {Path(e['tmp']).name}  <- {e['caller']}"
                for e in relevant
            ] or ["<no atomic writes recorded for this directory>"]

            ours, foreign = _classify_leftovers(remaining_files, relevant, snapshot)
            detail = (
                "Entries at cleanup time:\n  "
                + "\n  ".join(snapshot or ["<empty>"])
                + "\nFiles still present:\n  "
                + "\n  ".join(remaining_files)
                + "\nAtomic-write audit for this directory:\n  "
                + "\n  ".join(audit_lines)
            )
            if ours:
                raise LeftoverFilesError(
                    "Files this process created survived cleanup — a leaked "
                    "handle or a stray temp file.\n"
                    f"Attributable to us: {ours}\n" + detail
                )
            # Re-read the filesystem before judging. Some of these entries are
            # transient: they exist for a few milliseconds while we delete the
            # real file and are gone again immediately. The invariant is "no
            # file survives cleanup" — a file that no longer exists did not
            # survive, and asserting on a stale listing would report a leak
            # that is not there. This is not a retry of a failed assertion:
            # anything attributable to us has already failed above, and a
            # leftover that is still present below still fails.
            persistent = [
                rel for rel in foreign if (self.path / rel).exists()
            ]
            self.transient_leftovers = [r for r in foreign if r not in persistent]
            if persistent:
                self.foreign_leftovers = persistent
                raise InconclusiveCleanupError(
                    "Unidentified files survived cleanup and are still present. "
                    "Their names are not ones this code emits and every temp "
                    "file we created is accounted for, but no process-level "
                    "evidence was collected, so this cannot be scored as a "
                    "pass.\n"
                    f"Still present: {persistent}\n" + detail
                )

        # Step 3 — remove the (now empty) directories.
        self.pending_delete_dirs = _rmdir_all(self.path)
        if self.pending_delete_dirs:
            # Windows can hold an emptied directory entry open for a moment.
            # Rather than leaving our own temp trees behind for good, finish
            # the job at interpreter exit — by then every handle is closed.
            # This only ever touches directories THIS run created, and it is
            # not a retry of a failed assertion: the files are already gone.
            _register_exit_sweep(self.path)

    def __enter__(self) -> "DiagnosticTempDir":
        return self

    def __exit__(self, *_exc) -> None:
        self.cleanup()


# Temp roots this process created that Windows would not let us remove yet.
_EXIT_SWEEP: list[Path] = []
_EXIT_SWEEP_REGISTERED = False


def _register_exit_sweep(path: Path) -> None:
    """Queue an empty temp root for one final removal attempt at exit."""
    global _EXIT_SWEEP_REGISTERED
    _EXIT_SWEEP.append(path)
    if not _EXIT_SWEEP_REGISTERED:
        atexit.register(_sweep_at_exit)
        _EXIT_SWEEP_REGISTERED = True


def _sweep_at_exit() -> None:
    for path in _EXIT_SWEEP:
        try:
            if not path.exists():
                continue
            # Only ever remove a tree we already emptied.
            if any(p.is_file() for p in path.rglob("*")):
                continue
            shutil.rmtree(path, ignore_errors=True)
        except OSError:
            pass


def _classify_leftovers(
    remaining: list[str], audit_entries: list[dict], snapshot: list[str]
) -> tuple[list[str], list[str]]:
    """
    Split surviving files into "ours to answer for" and "another process's".

    A file is **ours** when either:
      * it existed before cleanup started (we listed it, we tried to delete
        it, it is still there — that is a failure to clean up, whatever its
        name), or
      * its name is one the atomic writer can produce (``hvt*.tmp``) or one
        the audit recorded us creating.

    A file is **foreign** only when it materialised *during* cleanup and
    carries a name we have no code path to emit. That is exactly the observed
    case: every temp file we created was accounted for as ``replaced``, and a
    differently-named ``<NAME>.TMP`` appeared after we deleted the real file.
    """
    audited_names = {Path(e["tmp"]).name.lower() for e in audit_entries}
    known_before = {line.split("  ")[0].strip().lower() for line in snapshot}

    ours: list[str] = []
    foreign: list[str] = []
    for rel in remaining:
        name = Path(rel).name.lower()
        existed_before = rel.lower() in known_before
        looks_like_ours = (
            name in audited_names
            or (name.startswith("hvt") and name.endswith(".tmp"))
        )
        if existed_before or looks_like_ours:
            ours.append(rel)
        else:
            foreign.append(rel)
    return ours, foreign


def _is_reparse(path: Path) -> bool:
    """True for a symlink or a Windows junction/reparse point."""
    if path.is_symlink():
        return True
    try:
        attrs = os.lstat(path).st_file_attributes  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return False
    return bool(attrs & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


def _walk_no_follow(root: Path) -> list[Path]:
    """
    Every entry under *root*, deepest first, **without** descending into
    reparse points. Following a junction here would walk the same tree over
    and over (a cycle) or delete files outside the temp directory entirely.
    """
    out: list[Path] = []

    def _walk(directory: Path) -> None:
        try:
            with os.scandir(directory) as it:
                entries = list(it)
        except OSError:
            return
        for entry in entries:
            path = Path(entry.path)
            out.append(path)
            if entry.is_dir(follow_symlinks=False) and not _is_reparse(path):
                _walk(path)

    _walk(root)
    out.sort(key=lambda p: len(p.parts), reverse=True)
    return out


def _unlink_all_files(root: Path) -> None:
    """Delete every file under *root*. Failures propagate — they are real."""
    if not root.exists():
        return
    for entry in _walk_no_follow(root):
        if _is_reparse(entry):
            # Remove the link itself, never its target's contents.
            if entry.is_dir():
                os.rmdir(entry)
            else:
                os.unlink(entry)
        elif entry.is_file():
            os.unlink(entry)


def _rmdir_all(root: Path) -> list[str]:
    """
    Remove directories deepest-first.

    Returns the ones that refused removal *while verifiably empty* (Windows
    pending-delete). A non-empty directory that cannot be removed is a real
    problem and raises.
    """
    if not root.exists():
        return []
    pending: list[str] = []
    pending_set: set[Path] = set()
    dirs = [p for p in _walk_no_follow(root) if p.is_dir() and not _is_reparse(p)]
    for directory in [*dirs, root]:
        try:
            os.rmdir(directory)
        except OSError as exc:
            # Only ERROR_DIR_NOT_EMPTY (145) / ENOTEMPTY may be tolerated, and
            # only when the directory is verifiably empty (or held open solely
            # by an already-pending child). Access-denied, sharing violations
            # and anything else are real problems and must surface.
            if getattr(exc, "winerror", None) not in _TOLERATED_RMDIR_WINERRORS \
                    and exc.errno not in _TOLERATED_RMDIR_ERRNOS:
                raise
            children = list(directory.iterdir()) if directory.exists() else []
            if all(child in pending_set for child in children):
                pending.append(str(directory))
                pending_set.add(directory)
                continue
            # Something is inside that was not there when we checked. Name it:
            # a bare OSError here says nothing about what appeared.
            listing = []
            for child in children:
                try:
                    kind = "dir" if child.is_dir() else f"{child.stat().st_size} bytes"
                except OSError as stat_exc:
                    kind = f"<stat failed: {stat_exc}>"
                listing.append(f"{child.name}  ({kind})")
            raise InconclusiveCleanupError(
                f"Directory refused removal and is not empty: {directory}\n"
                f"Unexplained contents: {listing}\n"
                "These appeared after the leftover check, so they were created "
                "during cleanup by something we did not observe. Without "
                "process-level evidence this run cannot be scored as a pass."
            ) from exc
    return pending
