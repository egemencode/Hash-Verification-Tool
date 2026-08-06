"""
Tests for the test harness itself.

DiagnosticTempDir must keep failing on a *real* leak (a stray file we cannot
account for) while tolerating the Windows pending-delete case where an empty
directory briefly refuses removal. If this distinction breaks, the suite
either goes flaky again or stops catching leaked handles.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from tests import support
from tests.support import (
    DiagnosticTempDir,
    InconclusiveCleanupError,
    LeftoverFilesError,
)


class DiagnosticTempDirTests(unittest.TestCase):
    def test_clean_tree_is_removed(self) -> None:
        tmp = DiagnosticTempDir()
        (tmp.path / "sub").mkdir()
        (tmp.path / "sub" / "f.txt").write_text("x", encoding="utf-8")
        tmp.cleanup()
        self.assertFalse(tmp.path.exists())
        self.assertEqual(tmp.pending_delete_dirs, [])

    def test_undeletable_file_raises_with_listing(self) -> None:
        tmp = DiagnosticTempDir()
        target = tmp.path / "stuck.tmp"
        target.write_text("x", encoding="utf-8")
        real_unlink = os.unlink

        def refuse(path, *a, **kw):
            if str(path).endswith("stuck.tmp"):
                return  # pretend the unlink silently did nothing
            return real_unlink(path, *a, **kw)

        with mock.patch("tests.support.os.unlink", refuse):
            with self.assertRaises(LeftoverFilesError) as ctx:
                tmp.cleanup()
        # The failure must name the offending file — that is the whole point.
        self.assertIn("stuck.tmp", str(ctx.exception))
        real_unlink(target)
        os.rmdir(tmp.path)

    def test_empty_dir_pending_delete_is_tolerated(self) -> None:
        # Windows marks a file for deletion but keeps the directory entry
        # until the last (external) handle closes. The empty directory — and
        # the parents it keeps alive — must be tolerated, not failed on.
        tmp = DiagnosticTempDir()
        stubborn = tmp.path / "locked"
        stubborn.mkdir()
        real_rmdir = os.rmdir

        def refuse(path, *a, **kw):
            if str(path).endswith("locked"):
                # How Windows actually reports it: winerror 145.
                exc = OSError(41, "Directory not empty")
                exc.winerror = 145
                raise exc
            return real_rmdir(path, *a, **kw)

        with mock.patch("tests.support.os.rmdir", refuse):
            tmp.cleanup()  # must not raise
        self.assertTrue(any("locked" in d for d in tmp.pending_delete_dirs))
        # The parent is tolerated too, because its only child is pending.
        self.assertTrue(any(d == str(tmp.path) for d in tmp.pending_delete_dirs))
        real_rmdir(stubborn)
        real_rmdir(tmp.path)

    def test_surviving_file_in_subdir_raises(self) -> None:
        # A file that survives inside a subdirectory must still be caught —
        # this is the "leaked handle / stray temp file" case we must not miss.
        tmp = DiagnosticTempDir()
        d = tmp.path / "keeps-a-file"
        d.mkdir()
        (d / "ghost.bin").write_bytes(b"x")
        real_unlink = os.unlink

        def skip_unlink(path, *a, **kw):
            if str(path).endswith("ghost.bin"):
                return
            return real_unlink(path, *a, **kw)

        with mock.patch("tests.support.os.unlink", skip_unlink):
            with self.assertRaises(LeftoverFilesError) as ctx:
                tmp.cleanup()
        self.assertIn("ghost.bin", str(ctx.exception))

        real_unlink(d / "ghost.bin")
        os.rmdir(d)
        os.rmdir(tmp.path)

    def test_access_denied_rmdir_is_not_tolerated(self) -> None:
        # Only "directory not empty" may be tolerated. A permission problem is
        # a real failure and must not be silently swallowed as pending-delete.
        tmp = DiagnosticTempDir()
        stubborn = tmp.path / "locked"
        stubborn.mkdir()
        real_rmdir = os.rmdir

        def denied(path, *a, **kw):
            if str(path).endswith("locked"):
                exc = OSError(13, "Access is denied")
                exc.winerror = 5
                raise exc
            return real_rmdir(path, *a, **kw)

        with mock.patch("tests.support.os.rmdir", denied):
            with self.assertRaises(OSError):
                tmp.cleanup()
        real_rmdir(stubborn)
        real_rmdir(tmp.path)

    def test_our_own_temp_file_still_fails(self) -> None:
        # Attribution must not become a loophole: a leftover matching the
        # atomic writer's own naming is a real leak and must still fail.
        tmp = DiagnosticTempDir()
        stray = tmp.path / "hvt12345.tmp"
        stray.write_text("x", encoding="utf-8")
        real_unlink = os.unlink

        def skip(path, *a, **kw):
            if str(path).endswith("hvt12345.tmp"):
                return
            return real_unlink(path, *a, **kw)

        with mock.patch("tests.support.os.unlink", skip):
            with self.assertRaises(LeftoverFilesError) as ctx:
                tmp.cleanup()
        self.assertIn("hvt12345.tmp", str(ctx.exception))
        real_unlink(stray)
        os.rmdir(tmp.path)

    def test_transient_entry_that_vanished_does_not_fail(self) -> None:
        # Observed on Windows: a `<NAME>.EXT.tmp` appears for a few ms while we
        # delete the real file, then disappears on its own. Nothing of ours
        # survived, so the run is clean — but it is recorded.
        tmp = DiagnosticTempDir()
        real_file = tmp.path / "known.json"
        real_file.write_text("{}", encoding="utf-8")
        ghost = tmp.path / "KNOWN.JSON.tmp"
        real_unlink = os.unlink

        def unlink_and_spawn(path, *a, **kw):
            result = real_unlink(path, *a, **kw)
            if str(path).endswith("known.json"):
                ghost.write_text("x", encoding="utf-8")
            return result

        real_classify = support._classify_leftovers

        def classify_then_vanish(*args, **kwargs):
            # Runs between the leftover listing and the existence re-check —
            # exactly where the observed file disappears.
            out = real_classify(*args, **kwargs)
            if ghost.exists():
                real_unlink(ghost)
            return out

        with mock.patch("tests.support.os.unlink", unlink_and_spawn), \
             mock.patch.object(support, "_classify_leftovers", classify_then_vanish):
            tmp.cleanup()   # must not raise

        self.assertEqual(tmp.foreign_leftovers, [])
        self.assertIn("KNOWN.JSON.tmp", tmp.transient_leftovers)
        self.assertFalse(tmp.path.exists(), "the empty tree was not removed")

    def test_unidentified_file_is_inconclusive_not_a_pass(self) -> None:
        # A file we cannot attribute must fail the run. Without process-level
        # evidence we may not declare it another program's and move on — a
        # delayed writer of ours could hide behind an unfamiliar name.
        tmp = DiagnosticTempDir()
        real_file = tmp.path / "known_files.json"
        real_file.write_text("{}", encoding="utf-8")
        stray = tmp.path / "KNOWN_FILES.JSON.tmp"
        real_unlink = os.unlink

        def unlink_and_spawn(path, *a, **kw):
            result = real_unlink(path, *a, **kw)
            if str(path).endswith("known_files.json"):
                stray.write_text("unexplained copy", encoding="utf-8")
            return result

        with mock.patch("tests.support.os.unlink", unlink_and_spawn):
            with self.assertRaises(InconclusiveCleanupError) as ctx:
                tmp.cleanup()
        self.assertIn("KNOWN_FILES.JSON.tmp", str(ctx.exception))
        self.assertIn("process-level evidence", str(ctx.exception))
        real_unlink(stray)
        os.rmdir(tmp.path)

    def test_preexisting_file_we_failed_to_delete_still_fails(self) -> None:
        # Whatever its name, a file that was there before cleanup and is still
        # there afterwards is our failure to clean up.
        tmp = DiagnosticTempDir()
        stray = tmp.path / "KNOWN_FILES.JSON.tmp"
        stray.write_text("x", encoding="utf-8")
        real_unlink = os.unlink

        def skip(path, *a, **kw):
            if str(path).endswith("KNOWN_FILES.JSON.tmp"):
                return
            return real_unlink(path, *a, **kw)

        with mock.patch("tests.support.os.unlink", skip):
            with self.assertRaises(LeftoverFilesError):
                tmp.cleanup()
        real_unlink(stray)
        os.rmdir(tmp.path)

    def test_listing_reports_sizes(self) -> None:
        tmp = DiagnosticTempDir()
        (tmp.path / "a.bin").write_bytes(b"1234")
        listing = tmp.listing()
        self.assertTrue(any("a.bin" in line and "4 bytes" in line for line in listing))
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
