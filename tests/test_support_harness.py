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
    DenialNeverFiredError,
    DiagnosticTempDir,
    InconclusiveCleanupError,
    LeftoverFilesError,
    deny_reads_of,
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


class DropInCompatibilityTests(unittest.TestCase):
    """``DiagnosticTempDir`` says it can stand in for ``TemporaryDirectory``.

    Most of that is real — ``.name``, ``__fspath__``, ``__str__`` — and it is
    why every path-taking API accepts it unchanged. The ``with`` block was the
    exception: ``tempfile.TemporaryDirectory.__enter__`` hands back a *string*,
    this one handed back the object, and ``os.fspath`` covers the difference
    everywhere except the places that want a real ``str``. Converting the
    suite's remaining plain temp dirs turned that up as four errors reading
    ``TypeError: str expected, not DiagnosticTempDir`` — all of them
    ``mock.patch.dict(os.environ, ...)``, which is exactly such a place.
    """

    def test_the_with_block_binds_a_string(self) -> None:
        with DiagnosticTempDir() as bound:
            self.assertIsInstance(bound, str)

    def test_the_bound_value_works_where_only_a_str_will_do(self) -> None:
        with DiagnosticTempDir() as bound:
            # os.environ refuses anything that is not a str, __fspath__ or no.
            with mock.patch.dict(os.environ, {"HVT_TEST_TMP": bound}):
                self.assertEqual(os.environ["HVT_TEST_TMP"], bound)

    def test_the_directory_still_goes_away_after_the_block(self) -> None:
        with DiagnosticTempDir() as bound:
            path = Path(bound)
            self.assertTrue(path.is_dir())
        self.assertFalse(path.exists())


class DenyReadsOfTests(unittest.TestCase):
    """The fixture that makes a file unreadable, and knows whether it did.

    Its predecessor compared ``str(path) == str(target)``, which is only
    correct while nobody spells the path another way. The product resolves
    the scan root before opening anything under it, so "another way" is the
    normal case as soon as the temp directory is reached by a short name, a
    different case, or an extended-length prefix — and then the denial is a
    no-op that no assertion notices.
    """

    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.target = Path(self._tmp.name) / "gizli.bin"
        self.target.write_bytes(b"data")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_reading_the_target_is_refused(self) -> None:
        with deny_reads_of(self.target) as denial:
            with self.assertRaises(PermissionError):
                self.target.open("rb")
        self.assertEqual(denial.denials, 1)

    def test_other_files_are_untouched(self) -> None:
        other = Path(self._tmp.name) / "acik.bin"
        other.write_bytes(b"fine")
        with deny_reads_of(self.target):
            with other.open("rb") as handle:
                self.assertEqual(handle.read(), b"fine")
            with self.assertRaises(PermissionError):
                self.target.open("rb")

    def test_a_differently_cased_spelling_is_still_the_same_file(self) -> None:
        """The regression. Windows is case-insensitive; ``str`` is not."""
        spelled = Path(str(self.target).upper())
        with deny_reads_of(self.target):
            with self.assertRaises(PermissionError):
                spelled.open("rb")

    def test_an_extended_length_spelling_is_still_the_same_file(self) -> None:
        spelled = Path("\\\\?\\" + str(self.target))
        with deny_reads_of(self.target):
            with self.assertRaises(PermissionError):
                spelled.open("rb")

    def test_a_denial_that_never_fires_is_an_error(self) -> None:
        """The part that stops a broken fixture from reporting success."""
        with self.assertRaises(DenialNeverFiredError):
            with deny_reads_of(self.target):
                pass

    def test_an_exception_from_the_block_is_not_masked(self) -> None:
        """A real failure inside is more informative than 'nothing fired'."""
        with self.assertRaises(ZeroDivisionError):
            with deny_reads_of(self.target):
                1 / 0

    def test_open_is_restored_afterwards(self) -> None:
        with self.assertRaises(DenialNeverFiredError):
            with deny_reads_of(self.target):
                pass
        with self.target.open("rb") as handle:
            self.assertEqual(handle.read(), b"data")
