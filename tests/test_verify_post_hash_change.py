"""
RT#5 — a change made *after* a file was hashed must not verify as clean.

The earlier suite mutated the file before ``verify()`` started, which the
hash comparison catches trivially. The real gap is a swap that happens once
the verifier has already read that file: its digest is then a fact about
bytes that are no longer on disk.

These tests inject the mutation between the hash call and the end of the
scan, and assert the *user-visible* outcome: the run is not reported clean.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from tests.support import DiagnosticTempDir
from core import verifier as verifier_mod
from core.manifest_manager import build_manifest_for_folder
from core.verifier import Verifier


class _Tree(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        (self.data / "a.bin").write_bytes(b"AAAA")
        (self.data / "b.bin").write_bytes(b"BBBB")
        self.manifest = build_manifest_for_folder(self.data).manifest

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _hash_hook(self, action):
        """Patch hash_file_with_snapshot to run *action* after each hash."""
        real = verifier_mod.hash_file_with_snapshot

        def hooked(path, *args, **kwargs):
            out = real(path, *args, **kwargs)
            action(Path(path))
            return out

        return mock.patch.object(verifier_mod, "hash_file_with_snapshot", hooked)


class PostHashSwapTests(_Tree):
    def test_content_swap_after_hash_is_not_clean(self) -> None:
        target = self.data / "a.bin"
        st = target.stat()
        done = {"swapped": False}

        def swap(path: Path) -> None:
            if path.name == "a.bin" and not done["swapped"]:
                done["swapped"] = True
                path.write_bytes(b"BBBB")           # same length
                os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))  # same mtime

        with self._hash_hook(swap):
            result = Verifier(self.manifest).verify(self.data)

        self.assertTrue(done["swapped"], "the injection did not run")
        self.assertEqual(target.read_bytes(), b"BBBB")
        self.assertFalse(
            result.is_clean,
            "a file swapped after hashing was reported as unchanged",
        )

    def test_file_added_while_scanning_is_not_clean(self) -> None:
        added = {"done": False}

        def add_late(path: Path) -> None:
            if not added["done"]:
                added["done"] = True
                (self.data / "late.txt").write_text("late", encoding="utf-8")

        with self._hash_hook(add_late):
            result = Verifier(self.manifest).verify(self.data)

        self.assertTrue(added["done"])
        self.assertFalse(result.is_clean, "a file added mid-scan was ignored")

    def test_file_deleted_after_hash_is_not_clean(self) -> None:
        removed = {"done": False}

        def delete_other(path: Path) -> None:
            other = self.data / "b.bin"
            if path.name == "a.bin" and not removed["done"] and other.exists():
                removed["done"] = True
                other.unlink()

        with self._hash_hook(delete_other):
            result = Verifier(self.manifest).verify(self.data)

        self.assertTrue(removed["done"])
        self.assertFalse(result.is_clean, "a file deleted mid-scan was ignored")

    def test_untouched_tree_is_still_clean(self) -> None:
        # Control: the new checks must not produce false positives.
        result = Verifier(self.manifest).verify(self.data)
        self.assertTrue(result.is_clean, f"unexpected: {result.summary()}")

    def test_scan_incompleteness_is_reported(self) -> None:
        done = {"swapped": False}

        def swap(path: Path) -> None:
            if path.name == "a.bin" and not done["swapped"]:
                done["swapped"] = True
                path.write_bytes(b"ZZZZ")

        with self._hash_hook(swap):
            result = Verifier(self.manifest).verify(self.data)

        self.assertFalse(result.scan_complete)
        self.assertTrue(result.changed_during_scan)


if __name__ == "__main__":
    unittest.main()
