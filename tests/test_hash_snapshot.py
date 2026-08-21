"""
Tests for single-pass multi-hash and mid-scan change detection (P0.3).
"""

from __future__ import annotations

import hashlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from tests.support import DiagnosticTempDir, same_path
from core import hash_utils
from core.hash_utils import (
    FileChangedDuringScanError,
    HashError,
    compute_file_hashes,
    hash_file_with_snapshot,
    snapshot_file,
)


class MultiHashTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.root = Path(self.tmp.name)
        self.payload = b"consistency-matters\n" * 5000
        self.sample = self.root / "sample.bin"
        self.sample.write_bytes(self.payload)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_all_digests_match_hashlib(self) -> None:
        digests = compute_file_hashes(self.sample, ("md5", "sha1", "sha256"))
        self.assertEqual(digests["md5"], hashlib.md5(self.payload).hexdigest())
        self.assertEqual(digests["sha1"], hashlib.sha1(self.payload).hexdigest())
        self.assertEqual(digests["sha256"], hashlib.sha256(self.payload).hexdigest())

    def test_single_pass_reads_file_once(self) -> None:
        # If the implementation opened the file once per algorithm this
        # counter would climb to 3. We assert exactly one open.
        real_open = Path.open
        opens = {"n": 0}

        def counting_open(self_path, *args, **kwargs):  # type: ignore[no-untyped-def]
            if same_path(self_path, self.sample):
                opens["n"] += 1
            return real_open(self_path, *args, **kwargs)

        original = Path.open
        Path.open = counting_open  # type: ignore[assignment]
        try:
            compute_file_hashes(self.sample, ("md5", "sha1", "sha256"))
        finally:
            Path.open = original  # type: ignore[assignment]
        self.assertEqual(opens["n"], 1)

    def test_zero_byte_file(self) -> None:
        empty = self.root / "empty.bin"
        empty.write_bytes(b"")
        digests = compute_file_hashes(empty, ("sha256",))
        self.assertEqual(digests["sha256"], hashlib.sha256(b"").hexdigest())

    def test_non_positive_chunk_size_rejected(self) -> None:
        for bad in (0, -1):
            with self.assertRaises(ValueError):
                compute_file_hashes(self.sample, ("sha256",), chunk_size=bad)

    def test_empty_algorithms_rejected(self) -> None:
        with self.assertRaises(ValueError):
            compute_file_hashes(self.sample, ())

    def test_missing_file_raises_hash_error(self) -> None:
        with self.assertRaises(HashError):
            compute_file_hashes(self.root / "nope.bin", ("sha256",))

    def test_large_file_not_read_into_memory(self) -> None:
        # Feed a 4 MiB file with a small chunk and assert the peak read
        # buffer never exceeds the chunk size (i.e. we stream).
        big = self.root / "big.bin"
        big.write_bytes(b"\xA5" * (4 * 1024 * 1024))
        max_seen = {"n": 0}
        real_open = Path.open

        def watching_open(self_path, *args, **kwargs):  # type: ignore[no-untyped-def]
            fh = real_open(self_path, *args, **kwargs)
            if not isinstance(fh, io.BufferedReader):
                return fh
            real_read = fh.read

            def watched_read(size=-1):  # type: ignore[no-untyped-def]
                data = real_read(size)
                max_seen["n"] = max(max_seen["n"], len(data))
                return data

            fh.read = watched_read  # type: ignore[assignment]
            return fh

        Path.open = watching_open  # type: ignore[assignment]
        try:
            compute_file_hashes(big, ("sha256",), chunk_size=64 * 1024)
        finally:
            Path.open = real_open  # type: ignore[assignment]
        self.assertLessEqual(max_seen["n"], 64 * 1024)


class MidScanChangeTests(unittest.TestCase):
    """A file mutated while being read must be flagged, not silently hashed."""

    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.root = Path(self.tmp.name)
        self.sample = self.root / "moving.bin"
        self.sample.write_bytes(b"original" * 1000)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_change_between_snapshots_raises(self) -> None:
        # Force the "after" snapshot to differ from the "before" snapshot by
        # patching the snapshot factory to return a mutated second value.
        real_from_stat = hash_utils.FileSnapshot.from_stat
        calls = {"n": 0}

        def fake_from_stat(st):  # type: ignore[no-untyped-def]
            calls["n"] += 1
            snap = real_from_stat(st)
            if calls["n"] >= 2:
                # Pretend the file grew mid-read.
                return hash_utils.FileSnapshot(
                    size=snap.size + 10,
                    mtime_ns=snap.mtime_ns + 1,
                    ino=snap.ino,
                    dev=snap.dev,
                )
            return snap

        hash_utils.FileSnapshot.from_stat = staticmethod(fake_from_stat)  # type: ignore[assignment]
        try:
            with self.assertRaises(FileChangedDuringScanError):
                compute_file_hashes(self.sample, ("sha256",), ensure_stable=True)
        finally:
            hash_utils.FileSnapshot.from_stat = staticmethod(real_from_stat)  # type: ignore[assignment]

    def test_lenient_mode_does_not_raise(self) -> None:
        # compute_file_hash keeps the old tolerant behaviour.
        digest = hash_utils.compute_file_hash(self.sample)
        self.assertTrue(digest)

    def test_snapshot_of_missing_file_raises(self) -> None:
        with self.assertRaises(HashError):
            snapshot_file(self.root / "gone.bin")

    def test_hash_with_snapshot_returns_size(self) -> None:
        digest, snap = hash_file_with_snapshot(self.sample, "sha256")
        self.assertEqual(snap.size, self.sample.stat().st_size)
        self.assertTrue(digest)


if __name__ == "__main__":
    unittest.main()
