"""Unit tests for core.hash_utils."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Allow running with `python -m unittest` from the project root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.hash_utils import (  # noqa: E402
    DEFAULT_ALGORITHM,
    SUPPORTED_ALGORITHMS,
    HashError,
    ProgressEvent,
    compute_file_hash,
    count_files,
    iter_files,
)


class HashUtilsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.payload = b"hash-verification-tool test payload\n" * 1024
        self.sample = self.root / "sample.bin"
        self.sample.write_bytes(self.payload)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # ----- compute_file_hash -------------------------------------------
    def test_default_algorithm_matches_hashlib(self) -> None:
        expected = hashlib.sha256(self.payload).hexdigest()
        self.assertEqual(compute_file_hash(self.sample), expected)

    def test_each_supported_algorithm_works(self) -> None:
        for algo in SUPPORTED_ALGORITHMS:
            with self.subTest(algorithm=algo):
                expected = hashlib.new(algo, self.payload).hexdigest()
                self.assertEqual(
                    compute_file_hash(self.sample, algorithm=algo), expected
                )

    def test_unsupported_algorithm_raises(self) -> None:
        with self.assertRaises(ValueError):
            compute_file_hash(self.sample, algorithm="nope")

    def test_missing_file_raises_hash_error(self) -> None:
        with self.assertRaises(HashError):
            compute_file_hash(self.root / "does-not-exist.bin")

    def test_directory_raises_hash_error(self) -> None:
        with self.assertRaises(HashError):
            compute_file_hash(self.root)

    def test_chunked_read_matches_full_read(self) -> None:
        # A tiny chunk size should still produce the same digest.
        full = compute_file_hash(self.sample)
        small_chunks = compute_file_hash(self.sample, chunk_size=7)
        self.assertEqual(full, small_chunks)

    # ----- iter_files --------------------------------------------------
    def test_iter_files_walks_recursively(self) -> None:
        nested_dir = self.root / "nested"
        nested_dir.mkdir()
        nested_file = nested_dir / "deep.txt"
        nested_file.write_text("deep")

        found = {p.relative_to(self.root).as_posix() for p in iter_files(self.root)}
        self.assertIn("sample.bin", found)
        self.assertIn("nested/deep.txt", found)

    def test_iter_files_missing_folder_raises(self) -> None:
        with self.assertRaises(HashError):
            list(iter_files(self.root / "nope"))

    def test_default_algorithm_is_sha256(self) -> None:
        self.assertEqual(DEFAULT_ALGORITHM, "sha256")

    # ----- count_files -------------------------------------------------
    def test_count_files_matches_iter_files(self) -> None:
        (self.root / "extra" / "deep").mkdir(parents=True)
        (self.root / "extra" / "deep" / "x.bin").write_bytes(b"x")
        self.assertEqual(count_files(self.root), len(list(iter_files(self.root))))

    def test_count_files_missing_folder_raises(self) -> None:
        with self.assertRaises(HashError):
            count_files(self.root / "nope")

    # ----- ProgressEvent -----------------------------------------------
    def test_progress_event_percent(self) -> None:
        self.assertAlmostEqual(ProgressEvent(25, 100, "x").percent, 25.0)
        # zero total must not raise
        self.assertEqual(ProgressEvent(0, 0, "x").percent, 0.0)


if __name__ == "__main__":
    unittest.main()
