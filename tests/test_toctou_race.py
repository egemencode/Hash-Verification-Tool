"""
Blocker 2 regression suite: no TOCTOU window between hashing a file and
trusting the metadata / verdict produced for it.

The tests mutate real files at the exact moments an attacker would (during
the read loop, and between hashing and the post-VT re-check) and assert the
scan refuses to produce a verdict — including the hard case where size and
mtime are restored to their original values.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.support import DiagnosticTempDir
from core import trust_pipeline
from core.hash_utils import (
    FileChangedDuringScanError,
    compute_file_hashes_with_snapshot,
    hash_file_with_snapshot,
)
from core.manifest_manager import build_manifest_for_folder
from core.trust_pipeline import TRUST_ALGORITHMS, run_trust_check
from core.vt_client import VirusTotalClient


class MidReadMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.root = Path(self.tmp.name)
        self.sample = self.root / "victim.bin"
        self.sample.write_bytes(b"A" * (256 * 1024))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_size_change_during_hashing_is_caught(self) -> None:
        # 2. Growing the file mid-read must be detected. The mutation fires
        # exactly ONCE (a repeated append would keep moving EOF and the read
        # loop would never terminate).
        real_open = Path.open
        state = {"wrapped": False, "grown": False}

        def opener(self_path, *args, **kwargs):
            fh = real_open(self_path, *args, **kwargs)
            if str(self_path) == str(self.sample) and not state["wrapped"]:
                state["wrapped"] = True
                real_read = fh.read

                def read(size=-1):
                    data = real_read(size)
                    if data and not state["grown"]:
                        state["grown"] = True
                        with open(self.sample, "ab") as victim:
                            victim.write(b"EXTRA" * 1000)
                    return data

                fh.read = read  # type: ignore[assignment]
            return fh

        with mock.patch.object(Path, "open", opener):
            with self.assertRaises(FileChangedDuringScanError):
                compute_file_hashes_with_snapshot(
                    self.sample, ("sha256",), chunk_size=4096, ensure_stable=True
                )

    def test_single_pass_still_used_for_three_algorithms(self) -> None:
        # 6. MD5/SHA-1/SHA-256 must still come from ONE read of the file.
        opens = {"n": 0}
        real_open = Path.open

        def counting(self_path, *args, **kwargs):
            if str(self_path) == str(self.sample):
                opens["n"] += 1
            return real_open(self_path, *args, **kwargs)

        with mock.patch.object(Path, "open", counting):
            digests, snap = compute_file_hashes_with_snapshot(
                self.sample, TRUST_ALGORITHMS
            )
        self.assertEqual(opens["n"], 1)
        payload = self.sample.read_bytes()
        self.assertEqual(digests["md5"], hashlib.md5(payload).hexdigest())
        self.assertEqual(digests["sha1"], hashlib.sha1(payload).hexdigest())
        self.assertEqual(digests["sha256"], hashlib.sha256(payload).hexdigest())
        # The snapshot is handle-bound, so it describes what we hashed.
        self.assertEqual(snap.size, len(payload))


class PipelineRaceTests(unittest.TestCase):
    """Changes between hashing and the final verdict must abort the scan."""

    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.root = Path(self.tmp.name)
        self.sample = self.root / "target.bin"
        self.sample.write_bytes(b"ORIGINAL-CONTENT" * 100)
        self.client = VirusTotalClient(api_key=None)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self):
        return run_trust_check(
            str(self.sample),
            vt_client=self.client,
            local_store=None,
            check_signature_flag=False,
            query_virustotal=False,
        )

    def test_baseline_stable_file_succeeds(self) -> None:
        result = self._run()
        self.assertEqual(len(result.sha256), 64)

    def test_swap_between_hash_and_recheck_is_caught(self) -> None:
        # 1. Attacker swaps the file after hashing, before the verdict.
        original_snapshot = trust_pipeline.snapshot_file

        def swapping_snapshot(path):
            snap = original_snapshot(path)
            # Rewrite with DIFFERENT length so the stat check trips.
            Path(path).write_bytes(b"SWAPPED")
            return snap

        with mock.patch.object(trust_pipeline, "snapshot_file", swapping_snapshot):
            with self.assertRaises(FileChangedDuringScanError):
                self._run()

    def test_same_size_content_change_is_caught(self) -> None:
        # 3. Same length, different bytes — a stat-only check would miss this.
        original = self.sample.read_bytes()
        replacement = b"X" * len(original)
        self.assertEqual(len(original), len(replacement))

        original_snapshot = trust_pipeline.snapshot_file

        def swapping_snapshot(path):
            Path(path).write_bytes(replacement)
            return original_snapshot(path)

        with mock.patch.object(trust_pipeline, "snapshot_file", swapping_snapshot):
            with self.assertRaises(FileChangedDuringScanError):
                self._run()

    def test_content_change_with_restored_size_and_mtime_is_caught(self) -> None:
        # 4. The strongest case: attacker restores BOTH size and mtime, so
        # every metadata signal looks untouched. Only a content re-hash
        # catches it — this asserts we do not rely on stat alone.
        original = self.sample.read_bytes()
        st = self.sample.stat()
        replacement = b"Z" * len(original)

        original_snapshot = trust_pipeline.snapshot_file

        def swapping_snapshot(path):
            p = Path(path)
            p.write_bytes(replacement)
            # Restore mtime/atime exactly as the original.
            os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
            return original_snapshot(path)

        with mock.patch.object(trust_pipeline, "snapshot_file", swapping_snapshot):
            with self.assertRaises(FileChangedDuringScanError):
                self._run()


class ManifestStrictModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.root = Path(self.tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        (self.data / "stable.txt").write_text("stable", encoding="utf-8")
        self.moving = self.data / "moving.bin"
        self.moving.write_bytes(b"M" * (256 * 1024))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_hash_file_with_snapshot_defaults_to_strict(self) -> None:
        import inspect

        sig = inspect.signature(hash_file_with_snapshot)
        self.assertIs(sig.parameters["ensure_stable"].default, True)

    def test_changing_file_is_not_recorded_as_manifest_entry(self) -> None:
        # 5. A file mutated during the scan must be reported as an error and
        # left OUT of the manifest, never recorded with an untrustworthy hash.
        real_open = Path.open
        state = {"wrapped": False, "grown": False}

        def opener(self_path, *args, **kwargs):
            fh = real_open(self_path, *args, **kwargs)
            if str(self_path) == str(self.moving) and not state["wrapped"]:
                state["wrapped"] = True
                real_read = fh.read

                def read(size=-1):
                    data = real_read(size)
                    # One-shot: repeated appends would keep pushing EOF away.
                    if data and not state["grown"]:
                        state["grown"] = True
                        with open(self.moving, "ab") as victim:
                            victim.write(b"GROW")
                    return data

                fh.read = read  # type: ignore[assignment]
            return fh

        errors: list[tuple[str, Exception]] = []
        with mock.patch.object(Path, "open", opener):
            build = build_manifest_for_folder(
                self.data,
                on_error=lambda rel, exc: errors.append((rel, exc)),
            )

        self.assertNotIn("moving.bin", build.manifest.entries)
        self.assertIn("stable.txt", build.manifest.entries)
        self.assertTrue(any(isinstance(e, FileChangedDuringScanError) for _r, e in errors))
        # A skipped file must also make the build itself incomplete.
        self.assertFalse(build.complete)
        self.assertIn("moving.bin", build.skipped)


if __name__ == "__main__":
    unittest.main()
