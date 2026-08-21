"""
RT#6 — an incomplete build must not produce an ordinary manifest.

The reported defect: the manifest was written *before* ``complete`` was
checked, carried no marker of its own incompleteness, and could then be
signed and verified as if it described the whole folder.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from tests.support import DiagnosticTempDir, deny_reads_of
from core import manifest_signing
from core.manifest_manager import (
    Manifest,
    ManifestError,
    build_manifest_for_folder,
)
from core.verifier import Verifier

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_HAVE_CRYPTO = manifest_signing.is_available()


class _PartialTree(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        (self.data / "good.txt").write_text("ok", encoding="utf-8")
        self.bad = self.data / "bad.bin"
        self.bad.write_bytes(b"data")
        self.out = self.root / "m.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _deny_bad(self):
        # deny_reads_of asks the filesystem which file it is looking at
        # instead of comparing path strings, and refuses to leave the block
        # if nothing was ever denied. The hand-written version this replaced
        # compared str(path) == str(self.bad) and therefore stopped denying
        # anything the moment the temp directory was reachable by another
        # spelling — every test below then described an incomplete scan while
        # measuring a complete one.
        return deny_reads_of(self.bad)

    def _build_partial(self):
        with self._deny_bad():
            return build_manifest_for_folder(self.data)


class DefaultRefusesToWriteTests(_PartialTree):
    def test_incomplete_build_does_not_write_the_manifest(self) -> None:
        build = self._build_partial()
        self.assertFalse(build.complete)
        with self.assertRaises(ManifestError):
            build.save(self.out)
        self.assertFalse(
            self.out.exists(), "a partial build wrote an ordinary manifest"
        )

    def test_complete_build_writes_normally(self) -> None:
        build = build_manifest_for_folder(self.data)
        self.assertTrue(build.complete)
        build.save(self.out)
        self.assertTrue(self.out.exists())
        raw = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertIs(raw["metadata"]["complete"], True)


class PartialArtefactTests(_PartialTree):
    def test_explicit_partial_write_uses_a_distinct_name(self) -> None:
        build = self._build_partial()
        written = build.save(self.out, allow_partial=True)
        self.assertNotEqual(written, self.out)
        self.assertTrue(str(written).endswith(".partial.json"))
        self.assertFalse(self.out.exists())

    def test_partial_artefact_carries_its_status(self) -> None:
        build = self._build_partial()
        written = build.save(self.out, allow_partial=True)
        meta = json.loads(written.read_text(encoding="utf-8"))["metadata"]
        self.assertIs(meta["complete"], False)
        self.assertGreaterEqual(meta["skipped_count"], 1)
        self.assertTrue(meta["skipped"])
        self.assertIn("errors", meta)

    def test_partial_manifest_is_rejected_by_load(self) -> None:
        build = self._build_partial()
        written = build.save(self.out, allow_partial=True)
        with self.assertRaises(ManifestError):
            Manifest.load(written)

    def test_partial_manifest_can_be_inspected_explicitly(self) -> None:
        build = self._build_partial()
        written = build.save(self.out, allow_partial=True)
        loaded = Manifest.load(written, allow_incomplete=True)
        self.assertFalse(loaded.complete)

    def test_partial_manifest_cannot_be_signed(self) -> None:
        if not _HAVE_CRYPTO:
            self.skipTest("cryptography not installed")
        build = self._build_partial()
        priv, _pub = manifest_signing.generate_keypair()
        with self.assertRaises(ManifestError):
            build.manifest.sign(priv)

    def test_partial_manifest_is_rejected_by_verify(self) -> None:
        build = self._build_partial()
        written = build.save(self.out, allow_partial=True)
        loaded = Manifest.load(written, allow_incomplete=True)
        with self.assertRaises(ManifestError):
            Verifier(loaded).verify(self.data)


class CliPartialTests(_PartialTree):
    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "main.py", *args],
            cwd=str(_PROJECT_ROOT), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=120,
        )

    def test_cli_does_not_leave_a_normal_manifest_on_partial(self) -> None:
        # Deny read access to one file for the child process.
        import os

        user = os.environ.get("USERNAME") or ""
        if sys.platform.startswith("win"):
            proc = subprocess.run(
                ["icacls", str(self.bad), "/inheritance:r", "/deny", f"{user}:(R)"],
                capture_output=True, text=True,
            )
            if proc.returncode != 0:
                self.skipTest("cannot deny read access on this system")
        else:
            os.chmod(self.bad, 0o000)
        try:
            result = self._run(
                "hash", "--folder", str(self.data), "--output", str(self.out)
            )
            if result.returncode == 0:
                self.skipTest("the OS still allowed reading the denied file")
            self.assertFalse(
                self.out.exists(),
                "the CLI wrote an ordinary manifest for an incomplete scan",
            )
        finally:
            if sys.platform.startswith("win"):
                subprocess.run(["icacls", str(self.bad), "/reset"],
                               capture_output=True, text=True)
                subprocess.run(["icacls", str(self.bad), "/grant", f"{user}:(F)"],
                               capture_output=True, text=True)
            else:
                os.chmod(self.bad, 0o644)


if __name__ == "__main__":
    unittest.main()
