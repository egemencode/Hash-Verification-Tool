"""
Blocker 1 regression suite: a signed manifest must actually be verified by
the ordinary load -> Verifier flow, and a broken signature can never yield a
"clean" verification result.

These tests exercise user-observable outcomes (verification refuses to run,
CLI exit code is non-zero) rather than just asserting on mocks.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.support import DiagnosticTempDir
from core import manifest_signing
from core.manifest_manager import (
    INTEGRITY_ED25519,
    Manifest,
    ManifestError,
    ManifestIntegrityError,
    SignatureState,
    build_manifest_for_folder,
)
from core.verifier import Verifier

_HAVE_CRYPTO = manifest_signing.is_available()
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _make_tree(root: Path) -> None:
    (root / "a.txt").write_text("alpha", encoding="utf-8")
    (root / "sub").mkdir(exist_ok=True)
    (root / "sub" / "b.txt").write_text("beta", encoding="utf-8")


class UnsignedBackCompatTests(unittest.TestCase):
    """Legacy unsigned manifests keep working — but are labelled as such."""

    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.root = Path(self.tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        _make_tree(self.data)
        self.mpath = self.root / "m.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_unsigned_manifest_verifies_clean(self) -> None:
        build_manifest_for_folder(self.data).manifest.save(self.mpath)
        loaded = Manifest.load(self.mpath)
        self.assertEqual(loaded.signature_state, SignatureState.UNSIGNED)
        result = Verifier(loaded).verify(self.data)
        self.assertTrue(result.is_clean)
        self.assertEqual(result.signature_state, SignatureState.UNSIGNED)

    def test_unsigned_is_distinct_from_invalid(self) -> None:
        # "no signature" must never be reported using the invalid state.
        build_manifest_for_folder(self.data).manifest.save(self.mpath)
        self.assertNotEqual(
            Manifest.load(self.mpath).signature_state, SignatureState.INVALID
        )

    def test_ed25519_mode_without_signature_block_is_rejected(self) -> None:
        m = build_manifest_for_folder(self.data).manifest
        m.integrity_mode = INTEGRITY_ED25519  # claims signing, has no signature
        m.save(self.mpath)
        with self.assertRaises(ManifestIntegrityError):
            Manifest.load(self.mpath)

    def test_unknown_integrity_mode_is_rejected(self) -> None:
        m = build_manifest_for_folder(self.data).manifest
        m.save(self.mpath)
        raw = json.loads(self.mpath.read_text(encoding="utf-8"))
        raw["metadata"]["integrity_mode"] = "quantum-magic"
        self.mpath.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(ManifestError):
            Manifest.load(self.mpath)


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed")
class SignedManifestFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.root = Path(self.tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        _make_tree(self.data)
        self.mpath = self.root / "signed.json"
        self.priv, self.pub = manifest_signing.generate_keypair()
        m = build_manifest_for_folder(self.data).manifest
        m.sign(self.priv)
        m.save(self.mpath)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _rewrite(self, mutate) -> None:
        raw = json.loads(self.mpath.read_text(encoding="utf-8"))
        mutate(raw)
        self.mpath.write_text(json.dumps(raw), encoding="utf-8")

    # --- 1. happy path -------------------------------------------------
    def test_valid_signed_manifest_verifies(self) -> None:
        loaded = Manifest.load(self.mpath, trusted_public_hex=self.pub)
        self.assertEqual(loaded.signature_state, SignatureState.TRUSTED)
        result = Verifier(loaded, trusted_public_hex=self.pub).verify(self.data)
        self.assertTrue(result.is_clean)

    def test_valid_without_trusted_key_is_embedded_only(self) -> None:
        loaded = Manifest.load(self.mpath)
        self.assertEqual(loaded.signature_state, SignatureState.VALID_EMBEDDED)

    # --- 2. flipped signature byte -------------------------------------
    def test_tampered_signature_bytes_rejected(self) -> None:
        def flip(raw):
            sig = raw["signature"]["signature"]
            first = "0" if sig[0] != "0" else "1"
            raw["signature"]["signature"] = first + sig[1:]

        self._rewrite(flip)
        with self.assertRaises(ManifestIntegrityError):
            Manifest.load(self.mpath, trusted_public_hex=self.pub)

    # --- 3. entry changed after signing --------------------------------
    def test_entry_hash_changed_after_signing_rejected(self) -> None:
        def tamper(raw):
            key = next(iter(raw["entries"]))
            raw["entries"][key]["hash"] = "d" * 64

        self._rewrite(tamper)
        with self.assertRaises(ManifestIntegrityError):
            Manifest.load(self.mpath, trusted_public_hex=self.pub)

    def test_added_entry_after_signing_rejected(self) -> None:
        def tamper(raw):
            raw["entries"]["evil.exe"] = {
                "hash": "e" * 64, "algorithm": "sha256", "size": 1, "mtime": 1.0
            }

        self._rewrite(tamper)
        with self.assertRaises(ManifestIntegrityError):
            Manifest.load(self.mpath)

    # --- 4. missing signature block in ed25519 mode --------------------
    def test_signature_block_removed_rejected(self) -> None:
        self._rewrite(lambda raw: raw.pop("signature"))
        with self.assertRaises(ManifestIntegrityError):
            Manifest.load(self.mpath)

    def test_malformed_signature_block_rejected(self) -> None:
        self._rewrite(lambda raw: raw.__setitem__("signature", {"algorithm": "ed25519"}))
        with self.assertRaises(ManifestIntegrityError):
            Manifest.load(self.mpath)

    # --- 7. Verifier itself must not call a broken manifest clean ------
    def test_verifier_refuses_in_memory_tampered_manifest(self) -> None:
        # Bypass load()'s gate the way a caller with an in-memory manifest would.
        loaded = Manifest.load(self.mpath, verify_integrity=False)
        loaded.entries[next(iter(loaded.entries))].hash = "f" * 64
        with self.assertRaises(ManifestIntegrityError):
            Verifier(loaded, trusted_public_hex=self.pub).verify(self.data)

    def test_invalid_signature_state_is_never_clean(self) -> None:
        from core.verifier import VerificationResult

        r = VerificationResult(
            folder=str(self.data),
            algorithm="sha256",
            signature_state=SignatureState.INVALID,
        )
        # Nothing modified/new/missing, yet it must not be reported clean.
        self.assertTrue(r.is_clean is False)

    def test_wrong_trusted_key_rejected(self) -> None:
        _other_priv, other_pub = manifest_signing.generate_keypair()
        with self.assertRaises(ManifestIntegrityError):
            Manifest.load(self.mpath, trusted_public_hex=other_pub)


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed")
class CliExitCodeTests(unittest.TestCase):
    """6. The real CLI must exit non-zero on a broken manifest signature."""

    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.root = Path(self.tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        _make_tree(self.data)
        self.mpath = self.root / "signed.json"
        self.priv, self.pub = manifest_signing.generate_keypair()
        m = build_manifest_for_folder(self.data).manifest
        m.sign(self.priv)
        m.save(self.mpath)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run_verify(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable, "main.py", "verify",
                "--folder", str(self.data),
                "--manifest", str(self.mpath),
                "--trusted-key", self.pub,
            ],
            cwd=str(_PROJECT_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )

    def test_cli_ok_on_valid_signature(self) -> None:
        proc = self._run_verify()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_cli_non_zero_on_tampered_signature(self) -> None:
        raw = json.loads(self.mpath.read_text(encoding="utf-8"))
        sig = raw["signature"]["signature"]
        raw["signature"]["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        self.mpath.write_text(json.dumps(raw), encoding="utf-8")

        proc = self._run_verify()
        self.assertNotEqual(proc.returncode, 0)
        combined = (proc.stdout + proc.stderr).lower()
        self.assertIn("imza", combined)

    def test_cli_non_zero_when_entries_tampered(self) -> None:
        raw = json.loads(self.mpath.read_text(encoding="utf-8"))
        key = next(iter(raw["entries"]))
        raw["entries"][key]["hash"] = "9" * 64
        self.mpath.write_text(json.dumps(raw), encoding="utf-8")

        proc = self._run_verify()
        self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
