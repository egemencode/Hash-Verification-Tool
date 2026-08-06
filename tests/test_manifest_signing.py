"""
Ed25519 signed-manifest tests + schema-version guarding.

The signing tests are skipped when the optional ``cryptography`` package
is not installed, but the tamper/trust semantics are the whole point of
the feature so they run in CI where the dependency is present.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.support import DiagnosticTempDir
from core import manifest_signing
from core.manifest_manager import (
    INTEGRITY_ED25519,
    INTEGRITY_NONE,
    FileEntry,
    Manifest,
    ManifestError,
)

_HAVE_CRYPTO = manifest_signing.is_available()


def _sample_manifest() -> Manifest:
    m = Manifest(root_path="C:/data", algorithm="sha256", created_at="2026-01-01T00:00:00+00:00")
    m.add("a.txt", FileEntry(hash="a" * 64, algorithm="sha256", size=10, mtime=1.0))
    m.add("b.txt", FileEntry(hash="b" * 64, algorithm="sha256", size=20, mtime=2.0))
    return m


class SchemaVersionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_round_trip_preserves_integrity_mode(self) -> None:
        path = self.root / "m.json"
        _sample_manifest().save(path)
        loaded = Manifest.load(path)
        self.assertEqual(loaded.integrity_mode, INTEGRITY_NONE)
        self.assertEqual(len(loaded.entries), 2)

    def test_unknown_schema_version_rejected(self) -> None:
        path = self.root / "future.json"
        m = _sample_manifest()
        m.schema_version = "99.0"
        m.save(path)
        with self.assertRaises(ManifestError):
            Manifest.load(path)

    def test_corrupt_metadata_type_rejected(self) -> None:
        path = self.root / "bad.json"
        path.write_text('{"metadata": "not-an-object", "entries": {}}', encoding="utf-8")
        with self.assertRaises(ManifestError):
            Manifest.load(path)


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed")
class Ed25519SigningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.root = Path(self.tmp.name)
        self.priv, self.pub = manifest_signing.generate_keypair()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_sign_sets_mode_and_verifies_with_trusted_key(self) -> None:
        m = _sample_manifest()
        m.sign(self.priv)
        self.assertEqual(m.integrity_mode, INTEGRITY_ED25519)
        self.assertTrue(m.is_signed)
        result = m.verify_signature(trusted_public_hex=self.pub)
        self.assertTrue(result.valid)
        self.assertTrue(result.trusted)

    def test_signature_survives_save_load(self) -> None:
        m = _sample_manifest()
        m.sign(self.priv)
        path = self.root / "signed.json"
        m.save(path)
        loaded = Manifest.load(path)
        self.assertTrue(loaded.is_signed)
        self.assertTrue(loaded.verify_signature(trusted_public_hex=self.pub).valid)

    def test_tampered_entries_fail_verification(self) -> None:
        m = _sample_manifest()
        m.sign(self.priv)
        path = self.root / "signed.json"
        m.save(path)
        loaded = Manifest.load(path)
        # Attacker edits an entry after signing.
        loaded.entries["a.txt"] = FileEntry(hash="c" * 64, algorithm="sha256", size=10, mtime=1.0)
        result = loaded.verify_signature(trusted_public_hex=self.pub)
        self.assertFalse(result.valid)

    def test_embedded_only_is_valid_but_not_trusted(self) -> None:
        m = _sample_manifest()
        m.sign(self.priv)
        # No out-of-band key: verifying against the manifest's own key proves
        # consistency but must not be reported as externally trusted.
        result = m.verify_signature(trusted_public_hex=None)
        self.assertTrue(result.valid)
        self.assertFalse(result.trusted)

    def test_wrong_trusted_key_is_untrusted(self) -> None:
        m = _sample_manifest()
        m.sign(self.priv)
        _other_priv, other_pub = manifest_signing.generate_keypair()
        result = m.verify_signature(trusted_public_hex=other_pub)
        self.assertFalse(result.valid)

    def test_public_key_derivation_is_stable(self) -> None:
        self.assertEqual(manifest_signing.public_key_for(self.priv), self.pub)


if __name__ == "__main__":
    unittest.main()
