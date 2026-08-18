"""
CLI folder/output contract (§3.3) and legacy-algorithm semantics (§3.5).

Four defects are pinned here:

* ``hash --file X --output X`` destroys X — the tool overwrites the very file
  the user asked it to fingerprint, and the digest it prints describes bytes
  that no longer exist anywhere.
* the single-file ``--output`` path reads the file twice, so the printed digest
  and the manifest entry come from two separate reads of a file that may have
  changed in between.
* writing the manifest into the folder being scanned is not called out, so the
  user cannot tell that the next verify will see a file the manifest omits.
* MD5/SHA-1 produce the same "verified" wording as SHA-256, even though a
  match under a collision-prone algorithm is a legacy checksum, not tamper
  evidence.
"""

from __future__ import annotations

import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

import core.hash_utils as hash_utils
import main as cli
from core import manifest_signing
from core.manifest_manager import Manifest
from core.verifier import Verifier
from tests.support import DiagnosticTempDir


def run_cli(args: list[str]) -> tuple[int, str, str]:
    out, err = StringIO(), StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(args)
    return code, out.getvalue(), err.getvalue()


class SingleFileOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.target = self.root / "important.bin"
        self.target.write_bytes(b"the only copy of this data")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_output_pointing_at_the_input_does_not_destroy_it(self) -> None:
        original = self.target.read_bytes()
        code, out, err = run_cli(
            ["hash", "--file", str(self.target), "--output", str(self.target)]
        )
        self.assertEqual(
            self.target.read_bytes(),
            original,
            "the file being hashed was overwritten by its own manifest",
        )
        self.assertEqual(code, cli.EXIT_USAGE, out + err)

    def test_output_pointing_at_the_input_via_a_different_spelling(self) -> None:
        # Same file, different path string: the check must compare identities,
        # not strings.
        original = self.target.read_bytes()
        indirect = self.root / "sub" / ".." / "important.bin"
        (self.root / "sub").mkdir()
        code, _out, _err = run_cli(
            ["hash", "--file", str(self.target), "--output", str(indirect)]
        )
        self.assertEqual(self.target.read_bytes(), original)
        self.assertEqual(code, cli.EXIT_USAGE)

    def test_single_file_manifest_reads_the_file_once(self) -> None:
        # Two reads mean two different points in time: the digest printed to
        # the console and the one stored in the manifest need not agree.
        real = hash_utils._guarded_hash_stream
        reads: list[str] = []

        def counting(path, algos, chunk_size):
            reads.append(str(Path(path).resolve()))
            return real(path, algos, chunk_size)

        hash_utils._guarded_hash_stream = counting
        try:
            code, _out, err = run_cli(
                ["hash", "--file", str(self.target),
                 "--output", str(self.root / "m.json")]
            )
        finally:
            hash_utils._guarded_hash_stream = real

        self.assertEqual(code, cli.EXIT_OK, err)
        mine = [r for r in reads if r == str(self.target.resolve())]
        self.assertEqual(
            len(mine), 1,
            f"the file was read {len(mine)} times for one manifest",
        )

    def test_printed_digest_matches_the_manifest_entry(self) -> None:
        manifest_path = self.root / "m.json"
        code, out, err = run_cli(
            ["hash", "--file", str(self.target), "--output", str(manifest_path)]
        )
        self.assertEqual(code, cli.EXIT_OK, err)
        doc = json.loads(manifest_path.read_text(encoding="utf-8"))
        stored = doc["entries"][self.target.name]["hash"]
        self.assertIn(stored, out, "the manifest digest was never shown to the user")


class ManifestInsideScannedFolderTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.data = Path(self._tmp.name) / "data"
        self.data.mkdir()
        (self.data / "a.txt").write_text("alpha", encoding="utf-8")
        (self.data / "b.txt").write_text("beta", encoding="utf-8")
        self.manifest = self.data / "manifest.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_user_is_warned_when_the_manifest_lands_inside_the_folder(self) -> None:
        code, out, err = run_cli(
            ["hash", "--folder", str(self.data), "--output", str(self.manifest)]
        )
        self.assertEqual(code, cli.EXIT_OK, err)
        combined = (out + err).lower()
        self.assertIn(
            "manifest.json", combined,
            "nothing told the user the manifest sits inside the scanned folder",
        )
        self.assertTrue(
            "hariç" in combined or "excluded" in combined or "uyari" in combined
            or "uyarı" in combined,
            f"no warning about the manifest being inside the tree:\n{out}\n{err}",
        )

    def test_hash_then_verify_is_clean_with_the_manifest_in_the_tree(self) -> None:
        run_cli(["hash", "--folder", str(self.data), "--output", str(self.manifest)])
        code, out, err = run_cli(
            ["verify", "--folder", str(self.data),
             "--manifest", str(self.manifest), "--allow-unsigned"]
        )
        self.assertEqual(
            code, cli.EXIT_OK,
            f"a freshly written manifest did not verify clean:\n{out}\n{err}",
        )

    def test_report_written_into_the_tree_is_not_verified_as_new(self) -> None:
        run_cli(["hash", "--folder", str(self.data), "--output", str(self.manifest)])
        report = self.data / "report.json"
        code, out, err = run_cli(
            ["verify", "--folder", str(self.data), "--manifest", str(self.manifest),
             "--report", str(report), "--allow-unsigned"]
        )
        self.assertEqual(code, cli.EXIT_OK, out + err)
        doc = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(doc["details"]["new"], [])


class InsecureAlgorithmTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        (self.data / "a.txt").write_text("alpha", encoding="utf-8")
        self.manifest = self.root / "m.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_md5_folder_manifest_requires_an_explicit_opt_in(self) -> None:
        code, out, err = run_cli(
            ["hash", "--folder", str(self.data),
             "--output", str(self.manifest), "--algo", "md5"]
        )
        self.assertEqual(code, cli.EXIT_USAGE, out + err)
        self.assertFalse(
            self.manifest.exists(),
            "an MD5 integrity manifest was produced without the user opting in",
        )
        self.assertIn("--allow-insecure-algorithm", out + err)

    def test_sha1_requires_the_same_opt_in(self) -> None:
        code, _out, _err = run_cli(
            ["hash", "--folder", str(self.data),
             "--output", str(self.manifest), "--algo", "sha1"]
        )
        self.assertEqual(code, cli.EXIT_USAGE)

    def test_opt_in_allows_md5_and_warns(self) -> None:
        code, out, err = run_cli(
            ["hash", "--folder", str(self.data), "--output", str(self.manifest),
             "--algo", "md5", "--allow-insecure-algorithm"]
        )
        self.assertEqual(code, cli.EXIT_OK, out + err)
        self.assertTrue(self.manifest.exists())
        self.assertIn("md5", (out + err).lower())

    def test_plain_digest_printing_needs_no_opt_in(self) -> None:
        # Printing a checksum is not an integrity claim; only building a
        # manifest that will later be used as a reference is.
        target = self.data / "a.txt"
        code, out, err = run_cli(["hash", "--file", str(target), "--algo", "md5"])
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertIn("md5", out.lower())

    def test_md5_match_is_not_reported_as_verified_integrity(self) -> None:
        run_cli(["hash", "--folder", str(self.data), "--output", str(self.manifest),
                 "--algo", "md5", "--allow-insecure-algorithm"])
        code, out, err = run_cli(
            ["verify", "--folder", str(self.data),
             "--manifest", str(self.manifest), "--allow-unsigned"]
        )
        self.assertEqual(code, cli.EXIT_OK, err)
        lowered = out.lower()
        self.assertTrue(
            "md5" in lowered and ("çakış" in lowered or "collision" in lowered
                                  or "legacy" in lowered),
            f"an MD5 match was reported without qualifying it:\n{out}",
        )

    def test_collision_prone_algorithm_never_yields_trusted_match(self) -> None:
        # The interesting case is the one where every OTHER condition for
        # trusted_match holds: files match, the scan was complete, and the
        # manifest verified against an out-of-band trusted key. Asserting this
        # on an unsigned manifest proves nothing — reference_trusted is already
        # False there, so the assertion passes whether or not the algorithm is
        # taken into account at all.
        if not manifest_signing.is_available():
            self.fail("signing backend missing; this assertion needs a trusted key")

        key = self.root / "keys" / "signing.key"
        key.parent.mkdir(exist_ok=True)
        code, _out, err = run_cli(["keygen", "--out", str(key)])
        self.assertEqual(code, cli.EXIT_OK, err)

        code, _out, err = run_cli(
            ["hash", "--folder", str(self.data), "--output", str(self.manifest),
             "--algo", "md5", "--allow-insecure-algorithm", "--sign-key", str(key)]
        )
        self.assertEqual(code, cli.EXIT_OK, err)

        trusted_hex = cli.load_public_key(str(key.with_suffix(".key.pub")))
        manifest = Manifest.load(self.manifest, trusted_public_hex=trusted_hex)
        result = Verifier(manifest, trusted_public_hex=trusted_hex).verify(self.data)

        # Everything except the algorithm says "trusted".
        self.assertTrue(result.files_match)
        self.assertTrue(result.scan_complete)
        self.assertTrue(
            result.reference_trusted,
            "the fixture failed to produce a trusted reference, so this test "
            "would prove nothing",
        )
        self.assertTrue(result.collision_prone_algorithm)
        self.assertFalse(
            result.trusted_match,
            "an MD5 comparison against a trusted key was reported as a "
            "trusted match — a digest an attacker can collide",
        )
        self.assertTrue(result.to_dict()["collision_prone_algorithm"])
        self.assertFalse(result.to_dict()["trusted_match"])

    def test_sha256_with_a_trusted_key_does_yield_trusted_match(self) -> None:
        # The counterpart: without it, the test above could pass simply because
        # trusted_match is broken and always False.
        if not manifest_signing.is_available():
            self.fail("signing backend missing")
        key = self.root / "keys" / "signing.key"
        key.parent.mkdir(exist_ok=True)
        run_cli(["keygen", "--out", str(key)])
        run_cli(["hash", "--folder", str(self.data), "--output", str(self.manifest),
                 "--sign-key", str(key)])

        trusted_hex = cli.load_public_key(str(key.with_suffix(".key.pub")))
        manifest = Manifest.load(self.manifest, trusted_public_hex=trusted_hex)
        result = Verifier(manifest, trusted_public_hex=trusted_hex).verify(self.data)
        self.assertTrue(result.trusted_match)

    def test_sha256_is_not_flagged(self) -> None:
        run_cli(["hash", "--folder", str(self.data), "--output", str(self.manifest)])
        manifest = Manifest.load(self.manifest)
        result = Verifier(manifest).verify(self.data)
        self.assertFalse(result.collision_prone_algorithm)


if __name__ == "__main__":
    unittest.main()
