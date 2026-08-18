"""
The hash-request decision table.

The CLI and the GUI both render these notices, so this is where the rules are
stated once. The front-end suites assert that each interface *acts* on them;
this one pins what the table itself decides, including the combinations no
single front end exercises.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from core.scan_policy import (
    PolicyLevel,
    confirmations,
    evaluate_hash_request,
    first_blocking,
    warnings as policy_warnings,
)
from tests.support import DiagnosticTempDir


class HashRequestPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        (self.data / "a.txt").write_text("alpha", encoding="utf-8")
        self.manifest = self.root / "m.json"
        self.key = self.root / "keys" / "signing.key"
        self.key.parent.mkdir()
        self.key.write_text("{}", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _codes(self, notices) -> list[str]:
        return [n.code for n in notices]

    # ---- nothing to say -----------------------------------------------
    def test_plain_sha256_folder_scan_is_silent(self) -> None:
        notices = evaluate_hash_request(
            mode="folder", target=self.data, output=self.manifest
        )
        self.assertEqual(notices, [])

    def test_printing_a_digest_needs_no_opt_in(self) -> None:
        # No output means no stored reference, so no integrity claim is made.
        notices = evaluate_hash_request(
            mode="file", target=self.data / "a.txt", output=None, algorithm="md5"
        )
        self.assertEqual(notices, [])

    # ---- blocking ------------------------------------------------------
    def test_output_over_the_input_blocks(self) -> None:
        target = self.data / "a.txt"
        notices = evaluate_hash_request(mode="file", target=target, output=target)
        blocking = first_blocking(notices)
        self.assertIsNotNone(blocking)
        self.assertEqual(blocking.code, "output_overwrites_input")

    def test_signing_key_inside_the_folder_blocks(self) -> None:
        inside = self.data / "signing.key"
        inside.write_text("{}", encoding="utf-8")
        notices = evaluate_hash_request(
            mode="folder", target=self.data, output=self.manifest, sign_key=inside
        )
        self.assertEqual(first_blocking(notices).code, "sign_key_inside_folder")

    def test_signing_key_beside_the_manifest_blocks(self) -> None:
        beside = self.root / "signing.key"
        beside.write_text("{}", encoding="utf-8")
        notices = evaluate_hash_request(
            mode="folder", target=self.data, output=self.manifest, sign_key=beside
        )
        self.assertEqual(first_blocking(notices).code, "sign_key_beside_manifest")

    def test_a_key_kept_elsewhere_is_fine(self) -> None:
        notices = evaluate_hash_request(
            mode="folder", target=self.data, output=self.manifest, sign_key=self.key
        )
        self.assertEqual(notices, [])

    # ---- confirmation vs warning ---------------------------------------
    def test_md5_manifest_needs_confirmation(self) -> None:
        notices = evaluate_hash_request(
            mode="folder", target=self.data, output=self.manifest, algorithm="md5"
        )
        self.assertEqual(self._codes(confirmations(notices)), ["insecure_algorithm"])
        self.assertIn("MD5", notices[0].message)

    def test_sha1_needs_confirmation_too(self) -> None:
        notices = evaluate_hash_request(
            mode="folder", target=self.data, output=self.manifest, algorithm="sha1"
        )
        self.assertEqual(self._codes(confirmations(notices)), ["insecure_algorithm"])

    def test_opting_in_downgrades_the_confirmation_to_a_warning(self) -> None:
        notices = evaluate_hash_request(
            mode="folder", target=self.data, output=self.manifest,
            algorithm="md5", allow_insecure_algorithm=True,
        )
        self.assertEqual(confirmations(notices), [])
        self.assertEqual(self._codes(policy_warnings(notices)), ["insecure_algorithm"])

    def test_sha512_is_not_flagged(self) -> None:
        notices = evaluate_hash_request(
            mode="folder", target=self.data, output=self.manifest, algorithm="sha512"
        )
        self.assertEqual(notices, [])

    # ---- warnings -------------------------------------------------------
    def test_manifest_written_inside_the_folder_warns(self) -> None:
        inside = self.data / "manifest.json"
        notices = evaluate_hash_request(
            mode="folder", target=self.data, output=inside
        )
        self.assertEqual(self._codes(policy_warnings(notices)), ["manifest_inside_folder"])

    def test_manifest_outside_the_folder_does_not_warn(self) -> None:
        notices = evaluate_hash_request(
            mode="folder", target=self.data, output=self.manifest
        )
        self.assertEqual(policy_warnings(notices), [])

    # ---- ordering --------------------------------------------------------
    def test_blocking_notices_come_first(self) -> None:
        inside_key = self.data / "signing.key"
        inside_key.write_text("{}", encoding="utf-8")
        inside_manifest = self.data / "manifest.json"
        notices = evaluate_hash_request(
            mode="folder", target=self.data, output=inside_manifest,
            algorithm="md5", sign_key=inside_key,
        )
        self.assertGreater(len(notices), 1)
        self.assertIs(notices[0].level, PolicyLevel.BLOCK)
        # A user who cannot proceed should not be asked to confirm anything.
        self.assertIsNotNone(first_blocking(notices))


if __name__ == "__main__":
    unittest.main()
