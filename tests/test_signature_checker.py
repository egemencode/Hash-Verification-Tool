"""
Signature-classification tests.

The real check shells out to PowerShell (Windows only), so we mock
``subprocess.run`` and force the Windows code path. This lets the mapping
from raw PowerShell status strings to :class:`SignatureStatus` be verified
on any platform (including CI Linux).
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core import signature_checker as sc
from core.signature_checker import SignatureStatus, check_signature, _escape_for_powershell


def _completed(status: str, signer: str | None = None, message: str = "") -> mock.Mock:
    payload = {"Status": status, "StatusMessage": message, "Signer": signer}
    cp = mock.Mock()
    cp.returncode = 0
    cp.stdout = json.dumps(payload)
    cp.stderr = ""
    return cp


class SignatureClassificationTests(unittest.TestCase):
    def setUp(self) -> None:
        fd, self.path = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        with open(self.path, "wb") as fh:
            fh.write(b"payload")

    def tearDown(self) -> None:
        try:
            os.unlink(self.path)
        except OSError:
            pass

    def _classify(
        self, raw_status: str, signer: str | None = None, path: str | None = None
    ) -> SignatureStatus:
        with mock.patch.object(sc, "_is_windows", return_value=True), mock.patch.object(
            sc, "_powershell_executable", return_value="ps.exe"
        ), mock.patch.object(
            sc.subprocess, "run", return_value=_completed(raw_status, signer)
        ):
            return check_signature(path or self.path).status

    def _classify_signable(self, raw_status: str) -> SignatureStatus:
        """Same, but against a file whose type *can* carry a signature."""
        fd, exe_path = tempfile.mkstemp(suffix=".exe")
        os.close(fd)
        try:
            with open(exe_path, "wb") as fh:
                fh.write(b"MZ")
            return self._classify(raw_status, path=exe_path)
        finally:
            try:
                os.unlink(exe_path)
            except OSError:
                pass

    def test_valid(self) -> None:
        self.assertEqual(
            self._classify("Valid", "CN=Microsoft Corporation"),
            SignatureStatus.SIGNED_VALID,
        )

    def test_hash_mismatch(self) -> None:
        self.assertEqual(self._classify("HashMismatch"), SignatureStatus.HASH_MISMATCH)

    def test_not_trusted(self) -> None:
        self.assertEqual(self._classify("NotTrusted"), SignatureStatus.UNTRUSTED)

    def test_unsigned(self) -> None:
        self.assertEqual(self._classify("NotSigned"), SignatureStatus.UNSIGNED)

    def test_not_supported_format_is_not_applicable(self) -> None:
        self.assertEqual(
            self._classify("NotSupportedFileFormat"), SignatureStatus.NOT_APPLICABLE
        )

    def test_unknown_error_on_signable_file_stays_unknown(self) -> None:
        # A genuine, inconclusive check failure on a file that *could* be
        # signed must stay UNKNOWN — not be downgraded to "not applicable".
        self.assertEqual(
            self._classify_signable("UnknownError"), SignatureStatus.UNKNOWN
        )

    def test_unknown_error_on_unsignable_file_is_not_applicable(self) -> None:
        # Windows reports plain data files as UnknownError; that is a file-type
        # fact, not an inconclusive security check.
        self.assertEqual(
            self._classify("UnknownError"), SignatureStatus.NOT_APPLICABLE
        )

    def test_unsupported_format_is_never_invalid_looking(self) -> None:
        # Regression: an inapplicable format or a failed check must NOT be
        # reported as if the file were "signed but broken".
        for raw in ("NotSupportedFileFormat", "UnknownError", "SomethingBrandNew"):
            for status in (self._classify(raw), self._classify_signable(raw)):
                self.assertNotEqual(status, SignatureStatus.HASH_MISMATCH)
                self.assertNotEqual(status, SignatureStatus.UNTRUSTED)

    def test_zero_byte_file_does_not_crash(self) -> None:
        fd, empty = tempfile.mkstemp(suffix=".bin")
        os.close(fd)  # leave it 0 bytes
        try:
            with mock.patch.object(sc, "_is_windows", return_value=True), mock.patch.object(
                sc.subprocess, "run", return_value=_completed("NotSigned")
            ):
                self.assertEqual(check_signature(empty).status, SignatureStatus.UNSIGNED)
        finally:
            os.unlink(empty)

    def test_non_windows_is_unsupported(self) -> None:
        with mock.patch.object(sc, "_is_windows", return_value=False):
            self.assertEqual(
                check_signature(self.path).status, SignatureStatus.UNSUPPORTED
            )

    def test_missing_file_is_error(self) -> None:
        with mock.patch.object(sc, "_is_windows", return_value=True):
            self.assertEqual(
                check_signature(self.path + ".nope").status, SignatureStatus.ERROR
            )


class PowerShellEscapingTests(unittest.TestCase):
    def test_single_quote_is_doubled(self) -> None:
        self.assertEqual(_escape_for_powershell("O'Brien"), "O''Brien")

    def test_no_quote_unchanged(self) -> None:
        self.assertEqual(_escape_for_powershell("C:/Users/x/file.exe"), "C:/Users/x/file.exe")


class CommandHardeningTests(unittest.TestCase):
    """P1.1: the PowerShell invocation must be injection-safe and hardened."""

    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def _capture_invocation(self, filename: str) -> list[str]:
        p = Path(self.dir) / filename
        p.write_bytes(b"x")
        captured: dict[str, list[str]] = {}

        def fake_run(args, **kwargs):  # type: ignore[no-untyped-def]
            captured["args"] = list(args)
            cp = mock.Mock()
            cp.returncode = 0
            cp.stdout = json.dumps({"Status": "NotSigned", "StatusMessage": "", "Signer": None})
            cp.stderr = ""
            return cp

        with mock.patch.object(sc, "_is_windows", return_value=True), mock.patch.object(
            sc, "_powershell_executable",
            return_value=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ), mock.patch.object(sc.subprocess, "run", side_effect=fake_run):
            sc.check_signature(str(p))
        return captured["args"]

    def test_single_quote_in_name_is_escaped(self) -> None:
        args = self._capture_invocation("ev'il.txt")
        command = args[-1]
        # The single quote must be doubled so it cannot terminate the PS string.
        self.assertIn("ev''il.txt", command)

    def test_semicolon_space_unicode_stay_inside_literal(self) -> None:
        args = self._capture_invocation("a; kötü çünkü.txt")
        command = args[-1]
        self.assertIn("-LiteralPath", command)
        self.assertIn("a; kötü çünkü.txt", command)

    def test_no_execution_policy_bypass(self) -> None:
        args = self._capture_invocation("plain.txt")
        self.assertNotIn("Bypass", args)
        self.assertIn("-NoProfile", args)
        self.assertIn("-NonInteractive", args)

    def test_executable_is_absolute_powershell(self) -> None:
        args = self._capture_invocation("plain.txt")
        self.assertTrue(args[0].lower().endswith("powershell.exe"))
        self.assertTrue(os.path.isabs(args[0]))


if __name__ == "__main__":
    unittest.main()
