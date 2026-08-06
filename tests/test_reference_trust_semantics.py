"""
P0.6 — "the files match" is not "the reference is trustworthy".

Behaviours under test:
  * An unsigned or self-signed manifest may only ever produce a *qualified*
    result. The CLI must not print "Integrity OK" for it, and must not exit
    with the same success code as a trusted verification.
  * The local fingerprint store is a plain JSON file the user (or malware)
    can edit; it is never a trust root.
  * "Remember this version" must not silently overwrite a baseline that has
    already changed, and must be blocked when the current scan looks bad.
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
from core.baseline import (
    BaselineDecision,
    evaluate_baseline_request,
)
from core.local_verify import LocalVerifyStatus
from core.manifest_manager import SignatureState, build_manifest_for_folder
from core.risk_engine import RiskLevel

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_HAVE_CRYPTO = manifest_signing.is_available()


class CliTrustWordingTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        (self.data / "a.txt").write_text("alpha", encoding="utf-8")
        self.mpath = self.root / "m.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "main.py", *args],
            cwd=str(_PROJECT_ROOT), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=120,
        )

    def _hash(self) -> None:
        self._run("hash", "--folder", str(self.data), "--output", str(self.mpath))

    def test_unsigned_match_is_not_called_integrity_ok(self) -> None:
        self._hash()
        proc = self._run("verify", "--folder", str(self.data), "--manifest", str(self.mpath))
        out = proc.stdout + proc.stderr
        self.assertNotIn("Integrity OK", out)
        self.assertNotIn("güvenilir", out.lower().replace("güvenilmiyor", ""))

    def test_unsigned_match_exit_code_differs_from_trusted(self) -> None:
        self._hash()
        unsigned_code = self._run(
            "verify", "--folder", str(self.data), "--manifest", str(self.mpath)
        ).returncode
        self.assertNotEqual(
            unsigned_code, 0,
            "an unsigned reference must not produce the same success code as a "
            "trusted one",
        )

    @unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed")
    def test_trusted_match_exits_zero(self) -> None:
        priv, pub = manifest_signing.generate_keypair()
        build = build_manifest_for_folder(self.data)
        build.manifest.sign(priv)
        build.manifest.save(self.mpath)
        proc = self._run(
            "verify", "--folder", str(self.data), "--manifest", str(self.mpath),
            "--trusted-key", pub,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    @unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed")
    def test_self_signed_is_not_treated_as_trusted(self) -> None:
        priv, _pub = manifest_signing.generate_keypair()
        build = build_manifest_for_folder(self.data)
        build.manifest.sign(priv)
        build.manifest.save(self.mpath)
        # No --trusted-key: only the embedded key is available.
        proc = self._run("verify", "--folder", str(self.data), "--manifest", str(self.mpath))
        self.assertNotEqual(proc.returncode, 0)

    def test_allow_unsigned_flag_opts_in_explicitly(self) -> None:
        # Backwards compatibility stays available, but only on request.
        self._hash()
        proc = self._run(
            "verify", "--folder", str(self.data), "--manifest", str(self.mpath),
            "--allow-unsigned",
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


class BaselineDecisionTests(unittest.TestCase):
    """'Remember this version' must not quietly destroy an existing baseline."""

    def test_first_record_is_a_plain_save(self) -> None:
        decision = evaluate_baseline_request(
            local_status=LocalVerifyStatus.NOT_TRACKED,
            risk_level=RiskLevel.LOW,
        )
        self.assertEqual(decision, BaselineDecision.SAVE)

    def test_changed_baseline_requires_confirmation(self) -> None:
        decision = evaluate_baseline_request(
            local_status=LocalVerifyStatus.CHANGED,
            risk_level=RiskLevel.LOW,
        )
        self.assertEqual(decision, BaselineDecision.CONFIRM_REPLACE)

    def test_high_risk_is_blocked(self) -> None:
        decision = evaluate_baseline_request(
            local_status=LocalVerifyStatus.NOT_TRACKED,
            risk_level=RiskLevel.HIGH,
        )
        self.assertEqual(decision, BaselineDecision.BLOCKED)

    def test_changed_and_high_risk_is_blocked_not_merely_confirmed(self) -> None:
        decision = evaluate_baseline_request(
            local_status=LocalVerifyStatus.CHANGED,
            risk_level=RiskLevel.HIGH,
        )
        self.assertEqual(decision, BaselineDecision.BLOCKED)

    def test_hash_mismatch_signature_blocks(self) -> None:
        decision = evaluate_baseline_request(
            local_status=LocalVerifyStatus.NOT_TRACKED,
            risk_level=RiskLevel.LOW,
            signature_broken=True,
        )
        self.assertEqual(decision, BaselineDecision.BLOCKED)

    def test_same_file_is_a_no_op(self) -> None:
        decision = evaluate_baseline_request(
            local_status=LocalVerifyStatus.SAME,
            risk_level=RiskLevel.LOW,
        )
        self.assertEqual(decision, BaselineDecision.ALREADY_CURRENT)

    def test_medium_risk_requires_confirmation(self) -> None:
        decision = evaluate_baseline_request(
            local_status=LocalVerifyStatus.NOT_TRACKED,
            risk_level=RiskLevel.MEDIUM,
        )
        self.assertEqual(decision, BaselineDecision.CONFIRM_RISKY)


class BaselineHistoryTests(unittest.TestCase):
    """Replacing a baseline must keep the previous record for audit."""

    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.path = Path(self._tmp.name) / "known_files.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_previous_baseline_is_retained(self) -> None:
        from core.local_verify import LocalVerifyStore

        store = LocalVerifyStore(self.path)
        store.remember("C:/x/f.bin", "a" * 64, 10)
        store.remember("C:/x/f.bin", "b" * 64, 12)

        record = store.get("C:/x/f.bin")
        self.assertEqual(record.sha256, "b" * 64)
        self.assertTrue(record.previous, "the replaced baseline was discarded")
        self.assertEqual(record.previous[-1]["sha256"], "a" * 64)

    def test_history_survives_a_reload(self) -> None:
        from core.local_verify import LocalVerifyStore

        LocalVerifyStore(self.path).remember("C:/x/f.bin", "a" * 64, 10)
        LocalVerifyStore(self.path).remember("C:/x/f.bin", "b" * 64, 12)
        reloaded = LocalVerifyStore(self.path).get("C:/x/f.bin")
        self.assertEqual(reloaded.previous[-1]["sha256"], "a" * 64)


if __name__ == "__main__":
    unittest.main()
