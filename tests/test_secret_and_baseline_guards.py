"""
RT#7 — an unreadable encrypted API key must be preserved, not deleted.
RT#8 — a file with an active detection must never become a baseline.
"""

from __future__ import annotations

import json
import unittest
from unittest import mock

from tests.support import DiagnosticTempDir
from pathlib import Path

from core import secret_store
from core.baseline import BaselineDecision, evaluate_baseline_request
from core.local_verify import LocalVerifyStatus
from core.risk_engine import RiskLevel
from utils import settings as S
from utils.settings import KEY_VT_API_KEY_ENC, AppSettings, SecretState

_HAVE_DPAPI = secret_store.is_available()


@unittest.skipUnless(_HAVE_DPAPI, "DPAPI (Windows) not available")
class UnreadableTokenTests(unittest.TestCase):
    """An undecryptable token is not the same thing as "no key"."""

    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.base = Path(self._tmp.name)
        self.file = self.base / "hashtool_settings.json"
        S.clear_migration_warnings()
        S._reset_write_disabled_for_tests()

    def tearDown(self) -> None:
        S.clear_migration_warnings()
        S._reset_write_disabled_for_tests()
        self._tmp.cleanup()

    def _write_unreadable_token(self) -> str:
        # Valid base64, but not a DPAPI blob this user can open.
        token = "AQAAANCMnd8BFdERjHoAwE_Cl-sBAAAAbroken"
        self.file.write_text(
            json.dumps({KEY_VT_API_KEY_ENC: token, "language": "tr"}), encoding="utf-8"
        )
        return token

    def test_unreadable_token_is_reported_distinctly(self) -> None:
        self._write_unreadable_token()
        with mock.patch.object(S, "_base_dir", return_value=self.base):
            loaded = AppSettings.load()
        self.assertEqual(loaded.secret_state, SecretState.UNREADABLE)
        self.assertNotEqual(
            loaded.secret_state, SecretState.ABSENT,
            "an unreadable token was reported as 'no key'",
        )

    def test_unrelated_save_does_not_delete_the_token(self) -> None:
        token = self._write_unreadable_token()
        with mock.patch.object(S, "_base_dir", return_value=self.base):
            loaded = AppSettings.load()
            loaded.language = "en"          # user only changes the language
            loaded.save()
            raw = json.loads(self.file.read_text(encoding="utf-8"))
        self.assertEqual(
            raw.get(KEY_VT_API_KEY_ENC), token,
            "an unreadable key was silently destroyed by an unrelated save",
        )
        self.assertEqual(raw.get("language"), "en")

    def test_user_can_still_remove_the_key_explicitly(self) -> None:
        self._write_unreadable_token()
        with mock.patch.object(S, "_base_dir", return_value=self.base):
            loaded = AppSettings.load()
            loaded.clear_api_key()          # explicit "remove key"
            loaded.save()
            raw = json.loads(self.file.read_text(encoding="utf-8"))
        self.assertNotIn(KEY_VT_API_KEY_ENC, raw)

    def test_setting_a_new_key_replaces_the_unreadable_one(self) -> None:
        self._write_unreadable_token()
        with mock.patch.object(S, "_base_dir", return_value=self.base):
            loaded = AppSettings.load()
            loaded.virustotal_api_key = "FRESH-KEY"
            loaded.save()
            reloaded = AppSettings.load()
        self.assertEqual(reloaded.virustotal_api_key, "FRESH-KEY")

    def test_a_warning_is_raised_and_redacted(self) -> None:
        self._write_unreadable_token()
        with mock.patch.object(S, "_base_dir", return_value=self.base):
            AppSettings.load()
            warnings = S.pending_migration_warnings()
        self.assertTrue(warnings, "the user was not told the key is unreadable")
        joined = " ".join(warnings)
        self.assertNotIn("AQAAANCMnd8", joined, "the token leaked into a warning")


class BaselineDetectionGuardTests(unittest.TestCase):
    """A file any engine flagged must not be recorded as 'known good'."""

    def test_suspicious_detection_blocks_baseline(self) -> None:
        # The reported case: 1 suspicious + 69 undetected -> MEDIUM, and the
        # user clicking "yes" was enough to enshrine it.
        decision = evaluate_baseline_request(
            local_status=LocalVerifyStatus.NOT_TRACKED,
            risk_level=RiskLevel.MEDIUM,
            vt_malicious=0,
            vt_suspicious=1,
        )
        self.assertEqual(decision, BaselineDecision.BLOCKED)

    def test_malicious_detection_blocks_baseline(self) -> None:
        decision = evaluate_baseline_request(
            local_status=LocalVerifyStatus.NOT_TRACKED,
            risk_level=RiskLevel.MEDIUM,
            vt_malicious=1,
            vt_suspicious=0,
        )
        self.assertEqual(decision, BaselineDecision.BLOCKED)

    def test_detection_blocks_even_when_file_changed(self) -> None:
        decision = evaluate_baseline_request(
            local_status=LocalVerifyStatus.CHANGED,
            risk_level=RiskLevel.MEDIUM,
            vt_suspicious=2,
        )
        self.assertEqual(decision, BaselineDecision.BLOCKED)

    def test_high_and_hash_mismatch_still_blocked(self) -> None:
        self.assertEqual(
            evaluate_baseline_request(
                local_status=LocalVerifyStatus.NOT_TRACKED, risk_level=RiskLevel.HIGH
            ),
            BaselineDecision.BLOCKED,
        )
        self.assertEqual(
            evaluate_baseline_request(
                local_status=LocalVerifyStatus.NOT_TRACKED,
                risk_level=RiskLevel.LOW,
                signature_broken=True,
            ),
            BaselineDecision.BLOCKED,
        )

    def test_changed_without_detection_still_asks_for_confirmation(self) -> None:
        decision = evaluate_baseline_request(
            local_status=LocalVerifyStatus.CHANGED,
            risk_level=RiskLevel.LOW,
            vt_malicious=0,
            vt_suspicious=0,
        )
        self.assertEqual(decision, BaselineDecision.CONFIRM_REPLACE)

    def test_clean_new_file_still_saves(self) -> None:
        decision = evaluate_baseline_request(
            local_status=LocalVerifyStatus.NOT_TRACKED,
            risk_level=RiskLevel.LOW,
            vt_malicious=0,
            vt_suspicious=0,
        )
        self.assertEqual(decision, BaselineDecision.SAVE)


if __name__ == "__main__":
    unittest.main()
