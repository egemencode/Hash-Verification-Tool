"""
Regression tests for the v2 risk-decision policy.

These encode the acceptance criteria: certain signal combinations must
never collapse into a reassuring LOW, and hard danger signals must force
HIGH regardless of the numeric score.
"""

from __future__ import annotations

import unittest

from core.local_verify import LocalVerifyResult, LocalVerifyStatus
from core.risk_engine import (
    RISK_POLICY_VERSION,
    SCORE_MAX,
    SCORE_MIN,
    RiskLevel,
    assess,
)
from core.signature_checker import SignatureResult, SignatureStatus
from core.vt_client import VTAnalysisStats, VTLookupResult, VTStatus


def _vt_ok(malicious: int = 0, suspicious: int = 0, engines: int = 70) -> VTLookupResult:
    harmless = max(0, engines - malicious - suspicious)
    return VTLookupResult(
        status=VTStatus.OK,
        hash_value="a" * 64,
        stats=VTAnalysisStats(malicious=malicious, suspicious=suspicious, harmless=harmless),
        total_engines=engines,
        analysing_engines=engines,
    )


def _vt(status: VTStatus) -> VTLookupResult:
    return VTLookupResult(status=status, hash_value="a" * 64)


def _sig(status: SignatureStatus) -> SignatureResult:
    return SignatureResult(status=status)


def _local(status: LocalVerifyStatus) -> LocalVerifyResult:
    return LocalVerifyResult(status=status, previous_hash="aa", current_hash="bb")


class DecisionTableTests(unittest.TestCase):
    def test_hash_mismatch_with_clean_vt_is_high(self) -> None:
        a = assess(_vt_ok(), _sig(SignatureStatus.HASH_MISMATCH))
        self.assertEqual(a.level, RiskLevel.HIGH)

    def test_vt_not_found_unsigned_is_unknown(self) -> None:
        a = assess(_vt(VTStatus.NOT_FOUND), _sig(SignatureStatus.UNSIGNED))
        self.assertEqual(a.level, RiskLevel.UNKNOWN)

    def test_vt_not_found_valid_signature_is_unknown(self) -> None:
        # A valid signature is NOT malware evidence -> still not enough data.
        a = assess(_vt(VTStatus.NOT_FOUND), _sig(SignatureStatus.SIGNED_VALID))
        self.assertEqual(a.level, RiskLevel.UNKNOWN)

    def test_vt_clean_valid_signature_can_be_low(self) -> None:
        a = assess(_vt_ok(), _sig(SignatureStatus.SIGNED_VALID))
        self.assertEqual(a.level, RiskLevel.LOW)

    def test_single_malicious_is_high(self) -> None:
        self.assertEqual(assess(_vt_ok(malicious=1)).level, RiskLevel.HIGH)

    def test_local_changed_is_high(self) -> None:
        a = assess(_vt_ok(), local_result=_local(LocalVerifyStatus.CHANGED))
        self.assertEqual(a.level, RiskLevel.HIGH)

    def test_no_signal_is_unknown(self) -> None:
        self.assertEqual(assess().level, RiskLevel.UNKNOWN)

    def test_untrusted_signature_is_at_least_medium(self) -> None:
        a = assess(signature_result=_sig(SignatureStatus.UNTRUSTED))
        self.assertIn(a.level, (RiskLevel.MEDIUM, RiskLevel.HIGH))

    def test_local_same_only_is_not_low(self) -> None:
        # No VT verdict + matching local fingerprint + unsigned must not be LOW.
        a = assess(
            _vt(VTStatus.NO_API_KEY),
            _sig(SignatureStatus.UNSIGNED),
            _local(LocalVerifyStatus.SAME),
        )
        self.assertEqual(a.level, RiskLevel.UNKNOWN)

    def test_vt_ok_zero_engines_is_not_low(self) -> None:
        a = assess(_vt_ok(engines=0))
        self.assertEqual(a.level, RiskLevel.UNKNOWN)

    def test_not_applicable_signature_does_not_raise_risk(self) -> None:
        # A .txt-style file whose type can't carry a signature: neutral.
        a = assess(_vt_ok(), _sig(SignatureStatus.NOT_APPLICABLE))
        self.assertEqual(a.level, RiskLevel.LOW)


class PolicyMetadataTests(unittest.TestCase):
    def test_policy_version_in_report(self) -> None:
        self.assertEqual(assess().to_dict()["policy_version"], RISK_POLICY_VERSION)

    def test_evidence_flag_is_separate_from_level(self) -> None:
        self.assertFalse(assess(_vt(VTStatus.NOT_FOUND)).evidence_sufficient)
        self.assertTrue(assess(_vt_ok()).evidence_sufficient)

    def test_score_is_clamped(self) -> None:
        a = assess(
            _vt_ok(malicious=15),
            _sig(SignatureStatus.HASH_MISMATCH),
            _local(LocalVerifyStatus.CHANGED),
        )
        self.assertLessEqual(a.score, SCORE_MAX)
        self.assertGreaterEqual(a.score, SCORE_MIN)


if __name__ == "__main__":
    unittest.main()
