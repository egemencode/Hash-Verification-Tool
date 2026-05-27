"""Smoke tests for the risk-scoring engine."""

from __future__ import annotations

import unittest

from core.local_verify import LocalVerifyResult, LocalVerifyStatus
from core.risk_engine import RiskLevel, assess
from core.signature_checker import SignatureResult, SignatureStatus
from core.vt_client import VTAnalysisStats, VTLookupResult, VTStatus


def _vt_ok(malicious: int = 0, suspicious: int = 0) -> VTLookupResult:
    return VTLookupResult(
        status=VTStatus.OK,
        hash_value="x" * 64,
        stats=VTAnalysisStats(malicious=malicious, suspicious=suspicious, harmless=70),
        total_engines=70,
        message="ok",
    )


class RiskEngineTests(unittest.TestCase):
    def test_clean_vt_plus_valid_signature_is_low(self) -> None:
        result = assess(
            vt_result=_vt_ok(),
            signature_result=SignatureResult(
                status=SignatureStatus.SIGNED_VALID, signer="Microsoft"
            ),
            local_result=None,
        )
        self.assertEqual(result.level, RiskLevel.LOW)

    def test_single_malicious_hit_is_high(self) -> None:
        result = assess(
            vt_result=_vt_ok(malicious=1),
            signature_result=SignatureResult(status=SignatureStatus.SIGNED_VALID),
            local_result=None,
        )
        self.assertEqual(result.level, RiskLevel.HIGH)

    def test_many_malicious_hits_are_high(self) -> None:
        result = assess(
            vt_result=_vt_ok(malicious=15),
            signature_result=None,
            local_result=None,
        )
        self.assertEqual(result.level, RiskLevel.HIGH)

    def test_changed_local_is_high_even_when_vt_clean(self) -> None:
        result = assess(
            vt_result=_vt_ok(),
            signature_result=None,
            local_result=LocalVerifyResult(
                status=LocalVerifyStatus.CHANGED,
                previous_hash="aa",
                current_hash="bb",
            ),
        )
        self.assertEqual(result.level, RiskLevel.HIGH)

    def test_unknown_when_no_signals(self) -> None:
        result = assess(
            vt_result=VTLookupResult(status=VTStatus.NO_API_KEY),
            signature_result=SignatureResult(status=SignatureStatus.UNSUPPORTED),
            local_result=None,
        )
        self.assertEqual(result.level, RiskLevel.UNKNOWN)

    def test_factors_are_explainable(self) -> None:
        # The audit list should always carry a row for each provided
        # signal so the UI can render "why" without consulting the
        # numeric score.
        result = assess(
            vt_result=_vt_ok(malicious=2),
            signature_result=SignatureResult(status=SignatureStatus.UNSIGNED),
            local_result=None,
        )
        labels = [f.label for f in result.factors]
        self.assertIn("VirusTotal", labels)
        self.assertIn("Dijital İmza", labels)


if __name__ == "__main__":
    unittest.main()
