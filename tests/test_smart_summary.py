"""Lightweight sanity checks for the Turkish summary builder."""

from __future__ import annotations

import unittest

from core.local_verify import LocalVerifyResult, LocalVerifyStatus
from core.risk_engine import assess
from core.signature_checker import SignatureResult, SignatureStatus
from core.smart_summary import build_summary
from core.vt_client import VTAnalysisStats, VTLookupResult, VTStatus


def _vt(stats: VTAnalysisStats, status: VTStatus = VTStatus.OK) -> VTLookupResult:
    return VTLookupResult(status=status, hash_value="a" * 64, stats=stats, total_engines=70)


class SmartSummaryTests(unittest.TestCase):
    def test_summary_contains_headline_and_advice(self) -> None:
        vt = _vt(VTAnalysisStats(malicious=0, suspicious=0, harmless=70))
        sig = SignatureResult(status=SignatureStatus.SIGNED_VALID, signer="Microsoft Corp")
        assessment = assess(vt_result=vt, signature_result=sig)
        summary = build_summary(assessment, vt=vt, sig=sig)
        self.assertTrue(summary.headline)
        self.assertTrue(summary.advice)
        text = summary.as_text()
        self.assertIn("•", text)

    def test_malicious_is_called_out(self) -> None:
        vt = _vt(VTAnalysisStats(malicious=5, suspicious=0))
        assessment = assess(vt_result=vt)
        summary = build_summary(assessment, vt=vt)
        text = summary.as_text().lower()
        self.assertIn("zararlı", text)

    def test_changed_local_record_appears_in_bullets(self) -> None:
        local = LocalVerifyResult(status=LocalVerifyStatus.CHANGED,
                                  previous_hash="x", current_hash="y")
        assessment = assess(local_result=local)
        summary = build_summary(assessment, local=local)
        self.assertTrue(
            any("farklı" in b.lower() for b in summary.bullets),
            f"bullets were: {summary.bullets}",
        )


if __name__ == "__main__":
    unittest.main()
