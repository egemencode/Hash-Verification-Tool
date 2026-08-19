"""
Lightweight sanity checks for the summary builder.

The builder returns phrase keys, not prose, so these assert on which sentence
was chosen. That is the stronger claim: a key names the decision, while a
substring only records that some wording happened to contain a word.
"""

from __future__ import annotations

import unittest

from core.local_verify import LocalVerifyResult, LocalVerifyStatus
from core.risk_engine import assess
from core.signature_checker import SignatureResult, SignatureStatus
from core.smart_summary import build_summary
from core.vt_client import VTAnalysisStats, VTLookupResult, VTStatus


def _vt(stats: VTAnalysisStats, status: VTStatus = VTStatus.OK) -> VTLookupResult:
    return VTLookupResult(status=status, hash_value="a" * 64, stats=stats, total_engines=70, analysing_engines=70)


class SmartSummaryTests(unittest.TestCase):
    def test_summary_contains_headline_and_advice(self) -> None:
        vt = _vt(VTAnalysisStats(malicious=0, suspicious=0, harmless=70))
        sig = SignatureResult(status=SignatureStatus.SIGNED_VALID, signer="Microsoft Corp")
        assessment = assess(vt_result=vt, signature_result=sig)
        summary = build_summary(assessment, vt=vt, sig=sig)
        self.assertTrue(summary.headline)
        self.assertTrue(summary.advice)
        self.assertTrue(summary.bullets, "the summary said nothing at all")

    def test_malicious_is_called_out(self) -> None:
        vt = _vt(VTAnalysisStats(malicious=5, suspicious=0))
        summary = build_summary(assess(vt_result=vt), vt=vt)
        malicious = [b for b in summary.bullets if b.key == "summary.vt.malicious"]
        self.assertEqual(len(malicious), 1, f"bullets were: {summary.bullets}")
        # The count travels with the sentence rather than being baked into it,
        # so a translation cannot lose it by rewording.
        self.assertEqual(malicious[0].params.get("count"), 5)

    def test_changed_local_record_appears_in_bullets(self) -> None:
        local = LocalVerifyResult(status=LocalVerifyStatus.CHANGED,
                                  previous_hash="x", current_hash="y")
        assessment = assess(local_result=local)
        summary = build_summary(assessment, local=local)
        self.assertIn(
            "summary.local.changed", [b.key for b in summary.bullets],
            f"bullets were: {summary.bullets}",
        )


if __name__ == "__main__":
    unittest.main()
