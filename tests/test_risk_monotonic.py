"""
P0.4 — the risk model must be monotonic in the security direction.

Invariants:
  * ``malicious >= 1``  → at least HIGH
  * ``suspicious >= 1`` → at least MEDIUM
  * A valid signature or a matching local fingerprint provides *context*;
    it can never cancel out an engine detection.
  * Negative / non-numeric / missing engine counters make the stats
    malformed — they must not be laundered into "clean" evidence.
  * Risk level and evidence sufficiency are separate fields.
  * LOW requires a documented minimum number of engines.
"""

from __future__ import annotations

import unittest

from core.local_verify import LocalVerifyResult, LocalVerifyStatus
from core.risk_engine import (
    MIN_ENGINES_FOR_LOW,
    RiskLevel,
    assess,
)
from core.signature_checker import SignatureResult, SignatureStatus
from core.vt_client import VTAnalysisStats, VTLookupResult, VTStatus

NOW = 2_000_000_000
_ORDER = {RiskLevel.UNKNOWN: 0, RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3}


def _vt(malicious=0, suspicious=0, harmless=0, undetected=0, fresh=True):
    total = malicious + suspicious + harmless + undetected
    return VTLookupResult(
        status=VTStatus.OK,
        hash_value="a" * 64,
        stats=VTAnalysisStats(
            malicious=malicious, suspicious=suspicious,
            harmless=harmless, undetected=undetected,
        ),
        total_engines=total,
        analysing_engines=total,
        last_analysis_epoch=NOW - 3600,
        freshness_unknown=not fresh,
    )


def _sig(status): return SignatureResult(status=status)
def _local(status): return LocalVerifyResult(status=status, current_hash="b" * 64)


def _at_least(level: RiskLevel, floor: RiskLevel) -> bool:
    return _ORDER[level] >= _ORDER[floor]


class MaliciousFloorTests(unittest.TestCase):
    def test_single_malicious_is_high_regardless_of_context(self) -> None:
        combos = [
            (None, None),
            (_sig(SignatureStatus.SIGNED_VALID), None),
            (_sig(SignatureStatus.SIGNED_VALID), _local(LocalVerifyStatus.SAME)),
            (None, _local(LocalVerifyStatus.SAME)),
        ]
        for sig, local in combos:
            with self.subTest(sig=sig, local=local):
                a = assess(_vt(malicious=1, harmless=69), sig, local)
                self.assertEqual(a.level, RiskLevel.HIGH)

    def test_many_positives_cannot_be_offset(self) -> None:
        a = assess(
            _vt(malicious=10, harmless=60),
            _sig(SignatureStatus.SIGNED_VALID),
            _local(LocalVerifyStatus.SAME),
        )
        self.assertEqual(a.level, RiskLevel.HIGH)


class SuspiciousFloorTests(unittest.TestCase):
    def test_one_suspicious_among_many_clean_is_at_least_medium(self) -> None:
        # The exact case called out in the audit: 1 suspicious + 69 undetected.
        a = assess(_vt(suspicious=1, undetected=69))
        self.assertTrue(
            _at_least(a.level, RiskLevel.MEDIUM),
            f"expected >= MEDIUM, got {a.level}",
        )

    def test_suspicious_cannot_be_cancelled_by_signature(self) -> None:
        a = assess(_vt(suspicious=1, undetected=69), _sig(SignatureStatus.SIGNED_VALID))
        self.assertTrue(_at_least(a.level, RiskLevel.MEDIUM), a.level)

    def test_suspicious_cannot_be_cancelled_by_local_match(self) -> None:
        a = assess(
            _vt(suspicious=1, undetected=69),
            _sig(SignatureStatus.SIGNED_VALID),
            _local(LocalVerifyStatus.SAME),
        )
        self.assertTrue(_at_least(a.level, RiskLevel.MEDIUM), a.level)

    def test_adding_a_detection_never_lowers_the_level(self) -> None:
        base = assess(_vt(undetected=70)).level
        worse = assess(_vt(suspicious=1, undetected=69)).level
        worst = assess(_vt(malicious=1, undetected=69)).level
        self.assertTrue(_ORDER[worse] >= _ORDER[base])
        self.assertTrue(_ORDER[worst] >= _ORDER[worse])


class MalformedCountersTests(unittest.TestCase):
    def _raw(self, **stats) -> VTLookupResult:
        return VTLookupResult(
            status=VTStatus.OK,
            hash_value="a" * 64,
            stats=VTAnalysisStats(**stats),
            total_engines=sum(v for v in stats.values() if isinstance(v, int) and v > 0),
            last_analysis_epoch=NOW - 60,
        )

    def test_negative_counter_is_not_clean_evidence(self) -> None:
        result = self._raw(malicious=-3, harmless=70)
        result.stats_malformed = True   # what the client must flag
        a = assess(result)
        self.assertFalse(a.evidence_sufficient)
        self.assertNotEqual(a.level, RiskLevel.LOW)

    def test_malformed_flag_blocks_low(self) -> None:
        result = _vt(undetected=70)
        result.stats_malformed = True
        a = assess(result)
        self.assertNotEqual(a.level, RiskLevel.LOW)


class EvidenceThresholdTests(unittest.TestCase):
    def test_low_requires_minimum_engine_count(self) -> None:
        too_few = assess(_vt(undetected=MIN_ENGINES_FOR_LOW - 1))
        self.assertNotEqual(too_few.level, RiskLevel.LOW)
        self.assertFalse(too_few.evidence_sufficient)

        enough = assess(_vt(undetected=MIN_ENGINES_FOR_LOW))
        self.assertEqual(enough.level, RiskLevel.LOW)
        self.assertTrue(enough.evidence_sufficient)

    def test_stale_result_cannot_be_low(self) -> None:
        stale = _vt(undetected=70)
        stale.is_stale = True
        self.assertNotEqual(assess(stale).level, RiskLevel.LOW)

    def test_undated_result_cannot_be_low(self) -> None:
        self.assertNotEqual(assess(_vt(undetected=70, fresh=False)).level, RiskLevel.LOW)

    def test_zero_engine_result_cannot_be_low(self) -> None:
        self.assertNotEqual(assess(_vt()).level, RiskLevel.LOW)

    def test_risk_and_confidence_are_separate_fields(self) -> None:
        a = assess(_vt(malicious=5, harmless=65))
        self.assertEqual(a.level, RiskLevel.HIGH)
        # A detection is a usable verdict: high risk WITH sufficient evidence.
        self.assertTrue(a.evidence_sufficient)

        b = assess(VTLookupResult(status=VTStatus.NOT_FOUND, hash_value="a" * 64))
        self.assertEqual(b.level, RiskLevel.UNKNOWN)
        self.assertFalse(b.evidence_sufficient)


class LocalFingerprintIsNotATrustRootTests(unittest.TestCase):
    def test_local_match_alone_never_reaches_low(self) -> None:
        a = assess(None, None, _local(LocalVerifyStatus.SAME))
        self.assertEqual(a.level, RiskLevel.UNKNOWN)

    def test_local_match_does_not_reduce_a_detection(self) -> None:
        with_local = assess(_vt(suspicious=3, undetected=67), None,
                            _local(LocalVerifyStatus.SAME)).level
        without = assess(_vt(suspicious=3, undetected=67)).level
        self.assertTrue(_ORDER[with_local] >= _ORDER[without])


if __name__ == "__main__":
    unittest.main()
