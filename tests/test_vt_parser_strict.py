"""
RT#4 — malformed engine counters must never become a clean verdict.

Every test here drives the **real chain**: raw HTTP JSON body ->
VirusTotalClient.lookup_hash -> VTLookupResult -> assess(). No flag is set by
hand, because the previous suite did exactly that and so never exercised the
parser that was actually broken.
"""

from __future__ import annotations

import unittest
from unittest import mock

from core import vt_client
from core.risk_engine import RiskLevel, assess
from core.vt_client import RateLimiter, TTLCache, VirusTotalClient

NOW = 2_000_000_000
_ORDER = {RiskLevel.UNKNOWN: 0, RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3}


def _client():
    return VirusTotalClient(
        api_key="k",
        rate_limiter=RateLimiter(max_calls=10_000, period=1.0),
        cache=TTLCache(ttl=0),
        now=lambda: NOW,
    )


def _lookup(stats, *, date=NOW - 3600):
    """Run a raw VT body through the real client."""
    attributes = {"last_analysis_stats": stats}
    if date is not None:
        attributes["last_analysis_date"] = date
    body = {"data": {"attributes": attributes}}

    def transport(url, headers, timeout):
        return 200, body, {}

    with mock.patch.object(vt_client, "_http_get", transport):
        return _client().lookup_hash("a" * 64)


class MalformedCounterTests(unittest.TestCase):
    """The exact inputs from the independent reproduction."""

    def test_negative_malicious_is_malformed_not_clean(self) -> None:
        result = _lookup({"malicious": -3, "undetected": 70})
        self.assertTrue(result.stats_malformed, "a negative counter was accepted")
        a = assess(result)
        self.assertFalse(a.evidence_sufficient)
        self.assertNotEqual(a.level, RiskLevel.LOW)

    def test_string_malicious_is_malformed_not_clean(self) -> None:
        result = _lookup({"malicious": "lots", "undetected": 70})
        self.assertTrue(result.stats_malformed)
        a = assess(result)
        self.assertFalse(a.evidence_sufficient)
        self.assertNotEqual(a.level, RiskLevel.LOW)

    def test_boolean_counter_is_malformed(self) -> None:
        result = _lookup({"malicious": True, "undetected": 70})
        self.assertTrue(result.stats_malformed)
        self.assertNotEqual(assess(result).level, RiskLevel.LOW)

    def test_fractional_counter_is_malformed(self) -> None:
        result = _lookup({"malicious": 0.5, "undetected": 70})
        self.assertTrue(result.stats_malformed)
        self.assertNotEqual(assess(result).level, RiskLevel.LOW)

    def test_missing_required_counter_is_malformed(self) -> None:
        # No 'malicious' key at all: we cannot claim "zero detections".
        result = _lookup({"undetected": 70})
        self.assertTrue(result.stats_malformed)
        self.assertNotEqual(assess(result).level, RiskLevel.LOW)

    def test_stats_not_an_object_is_malformed(self) -> None:
        result = _lookup("not-an-object")
        self.assertTrue(result.stats_malformed)
        self.assertNotEqual(assess(result).level, RiskLevel.LOW)


class NonAnalysingEnginesTests(unittest.TestCase):
    """timeout / failure / unsupported engines did not analyse anything."""

    def test_only_timeouts_is_not_low(self) -> None:
        result = _lookup(
            {"malicious": 0, "suspicious": 0, "harmless": 0,
             "undetected": 0, "timeout": 70}
        )
        self.assertEqual(result.analysing_engines, 0)
        a = assess(result)
        self.assertNotEqual(a.level, RiskLevel.LOW)
        self.assertFalse(a.evidence_sufficient)

    def test_small_timeout_count_does_not_pad_the_quorum(self) -> None:
        # 5 real verdicts + 10 timeouts must not reach a 10-engine quorum.
        result = _lookup(
            {"malicious": 0, "suspicious": 0, "harmless": 5,
             "undetected": 0, "timeout": 10}
        )
        self.assertEqual(result.analysing_engines, 5)
        self.assertNotEqual(assess(result).level, RiskLevel.LOW)

    def test_failure_and_unsupported_are_excluded(self) -> None:
        result = _lookup(
            {"malicious": 0, "suspicious": 0, "harmless": 4, "undetected": 0,
             "timeout": 0, "failure": 30, "type-unsupported": 40}
        )
        self.assertEqual(result.analysing_engines, 4)
        self.assertNotEqual(assess(result).level, RiskLevel.LOW)

    def test_enough_real_verdicts_can_be_low(self) -> None:
        result = _lookup(
            {"malicious": 0, "suspicious": 0, "harmless": 40,
             "undetected": 30, "timeout": 5}
        )
        self.assertEqual(result.analysing_engines, 70)
        a = assess(result)
        self.assertEqual(a.level, RiskLevel.LOW)
        self.assertTrue(a.evidence_sufficient)


class DetectionSurvivesMalformationTests(unittest.TestCase):
    """A real detection must not be lost because another field is broken."""

    def test_malicious_with_a_broken_sibling_is_still_high(self) -> None:
        result = _lookup({"malicious": 3, "undetected": "?", "harmless": 60})
        self.assertEqual(assess(result).level, RiskLevel.HIGH)

    def test_suspicious_with_a_broken_sibling_is_at_least_medium(self) -> None:
        result = _lookup({"suspicious": 2, "undetected": None, "harmless": 60})
        level = assess(result).level
        self.assertGreaterEqual(
            _ORDER[level], _ORDER[RiskLevel.MEDIUM], f"got {level}"
        )

    def test_malicious_with_negative_sibling_is_still_high(self) -> None:
        result = _lookup({"malicious": 1, "harmless": -5, "undetected": 60})
        self.assertEqual(assess(result).level, RiskLevel.HIGH)


if __name__ == "__main__":
    unittest.main()
