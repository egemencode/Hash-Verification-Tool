"""
Blocker 3 regression suite: a VirusTotal answer whose freshness cannot be
established must never become positive "clean" evidence.

The headline case: 70 engines, zero detections, **no analysis date** — this
previously produced LOW + evidence_sufficient, i.e. the UI reassured the user
about a verdict that could have been years old or forged.
"""

from __future__ import annotations

import unittest
from unittest import mock

from core import vt_client
from core.risk_engine import RiskLevel, assess
from core.smart_summary import build_summary
from core.vt_client import (
    RateLimiter,
    STALE_AFTER_SECONDS,
    TTLCache,
    VirusTotalClient,
    VTStatus,
)

NOW = 2_000_000_000


def _transport(status, body=None, headers=None):
    def _get(url, hdrs, timeout):
        return status, (body or {}), (headers or {})

    return _get


def _client():
    return VirusTotalClient(
        api_key="k",
        rate_limiter=RateLimiter(max_calls=10_000, period=1.0),
        cache=TTLCache(ttl=0),  # never serve a cached copy between tests
        now=lambda: NOW,
    )


def _lookup(attributes: dict):
    body = {"data": {"attributes": attributes}}
    with mock.patch.object(vt_client, "_http_get", _transport(200, body)):
        return _client().lookup_hash("a" * 64)


def _stats(malicious=0, suspicious=0, harmless=0, undetected=0, timeout=0):
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": timeout,
    }


class FreshnessTests(unittest.TestCase):
    def test_missing_date_is_not_fresh(self) -> None:
        r = _lookup({"last_analysis_stats": _stats(undetected=70)})
        self.assertTrue(r.freshness_unknown)
        self.assertFalse(r.is_fresh)
        self.assertFalse(r.is_usable_verdict)

    def test_invalid_date_is_not_fresh(self) -> None:
        for bad in ("yesterday", None, {}, [], True):
            with self.subTest(value=bad):
                r = _lookup(
                    {"last_analysis_stats": _stats(undetected=70), "last_analysis_date": bad}
                )
                self.assertTrue(r.freshness_unknown)

    def test_future_date_is_not_fresh(self) -> None:
        r = _lookup(
            {
                "last_analysis_stats": _stats(undetected=70),
                "last_analysis_date": NOW + 86_400,
            }
        )
        self.assertTrue(r.freshness_unknown)

    def test_recent_date_is_fresh(self) -> None:
        r = _lookup(
            {"last_analysis_stats": _stats(harmless=70), "last_analysis_date": NOW - 3600}
        )
        self.assertTrue(r.is_fresh)
        self.assertTrue(r.is_usable_verdict)
        self.assertTrue(r.is_clean_evidence)

    def test_old_date_is_stale_not_unknown(self) -> None:
        r = _lookup(
            {
                "last_analysis_stats": _stats(harmless=70),
                "last_analysis_date": NOW - (STALE_AFTER_SECONDS + 10),
            }
        )
        self.assertTrue(r.is_stale)
        self.assertFalse(r.freshness_unknown)
        self.assertFalse(r.is_clean_evidence)


class RiskIntegrationTests(unittest.TestCase):
    def test_undated_70_undetected_is_not_low_with_evidence(self) -> None:
        """The mandated headline test for this blocker."""
        r = _lookup({"last_analysis_stats": _stats(undetected=70)})
        assessment = assess(vt_result=r)
        self.assertFalse(assessment.evidence_sufficient)
        self.assertNotEqual(assessment.level, RiskLevel.LOW)
        self.assertEqual(assessment.level, RiskLevel.UNKNOWN)

    def test_dated_clean_result_can_be_low(self) -> None:
        r = _lookup(
            {"last_analysis_stats": _stats(harmless=70), "last_analysis_date": NOW - 3600}
        )
        assessment = assess(vt_result=r)
        self.assertTrue(assessment.evidence_sufficient)
        self.assertEqual(assessment.level, RiskLevel.LOW)

    def test_stale_malicious_still_high(self) -> None:
        # A stale detection is still a detection — age must not hide it.
        r = _lookup(
            {
                "last_analysis_stats": _stats(malicious=8, harmless=60),
                "last_analysis_date": NOW - (STALE_AFTER_SECONDS + 10),
            }
        )
        self.assertEqual(assess(vt_result=r).level, RiskLevel.HIGH)

    def test_undated_malicious_still_high(self) -> None:
        r = _lookup({"last_analysis_stats": _stats(malicious=3, harmless=60)})
        self.assertEqual(assess(vt_result=r).level, RiskLevel.HIGH)

    def test_malformed_stats_not_clean_evidence(self) -> None:
        r = _lookup({"last_analysis_stats": "not-an-object", "last_analysis_date": NOW - 60})
        self.assertTrue(r.stats_malformed)
        self.assertFalse(r.is_clean_evidence)
        self.assertNotEqual(assess(vt_result=r).level, RiskLevel.LOW)

    def test_undated_summary_does_not_reassure(self) -> None:
        r = _lookup({"last_analysis_stats": _stats(undetected=70)})
        summary = build_summary(assess(vt_result=r), vt=r)
        text = " ".join(summary.bullets).lower()
        # It must qualify the result rather than presenting a bare "no flags".
        self.assertTrue(
            ("belirsiz" in text) or ("eski" in text) or ("güncel" in text),
            f"bullets were: {summary.bullets}",
        )


class SanitisationTests(unittest.TestCase):
    def test_negative_counters_clamped_to_zero(self) -> None:
        r = _lookup(
            {
                "last_analysis_stats": _stats(malicious=-5, harmless=-2, undetected=70),
                "last_analysis_date": NOW - 60,
            }
        )
        self.assertEqual(r.stats.malicious, 0)
        self.assertEqual(r.stats.harmless, 0)
        self.assertGreaterEqual(r.total_engines, 0)

    def test_non_numeric_counters_become_zero(self) -> None:
        r = _lookup(
            {
                "last_analysis_stats": {"malicious": "lots", "harmless": {"a": 1}},
                "last_analysis_date": NOW - 60,
            }
        )
        self.assertEqual(r.stats.malicious, 0)
        self.assertEqual(r.stats.harmless, 0)

    def test_text_fields_reject_containers(self) -> None:
        r = _lookup(
            {
                "last_analysis_stats": _stats(harmless=70),
                "last_analysis_date": NOW - 60,
                "meaningful_name": {"evil": "dict"},
                "type_description": ["a", "list"],
            }
        )
        self.assertIsNone(r.meaningful_name)
        self.assertIsNone(r.type_description)

    def test_text_fields_keep_real_strings(self) -> None:
        r = _lookup(
            {
                "last_analysis_stats": _stats(harmless=70),
                "last_analysis_date": NOW - 60,
                "meaningful_name": "setup.exe",
            }
        )
        self.assertEqual(r.meaningful_name, "setup.exe")

    def test_non_clean_statuses_are_never_evidence(self) -> None:
        for status in (
            VTStatus.NOT_FOUND,
            VTStatus.NO_API_KEY,
            VTStatus.UNAUTHORIZED,
            VTStatus.RATE_LIMITED,
            VTStatus.NETWORK_ERROR,
            VTStatus.ERROR,
        ):
            with self.subTest(status=status):
                from core.vt_client import VTLookupResult

                r = VTLookupResult(status=status, hash_value="a" * 64)
                self.assertFalse(r.is_usable_verdict)
                self.assertFalse(assess(vt_result=r).evidence_sufficient)


if __name__ == "__main__":
    unittest.main()
