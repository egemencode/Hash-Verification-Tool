"""
Red-team round 2 — core defects (#5 #6 #7 #8).

Each test drives the real chain (raw JSON / real files / real manifest I/O)
and asserts a user-observable outcome.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest import mock

from tests.support import DiagnosticTempDir
from core import vt_client, verifier as verifier_mod
from core.manifest_manager import (
    Manifest,
    ManifestError,
    build_manifest_for_folder,
)
from core.risk_engine import RiskLevel, assess
from core.smart_summary import build_summary
from core.verifier import Verifier
from core.vt_client import RateLimiter, TTLCache, VirusTotalClient

NOW = 2_000_000_000


# ======================================================================
# 5 — every known counter must be validated strictly
# ======================================================================
def _lookup(stats, *, date=NOW - 3600):
    attributes = {"last_analysis_stats": stats}
    if date is not None:
        attributes["last_analysis_date"] = date
    body = {"data": {"attributes": attributes}}

    def transport(url, headers, timeout):
        return 200, body, {}

    client = VirusTotalClient(
        api_key="k",
        rate_limiter=RateLimiter(max_calls=10_000, period=1.0),
        cache=TTLCache(ttl=0),
        now=lambda: NOW,
    )
    with mock.patch.object(vt_client, "_http_get", transport):
        return client.lookup_hash("a" * 64)


def _clean_stats(**overrides):
    stats = {
        "malicious": 0, "suspicious": 0, "harmless": 70,
        "undetected": 0, "timeout": 0,
    }
    stats.update(overrides)
    return stats


class AllCountersStrictTests(unittest.TestCase):
    """The reported values that still slipped through as clean."""

    def test_negative_timeout_is_malformed(self) -> None:
        r = _lookup(_clean_stats(timeout=-1))
        self.assertTrue(r.stats_malformed, "timeout=-1 was accepted")
        self.assertNotEqual(assess(r).level, RiskLevel.LOW)

    def test_string_failure_is_malformed(self) -> None:
        r = _lookup(_clean_stats(failure="oops"))
        self.assertTrue(r.stats_malformed, 'failure="oops" was accepted')
        self.assertNotEqual(assess(r).level, RiskLevel.LOW)

    def test_boolean_type_unsupported_is_malformed(self) -> None:
        r = _lookup(_clean_stats(**{"type-unsupported": True}))
        self.assertTrue(r.stats_malformed, "type-unsupported=true was accepted")
        self.assertNotEqual(assess(r).level, RiskLevel.LOW)

    def test_float_confirmed_timeout_is_malformed(self) -> None:
        r = _lookup(_clean_stats(**{"confirmed-timeout": 1.5}))
        self.assertTrue(r.stats_malformed, "confirmed-timeout=1.5 was accepted")
        self.assertNotEqual(assess(r).level, RiskLevel.LOW)

    def test_null_counter_is_malformed(self) -> None:
        r = _lookup(_clean_stats(timeout=None))
        self.assertTrue(r.stats_malformed)

    def test_all_valid_counters_still_low(self) -> None:
        r = _lookup(_clean_stats(timeout=3, failure=1))
        self.assertFalse(r.stats_malformed)
        self.assertEqual(assess(r).level, RiskLevel.LOW)

    def test_detection_survives_malformed_sibling(self) -> None:
        r = _lookup(_clean_stats(malicious=2, timeout=-5))
        self.assertTrue(r.stats_malformed)
        self.assertEqual(assess(r).level, RiskLevel.HIGH)


class SummaryUsesAnalysingEnginesTests(unittest.TestCase):
    """A timeout-only answer must not be narrated as 'no engine flagged it'."""

    def test_timeout_only_does_not_claim_no_detections(self) -> None:
        r = _lookup({"malicious": 0, "suspicious": 0, "harmless": 0,
                     "undetected": 0, "timeout": 70})
        summary = build_summary(assess(r), vt=r)
        text = " ".join(summary.bullets)
        self.assertNotIn("zararlı veya şüpheli işareti gelmedi", text)
        self.assertIn("motor", text.lower())

    def test_real_clean_result_still_says_no_detections(self) -> None:
        r = _lookup(_clean_stats())
        text = " ".join(build_summary(assess(r), vt=r).bullets)
        self.assertIn("zararlı veya şüpheli işareti gelmedi", text)


# ======================================================================
# 6 — an inventory must be taken AFTER the final re-hash
# ======================================================================
class InventoryAfterRehashTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        (self.data / "a.bin").write_bytes(b"AAAA")
        self.manifest = build_manifest_for_folder(self.data).manifest

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_file_added_after_the_second_inventory_is_caught(self) -> None:
        real = verifier_mod.snapshot_inventory
        calls = {"n": 0}

        def hooked(*args, **kwargs):
            result = real(*args, **kwargs)
            calls["n"] += 1
            if calls["n"] == 2:          # right after the mid-scan inventory
                (self.data / "late.txt").write_text("late", encoding="utf-8")
            return result

        with mock.patch.object(verifier_mod, "snapshot_inventory", hooked):
            result = Verifier(self.manifest).verify(self.data)

        self.assertTrue((self.data / "late.txt").exists())
        self.assertGreaterEqual(calls["n"], 3, "no inventory was taken after the re-hash")
        self.assertFalse(result.scan_complete, "a late addition was not detected")
        self.assertFalse(result.is_clean)

    def test_untouched_tree_still_clean(self) -> None:
        result = Verifier(self.manifest).verify(self.data)
        self.assertTrue(result.is_clean, result.summary())


# ======================================================================
# 7 — 'complete' must be a real boolean, with cross-field invariants
# ======================================================================
class CompleteFieldTypeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        (self.data / "a.txt").write_text("a", encoding="utf-8")
        self.path = self.root / "m.json"
        build_manifest_for_folder(self.data).save(self.path)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _rewrite(self, mutate):
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        mutate(raw)
        self.path.write_text(json.dumps(raw), encoding="utf-8")

    def test_string_false_is_rejected(self) -> None:
        self._rewrite(lambda raw: raw["metadata"].__setitem__("complete", "false"))
        with self.assertRaises(ManifestError):
            Manifest.load(self.path)

    def test_string_true_is_rejected(self) -> None:
        self._rewrite(lambda raw: raw["metadata"].__setitem__("complete", "true"))
        with self.assertRaises(ManifestError):
            Manifest.load(self.path)

    def test_number_is_rejected(self) -> None:
        self._rewrite(lambda raw: raw["metadata"].__setitem__("complete", 1))
        with self.assertRaises(ManifestError):
            Manifest.load(self.path)

    def test_null_and_containers_are_rejected(self) -> None:
        for bad in (None, [], {}):
            with self.subTest(value=bad):
                self._rewrite(lambda raw, b=bad: raw["metadata"].__setitem__("complete", b))
                with self.assertRaises(ManifestError):
                    Manifest.load(self.path)

    def test_complete_true_with_skipped_entries_is_rejected(self) -> None:
        def tamper(raw):
            raw["metadata"]["complete"] = True
            raw["metadata"]["skipped"] = ["hidden.bin"]
            raw["metadata"]["skipped_count"] = 1

        self._rewrite(tamper)
        with self.assertRaises(ManifestError):
            Manifest.load(self.path)

    def test_count_must_match_the_list(self) -> None:
        def tamper(raw):
            raw["metadata"]["complete"] = False
            raw["metadata"]["skipped"] = ["a", "b"]
            raw["metadata"]["skipped_count"] = 99

        self._rewrite(tamper)
        with self.assertRaises(ManifestError):
            Manifest.load(self.path, allow_incomplete=True)

    def test_missing_complete_in_current_schema_is_rejected(self) -> None:
        self._rewrite(lambda raw: raw["metadata"].pop("complete", None))
        with self.assertRaises(ManifestError):
            Manifest.load(self.path)

    def test_string_false_cannot_be_signed_or_verified(self) -> None:
        self._rewrite(lambda raw: raw["metadata"].__setitem__("complete", "false"))
        with self.assertRaises(ManifestError):
            Manifest.load(self.path, allow_incomplete=True)


# ======================================================================
# 8 — the typed outcome must reach consumers
# ======================================================================
class TypedOutcomeExportedTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        (self.data / "a.txt").write_text("a", encoding="utf-8")
        self.path = self.root / "m.json"
        build_manifest_for_folder(self.data).save(self.path)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_to_dict_exposes_every_typed_field(self) -> None:
        result = Verifier(Manifest.load(self.path)).verify(self.data)
        payload = result.to_dict()
        for key in (
            "files_match", "scan_complete", "reference_trusted",
            "trusted_match", "policy_accepted", "changed_during_scan",
            "manifest_signature",
        ):
            self.assertIn(key, payload, f"{key} missing from the JSON report")

    def test_typed_values_are_consistent(self) -> None:
        result = Verifier(Manifest.load(self.path)).verify(self.data)
        payload = result.to_dict()
        self.assertIs(payload["files_match"], True)
        self.assertIs(payload["scan_complete"], True)
        self.assertIs(payload["reference_trusted"], False)   # unsigned
        self.assertIs(payload["trusted_match"], False)

    def test_is_clean_never_implies_trusted(self) -> None:
        result = Verifier(Manifest.load(self.path)).verify(self.data)
        self.assertTrue(result.is_clean)
        self.assertFalse(
            result.reference_trusted,
            "is_clean must not be read as 'reference trusted'",
        )


if __name__ == "__main__":
    unittest.main()
