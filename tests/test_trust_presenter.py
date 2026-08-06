"""
Presenter regression suite: the *wording* the user sees for manifest trust.

The rule under test: matching files must never be reported as an unqualified
"clean" result when the manifest's provenance was not established.
"""

from __future__ import annotations

import unittest

from core.manifest_manager import SignatureState
from core.verifier import ErrorEntry, ModifiedEntry, VerificationResult
from gui.trust_presenter import (
    SEV_BAD,
    SEV_GOOD,
    SEV_WARN,
    collect_startup_warnings,
    describe_result,
    trust_badge,
    verification_headline,
)

ALL_STATES = (
    SignatureState.UNSIGNED,
    SignatureState.VALID_EMBEDDED,
    SignatureState.TRUSTED,
    SignatureState.INVALID,
)


def _result(state: SignatureState, *, dirty: bool = False) -> VerificationResult:
    r = VerificationResult(folder="C:/x", algorithm="sha256", signature_state=state)
    r.unchanged.append("a.txt")
    if dirty:
        r.modified.append(
            ModifiedEntry(path="b.txt", old_hash="a", new_hash="b", old_size=1, new_size=2)
        )
    return r


class BadgeTests(unittest.TestCase):
    def test_every_state_has_distinct_wording(self) -> None:
        labels = {trust_badge(s).label for s in ALL_STATES}
        self.assertEqual(len(labels), 4, "each state needs its own label")

    def test_states_are_not_conveyed_by_colour_alone(self) -> None:
        for state in ALL_STATES:
            badge = trust_badge(state)
            self.assertTrue(badge.icon, f"{state} has no icon")
            self.assertTrue(badge.label, f"{state} has no label")
            self.assertTrue(badge.detail, f"{state} has no explanation")

    def test_provenance_only_established_for_trusted(self) -> None:
        self.assertTrue(trust_badge(SignatureState.TRUSTED).provenance_established)
        for state in (
            SignatureState.UNSIGNED,
            SignatureState.VALID_EMBEDDED,
            SignatureState.INVALID,
        ):
            self.assertFalse(trust_badge(state).provenance_established, state)

    def test_severities(self) -> None:
        self.assertEqual(trust_badge(SignatureState.TRUSTED).severity, SEV_GOOD)
        self.assertEqual(trust_badge(SignatureState.INVALID).severity, SEV_BAD)
        self.assertEqual(trust_badge(SignatureState.UNSIGNED).severity, SEV_WARN)
        self.assertEqual(trust_badge(SignatureState.VALID_EMBEDDED).severity, SEV_WARN)

    def test_unsigned_mentions_the_manifest_can_be_altered(self) -> None:
        detail = trust_badge(SignatureState.UNSIGNED).detail.lower()
        self.assertIn("değiştirilmiş olabilir", detail)

    def test_embedded_explains_why_it_is_not_enough(self) -> None:
        detail = trust_badge(SignatureState.VALID_EMBEDDED).detail.lower()
        self.assertIn("kendi", detail)  # "manifestin kendi içindeki anahtar"


class HeadlineTests(unittest.TestCase):
    def test_trusted_match_is_the_only_unqualified_pass(self) -> None:
        h = verification_headline(files_match=True, state=SignatureState.TRUSTED)
        self.assertEqual(h.severity, SEV_GOOD)

    def test_valid_embedded_match_is_qualified(self) -> None:
        h = verification_headline(files_match=True, state=SignatureState.VALID_EMBEDDED)
        self.assertEqual(h.severity, SEV_WARN)
        self.assertIn("kaynağı doğrulanmadı", h.text)
        # Must NOT read as a bare "clean".
        self.assertNotEqual(h.text.strip().lower(), "temiz")

    def test_unsigned_match_is_qualified(self) -> None:
        h = verification_headline(files_match=True, state=SignatureState.UNSIGNED)
        self.assertEqual(h.severity, SEV_WARN)
        self.assertIn("imzasız", h.text)

    def test_invalid_never_reports_a_match(self) -> None:
        h = verification_headline(files_match=True, state=SignatureState.INVALID)
        self.assertEqual(h.severity, SEV_BAD)
        self.assertIn("geçersiz", h.text.lower())

    def test_mismatch_is_reported_even_when_trusted(self) -> None:
        h = verification_headline(files_match=False, state=SignatureState.TRUSTED)
        self.assertEqual(h.severity, SEV_BAD)

    def test_no_state_produces_a_bare_clean_claim(self) -> None:
        # Regression for "valid_embedded shows up as plain clean".
        for state in ALL_STATES:
            h = verification_headline(files_match=True, state=state)
            if state is not SignatureState.TRUSTED:
                self.assertNotEqual(
                    h.severity, SEV_GOOD, f"{state} must not be presented as fully clean"
                )


class DescribeResultTests(unittest.TestCase):
    def test_matches_result_state(self) -> None:
        for state in ALL_STATES:
            headline, badge = describe_result(_result(state))
            self.assertEqual(badge.state, state)

    def test_dirty_result_beats_trust(self) -> None:
        headline, _badge = describe_result(_result(SignatureState.TRUSTED, dirty=True))
        self.assertEqual(headline.severity, SEV_BAD)

    def test_embedded_clean_files_still_warns(self) -> None:
        headline, badge = describe_result(_result(SignatureState.VALID_EMBEDDED))
        self.assertEqual(headline.severity, SEV_WARN)
        self.assertFalse(badge.provenance_established)

    def test_error_entries_count_as_mismatch(self) -> None:
        r = _result(SignatureState.TRUSTED)
        r.errors.append(ErrorEntry(path="x", error="boom"))
        headline, _ = describe_result(r)
        self.assertEqual(headline.severity, SEV_BAD)


class StartupWarningTests(unittest.TestCase):
    def test_none_when_nothing_to_report(self) -> None:
        self.assertIsNone(collect_startup_warnings())
        self.assertIsNone(
            collect_startup_warnings(
                settings_warnings=[], history_warning=None, local_store_warning=None
            )
        )

    def test_history_warning_is_included(self) -> None:
        warning = collect_startup_warnings(history_warning="geçmiş bozuktu")
        self.assertIsNotNone(warning)
        self.assertIn("geçmiş bozuktu", warning.body)

    def test_all_sources_are_merged(self) -> None:
        warning = collect_startup_warnings(
            settings_warnings=["ayar sorunu"],
            history_warning="geçmiş sorunu",
            local_store_warning="parmak izi sorunu",
        )
        for fragment in ("ayar sorunu", "geçmiş sorunu", "parmak izi sorunu"):
            self.assertIn(fragment, warning.body)

    def test_title_is_generic_not_api_key_specific(self) -> None:
        warning = collect_startup_warnings(history_warning="x")
        self.assertNotIn("API", warning.title)


if __name__ == "__main__":
    unittest.main()
