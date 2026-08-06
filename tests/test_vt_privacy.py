"""
P0.3 — the online-check preference must actually be honoured.

The privacy promise is concrete: when the user has not enabled online
checks, **no request may leave the machine**. These tests assert that at the
transport level (the HTTP function is replaced by one that fails the test if
it is ever called), not by inspecting flags.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.support import DiagnosticTempDir
from core import vt_client
from core.trust_pipeline import resolve_online_checks, run_trust_check
from core.vt_client import RateLimiter, TTLCache, VirusTotalClient, VTStatus
from utils import settings as S
from utils.settings import KEY_VT_AUTOQUERY, AppSettings


class _NetworkGuard:
    """Replaces the HTTP layer with a tripwire."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, url, headers, timeout):
        self.calls += 1
        raise AssertionError(f"network request made to {url} despite opt-out")


def _client(key="KEY"):
    return VirusTotalClient(
        api_key=key,
        rate_limiter=RateLimiter(max_calls=10_000, period=1.0),
        cache=TTLCache(ttl=0),
    )


class ResolveOnlineChecksTests(unittest.TestCase):
    """The single place that decides whether we may go online."""

    def test_disabled_preference_wins_over_key(self) -> None:
        self.assertFalse(resolve_online_checks(autoquery=False, has_key=True))

    def test_no_key_means_no_query(self) -> None:
        self.assertFalse(resolve_online_checks(autoquery=True, has_key=False))

    def test_enabled_with_key(self) -> None:
        self.assertTrue(resolve_online_checks(autoquery=True, has_key=True))

    def test_explicit_override_can_disable(self) -> None:
        self.assertFalse(
            resolve_online_checks(autoquery=True, has_key=True, online_allowed=False)
        )


class NoNetworkWhenOptedOutTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.path = Path(self._tmp.name) / "sample.txt"
        self.path.write_text("hello", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_zero_network_calls_when_autoquery_disabled(self) -> None:
        guard = _NetworkGuard()
        with mock.patch.object(vt_client, "_http_get", guard):
            result = run_trust_check(
                str(self.path),
                vt_client=_client(),
                local_store=None,
                check_signature_flag=False,
                query_virustotal=resolve_online_checks(autoquery=False, has_key=True),
            )
        self.assertEqual(guard.calls, 0)
        self.assertIsNone(result.vt)

    def test_local_checks_still_run_when_offline(self) -> None:
        guard = _NetworkGuard()
        with mock.patch.object(vt_client, "_http_get", guard):
            result = run_trust_check(
                str(self.path),
                vt_client=_client(),
                local_store=None,
                check_signature_flag=False,
                query_virustotal=False,
            )
        self.assertEqual(guard.calls, 0)
        # Hashes are computed locally and must still be present.
        self.assertEqual(len(result.sha256), 64)
        self.assertTrue(result.assessment)

    def test_lookup_is_not_called_on_the_client(self) -> None:
        client = _client()
        with mock.patch.object(
            client, "lookup_hash", side_effect=AssertionError("lookup_hash called")
        ):
            run_trust_check(
                str(self.path),
                vt_client=client,
                local_store=None,
                check_signature_flag=False,
                query_virustotal=False,
            )


class DefaultIsOptInTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.base = Path(self._tmp.name)
        S.clear_migration_warnings()
        S._reset_write_disabled_for_tests()

    def tearDown(self) -> None:
        S.clear_migration_warnings()
        S._reset_write_disabled_for_tests()
        self._tmp.cleanup()

    def test_fresh_install_defaults_to_offline(self) -> None:
        with mock.patch.object(S, "_base_dir", return_value=self.base):
            settings = AppSettings.load()
        self.assertFalse(
            settings.virustotal_autoquery,
            "a fresh install must not send hashes before the user opts in",
        )

    def test_existing_preference_is_preserved(self) -> None:
        (self.base).mkdir(parents=True, exist_ok=True)
        (self.base / "hashtool_settings.json").write_text(
            json.dumps({KEY_VT_AUTOQUERY: True}), encoding="utf-8"
        )
        with mock.patch.object(S, "_base_dir", return_value=self.base):
            self.assertTrue(AppSettings.load().virustotal_autoquery)

    def test_existing_disabled_preference_is_preserved(self) -> None:
        (self.base).mkdir(parents=True, exist_ok=True)
        (self.base / "hashtool_settings.json").write_text(
            json.dumps({KEY_VT_AUTOQUERY: False}), encoding="utf-8"
        )
        with mock.patch.object(S, "_base_dir", return_value=self.base):
            self.assertFalse(AppSettings.load().virustotal_autoquery)


class FailedSaveDoesNotMutateLiveSettingsTests(unittest.TestCase):
    """A failed disk write must leave the in-memory settings untouched."""

    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.base = Path(self._tmp.name)
        S.clear_migration_warnings()
        S._reset_write_disabled_for_tests()

    def tearDown(self) -> None:
        S.clear_migration_warnings()
        S._reset_write_disabled_for_tests()
        self._tmp.cleanup()

    def test_draft_changes_are_discarded_when_save_fails(self) -> None:
        with mock.patch.object(S, "_base_dir", return_value=self.base):
            live = AppSettings.load()
            self.assertFalse(live.virustotal_autoquery)

            draft = live.copy_for_edit()
            draft.virustotal_autoquery = True
            draft.language = "en"

            with mock.patch.object(
                S, "write_json_atomic", side_effect=OSError("disk full")
            ):
                with self.assertRaises(S.SettingsError):
                    draft.save()

        # The live object must not have been mutated by the failed attempt.
        self.assertFalse(live.virustotal_autoquery)
        self.assertEqual(live.language, "tr")

    def test_draft_is_an_independent_copy(self) -> None:
        with mock.patch.object(S, "_base_dir", return_value=self.base):
            live = AppSettings.load()
        draft = live.copy_for_edit()
        draft.virustotal_autoquery = True
        draft.history_limit = 999
        self.assertFalse(live.virustotal_autoquery)
        self.assertNotEqual(live.history_limit, 999)


if __name__ == "__main__":
    unittest.main()
