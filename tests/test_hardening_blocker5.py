"""
Blocker 5 regression suite:
  * PowerShell is only ever launched from a trusted system path (no PATH).
  * A real Windows integration check (skipped off-Windows).
  * VT limiter/cache are thread-safe and namespaced per endpoint+credential.
  * Retry-After accepts both delta-seconds and HTTP-date.
  * A corrupt store is quarantined, not silently emptied.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from tests.support import DiagnosticTempDir
from core import signature_checker as sc
from core import vt_client
from core.history_manager import HistoryManager
from core.local_verify import LocalVerifyStore
from core.signature_checker import SignatureStatus, check_signature
from core.vt_client import (
    RateLimiter,
    TTLCache,
    VirusTotalClient,
    VTStatus,
    _parse_retry_after,
)

IS_WINDOWS = sys.platform.startswith("win")


class PowerShellPathTests(unittest.TestCase):
    def test_no_path_fallback_when_no_trusted_location_exists(self) -> None:
        # When neither the Win32-reported system directory nor the Windows
        # directory yields powershell.exe we must raise — never fall back to
        # a PATH lookup.
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(sc, "_system_directory", return_value=None), \
                 mock.patch.object(sc, "_windows_directory", return_value=d):
                with self.assertRaises(FileNotFoundError):
                    sc._powershell_executable()

    @unittest.skipUnless(IS_WINDOWS, "Windows-only")
    def test_spoofed_env_does_not_change_resolution(self) -> None:
        # Contract change (P0.7): the path now comes from the Win32 API, so a
        # spoofed SystemRoot no longer redirects us — it is simply ignored.
        genuine = sc._powershell_executable()
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"SystemRoot": d, "windir": d}):
                self.assertEqual(sc._powershell_executable(), genuine)

    def test_missing_system_powershell_yields_controlled_error(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "f.txt"
            target.write_text("x", encoding="utf-8")
            with mock.patch.object(sc, "_is_windows", return_value=True), \
                 mock.patch.object(
                     sc, "_powershell_executable",
                     side_effect=FileNotFoundError("no trusted powershell"),
                 ):
                result = check_signature(str(target))
        self.assertEqual(result.status, SignatureStatus.ERROR)
        self.assertIn("powershell", result.message.lower())

    @unittest.skipUnless(IS_WINDOWS, "Windows-only path layout")
    def test_resolves_real_system_powershell(self) -> None:
        exe = sc._powershell_executable()
        self.assertTrue(os.path.isabs(exe))
        self.assertTrue(Path(exe).is_file())
        # Must live under the Windows directory, not somewhere on PATH.
        windir = (os.environ.get("SystemRoot") or r"C:\Windows").lower()
        self.assertTrue(exe.lower().startswith(windir))


class UnknownErrorClassificationTests(unittest.TestCase):
    """A .txt is not 'signed but broken' — it simply cannot be signed."""

    def _classify(self, filename: str, raw_status: str) -> SignatureStatus:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / filename
            p.write_bytes(b"data")
            cp = mock.Mock()
            cp.returncode = 0
            cp.stdout = json.dumps(
                {"Status": raw_status, "StatusMessage": "", "Signer": None}
            )
            cp.stderr = ""
            with mock.patch.object(sc, "_is_windows", return_value=True), \
                 mock.patch.object(sc, "_powershell_executable", return_value="ps.exe"), \
                 mock.patch.object(sc.subprocess, "run", return_value=cp):
                return check_signature(str(p)).status

    def test_unknown_error_on_txt_is_not_applicable(self) -> None:
        self.assertEqual(
            self._classify("notes.txt", "UnknownError"), SignatureStatus.NOT_APPLICABLE
        )

    def test_unknown_error_on_exe_stays_unknown(self) -> None:
        # A genuine check failure on a signable file must NOT be downgraded.
        self.assertEqual(
            self._classify("app.exe", "UnknownError"), SignatureStatus.UNKNOWN
        )

    def test_unknown_error_on_ps1_stays_unknown(self) -> None:
        self.assertEqual(
            self._classify("script.ps1", "UnknownError"), SignatureStatus.UNKNOWN
        )

    @unittest.skipUnless(IS_WINDOWS, "real PowerShell integration test")
    def test_real_windows_txt_is_never_reported_as_broken_signature(self) -> None:
        # End-to-end against the real Get-AuthenticodeSignature cmdlet.
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "plain notes.txt"
            p.write_text("hello", encoding="utf-8")
            result = check_signature(str(p))
        self.assertIn(
            result.status,
            (SignatureStatus.NOT_APPLICABLE, SignatureStatus.UNSIGNED),
            f"unexpected status {result.status} ({result.raw_status})",
        )
        self.assertNotIn(
            result.status,
            (SignatureStatus.HASH_MISMATCH, SignatureStatus.UNTRUSTED),
        )

    @unittest.skipUnless(IS_WINDOWS, "real PowerShell integration test")
    def test_real_windows_signed_system_binary_is_valid(self) -> None:
        system_exe = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "notepad.exe"
        if not system_exe.is_file():
            self.skipTest("notepad.exe not present")
        result = check_signature(str(system_exe))
        self.assertEqual(result.status, SignatureStatus.SIGNED_VALID)
        self.assertTrue(result.signer)

    @unittest.skipUnless(IS_WINDOWS, "real PowerShell integration test")
    def test_real_windows_quote_and_unicode_filename(self) -> None:
        # Injection-shaped name must survive the real invocation unharmed.
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "ev'il; rm -rf ç kötü.txt"
            p.write_text("x", encoding="utf-8")
            result = check_signature(str(p))
        self.assertIn(
            result.status,
            (SignatureStatus.NOT_APPLICABLE, SignatureStatus.UNSIGNED),
            f"unexpected status {result.status}: {result.message}",
        )


class RetryAfterTests(unittest.TestCase):
    def test_delta_seconds(self) -> None:
        self.assertEqual(_parse_retry_after({"retry-after": "42"}), 42)

    def test_http_date(self) -> None:
        now = 1_700_000_000
        # 120 seconds in the future, expressed as an HTTP-date.
        from email.utils import formatdate

        header = formatdate(now + 120, usegmt=True)
        parsed = _parse_retry_after({"retry-after": header}, lambda: now)
        self.assertIsNotNone(parsed)
        self.assertAlmostEqual(parsed, 120, delta=2)

    def test_past_http_date_clamps_to_zero(self) -> None:
        from email.utils import formatdate

        now = 1_700_000_000
        header = formatdate(now - 500, usegmt=True)
        self.assertEqual(_parse_retry_after({"retry-after": header}, lambda: now), 0)

    def test_garbage_is_none(self) -> None:
        self.assertIsNone(_parse_retry_after({"retry-after": "soon-ish"}))
        self.assertIsNone(_parse_retry_after({}))


class ThreadSafetyTests(unittest.TestCase):
    def test_rate_limiter_never_exceeds_budget_under_threads(self) -> None:
        """Concurrent callers must share one 4-per-minute budget."""
        granted: list[float] = []
        lock = threading.Lock()
        clock = {"t": 0.0}

        def fake_sleep(seconds: float) -> None:
            # Advance virtual time instead of really sleeping.
            with lock:
                clock["t"] += seconds

        limiter = RateLimiter(
            max_calls=4, period=60.0, clock=lambda: clock["t"], sleep=fake_sleep
        )

        def worker() -> None:
            limiter.acquire()
            with lock:
                granted.append(clock["t"])

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        self.assertEqual(len(granted), 12)
        # In any 60s window at most 4 calls may have been granted.
        granted.sort()
        for i, start in enumerate(granted):
            window = [g for g in granted[i:] if g - start < 60.0]
            self.assertLessEqual(
                len(window), 4, f"budget exceeded in window starting {start}"
            )

    def test_cache_is_thread_safe(self) -> None:
        cache = TTLCache(ttl=999)
        errors: list[Exception] = []

        def worker(n: int) -> None:
            try:
                for i in range(200):
                    from core.vt_client import VTLookupResult

                    cache.set(f"k{n}-{i}", VTLookupResult(status=VTStatus.OK))
                    cache.get(f"k{n}-{i}")
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertEqual(errors, [])


class CacheNamespaceTests(unittest.TestCase):
    def _client(self, key: str, cache: TTLCache, base="https://vt.test/api/v3"):
        return VirusTotalClient(
            api_key=key,
            base_url=base,
            rate_limiter=RateLimiter(max_calls=10_000, period=1.0),
            cache=cache,
        )

    def test_different_api_keys_do_not_share_cache(self) -> None:
        cache = TTLCache(ttl=999)
        body = {"data": {"attributes": {"last_analysis_stats": {"harmless": 1}}}}
        calls = {"n": 0}

        def transport(url, headers, timeout):
            calls["n"] += 1
            return 200, body, {}

        with mock.patch.object(vt_client, "_http_get", transport):
            self._client("KEY-A", cache).lookup_hash("a" * 64)
            self._client("KEY-B", cache).lookup_hash("a" * 64)
        # Two different credentials must each perform their own lookup.
        self.assertEqual(calls["n"], 2)

    def test_same_key_reuses_cache(self) -> None:
        cache = TTLCache(ttl=999)
        body = {"data": {"attributes": {"last_analysis_stats": {"harmless": 1}}}}
        calls = {"n": 0}

        def transport(url, headers, timeout):
            calls["n"] += 1
            return 200, body, {}

        with mock.patch.object(vt_client, "_http_get", transport):
            self._client("KEY-A", cache).lookup_hash("a" * 64)
            self._client("KEY-A", cache).lookup_hash("a" * 64)
        self.assertEqual(calls["n"], 1)

    def test_api_key_is_not_a_plaintext_cache_key(self) -> None:
        cache = TTLCache(ttl=999)
        body = {"data": {"attributes": {"last_analysis_stats": {"harmless": 1}}}}
        with mock.patch.object(
            vt_client, "_http_get", lambda u, h, t: (200, body, {})
        ):
            self._client("SUPER-SECRET-KEY", cache).lookup_hash("a" * 64)
        self.assertFalse(
            any("SUPER-SECRET-KEY" in k for k in cache._store),
            "raw API key must not appear in cache keys",
        )


class CorruptStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_corrupt_history_is_quarantined_not_lost(self) -> None:
        path = self.root / "history.json"
        path.write_text("{ this is not json", encoding="utf-8")
        hm = HistoryManager(path)
        self.assertEqual(hm.all(), [])
        self.assertTrue(hm.load_warning, "user must be told the file was corrupt")
        # The original bytes must still exist somewhere.
        quarantined = list(self.root.glob("history.json.corrupt*"))
        self.assertTrue(quarantined, "corrupt history was not preserved")
        self.assertIn("this is not json", quarantined[0].read_text(encoding="utf-8"))

    def test_corrupt_local_store_is_quarantined_not_lost(self) -> None:
        path = self.root / "known_files.json"
        path.write_text("<<<garbage>>>", encoding="utf-8")
        store = LocalVerifyStore(path)
        self.assertIsNone(store.get("C:/x/y.bin"))
        self.assertTrue(store.load_warning)
        quarantined = list(self.root.glob("known_files.json.corrupt*"))
        self.assertTrue(quarantined)
        self.assertIn("garbage", quarantined[0].read_text(encoding="utf-8"))

    def test_valid_store_is_untouched(self) -> None:
        path = self.root / "history.json"
        path.write_text(
            json.dumps({"schema": "trust-history/1.0", "entries": []}), encoding="utf-8"
        )
        hm = HistoryManager(path)
        self.assertEqual(hm.all(), [])
        self.assertIsNone(hm.load_warning)
        self.assertEqual(list(self.root.glob("*.corrupt*")), [])


if __name__ == "__main__":
    unittest.main()
