"""VirusTotal client hardening tests (P1.2)."""

from __future__ import annotations

import unittest
from unittest import mock

from core import vt_client
from core.vt_client import (
    RateLimiter,
    STALE_AFTER_SECONDS,
    TTLCache,
    VirusTotalClient,
    VTStatus,
)


def _fake_transport(status, body=None, headers=None):
    """Return a replacement for _http_get that yields a fixed response."""
    body = body or {}
    headers = headers or {}
    calls = {"n": 0}

    def _get(url, hdrs, timeout):
        calls["n"] += 1
        return status, body, headers

    _get.calls = calls  # type: ignore[attr-defined]
    return _get


def _ok_body(malicious=0, suspicious=0, harmless=70, last_epoch=None):
    attrs = {
        "last_analysis_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": 0,
            "timeout": 0,
        }
    }
    if last_epoch is not None:
        attrs["last_analysis_date"] = last_epoch
    return {"data": {"attributes": attrs}}


def _client(**kw):
    # Isolated limiter/cache so tests never touch the shared module defaults.
    kw.setdefault("rate_limiter", RateLimiter(max_calls=1000, period=1.0))
    kw.setdefault("cache", TTLCache(ttl=9999))
    return VirusTotalClient(api_key="k", **kw)


class HttpStatusTests(unittest.TestCase):
    def _lookup(self, status, body=None, headers=None, **kw):
        with mock.patch.object(vt_client, "_http_get", _fake_transport(status, body, headers)):
            return _client(**kw).lookup_hash("a" * 64)

    def test_200_ok(self):
        self.assertEqual(self._lookup(200, _ok_body()).status, VTStatus.OK)

    def test_404_not_found(self):
        self.assertEqual(self._lookup(404).status, VTStatus.NOT_FOUND)

    def test_401_unauthorized(self):
        self.assertEqual(self._lookup(401).status, VTStatus.UNAUTHORIZED)

    def test_403_unauthorized(self):
        self.assertEqual(self._lookup(403).status, VTStatus.UNAUTHORIZED)

    def test_429_rate_limited_with_retry_after(self):
        r = self._lookup(429, headers={"retry-after": "42"})
        self.assertEqual(r.status, VTStatus.RATE_LIMITED)
        self.assertEqual(r.retry_after_seconds, 42)

    def test_500_error(self):
        self.assertEqual(self._lookup(500).status, VTStatus.ERROR)

    def test_malformed_json_does_not_crash(self):
        # 200 with a body that is not the expected shape.
        self.assertEqual(self._lookup(200, {"unexpected": True}).status, VTStatus.ERROR)
        self.assertEqual(self._lookup(200, []).status, VTStatus.ERROR)

    def test_no_api_key(self):
        with mock.patch.object(vt_client, "_http_get", _fake_transport(200, _ok_body())):
            r = VirusTotalClient(api_key=None).lookup_hash("a" * 64)
        self.assertEqual(r.status, VTStatus.NO_API_KEY)

    def test_network_error(self):
        def boom(url, headers, timeout):
            raise OSError("no route to host")

        with mock.patch.object(vt_client, "_http_get", boom):
            r = _client().lookup_hash("a" * 64)
        self.assertEqual(r.status, VTStatus.NETWORK_ERROR)


class StaleAndEngineTests(unittest.TestCase):
    def test_zero_engines_flagged(self):
        body = _ok_body(harmless=0)
        with mock.patch.object(vt_client, "_http_get", _fake_transport(200, body)):
            r = _client().lookup_hash("a" * 64)
        self.assertEqual(r.total_engines, 0)

    def test_stale_result_flagged(self):
        # last analysis 3 years ago, "now" fixed.
        now = 2_000_000_000
        old = now - (3 * 365 * 24 * 3600)
        body = _ok_body(last_epoch=old)
        with mock.patch.object(vt_client, "_http_get", _fake_transport(200, body)):
            r = _client(now=lambda: now).lookup_hash("a" * 64)
        self.assertTrue(r.is_stale)

    def test_recent_result_not_stale(self):
        now = 2_000_000_000
        recent = now - 1000
        body = _ok_body(last_epoch=recent)
        with mock.patch.object(vt_client, "_http_get", _fake_transport(200, body)):
            r = _client(now=lambda: now).lookup_hash("a" * 64)
        self.assertFalse(r.is_stale)


class CacheTests(unittest.TestCase):
    def test_second_lookup_hits_cache(self):
        transport = _fake_transport(200, _ok_body())
        with mock.patch.object(vt_client, "_http_get", transport):
            c = _client()
            first = c.lookup_hash("a" * 64)
            second = c.lookup_hash("a" * 64)
        self.assertFalse(first.from_cache)
        self.assertTrue(second.from_cache)
        self.assertEqual(transport.calls["n"], 1)  # only one live request

    def test_errors_are_not_cached(self):
        transport = _fake_transport(500)
        with mock.patch.object(vt_client, "_http_get", transport):
            c = _client()
            c.lookup_hash("a" * 64)
            c.lookup_hash("a" * 64)
        self.assertEqual(transport.calls["n"], 2)  # retried, not cached


class RateLimiterTests(unittest.TestCase):
    def test_blocks_after_budget_exhausted(self):
        clock = {"t": 0.0}
        slept = []
        limiter = RateLimiter(
            max_calls=2,
            period=60.0,
            clock=lambda: clock["t"],
            sleep=lambda s: slept.append(s),
        )
        limiter.acquire()  # 1
        limiter.acquire()  # 2
        limiter.acquire()  # 3 -> must wait ~60s
        self.assertTrue(slept)
        self.assertAlmostEqual(slept[0], 60.0, delta=0.001)

    def test_window_slides(self):
        clock = {"t": 0.0}
        slept = []
        limiter = RateLimiter(
            max_calls=1,
            period=10.0,
            clock=lambda: clock["t"],
            sleep=lambda s: slept.append(s),
        )
        limiter.acquire()
        clock["t"] = 11.0  # past the window
        limiter.acquire()
        self.assertEqual(slept, [])  # no wait needed


if __name__ == "__main__":
    unittest.main()
