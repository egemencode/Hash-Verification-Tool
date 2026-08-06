"""
VirusTotal client — hash-lookup only.

Design constraints
------------------
* The client **never** uploads file contents. It queries the public
  VirusTotal API v3 with a precomputed SHA-256 (or any supported hash)
  and reports back what the community already knows about that hash.
* If ``requests`` is not installed we fall back to ``urllib`` from the
  standard library so the rest of the app still works — and both transports
  return the exact same normalised result.
* Errors map onto a small, well-defined enum (``VTStatus``) so the GUI
  can render a friendly message instead of decoding HTTP edge cases.
* Malformed / unexpected JSON never crashes the caller — every numeric
  field is parsed defensively.

Robustness features (P1.2)
--------------------------
* A client-side :class:`RateLimiter` keeps us within the public free-tier
  budget (4 requests / minute by default).
* A :class:`TTLCache` (keyed by hash) avoids re-querying the same file and
  is honoured before the rate limiter.
* ``429`` responses surface the ``Retry-After`` hint.
* A verdict whose last analysis is very old, or that has zero engines
  behind it, is flagged (``is_stale`` / ``total_engines == 0``) so the risk
  engine does not treat it as a positive "clean" signal.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import deque
from email.utils import parsedate_to_datetime
from dataclasses import dataclass, field, asdict, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional


VT_API_BASE = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT_SECONDS: float = 15.0
DEFAULT_CACHE_TTL_SECONDS: float = 3600.0
# Public free tier: 4 lookups per minute.
FREE_TIER_MAX_CALLS = 4
FREE_TIER_PERIOD_SECONDS = 60.0
# A verdict older than this is not treated as a positive trust signal.
STALE_AFTER_SECONDS = 365 * 24 * 3600


class VTStatus(str, Enum):
    """High-level outcome of a hash lookup."""

    OK = "ok"                       # API responded with a verdict
    NOT_FOUND = "not_found"         # hash never seen by VT
    NO_API_KEY = "no_api_key"       # user has not configured a key
    UNAUTHORIZED = "unauthorized"   # key rejected
    RATE_LIMITED = "rate_limited"   # 429
    NETWORK_ERROR = "network_error" # no connection / timeout
    ERROR = "error"                 # anything else


@dataclass
class VTAnalysisStats:
    """Engine-vote breakdown returned by VT for a known hash."""

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    timeout: int = 0

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass
class VTLookupResult:
    """Normalised view of a hash-lookup response."""

    status: VTStatus
    hash_value: str = ""
    stats: VTAnalysisStats = field(default_factory=VTAnalysisStats)
    reputation: Optional[int] = None
    last_analysis_date: Optional[str] = None
    last_analysis_epoch: Optional[int] = None
    total_engines: int = 0
    # Engines that actually returned a verdict (excludes timeout / failure /
    # type-unsupported). Only these may support a "low risk" conclusion.
    analysing_engines: int = 0
    meaningful_name: Optional[str] = None
    type_description: Optional[str] = None
    message: str = ""
    # A very old verdict — present but not a reliable "current" signal.
    is_stale: bool = False
    # True when the analysis date is missing, unparsable or in the future, so
    # we cannot establish that the verdict is current. Treated exactly like
    # "stale" for the purposes of positive (clean) evidence.
    freshness_unknown: bool = False
    # True when last_analysis_stats was missing or not an object at all.
    stats_malformed: bool = False
    # Populated from the Retry-After header on 429 responses.
    retry_after_seconds: Optional[int] = None
    # True when the result came from the local cache (not a live query).
    from_cache: bool = False

    @property
    def is_known(self) -> bool:
        return self.status == VTStatus.OK

    @property
    def is_fresh(self) -> bool:
        """
        True only when we can positively establish the verdict is current.

        A missing / unparsable / future analysis date makes freshness
        unknown, which must never be read as "recently confirmed clean".
        """
        return not (self.is_stale or self.freshness_unknown)

    @property
    def is_usable_verdict(self) -> bool:
        """
        True when this response carries a verdict we can actually reason
        about: a real OK answer, engines behind it, well-formed stats, and
        established freshness.

        A NOT_FOUND, a network/quota error, a zero-engine answer, malformed
        stats, or an undatable/stale verdict are all *not* usable — the
        correct user-facing outcome for those is "not enough data".
        """
        return bool(
            self.status == VTStatus.OK
            and self.analysing_engines > 0
            and not self.stats_malformed
            and self.is_fresh
        )

    @property
    def is_clean_evidence(self) -> bool:
        """
        True when this result is positive evidence that the file is not
        known-malicious: a usable verdict with no malicious/suspicious hits.
        """
        return bool(
            self.is_usable_verdict
            and self.stats.malicious == 0
            and self.stats.suspicious == 0
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "hash": self.hash_value,
            "stats": self.stats.to_dict(),
            "reputation": self.reputation,
            "last_analysis_date": self.last_analysis_date,
            "total_engines": self.total_engines,
            "meaningful_name": self.meaningful_name,
            "type_description": self.type_description,
            "message": self.message,
            "is_stale": self.is_stale,
            "freshness_unknown": self.freshness_unknown,
            "stats_malformed": self.stats_malformed,
            "retry_after_seconds": self.retry_after_seconds,
        }


# ----------------------------------------------------------------------
# Rate limiter & cache (small, injectable, testable)
# ----------------------------------------------------------------------
class RateLimiter:
    """
    Sliding-window limiter: at most *max_calls* per *period* seconds.

    Thread-safe. The GUI can run a trust scan on a worker thread while the
    user hits "test API key" on another; without a shared lock both would
    read the same window state and together exceed the free-tier budget. The
    lock is held across the wait so a queued caller cannot slip past.
    """

    def __init__(
        self,
        max_calls: int = FREE_TIER_MAX_CALLS,
        period: float = FREE_TIER_PERIOD_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._max = max(1, int(max_calls))
        self._period = float(period)
        self._clock = clock
        self._sleep = sleep
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            now = self._clock()
            self._prune(now)
            if len(self._calls) >= self._max:
                wait = self._period - (now - self._calls[0])
                if wait > 0:
                    self._sleep(wait)
                    now = self._clock()
                    self._prune(now)
            self._calls.append(now)

    def _prune(self, now: float) -> None:
        while self._calls and (now - self._calls[0]) >= self._period:
            self._calls.popleft()


class TTLCache:
    """Tiny, thread-safe time-to-live cache for lookup results."""

    def __init__(
        self,
        ttl: float = DEFAULT_CACHE_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = float(ttl)
        self._clock = clock
        self._store: dict[str, tuple[float, VTLookupResult]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[VTLookupResult]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            stored_at, value = entry
            if (self._clock() - stored_at) > self._ttl:
                self._store.pop(key, None)
                return None
            return value

    def set(self, key: str, value: VTLookupResult) -> None:
        with self._lock:
            self._store[key] = (self._clock(), value)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


# Module-level shared defaults so every client in the process shares one
# free-tier budget and one cache (a desktop app makes serial lookups).
_DEFAULT_RATE_LIMITER = RateLimiter()
_DEFAULT_CACHE = TTLCache()


# ----------------------------------------------------------------------
# HTTP transport — try ``requests`` first, fall back to stdlib urllib.
# ----------------------------------------------------------------------
def _http_get(
    url: str, headers: dict[str, str], timeout: float
) -> tuple[int, dict[str, Any], dict[str, str]]:
    """
    Perform a GET and return ``(status_code, parsed_json_or_empty, headers)``.

    Raises :class:`OSError` family exceptions on transport-level errors so
    the caller can map them to :data:`VTStatus.NETWORK_ERROR`.
    """
    try:
        import requests  # type: ignore

        response = requests.get(url, headers=headers, timeout=timeout)
        try:
            body = response.json() if response.content else {}
        except ValueError:
            body = {}
        resp_headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
        return response.status_code, body, resp_headers
    except ImportError:
        pass

    # Stdlib fallback — keeps the tool runnable without ``requests``.
    import urllib.error
    import urllib.request

    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            status = resp.getcode() or 0
            resp_headers = {str(k).lower(): str(v) for k, v in resp.headers.items()}
            body = _loads_or_empty(raw)
            return status, body, resp_headers
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        except (ValueError, OSError):
            raw = ""
        resp_headers = {}
        try:
            resp_headers = {str(k).lower(): str(v) for k, v in (exc.headers or {}).items()}
        except Exception:  # pragma: no cover - header parsing is best effort
            resp_headers = {}
        return exc.code, _loads_or_empty(raw), resp_headers


def _loads_or_empty(raw: str) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _strict_count(value: Any) -> Optional[int]:
    """
    Parse an engine counter strictly.

    Returns the integer, or ``None`` when the value is not a non-negative
    integer. Anything else — a bool, a negative number, a float, a string, a
    container — means the response is not what we think it is, and coercing it
    to 0 would silently manufacture "no detections".
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    return None


# Buckets that represent an engine that actually produced a verdict. Engines
# that timed out, failed, or do not support the file type analysed nothing,
# so they must not pad the quorum that a LOW verdict requires.
_VERDICT_BUCKETS = ("malicious", "suspicious", "harmless", "undetected")
_NON_ANALYSING_BUCKETS = ("timeout", "failure", "type-unsupported", "confirmed-timeout")


def _safe_text(value: Any) -> Optional[str]:
    """
    Accept only real text for user-facing string fields.

    VT is a third-party source: a dict/list (or anything non-scalar) landing
    in ``meaningful_name`` would otherwise be rendered straight into the UI
    and reports. Anything unexpected becomes ``None``.
    """
    if value is None or isinstance(value, (dict, list, tuple, set, bool)):
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    if isinstance(value, (int, float)):
        return str(value)
    return None


def _parse_retry_after(
    headers: dict[str, str], now: Optional[Callable[[], float]] = None
) -> Optional[int]:
    """
    Parse a ``Retry-After`` header.

    RFC 9110 allows two forms and servers use both:
      * delta-seconds — ``Retry-After: 42``
      * HTTP-date     — ``Retry-After: Wed, 21 Oct 2026 07:28:00 GMT``
    Anything unparsable yields ``None`` ("unknown"), never a bogus number.
    """
    raw = headers.get("retry-after")
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None

    # Form 1: plain seconds.
    try:
        return max(0, int(text))
    except (TypeError, ValueError):
        pass

    # Form 2: HTTP-date — convert to a delay relative to now.
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None:
        return None
    try:
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        current = (now or time.time)()
        return max(0, int(when.timestamp() - current))
    except (OSError, OverflowError, ValueError):
        return None


# ----------------------------------------------------------------------
# Public client
# ----------------------------------------------------------------------
class VirusTotalClient:
    """Thin wrapper around the VT v3 ``/files/{hash}`` endpoint."""

    def __init__(
        self,
        api_key: Optional[str],
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        base_url: str = VT_API_BASE,
        *,
        rate_limiter: Optional[RateLimiter] = None,
        cache: Optional[TTLCache] = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self._api_key = (api_key or "").strip()
        self._timeout = timeout
        self._base_url = base_url.rstrip("/")
        self._limiter = rate_limiter if rate_limiter is not None else _DEFAULT_RATE_LIMITER
        self._cache = cache if cache is not None else _DEFAULT_CACHE
        self._now = now

    @property
    def has_key(self) -> bool:
        return bool(self._api_key)

    def _cache_key(self, digest: str) -> str:
        """
        Namespace cached results by endpoint + credential.

        Two accounts (or a public vs. private endpoint) can legitimately see
        different data for the same hash, and the shared module-level cache
        is process-wide — keying on the digest alone would leak one tenant's
        verdict to another. The key is hashed so no API key is ever held as
        a plaintext dict key.
        """
        tenant = hashlib.sha256(
            f"{self._base_url}\x00{self._api_key}".encode("utf-8")
        ).hexdigest()[:16]
        return f"{tenant}:{digest}"

    def lookup_hash(self, hash_value: str) -> VTLookupResult:
        """Look up *hash_value* and return a :class:`VTLookupResult`."""
        digest = (hash_value or "").strip().lower()
        if not digest:
            return VTLookupResult(status=VTStatus.ERROR, message="Boş hash değeri.")
        if not self._api_key:
            return VTLookupResult(
                status=VTStatus.NO_API_KEY,
                hash_value=digest,
                message="VirusTotal API anahtarı ayarlanmamış.",
            )

        # Cache first — cheap and does not consume the rate-limit budget.
        cache_key = self._cache_key(digest)
        cached = self._cache.get(cache_key)
        if cached is not None:
            # Return a copy flagged as cache-sourced (never mutate the stored one).
            return replace(cached, from_cache=True)

        # Respect the free-tier budget before issuing a live request.
        self._limiter.acquire()

        url = f"{self._base_url}/files/{digest}"
        headers = {
            "x-apikey": self._api_key,
            "Accept": "application/json",
            "User-Agent": "HashTrustCheck/1.2 (+local)",
        }

        try:
            status_code, body, resp_headers = _http_get(url, headers, self._timeout)
        except (TimeoutError, OSError) as exc:
            return VTLookupResult(
                status=VTStatus.NETWORK_ERROR,
                hash_value=digest,
                message=f"VirusTotal sunucusuna ulaşılamadı: {exc}",
            )

        result = self._interpret_response(digest, status_code, body, resp_headers)
        # Only cache stable outcomes — never transient errors / rate limits.
        if result.status in (VTStatus.OK, VTStatus.NOT_FOUND):
            self._cache.set(cache_key, result)
        return result

    # ------------------------------------------------------------------
    # Response interpretation
    # ------------------------------------------------------------------
    def _interpret_response(
        self,
        digest: str,
        status_code: int,
        body: dict[str, Any],
        headers: dict[str, str],
    ) -> VTLookupResult:
        if status_code == 200:
            return self._parse_ok(digest, body)
        if status_code == 404:
            return VTLookupResult(
                status=VTStatus.NOT_FOUND,
                hash_value=digest,
                message="Bu hash VirusTotal veritabanında bulunamadı.",
            )
        if status_code in (401, 403):
            return VTLookupResult(
                status=VTStatus.UNAUTHORIZED,
                hash_value=digest,
                message="API anahtarı reddedildi. Anahtarınızı kontrol edin.",
            )
        if status_code == 429:
            retry_after = _parse_retry_after(headers, self._now)
            extra = f" (~{retry_after} sn sonra tekrar deneyin)" if retry_after else ""
            return VTLookupResult(
                status=VTStatus.RATE_LIMITED,
                hash_value=digest,
                retry_after_seconds=retry_after,
                message=f"Hız limitine takıldınız. Lütfen biraz bekleyin.{extra}",
            )
        return VTLookupResult(
            status=VTStatus.ERROR,
            hash_value=digest,
            message=f"VirusTotal beklenmedik bir yanıt döndü (HTTP {status_code}).",
        )

    def _parse_ok(self, digest: str, body: dict[str, Any]) -> VTLookupResult:
        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, dict):
            return VTLookupResult(
                status=VTStatus.ERROR,
                hash_value=digest,
                message="VirusTotal yanıtı çözümlenemedi.",
            )
        attributes = data.get("attributes")
        if not isinstance(attributes, dict):
            attributes = {}

        raw_stats = attributes.get("last_analysis_stats")
        stats_malformed = not isinstance(raw_stats, dict)
        if stats_malformed:
            raw_stats = {}

        # Parse every counter strictly and remember which ones were usable.
        parsed: dict[str, Optional[int]] = {
            name: _strict_count(raw_stats.get(name))
            for name in (*_VERDICT_BUCKETS, *_NON_ANALYSING_BUCKETS)
        }
        # The verdict buckets must all be present and valid; a missing or
        # broken one means we cannot claim to know the detection counts.
        if any(parsed[name] is None for name in _VERDICT_BUCKETS):
            stats_malformed = True
        # A non-analysing bucket is optional, but if it IS present it must be
        # a valid count. `timeout: -1` or `failure: "oops"` means the payload
        # is not what we think it is, and reading the rest of it as a clean
        # verdict would be guessing.
        for name in _NON_ANALYSING_BUCKETS:
            if name in raw_stats and parsed[name] is None:
                stats_malformed = True

        stats = VTAnalysisStats(
            malicious=parsed["malicious"] or 0,
            suspicious=parsed["suspicious"] or 0,
            harmless=parsed["harmless"] or 0,
            undetected=parsed["undetected"] or 0,
            timeout=parsed["timeout"] or 0,
        )
        # Only engines that actually returned a verdict count toward the
        # quorum: timeouts / failures / unsupported types analysed nothing.
        analysing_engines = sum(parsed[name] or 0 for name in _VERDICT_BUCKETS)

        last_ts = attributes.get("last_analysis_date")
        last_epoch: Optional[int] = None
        last_iso: Optional[str] = None
        # A boolean is an int subclass — exclude it explicitly.
        if isinstance(last_ts, (int, float)) and not isinstance(last_ts, bool):
            try:
                last_epoch = int(last_ts)
                last_iso = (
                    datetime.fromtimestamp(last_epoch, tz=timezone.utc)
                    .astimezone()
                    .isoformat(timespec="seconds")
                )
            except (OSError, OverflowError, ValueError):
                last_epoch = None
                last_iso = None

        total_engines = (
            stats.malicious + stats.suspicious + stats.harmless
            + stats.undetected + stats.timeout
        )

        # Freshness: only a parsable, non-future, recent-enough date counts as
        # "current". Missing / unparsable / future dates are explicitly
        # *unknown* freshness — never silently treated as fresh.
        now = self._now()
        is_stale = False
        freshness_unknown = False
        if last_epoch is None:
            freshness_unknown = True
        else:
            age = now - last_epoch
            if age < 0:
                # Timestamp in the future: clock skew or a forged value.
                freshness_unknown = True
            elif age > STALE_AFTER_SECONDS:
                is_stale = True

        reputation = attributes.get("reputation")
        has_reputation = isinstance(reputation, (int, float)) and not isinstance(
            reputation, bool
        )
        return VTLookupResult(
            status=VTStatus.OK,
            hash_value=digest,
            stats=stats,
            # reputation is a genuine signed score — do not clamp it.
            reputation=int(reputation) if has_reputation else None,
            last_analysis_date=last_iso,
            last_analysis_epoch=last_epoch,
            total_engines=total_engines,
            analysing_engines=analysing_engines,
            meaningful_name=_safe_text(attributes.get("meaningful_name")),
            type_description=_safe_text(attributes.get("type_description")),
            is_stale=is_stale,
            freshness_unknown=freshness_unknown,
            stats_malformed=stats_malformed,
            message="VirusTotal verisi alındı.",
        )
