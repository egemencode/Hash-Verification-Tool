"""
VirusTotal client — hash-lookup only.

Design constraints
------------------
* The client **never** uploads file contents. It queries the public
  VirusTotal API v3 with a precomputed SHA-256 (or any supported hash)
  and reports back what the community already knows about that hash.
* If ``requests`` is not installed we fall back to ``urllib`` from the
  standard library so the rest of the app still works.
* Errors map onto a small, well-defined enum (``VTStatus``) so the GUI
  can render a friendly message instead of decoding HTTP edge cases.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


VT_API_BASE = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT_SECONDS: float = 15.0


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
    total_engines: int = 0
    meaningful_name: Optional[str] = None
    type_description: Optional[str] = None
    message: str = ""

    @property
    def is_known(self) -> bool:
        return self.status == VTStatus.OK

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
        }


# ----------------------------------------------------------------------
# HTTP transport — try ``requests`` first, fall back to stdlib urllib.
# ----------------------------------------------------------------------
def _http_get(url: str, headers: dict[str, str], timeout: float) -> tuple[int, dict[str, Any]]:
    """
    Perform a GET and return ``(status_code, parsed_json_or_empty_dict)``.

    Raises :class:`OSError` family exceptions on transport-level errors
    so the caller can map them to :data:`VTStatus.NETWORK_ERROR`.
    """
    try:
        import requests  # type: ignore

        response = requests.get(url, headers=headers, timeout=timeout)
        try:
            body = response.json() if response.content else {}
        except ValueError:
            body = {}
        return response.status_code, body
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
            try:
                body = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                body = {}
            return status, body
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            body = json.loads(raw) if raw else {}
        except (ValueError, OSError):
            body = {}
        return exc.code, body


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
    ) -> None:
        self._api_key = (api_key or "").strip()
        self._timeout = timeout
        self._base_url = base_url.rstrip("/")

    @property
    def has_key(self) -> bool:
        return bool(self._api_key)

    def lookup_hash(self, hash_value: str) -> VTLookupResult:
        """Look up *hash_value* and return a :class:`VTLookupResult`."""
        digest = (hash_value or "").strip().lower()
        if not digest:
            return VTLookupResult(
                status=VTStatus.ERROR,
                message="Boş hash değeri.",
            )
        if not self._api_key:
            return VTLookupResult(
                status=VTStatus.NO_API_KEY,
                hash_value=digest,
                message="VirusTotal API anahtarı ayarlanmamış.",
            )

        url = f"{self._base_url}/files/{digest}"
        headers = {
            "x-apikey": self._api_key,
            "Accept": "application/json",
            # A descriptive UA helps when debugging rate-limit edges.
            "User-Agent": "HashTrustCheck/1.2 (+local)",
        }

        try:
            status_code, body = _http_get(url, headers, self._timeout)
        except (TimeoutError, OSError) as exc:
            return VTLookupResult(
                status=VTStatus.NETWORK_ERROR,
                hash_value=digest,
                message=f"VirusTotal sunucusuna ulaşılamadı: {exc}",
            )

        return self._interpret_response(digest, status_code, body)

    # ------------------------------------------------------------------
    # Response interpretation
    # ------------------------------------------------------------------
    @staticmethod
    def _interpret_response(
        digest: str, status_code: int, body: dict[str, Any]
    ) -> VTLookupResult:
        if status_code == 200:
            return VirusTotalClient._parse_ok(digest, body)
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
            return VTLookupResult(
                status=VTStatus.RATE_LIMITED,
                hash_value=digest,
                message="Hız limitine takıldınız. Lütfen biraz bekleyin.",
            )
        return VTLookupResult(
            status=VTStatus.ERROR,
            hash_value=digest,
            message=f"VirusTotal beklenmedik bir yanıt döndü (HTTP {status_code}).",
        )

    @staticmethod
    def _parse_ok(digest: str, body: dict[str, Any]) -> VTLookupResult:
        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, dict):
            return VTLookupResult(
                status=VTStatus.ERROR,
                hash_value=digest,
                message="VirusTotal yanıtı çözümlenemedi.",
            )
        attributes = data.get("attributes") if isinstance(data.get("attributes"), dict) else {}

        raw_stats = attributes.get("last_analysis_stats") or {}
        stats = VTAnalysisStats(
            malicious=int(raw_stats.get("malicious", 0) or 0),
            suspicious=int(raw_stats.get("suspicious", 0) or 0),
            harmless=int(raw_stats.get("harmless", 0) or 0),
            undetected=int(raw_stats.get("undetected", 0) or 0),
            timeout=int(raw_stats.get("timeout", 0) or 0),
        )

        last_ts = attributes.get("last_analysis_date")
        last_iso: Optional[str] = None
        if isinstance(last_ts, (int, float)):
            from datetime import datetime, timezone
            try:
                last_iso = (
                    datetime.fromtimestamp(int(last_ts), tz=timezone.utc)
                    .astimezone()
                    .isoformat(timespec="seconds")
                )
            except (OSError, OverflowError, ValueError):
                last_iso = None

        total_engines = (
            stats.malicious + stats.suspicious + stats.harmless +
            stats.undetected + stats.timeout
        )

        return VTLookupResult(
            status=VTStatus.OK,
            hash_value=digest,
            stats=stats,
            reputation=(
                int(attributes["reputation"])
                if isinstance(attributes.get("reputation"), (int, float))
                else None
            ),
            last_analysis_date=last_iso,
            total_engines=total_engines,
            meaningful_name=attributes.get("meaningful_name") or None,
            type_description=attributes.get("type_description") or None,
            message="VirusTotal verisi alındı.",
        )
