"""
Persistent scan history.

The history is a JSON file storing the last N scans in reverse-chronological
order. Each entry is a snapshot of what the user actually saw on screen
(headline, risk level, key hashes, VT counts) so the History tab can
render past results without re-running the analysis.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


DEFAULT_HISTORY_LIMIT: int = 50


@dataclass
class HistoryEntry:
    """Minimal record displayed in the history tab."""

    scanned_at: str
    file_name: str
    file_path: str
    sha256: str
    risk_level: str
    headline: str
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_status: str = ""
    signature_status: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HistoryEntry":
        return cls(
            scanned_at=str(data.get("scanned_at", "")),
            file_name=str(data.get("file_name", "")),
            file_path=str(data.get("file_path", "")),
            sha256=str(data.get("sha256", "")),
            risk_level=str(data.get("risk_level", "")),
            headline=str(data.get("headline", "")),
            vt_malicious=int(data.get("vt_malicious") or 0),
            vt_suspicious=int(data.get("vt_suspicious") or 0),
            vt_status=str(data.get("vt_status", "")),
            signature_status=str(data.get("signature_status", "")),
        )


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class HistoryManager:
    """Read-modify-write JSON store of past scans."""

    def __init__(self, store_path: str | Path, limit: int = DEFAULT_HISTORY_LIMIT) -> None:
        self._path = Path(store_path)
        self._limit = max(1, int(limit))
        self._entries: list[HistoryEntry] = []
        self._loaded = False

    # ------------------------------------------------------------------
    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self._path.exists():
            return
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(raw, dict):
            return
        items = raw.get("entries", [])
        if not isinstance(items, list):
            return
        self._entries = [
            HistoryEntry.from_dict(item)
            for item in items
            if isinstance(item, dict)
        ]

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "schema": "trust-history/1.0",
                "updated_at": _now_iso(),
                "entries": [entry.to_dict() for entry in self._entries],
            }
            with self._path.open("w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
        except OSError:
            pass

    # ------------------------------------------------------------------
    def add(self, entry: HistoryEntry) -> None:
        self._load()
        # Newest first, capped to *limit*.
        self._entries.insert(0, entry)
        if len(self._entries) > self._limit:
            self._entries = self._entries[: self._limit]
        self._save()

    def all(self) -> list[HistoryEntry]:
        self._load()
        return list(self._entries)

    def clear(self) -> None:
        self._load()
        self._entries.clear()
        self._save()

    def find_latest(self, file_path: str) -> Optional[HistoryEntry]:
        self._load()
        target = str(Path(file_path).resolve())
        for entry in self._entries:
            if entry.file_path == target:
                return entry
        return None


def make_entry(
    *,
    file_name: str,
    file_path: str,
    sha256: str,
    risk_level: str,
    headline: str,
    vt_malicious: int = 0,
    vt_suspicious: int = 0,
    vt_status: str = "",
    signature_status: str = "",
) -> HistoryEntry:
    """Convenience builder that fills the timestamp for the caller."""
    return HistoryEntry(
        scanned_at=_now_iso(),
        file_name=file_name,
        file_path=file_path,
        sha256=sha256,
        risk_level=risk_level,
        headline=headline,
        vt_malicious=vt_malicious,
        vt_suspicious=vt_suspicious,
        vt_status=vt_status,
        signature_status=signature_status,
    )
