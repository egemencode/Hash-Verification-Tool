"""
Local "fingerprint book" — remember a file's hash today, compare it
later.

The store is a flat JSON file (``known_files.json``) keyed by the
file's **absolute resolved path**. Each entry remembers the SHA-256
and the timestamp it was first recorded so the UI can show a
meaningful "last saved" line.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class LocalVerifyStatus(str, Enum):
    """Outcome of comparing the current hash against the saved one."""

    SAME = "same"             # bit-for-bit identical
    CHANGED = "changed"       # path known, hash differs
    NEW = "new"               # path was just recorded for the first time
    NOT_TRACKED = "not_tracked"  # path is not in the store yet


@dataclass
class LocalRecord:
    """Single persisted fingerprint."""

    path: str
    sha256: str
    size: int
    recorded_at: str
    last_seen_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LocalRecord":
        return cls(
            path=str(data.get("path", "")),
            sha256=str(data.get("sha256", "")),
            size=int(data.get("size") or 0),
            recorded_at=str(data.get("recorded_at", "")),
            last_seen_at=str(data.get("last_seen_at", "")),
        )


@dataclass
class LocalVerifyResult:
    status: LocalVerifyStatus
    record: Optional[LocalRecord] = None
    previous_hash: Optional[str] = None
    current_hash: Optional[str] = None
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "record": self.record.to_dict() if self.record else None,
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash,
            "message": self.message,
        }


# ----------------------------------------------------------------------
# Store
# ----------------------------------------------------------------------
def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _normalise(path: str | Path) -> str:
    return str(Path(path).resolve())


class LocalVerifyStore:
    """Read-modify-write JSON store of known file fingerprints."""

    def __init__(self, store_path: str | Path) -> None:
        self._path = Path(store_path)
        self._records: dict[str, LocalRecord] = {}
        self._loaded = False

    # ------------------------------------------------------------------
    # IO
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
            # Corrupt store should never crash the app — we just
            # start fresh.
            return
        if not isinstance(raw, dict):
            return
        entries = raw.get("records", {})
        if not isinstance(entries, dict):
            return
        for key, value in entries.items():
            if isinstance(value, dict):
                self._records[key] = LocalRecord.from_dict({**value, "path": key})

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "schema": "trust-store/1.0",
                "updated_at": _now_iso(),
                "records": {k: v.to_dict() for k, v in self._records.items()},
            }
            with self._path.open("w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
        except OSError:
            # Best-effort persistence — never propagate disk errors
            # from a background "save fingerprint" action.
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get(self, file_path: str | Path) -> Optional[LocalRecord]:
        self._load()
        return self._records.get(_normalise(file_path))

    def compare(self, file_path: str | Path, current_sha256: str) -> LocalVerifyResult:
        """Compare *current_sha256* with the stored one (if any)."""
        self._load()
        key = _normalise(file_path)
        existing = self._records.get(key)
        digest = (current_sha256 or "").lower().strip()

        if existing is None:
            return LocalVerifyResult(
                status=LocalVerifyStatus.NOT_TRACKED,
                current_hash=digest,
                message="Bu dosya daha önce kaydedilmemiş.",
            )
        if existing.sha256.lower() == digest:
            return LocalVerifyResult(
                status=LocalVerifyStatus.SAME,
                record=existing,
                previous_hash=existing.sha256,
                current_hash=digest,
                message="Dosya kayıtlı sürümüyle aynı.",
            )
        return LocalVerifyResult(
            status=LocalVerifyStatus.CHANGED,
            record=existing,
            previous_hash=existing.sha256,
            current_hash=digest,
            message="Dosya kayıtlı sürümünden farklı.",
        )

    def remember(
        self,
        file_path: str | Path,
        sha256: str,
        size: int,
    ) -> LocalVerifyResult:
        """Insert or refresh the saved fingerprint for *file_path*."""
        self._load()
        key = _normalise(file_path)
        now = _now_iso()
        digest = (sha256 or "").lower().strip()

        previous = self._records.get(key)
        record = LocalRecord(
            path=key,
            sha256=digest,
            size=int(size),
            recorded_at=previous.recorded_at if previous else now,
            last_seen_at=now,
        )
        self._records[key] = record
        self._save()
        return LocalVerifyResult(
            status=LocalVerifyStatus.NEW,
            record=record,
            current_hash=digest,
            message=(
                "Yeni dosya kaydı oluşturuldu."
                if previous is None
                else "Kayıt güncellendi."
            ),
        )

    def forget(self, file_path: str | Path) -> bool:
        """Drop a fingerprint. Returns True if a record existed."""
        self._load()
        key = _normalise(file_path)
        if key in self._records:
            del self._records[key]
            self._save()
            return True
        return False

    def all(self) -> list[LocalRecord]:
        self._load()
        return sorted(self._records.values(), key=lambda r: r.last_seen_at, reverse=True)
