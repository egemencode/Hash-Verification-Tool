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
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from core.atomic_io import corrupt_reason, quarantine_corrupt_file, write_json_atomic


class LocalStoreError(Exception):
    """Raised when the local fingerprint store cannot be persisted."""


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
    # Audit trail of superseded baselines, oldest first. Replacing a baseline
    # is destructive, so the previous value is kept rather than overwritten.
    previous: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LocalRecord":
        raw_previous = data.get("previous")
        return cls(
            path=str(data.get("path", "")),
            sha256=str(data.get("sha256", "")),
            size=int(data.get("size") or 0),
            recorded_at=str(data.get("recorded_at", "")),
            last_seen_at=str(data.get("last_seen_at", "")),
            previous=[p for p in raw_previous if isinstance(p, dict)]
            if isinstance(raw_previous, list)
            else [],
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
        # Set when a corrupt store was quarantined instead of being silently
        # replaced by an empty one.
        self.load_warning: Optional[str] = None
        # True when the existing file could NOT be preserved. While set, every
        # write is refused so the original bytes stay recoverable on disk.
        self.write_disabled: bool = False
        self.write_disabled_reason: str = ""

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
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            # A corrupt store must never crash the app — but it must not be
            # silently overwritten with an empty one either. Move it aside so
            # the fingerprints stay recoverable, and tell the caller.
            # (Binary garbage raises UnicodeDecodeError, not JSONDecodeError.)
            self._quarantine(corrupt_reason(exc))
            return
        except OSError as exc:
            # Readable-but-locked: keep the file intact and refuse to write,
            # rather than silently starting an empty store that would later
            # overwrite records we never managed to read.
            self._disable_writes(
                f"Yerel parmak izi kaydı açılamadı ({exc.__class__.__name__}): "
                f"{self._path}. Var olan kayıtların üzerine yazmamak için "
                "kayıt yazma devre dışı."
            )
            return
        if not isinstance(raw, dict):
            self._quarantine("beklenmeyen biçim")
            return
        entries = raw.get("records", {})
        if not isinstance(entries, dict):
            self._quarantine("'records' bölümü geçersiz")
            return
        for key, value in entries.items():
            if isinstance(value, dict):
                self._records[key] = LocalRecord.from_dict({**value, "path": key})

    def _quarantine(self, reason: str) -> None:
        moved = quarantine_corrupt_file(self._path)
        if moved is not None:
            self.load_warning = (
                f"Yerel parmak izi kaydı okunamadı ({reason}). Bozuk dosya "
                f"'{moved.name}' olarak saklandı; yeni bir kayıt başlatıldı."
            )
        else:
            self._disable_writes(
                f"Yerel parmak izi kaydı okunamadı ({reason}) ve yedeklenemedi: "
                f"{self._path}. Mevcut veriyi kaybetmemek için kayıt yazma "
                "devre dışı bırakıldı; dosyayı elle taşıyın veya silin."
            )

    def _disable_writes(self, reason: str) -> None:
        self.write_disabled = True
        self.write_disabled_reason = reason
        self.load_warning = reason

    def _guard_writable(self) -> None:
        if self.write_disabled:
            raise LocalStoreError(self.write_disabled_reason)

    def _save(self) -> None:
        # Never overwrite data we failed to preserve.
        self._guard_writable()
        payload = {
            "schema": "trust-store/1.0",
            "updated_at": _now_iso(),
            "records": {k: v.to_dict() for k, v in self._records.items()},
        }
        try:
            write_json_atomic(self._path, payload)
        except OSError as exc:
            # Do NOT swallow: a "saved" that silently failed is worse than an
            # error the caller (and the user) can react to.
            raise LocalStoreError(
                f"Yerel kayıt dosyası yazılamadı: {self._path}: {exc}"
            ) from exc

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
        history = list(previous.previous) if previous else []
        if previous is not None and previous.sha256.lower() != digest:
            # Keep what we are replacing: the old baseline is the only record
            # of what this file used to be.
            history.append(
                {
                    "sha256": previous.sha256,
                    "size": previous.size,
                    "recorded_at": previous.recorded_at,
                    "replaced_at": now,
                }
            )
        record = LocalRecord(
            path=key,
            sha256=digest,
            size=int(size),
            recorded_at=previous.recorded_at if previous else now,
            last_seen_at=now,
            previous=history,
        )
        self._records[key] = record
        try:
            self._save()
        except LocalStoreError:
            # Roll back the in-memory change so it matches the disk state.
            if previous is not None:
                self._records[key] = previous
            else:
                self._records.pop(key, None)
            raise
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
            removed = self._records.pop(key)
            try:
                self._save()
            except LocalStoreError:
                self._records[key] = removed
                raise
            return True
        return False

    def all(self) -> list[LocalRecord]:
        self._load()
        return sorted(self._records.values(), key=lambda r: r.last_seen_at, reverse=True)
