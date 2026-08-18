"""
JSON settings store + typed :class:`AppSettings` facade.

Storage location (P1.4)
-----------------------
By default everything lives under ``%LOCALAPPDATA%\\HashTool\\`` — never
next to the executable, so a read-only / shared install directory does not
break persistence and per-user data stays per-user. Dropping a file named
``portable.marker`` next to the executable opts into **portable mode**,
where settings/data sit beside the executable instead (explicit, not the
default). An exe-adjacent settings file from an older build is migrated to
the new location on first load.

Secret handling (P1.3)
----------------------
The VirusTotal API key is **never** stored as plaintext. It is protected
with Windows DPAPI (:mod:`core.secret_store`) and stored as an opaque token
under ``virustotal_api_key_enc``. A legacy plaintext key is migrated to the
protected slot on first load and the plaintext is removed. ``save_settings``
strips any plaintext key defensively so no code path can reintroduce it.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from core import secret_store
from core.atomic_io import (
    corrupt_reason as _corrupt_reason,
    quarantine_corrupt_file,
    write_json_atomic,
)

SETTINGS_FILENAME = "hashtool_settings.json"
PORTABLE_MARKER = "portable.marker"

# --- Keys ----------------------------------------------------------------
KEY_LANGUAGE = "language"
KEY_VT_API_KEY = "virustotal_api_key"           # legacy plaintext (migration only)
KEY_VT_API_KEY_ENC = "virustotal_api_key_enc"   # DPAPI-protected token
KEY_VT_AUTOQUERY = "virustotal_autoquery"
KEY_HISTORY_LIMIT = "history_limit"
KEY_LAST_FOLDER = "last_folder"

# --- Validation bounds / defaults ---------------------------------------
DEFAULT_LANGUAGE = "tr"
SUPPORTED_LANGUAGES = ("tr", "en")
DEFAULT_HISTORY_LIMIT = 50
HISTORY_LIMIT_MIN = 1
HISTORY_LIMIT_MAX = 10_000


class SettingsError(Exception):
    """Raised when settings cannot be persisted (surfaced to the user)."""


class SecretState(str, Enum):
    """
    What we know about the stored API key.

    ``ABSENT`` and ``UNREADABLE`` must stay distinct: treating an
    undecryptable token as "no key" made an ordinary settings save delete the
    user's only copy of it.
    """

    ABSENT = "absent"          # nothing stored
    AVAILABLE = "available"    # stored and decrypted successfully
    UNREADABLE = "unreadable"  # a token exists but this user cannot open it
    UNSUPPORTED = "unsupported"  # no secure store on this platform


# ----------------------------------------------------------------------
# Filesystem location
# ----------------------------------------------------------------------
def _executable_dir() -> Path:
    # PyInstaller sets sys.frozen; sys.executable points at the exe itself.
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def is_portable() -> bool:
    """True when a ``portable.marker`` file sits next to the executable."""
    return (_executable_dir() / PORTABLE_MARKER).exists()


def _base_dir() -> Path:
    if is_portable():
        return _executable_dir()
    local = os.environ.get("LOCALAPPDATA")
    if local:
        return Path(local) / "HashTool"
    return Path.home() / ".hashtool"


def _settings_path() -> Path:
    return _base_dir() / SETTINGS_FILENAME


def data_dir() -> Path:
    """Directory for history / trust-store JSON files."""
    return _base_dir() / "data"


def history_path() -> Path:
    return data_dir() / "history.json"


def trust_store_path() -> Path:
    return data_dir() / "known_files.json"


# ----------------------------------------------------------------------
# One-time migration from the old exe-adjacent location
# ----------------------------------------------------------------------
def _legacy_settings_path() -> Path:
    return _executable_dir() / SETTINGS_FILENAME


def _copy_json(src: Path, dst: Path) -> None:
    if src.exists() and not dst.exists():
        write_json_atomic(dst, json.loads(src.read_text(encoding="utf-8")))


# Populated when a legacy plaintext key could not be scrubbed from the old
# settings file. The GUI surfaces this so the user is never told the key is
# safe while a plaintext copy is still lying around.
_migration_warnings: list[str] = []


def pending_migration_warnings() -> list[str]:
    """Return (and keep) warnings raised during the last migration attempt."""
    return list(_migration_warnings)


def clear_migration_warnings() -> None:
    """
    Drop the pending warning list (the UI has shown them).

    Deliberately does NOT reset the write-disabled state: that reflects a
    still-unreadable file on disk, not a message we have delivered.
    """
    _migration_warnings.clear()


def _reset_write_disabled_for_tests() -> None:
    """Test-only: clear the sticky write-disabled latch."""
    global _settings_write_disabled, _settings_write_disabled_reason
    _settings_write_disabled = False
    _settings_write_disabled_reason = ""


def _legacy_plaintext_key() -> str:
    """
    Read a plaintext API key still sitting in the exe-adjacent settings file.

    Checked on *every* load, independently of whether the per-user profile
    already exists: otherwise an install that migrated once would leave the
    original plaintext copy on disk forever, and a crash between "wrote the
    protected slot" and "scrubbed the plaintext" would never heal.
    """
    if is_portable():
        return ""  # that file *is* the live settings file, handled normally
    old = _legacy_settings_path()
    try:
        if not old.exists() or old.resolve() == _settings_path().resolve():
            return ""
        raw = json.loads(old.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(raw, dict):
        return ""
    return str(raw.get(KEY_VT_API_KEY, "") or "")


def _scrub_legacy_plaintext_key(old: Path) -> None:
    """
    Remove ``virustotal_api_key`` from the *old* settings file, leaving every
    other setting in place.

    Called only after the key has been confirmed re-readable from the new
    protected store, so we never delete the sole copy of a secret. Failures
    are recorded as user-visible warnings — never silently ignored — and the
    messages never contain the key itself.
    """
    try:
        raw = json.loads(old.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        _migration_warnings.append(
            f"Eski ayar dosyası okunamadı, düz metin API anahtarı hâlâ orada "
            f"olabilir: {old} ({exc.__class__.__name__})"
        )
        return
    if not isinstance(raw, dict) or KEY_VT_API_KEY not in raw:
        return  # nothing to scrub — idempotent
    raw.pop(KEY_VT_API_KEY, None)
    try:
        write_json_atomic(old, raw)
    except OSError as exc:
        # Deliberately does NOT include the secret value.
        _migration_warnings.append(
            f"Eski ayar dosyasındaki düz metin API anahtarı silinemedi: "
            f"{old} ({exc.__class__.__name__}). Dosyayı elle silmeniz önerilir."
        )


def _migrate_data_files() -> None:
    """
    Bring history / fingerprint stores over from an exe-adjacent install.

    Independent of the settings file: a data-only legacy install (or one
    whose settings were already migrated) must still be picked up.
    """
    old_data = _executable_dir() / "data"
    if not old_data.is_dir() or old_data.resolve() == data_dir().resolve():
        return
    for name in ("history.json", "known_files.json"):
        try:
            _copy_json(old_data / name, data_dir() / name)
        except (OSError, ValueError, json.JSONDecodeError):
            # A damaged legacy store must not block startup.
            pass


def _maybe_migrate_location() -> None:
    """
    Move an exe-adjacent settings/data set into the per-user base dir.

    Idempotent: safe to call on every load. Never runs in portable mode,
    where the old and new paths are the same file.
    """
    if is_portable():
        return

    # Data files migrate regardless of the settings file's state.
    _migrate_data_files()

    new = _settings_path()
    old = _legacy_settings_path()
    if not old.exists() or old.resolve() == new.resolve():
        return
    try:
        _copy_json(old, new)
    except (OSError, ValueError, json.JSONDecodeError):
        # Migration is best-effort; a fresh profile is an acceptable fallback.
        return


# ----------------------------------------------------------------------
# Raw dict API
# ----------------------------------------------------------------------
# Set when the settings file was unreadable. Mirrors the history/fingerprint
# stores: a corrupt file is quarantined (never silently replaced), and if it
# cannot be preserved we refuse to overwrite it.
_settings_write_disabled = False
_settings_write_disabled_reason = ""


def settings_write_disabled() -> tuple[bool, str]:
    """Whether saving is currently refused, and why."""
    return _settings_write_disabled, _settings_write_disabled_reason


def _handle_corrupt_settings(path: Path, reason: str) -> None:
    """Quarantine an unparsable settings file instead of overwriting it."""
    global _settings_write_disabled, _settings_write_disabled_reason
    moved = quarantine_corrupt_file(path)
    if moved is not None:
        _migration_warnings.append(
            f"Ayar dosyası okunamadı ({reason}). Bozuk dosya '{moved.name}' "
            "olarak saklandı; varsayılan ayarlarla devam ediliyor."
        )
    else:
        _settings_write_disabled = True
        _settings_write_disabled_reason = (
            f"Ayar dosyası okunamadı ({reason}) ve yedeklenemedi: {path}. "
            "Mevcut ayarları kaybetmemek için kaydetme devre dışı bırakıldı; "
            "dosyayı elle taşıyın veya silin."
        )
        _migration_warnings.append(_settings_write_disabled_reason)


def load_settings() -> dict[str, Any]:
    """Return the settings dict, or an empty dict if nothing usable exists."""
    _maybe_migrate_location()
    path = _settings_path()
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        # Genuinely corrupt content -> preserve it, don't clobber it.
        # UnicodeDecodeError matters too: a binary-garbage file is not valid
        # JSON either, and it is NOT a json.JSONDecodeError.
        _handle_corrupt_settings(path, _corrupt_reason(exc))
        return {}
    except OSError as exc:
        # Merely locked / temporarily unreadable: the bytes may be perfectly
        # fine, so NEVER quarantine here. Refuse to write instead, so a save
        # cannot replace settings we could not read.
        global _settings_write_disabled, _settings_write_disabled_reason
        _settings_write_disabled = True
        _settings_write_disabled_reason = (
            f"Ayar dosyası açılamadı ({exc.__class__.__name__}): {path}. "
            "Var olan ayarların üzerine yazmamak için kaydetme devre dışı."
        )
        if _settings_write_disabled_reason not in _migration_warnings:
            _migration_warnings.append(_settings_write_disabled_reason)
        return {}

    if not isinstance(data, dict):
        _handle_corrupt_settings(path, "beklenmeyen biçim")
        return {}
    return data


# Keys that only :class:`AppSettings` may write. A caller passing a raw dict
# (typically one it loaded at startup and has been holding ever since) must
# not be able to push a stale copy of these back over a newer value — that is
# how a privacy preference the user had just switched off came back on.
_APPSETTINGS_OWNED_KEYS = frozenset(
    {KEY_VT_AUTOQUERY, KEY_VT_API_KEY_ENC, KEY_HISTORY_LIMIT, KEY_VT_API_KEY}
)


def save_settings(data: dict[str, Any], *, _owner: bool = False) -> None:
    """
    Persist *data* merged over what is on disk, atomically.

    Merges (rather than overwrites) so a partial write from one code path
    never drops keys written by another (e.g. the encrypted API key). Always
    strips the legacy plaintext key so it can never be reintroduced. Raises
    :class:`SettingsError` on failure — never silently swallows.

    Keys in :data:`_APPSETTINGS_OWNED_KEYS` are ignored unless the caller is
    :class:`AppSettings` itself (``_owner=True``): those have a single
    authoritative writer, and honouring them from an arbitrary dict is what
    allowed a stale snapshot to revert the user's choice.
    """
    if not _owner:
        data = {k: v for k, v in data.items() if k not in _APPSETTINGS_OWNED_KEYS}
    merged = load_settings()
    # load_settings() may have just disabled writing (unreadable original).
    if _settings_write_disabled:
        raise SettingsError(_settings_write_disabled_reason)
    merged.update(data)
    merged.pop(KEY_VT_API_KEY, None)
    # A None value is an explicit "remove this key" signal (merge can't
    # otherwise delete keys the caller intends to drop).
    merged = {k: v for k, v in merged.items() if v is not None}
    try:
        write_json_atomic(_settings_path(), merged)
    except OSError as exc:
        raise SettingsError(f"Ayarlar kaydedilemedi: {exc}") from exc


# ----------------------------------------------------------------------
# Validation helpers
# ----------------------------------------------------------------------
def _valid_language(value: Any) -> str:
    text = str(value or DEFAULT_LANGUAGE)
    return text if text in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE


def _valid_online_consent(value: Any) -> bool:
    """
    Only a real JSON ``true`` enables sending hashes to a third party.

    Python's ``bool()`` says ``bool("false") is True``, which would silently
    turn a privacy setting *on* because of a hand-edited or mis-serialised
    value. Strings, numbers, null, objects and lists are all treated as "not
    consented".
    """
    return value is True


def _valid_history_limit(value: Any) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return DEFAULT_HISTORY_LIMIT
    return max(HISTORY_LIMIT_MIN, min(HISTORY_LIMIT_MAX, n))


# ----------------------------------------------------------------------
# Typed wrapper
# ----------------------------------------------------------------------
@dataclass
class AppSettings:
    """Convenience facade over the raw settings dict."""

    language: str = DEFAULT_LANGUAGE
    virustotal_api_key: str = ""
    # Opt-in by design: sending a hash to a third party is a privacy decision
    # the user has to make, so a fresh install stays offline until they do.
    virustotal_autoquery: bool = False
    history_limit: int = DEFAULT_HISTORY_LIMIT
    last_folder: str = ""
    # Informational (for the Settings UI); not persisted directly.
    secret_backend: str = "none"
    key_migrated: bool = False
    secret_state: SecretState = SecretState.ABSENT
    # The stored token when it could not be decrypted. Carried so an
    # unrelated save can write it back untouched instead of dropping it.
    _opaque_token: Optional[str] = field(default=None, repr=False)
    # Set only by clear_api_key(): the one path allowed to delete the token.
    _clear_key_requested: bool = field(default=False, repr=False)

    def clear_api_key(self) -> None:
        """Explicitly remove the stored key (the only way it gets deleted)."""
        self.virustotal_api_key = ""
        self._opaque_token = None
        self._clear_key_requested = True
        self.secret_state = SecretState.ABSENT

    # ------------------------------------------------------------------
    @classmethod
    def load(cls) -> "AppSettings":
        raw = load_settings()

        key = ""
        secret_state = SecretState.ABSENT
        opaque_token: Optional[str] = None
        enc = raw.get(KEY_VT_API_KEY_ENC)
        if enc:
            if not secret_store.is_available():
                secret_state = SecretState.UNSUPPORTED
                opaque_token = str(enc)
            else:
                try:
                    key = secret_store.unprotect(str(enc))
                    secret_state = SecretState.AVAILABLE
                except secret_store.SecretStoreError:
                    # NOT the same as "no key": keep the token so an unrelated
                    # save cannot destroy the user's only copy.
                    secret_state = SecretState.UNREADABLE
                    opaque_token = str(enc)
                    _migration_warnings.append(
                        "Kayıtlı VirusTotal API anahtarı çözülemedi (farklı bir "
                        "Windows kullanıcısı ya da bozuk kayıt olabilir). Anahtar "
                        "silinmedi; Ayarlar'dan yeni bir anahtar girebilir veya "
                        "'Anahtarı Kaldır' diyebilirsiniz."
                    )
        # Plaintext can live in two places: the current profile (very old
        # builds) and the exe-adjacent legacy file. The latter is checked on
        # every load — not only when the profile is absent — so an install
        # that already migrated once does not keep a plaintext copy forever.
        legacy_plain = str(raw.get(KEY_VT_API_KEY, "") or "") or _legacy_plaintext_key()
        if not key and legacy_plain:
            key = legacy_plain  # migration source

        obj = cls(
            language=_valid_language(raw.get(KEY_LANGUAGE)),
            virustotal_api_key=key,
            # Absent key => not yet consented. An existing stored preference
            # is preserved, but only a genuine boolean true enables it.
            virustotal_autoquery=_valid_online_consent(raw.get(KEY_VT_AUTOQUERY)),
            history_limit=_valid_history_limit(raw.get(KEY_HISTORY_LIMIT, DEFAULT_HISTORY_LIMIT)),
            last_folder=str(raw.get(KEY_LAST_FOLDER, "") or ""),
            secret_backend=secret_store.backend_name(),
            secret_state=secret_state,
            _opaque_token=opaque_token,
        )

        # Migrate a legacy plaintext key into the protected slot.
        if legacy_plain and secret_store.is_available():
            # If a previous run already wrote (and we can still read back) the
            # protected slot, the encrypt step is done — this is the
            # "crashed before scrubbing" case, so go straight to the scrub.
            if not AppSettings._protected_key_readable(key):
                try:
                    obj.save()
                except SettingsError:
                    return obj  # will retry on the next load/save

            # Only scrub the plaintext copies once the protected value is
            # confirmed readable back — never destroy the sole copy of a key.
            if AppSettings._protected_key_readable(key):
                obj.key_migrated = True
                # a) the plaintext slot in the NEW file (already stripped by
                #    save_settings, but re-assert for older files copied in).
                new_raw = load_settings()
                if KEY_VT_API_KEY in new_raw:
                    try:
                        save_settings(new_raw)
                    except SettingsError:
                        pass
                # b) the ORIGINAL exe-adjacent file, which the copy left intact.
                if not is_portable():
                    old = _legacy_settings_path()
                    if old.exists() and old.resolve() != _settings_path().resolve():
                        _scrub_legacy_plaintext_key(old)
        return obj

    def copy_for_edit(self) -> "AppSettings":
        """
        Return an independent draft for an editing UI.

        The settings screen must mutate the draft, not the live object: if the
        disk write then fails, the running application keeps working with the
        settings it actually has (and the VirusTotal client is not rebuilt
        from values that were never persisted).
        """
        return replace(self)

    @staticmethod
    def _protected_key_readable(expected: str) -> bool:
        """True when the encrypted slot decrypts back to *expected*."""
        token = load_settings().get(KEY_VT_API_KEY_ENC)
        if not token:
            return False
        try:
            return secret_store.unprotect(str(token)) == expected
        except secret_store.SecretStoreError:
            return False

    def save(self) -> None:
        # Preserve any unknown keys the user might have hand-edited.
        raw = load_settings()
        raw[KEY_LANGUAGE] = _valid_language(self.language)
        raw[KEY_VT_AUTOQUERY] = _valid_online_consent(self.virustotal_autoquery)
        raw[KEY_HISTORY_LIMIT] = _valid_history_limit(self.history_limit)
        raw[KEY_LAST_FOLDER] = self.last_folder

        key = (self.virustotal_api_key or "").strip()
        if key:
            if not secret_store.is_available():
                raise SettingsError(
                    "API anahtarı güvenli biçimde saklanamıyor: bu sistemde "
                    "güvenli anahtar deposu (DPAPI) bulunmuyor."
                )
            try:
                raw[KEY_VT_API_KEY_ENC] = secret_store.protect(key)
            except secret_store.SecretStoreError as exc:
                raise SettingsError(f"API anahtarı şifrelenemedi: {exc}") from exc
        elif self._opaque_token is not None and not self._clear_key_requested:
            # We hold a token we could not decrypt. Saving anything else (a
            # language change, a history limit) must not delete it.
            raw[KEY_VT_API_KEY_ENC] = self._opaque_token
        else:
            # None → save_settings removes the encrypted slot entirely.
            raw[KEY_VT_API_KEY_ENC] = None

        # save_settings also strips the plaintext key defensively.
        raw.pop(KEY_VT_API_KEY, None)
        # _owner: AppSettings is the authoritative writer for the keys it owns.
        save_settings(raw, _owner=True)

    @property
    def has_virustotal_key(self) -> bool:
        return bool(self.virustotal_api_key.strip())

    @property
    def has_secure_store(self) -> bool:
        return secret_store.is_available()
