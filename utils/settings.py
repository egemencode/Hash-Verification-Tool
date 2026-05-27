"""
Tiny JSON settings store.

The file lives next to the running executable when the tool is built as
a PyInstaller --onefile bundle, and next to the source tree when run
as plain Python. Failures during load/save are swallowed so a corrupt
or read-only settings file never prevents the app from starting.

Beyond the original load/save API, this module also exposes a small
:class:`AppSettings` wrapper with typed accessors for the trust-check
preferences (VirusTotal API key, history limits, auto-scan toggles).
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SETTINGS_FILENAME = "hashtool_settings.json"

# --- Keys ----------------------------------------------------------------
# Keep these as module-level constants so unit tests and the GUI never
# have to repeat the string literals.
KEY_LANGUAGE = "language"
KEY_VT_API_KEY = "virustotal_api_key"
KEY_VT_AUTOQUERY = "virustotal_autoquery"
KEY_HISTORY_LIMIT = "history_limit"
KEY_LAST_FOLDER = "last_folder"


# ----------------------------------------------------------------------
# Filesystem location
# ----------------------------------------------------------------------
def _settings_path() -> Path:
    # PyInstaller sets sys.frozen; sys.executable points at the exe itself.
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / SETTINGS_FILENAME
    return Path(__file__).resolve().parent.parent / SETTINGS_FILENAME


def data_dir() -> Path:
    """
    Return the directory where history / trust-store JSON files live.

    Same parent as the settings file so everything ships together.
    """
    return _settings_path().parent / "data"


def history_path() -> Path:
    return data_dir() / "history.json"


def trust_store_path() -> Path:
    return data_dir() / "known_files.json"


# ----------------------------------------------------------------------
# Raw dict API (kept for backwards compatibility)
# ----------------------------------------------------------------------
def load_settings() -> dict[str, Any]:
    """Return the settings dict, or an empty dict if nothing usable exists."""
    path = _settings_path()
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_settings(data: dict[str, Any]) -> None:
    """Persist *data* as pretty-printed JSON. Best-effort — never raises."""
    path = _settings_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
    except OSError:
        pass


# ----------------------------------------------------------------------
# Typed wrapper
# ----------------------------------------------------------------------
@dataclass
class AppSettings:
    """Convenience facade over the raw settings dict."""

    language: str = "tr"
    virustotal_api_key: str = ""
    virustotal_autoquery: bool = True
    history_limit: int = 50
    last_folder: str = ""

    # ------------------------------------------------------------------
    @classmethod
    def load(cls) -> "AppSettings":
        raw = load_settings()
        return cls(
            language=str(raw.get(KEY_LANGUAGE, "tr") or "tr"),
            virustotal_api_key=str(raw.get(KEY_VT_API_KEY, "") or ""),
            virustotal_autoquery=bool(raw.get(KEY_VT_AUTOQUERY, True)),
            history_limit=int(raw.get(KEY_HISTORY_LIMIT, 50) or 50),
            last_folder=str(raw.get(KEY_LAST_FOLDER, "") or ""),
        )

    def save(self) -> None:
        # Preserve any unknown keys the user might have hand-edited.
        raw = load_settings()
        raw[KEY_LANGUAGE] = self.language
        raw[KEY_VT_API_KEY] = self.virustotal_api_key
        raw[KEY_VT_AUTOQUERY] = self.virustotal_autoquery
        raw[KEY_HISTORY_LIMIT] = self.history_limit
        raw[KEY_LAST_FOLDER] = self.last_folder
        save_settings(raw)

    @property
    def has_virustotal_key(self) -> bool:
        return bool(self.virustotal_api_key.strip())
