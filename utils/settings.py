"""
Tiny JSON settings store.

The file lives next to the running executable when the tool is built as
a PyInstaller --onefile bundle, and next to the source tree when run
as plain Python. Failures during load/save are swallowed so a corrupt
or read-only settings file never prevents the app from starting.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

SETTINGS_FILENAME = "hashtool_settings.json"


def _settings_path() -> Path:
    # PyInstaller sets sys.frozen; sys.executable points at the exe itself.
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / SETTINGS_FILENAME
    return Path(__file__).resolve().parent.parent / SETTINGS_FILENAME


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
