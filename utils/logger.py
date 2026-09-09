"""
Lightweight logging helper.

Use `get_logger("module.name")` everywhere instead of constructing a
new logger by hand. Logs go to stderr and, when a writable directory is
available, also to a `hash_tool.log` file under the per-user data dir.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

_LOG_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_root_configured = False


def _fallback_logs_dir() -> Path:
    """Source-adjacent logs dir, used only if the per-user base is unreachable."""
    return Path(__file__).resolve().parent.parent / "logs"


def _logs_dir() -> Path:
    """
    Where log files go: the per-user data dir that settings also uses.

    Imported lazily to avoid an import cycle — settings' own dependencies log
    through this module. Falls back to a source-adjacent ``logs/`` dir if
    settings cannot be reached, so logging never depends on it. This matters
    for PyInstaller onefile builds, whose ``__file__`` is a temporary _MEI
    directory that vanishes on exit — writing there loses the logs.
    """
    try:
        from utils.settings import base_dir
        return base_dir() / "logs"
    except (ImportError, OSError):
        return _fallback_logs_dir()


def _configure_root(level: int = logging.INFO) -> None:
    global _root_configured
    if _root_configured:
        return

    root = logging.getLogger("hash_tool")
    root.setLevel(level)
    root.propagate = False

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    # In PyInstaller --noconsole builds, sys.stderr is None — guard
    # against that so the GUI exe does not crash the first time we log.
    if sys.stderr is not None:
        stream = logging.StreamHandler(stream=sys.stderr)
        stream.setFormatter(formatter)
        root.addHandler(stream)

    # Best-effort file handler. If the directory cannot be created
    # (e.g. read-only install) we fall back to console-only logging.
    try:
        log_dir = _logs_dir()
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(
            log_dir / "hash_tool.log", encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except OSError:
        pass

    _root_configured = True


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """Return a child logger under the 'hash_tool' namespace."""
    _configure_root(level)
    return logging.getLogger(f"hash_tool.{name}")


def set_verbose(verbose: bool) -> None:
    """Switch the root logger between INFO and DEBUG."""
    _configure_root()
    logging.getLogger("hash_tool").setLevel(
        logging.DEBUG if verbose else logging.INFO
    )


def _reset() -> None:
    """Close and drop all handlers, allowing reconfiguration.

    Test hook: a test that redirects the per-user data dir to a temp tree must
    release the open log file before Windows will let that tree be removed. The
    next ``get_logger`` reopens handlers against the settings in force then.
    """
    global _root_configured
    root = logging.getLogger("hash_tool")
    for handler in list(root.handlers):
        handler.close()
        root.removeHandler(handler)
    _root_configured = False
