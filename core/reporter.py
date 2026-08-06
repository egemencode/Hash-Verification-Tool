"""
Reporting layer.

Renders a VerificationResult to:
  * the terminal (with optional colour),
  * a JSON file,
  * or a flat CSV file.

Colour support is loaded lazily via colorama. The tool degrades
gracefully if colorama is missing or if stdout is not a TTY.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any

from core.manifest_manager import SignatureState
from core.verifier import VerificationResult

# Try to enable colour on Windows. If colorama is missing we silently
# fall back to plain text — the CLI must work without optional deps.
try:
    from colorama import Fore, Style, init as _color_init  # type: ignore

    _color_init()
    _HAVE_COLOR = True
except Exception:  # pragma: no cover - optional dependency
    _HAVE_COLOR = False

    class _Dummy:
        def __getattr__(self, _name: str) -> str:
            return ""

    Fore = _Dummy()  # type: ignore
    Style = _Dummy()  # type: ignore


_STATUS_COLORS = {
    "unchanged": "GREEN",
    "modified": "YELLOW",
    "new": "CYAN",
    "missing": "RED",
    "errors": "MAGENTA",
}


class ReportError(Exception):
    """Raised when a report cannot be written."""


def _colorise(text: str, color_name: str) -> str:
    if not _HAVE_COLOR or not sys.stdout.isatty():
        return text
    color = getattr(Fore, color_name, "")
    reset = getattr(Style, "RESET_ALL", "")
    return f"{color}{text}{reset}"


# ----------------------------------------------------------------------
# Console
# ----------------------------------------------------------------------
def report_to_console(result: VerificationResult, verbose: bool = False) -> None:
    """Print a human-readable summary (and optional details) to stdout."""
    summary = result.summary()

    print()
    print(_colorise("=== Hash Verification Report ===", "CYAN"))
    print(f"Folder    : {result.folder}")
    print(f"Algorithm : {result.algorithm}")
    print()
    print("Summary:")
    print(f"  Total scanned : {summary['total_scanned']}")
    for key in ("unchanged", "modified", "new", "missing", "errors"):
        label = key.capitalize().ljust(13)
        value = summary[key]
        line = f"  {label} : {value}"
        print(_colorise(line, _STATUS_COLORS[key]) if value else line)

    if verbose:
        _print_detail_section("Modified", [m.path for m in result.modified], "YELLOW")
        _print_detail_section("New", result.new, "CYAN")
        _print_detail_section("Missing", result.missing, "RED")
        _print_detail_section(
            "Errors",
            [f"{e.path}  ->  {e.error}" for e in result.errors],
            "MAGENTA",
        )

    print()
    if not result.is_clean:
        print(_colorise("Differences detected. Review the report above.", "YELLOW"))
        return

    # "The files match" and "the reference can be trusted" are separate
    # claims. Only a manifest verified against an out-of-band key earns the
    # unqualified wording.
    if result.signature_state is SignatureState.TRUSTED:
        print(_colorise(
            "All files match a manifest verified with your trusted key.", "GREEN"
        ))
    elif result.signature_state is SignatureState.VALID_EMBEDDED:
        print(_colorise(
            "All files match the manifest, but the manifest's origin was not "
            "verified (it is signed only with its own embedded key).", "YELLOW"
        ))
    else:
        print(_colorise(
            "All files match the manifest, but the manifest is unsigned — the "
            "reference data itself could have been altered.", "YELLOW"
        ))


def _print_detail_section(title: str, items: list[str], color: str) -> None:
    if not items:
        return
    print()
    print(_colorise(f"-- {title} ({len(items)}) --", color))
    for item in items:
        print(f"  {item}")


# ----------------------------------------------------------------------
# JSON
# ----------------------------------------------------------------------
def report_to_json(
    result_or_dict: VerificationResult | dict[str, Any],
    output_path: str | Path,
) -> Path:
    """Persist the verification result as pretty-printed JSON."""
    data = (
        result_or_dict.to_dict()
        if isinstance(result_or_dict, VerificationResult)
        else result_or_dict
    )
    path = Path(output_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
    except OSError as exc:
        raise ReportError(f"Cannot write JSON report to {path}: {exc}") from exc
    return path


# ----------------------------------------------------------------------
# CSV
# ----------------------------------------------------------------------
_CSV_HEADER = ["status", "path", "old_hash", "new_hash", "old_size", "new_size", "error"]

# Cells beginning with any of these are interpreted as a formula by Excel /
# LibreOffice / Google Sheets. A hostile file path or error string could
# therefore run a formula in whoever opens the report. We neutralise them by
# prefixing with a single quote (the value is preserved, just forced to text).
_CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: Any) -> Any:
    """Neutralise a potential spreadsheet-formula cell (strings only)."""
    if isinstance(value, str) and value and value[0] in _CSV_INJECTION_PREFIXES:
        return "'" + value
    return value


def report_to_csv(
    result_or_dict: VerificationResult | dict[str, Any],
    output_path: str | Path,
    *,
    sanitize: bool = True,
) -> Path:
    """
    Persist the verification result as a flat CSV.

    By default (``sanitize=True``) any text cell that would be treated as a
    formula by a spreadsheet program is prefixed with a single quote so it is
    rendered as literal text. Pass ``sanitize=False`` only when producing CSV
    for machine consumption where the raw values are required.
    """
    data = (
        result_or_dict.to_dict()
        if isinstance(result_or_dict, VerificationResult)
        else result_or_dict
    )
    details = data.get("details", {})

    rows: list[list[Any]] = []
    for path in details.get("unchanged", []):
        rows.append(["unchanged", path, "", "", "", "", ""])
    for entry in details.get("modified", []):
        rows.append([
            "modified",
            entry.get("path", ""),
            entry.get("old_hash", ""),
            entry.get("new_hash", ""),
            entry.get("old_size", ""),
            entry.get("new_size", ""),
            "",
        ])
    for path in details.get("new", []):
        rows.append(["new", path, "", "", "", "", ""])
    for path in details.get("missing", []):
        rows.append(["missing", path, "", "", "", "", ""])
    for entry in details.get("errors", []):
        rows.append([
            "error",
            entry.get("path", ""),
            "",
            "",
            "",
            "",
            entry.get("error", ""),
        ])

    if sanitize:
        rows = [[_csv_safe(cell) for cell in row] for row in rows]

    path = Path(output_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # newline="" is required so csv does not double-write CRLF on Windows.
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(_CSV_HEADER)
            writer.writerows(rows)
    except OSError as exc:
        raise ReportError(f"Cannot write CSV report to {path}: {exc}") from exc
    return path


# ----------------------------------------------------------------------
# Convenience: convert an existing JSON report to another format.
# ----------------------------------------------------------------------
def convert_report(
    input_path: str | Path,
    output_path: str | Path,
    output_format: str,
) -> Path:
    """Read a JSON report from disk and re-emit it in *output_format*."""
    in_path = Path(input_path)
    if not in_path.exists():
        raise ReportError(f"Input report not found: {in_path}")
    try:
        with in_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ReportError(f"Input report is not valid JSON: {exc}") from exc

    fmt = output_format.lower().strip()
    if fmt == "json":
        return report_to_json(data, output_path)
    if fmt == "csv":
        return report_to_csv(data, output_path)
    raise ReportError(f"Unsupported report format: {output_format}")
