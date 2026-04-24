"""
Hash Verification Tool — command-line entry point.

Subcommands:
  hash    Compute hashes for a single file or every file under a folder
          and write a JSON manifest.
  verify  Re-scan a folder and compare it against a previously-saved
          manifest, reporting unchanged / modified / new / missing.
  report  Convert a JSON verification report to another format (CSV / JSON).

Run ``python main.py --help`` to see the full option list.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core import __version__
from core.hash_utils import (
    DEFAULT_ALGORITHM,
    SUPPORTED_ALGORITHMS,
    HashError,
    ProgressEvent,
    compute_file_hash,
)
from core.manifest_manager import (
    Manifest,
    ManifestError,
    build_manifest_for_file,
    build_manifest_for_folder,
)
from core.reporter import (
    ReportError,
    convert_report,
    report_to_console,
    report_to_csv,
    report_to_json,
)
from core.verifier import Verifier
from utils.logger import get_logger, set_verbose

log = get_logger("cli")

EXIT_OK = 0
EXIT_DIFFERENCES = 1   # verify ran, found drift
EXIT_USAGE = 2         # bad arguments
EXIT_FAILURE = 3       # unrecoverable error


# ----------------------------------------------------------------------
# Argument parser
# ----------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hash-tool",
        description=(
            "Generate and verify file/folder hashes for integrity checks. "
            "Useful for forensics, backup validation and tamper detection."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"hash-tool {__version__}"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug-level logging."
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ----- hash --------------------------------------------------------
    hash_p = subparsers.add_parser(
        "hash", help="Compute hashes for a file or folder."
    )
    target = hash_p.add_mutually_exclusive_group(required=True)
    target.add_argument("--file", type=str, help="Path to a single file.")
    target.add_argument("--folder", type=str, help="Path to a folder (scanned recursively).")
    hash_p.add_argument(
        "--algo",
        choices=SUPPORTED_ALGORITHMS,
        default=DEFAULT_ALGORITHM,
        help=f"Hash algorithm (default: {DEFAULT_ALGORITHM}).",
    )
    hash_p.add_argument(
        "--output",
        type=str,
        default=None,
        help=(
            "Where to write the manifest JSON. "
            "Defaults to 'manifest.json' for folders or printing the digest "
            "to stdout for single files."
        ),
    )

    # ----- verify ------------------------------------------------------
    verify_p = subparsers.add_parser(
        "verify", help="Verify a folder against a saved manifest."
    )
    verify_p.add_argument("--folder", type=str, required=True, help="Folder to verify.")
    verify_p.add_argument(
        "--manifest", type=str, required=True, help="Manifest JSON file to compare against."
    )
    verify_p.add_argument(
        "--report",
        type=str,
        default=None,
        help="Optional path to write the verification result (json or csv based on extension).",
    )
    verify_p.add_argument(
        "--format",
        choices=("json", "csv"),
        default=None,
        help="Force the report format (otherwise inferred from --report extension).",
    )
    verify_p.add_argument(
        "--show-details",
        action="store_true",
        help="Print every modified/new/missing entry, not just the summary.",
    )

    # ----- report ------------------------------------------------------
    report_p = subparsers.add_parser(
        "report", help="Convert a JSON verification report to another format."
    )
    report_p.add_argument("--input", type=str, required=True, help="Existing JSON report.")
    report_p.add_argument(
        "--format", choices=("json", "csv"), required=True, help="Output format."
    )
    report_p.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output path (defaults to <input>.csv or <input>.converted.json).",
    )

    return parser


# ----------------------------------------------------------------------
# Subcommand handlers
# ----------------------------------------------------------------------
def _cmd_hash(args: argparse.Namespace) -> int:
    if args.file:
        try:
            digest = compute_file_hash(args.file, algorithm=args.algo)
        except HashError as exc:
            log.error("%s", exc)
            return EXIT_FAILURE

        if args.output:
            try:
                manifest = build_manifest_for_file(args.file, algorithm=args.algo)
                manifest.save(args.output)
            except (HashError, ManifestError) as exc:
                log.error("%s", exc)
                return EXIT_FAILURE
            print(f"Manifest saved: {args.output}")
        else:
            print(f"{args.algo}  {digest}  {args.file}")
        return EXIT_OK

    # Folder branch
    output = args.output or "manifest.json"
    log.info("Hashing folder %s with %s", args.folder, args.algo)

    error_count = 0

    def _on_error(rel_path: str, exc: Exception) -> None:
        nonlocal error_count
        error_count += 1
        log.warning("Skipped %s: %s", rel_path, exc)

    def _on_progress(event: ProgressEvent) -> None:
        log.debug("hashed [%d/%d] %s", event.done, event.total, event.path)

    try:
        manifest = build_manifest_for_folder(
            args.folder,
            algorithm=args.algo,
            on_error=_on_error,
            on_progress=_on_progress,
        )
        manifest.save(output)
    except (HashError, ManifestError) as exc:
        log.error("%s", exc)
        return EXIT_FAILURE

    print(
        f"Manifest written to {output} "
        f"({len(manifest.entries)} files hashed, {error_count} skipped)."
    )
    return EXIT_OK


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        manifest = Manifest.load(args.manifest)
    except ManifestError as exc:
        log.error("Could not load manifest: %s", exc)
        return EXIT_FAILURE

    log.info(
        "Verifying %s against %s (algo=%s, %d entries)",
        args.folder,
        args.manifest,
        manifest.algorithm,
        len(manifest.entries),
    )

    def _on_verify_progress(event: ProgressEvent) -> None:
        log.debug("verified [%d/%d] %s", event.done, event.total, event.path)

    try:
        result = Verifier(manifest).verify(args.folder, on_progress=_on_verify_progress)
    except (FileNotFoundError, HashError) as exc:
        log.error("%s", exc)
        return EXIT_FAILURE

    report_to_console(result, verbose=args.show_details)

    if args.report:
        fmt = args.format or _infer_format(args.report)
        try:
            if fmt == "json":
                report_to_json(result, args.report)
            elif fmt == "csv":
                report_to_csv(result, args.report)
            else:
                log.error("Unknown report format: %s", fmt)
                return EXIT_USAGE
            print(f"Report written: {args.report}")
        except ReportError as exc:
            log.error("%s", exc)
            return EXIT_FAILURE

    return EXIT_OK if result.is_clean else EXIT_DIFFERENCES


def _cmd_report(args: argparse.Namespace) -> int:
    output = args.output or _default_output_for(args.input, args.format)
    try:
        path = convert_report(args.input, output, args.format)
    except ReportError as exc:
        log.error("%s", exc)
        return EXIT_FAILURE
    print(f"Report converted: {path}")
    return EXIT_OK


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _infer_format(path: str) -> str:
    suffix = Path(path).suffix.lower().lstrip(".")
    return suffix if suffix in {"json", "csv"} else "json"


def _default_output_for(input_path: str, fmt: str) -> str:
    p = Path(input_path)
    if fmt == "csv":
        return str(p.with_suffix(".csv"))
    return str(p.with_name(p.stem + ".converted.json"))


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    set_verbose(args.verbose)

    handlers = {
        "hash": _cmd_hash,
        "verify": _cmd_verify,
        "report": _cmd_report,
    }
    handler = handlers.get(args.command)
    if handler is None:  # argparse already enforces this, kept for safety
        parser.print_help()
        return EXIT_USAGE
    try:
        return handler(args)
    except KeyboardInterrupt:
        log.warning("Interrupted by user.")
        return EXIT_FAILURE
    except Exception as exc:  # last-resort safety net
        log.exception("Unexpected error: %s", exc)
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
