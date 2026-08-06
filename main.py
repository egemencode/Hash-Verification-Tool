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
    ManifestIntegrityError,
    SignatureState,
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


def _apply_output_encoding_contract() -> None:
    """
    Encoding contract: this CLI always writes UTF-8.

    Console output otherwise follows the active code page (cp1254 on a Turkish
    Windows), so the same message is bytes-different depending on who runs it
    — and Turkish characters in paths or messages raise
    UnicodeEncodeError outright. Callers and tests can therefore decode our
    stdout/stderr as UTF-8 unconditionally. ``errors="replace"`` keeps a
    stray undecodable byte from killing the run.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):  # pragma: no cover - exotic streams
                pass

# Exit codes are part of the CLI contract: each failure mode a script might
# want to react to differently gets its own code.
EXIT_OK = 0
EXIT_DIFFERENCES = 1        # verify ran, files differ from the manifest
EXIT_USAGE = 2              # bad arguments
EXIT_FAILURE = 3            # unrecoverable error (missing/unreadable input)
EXIT_MANIFEST_INVALID = 4   # manifest is corrupt / schema unsupported
EXIT_UNTRUSTED_REFERENCE = 5  # signature missing or unverifiable
EXIT_INCOMPLETE = 6         # scan could not cover the whole folder


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
        "--write-partial",
        action="store_true",
        help=(
            "If the folder cannot be fully scanned, still write a clearly "
            "marked <output>.partial.json artefact. Without this, an "
            "incomplete scan writes nothing, because a manifest sitting at "
            "the expected path would be taken as a full description of the "
            "folder."
        ),
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
    verify_p.add_argument(
        "--allow-unsigned",
        action="store_true",
        help=(
            "Accept a manifest whose origin cannot be verified (unsigned, or "
            "signed only with a key embedded in the manifest itself). Without "
            "this flag such a reference exits with code 5, because matching an "
            "unverifiable reference does not establish integrity."
        ),
    )
    verify_p.add_argument(
        "--trusted-key",
        type=str,
        default=None,
        help=(
            "Ed25519 public key (hex) to verify a signed manifest against. "
            "Without it a signed manifest can only be checked against its own "
            "embedded key, which proves consistency but not external trust."
        ),
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
        build = build_manifest_for_folder(
            args.folder,
            algorithm=args.algo,
            on_error=_on_error,
            on_progress=_on_progress,
            # Never let the manifest we are about to write become part of its
            # own inventory.
            exclude=[output],
        )
    except (HashError, ManifestError) as exc:
        log.error("%s", exc)
        return EXIT_FAILURE

    if build.complete:
        try:
            build.save(output)
        except ManifestError as exc:
            log.error("%s", exc)
            return EXIT_FAILURE
        print(f"Manifest written to {output} ({build.file_count} files hashed).")
        return EXIT_OK

    # A partial manifest is NOT a success: it records a folder we could not
    # fully read, so anything it misses would silently verify as "unchanged".
    # Nothing is written to the expected path — only, on request, a clearly
    # named .partial.json artefact.
    written = None
    if getattr(args, "write_partial", False):
        try:
            written = build.save(output, allow_partial=True)
        except ManifestError as exc:
            log.error("%s", exc)
    print(
        f"KISMİ tarama: {build.file_count} dosya işlendi, "
        f"{len(build.skipped)} atlandı, "
        f"{len(build.changed_during_scan)} dosya tarama sırasında değişti. "
        + (
            f"Kısmi artefakt: {written}"
            if written
            else f"Manifest YAZILMADI ({output}). Kısmi bir artefakt için "
                 "--write-partial kullanın."
        ),
        file=sys.stderr,
    )
    for rel, reason in build.errors[:20]:
        print(f"  atlandı: {rel} -> {reason}", file=sys.stderr)
    return EXIT_INCOMPLETE


def _cmd_verify(args: argparse.Namespace) -> int:
    trusted_key = getattr(args, "trusted_key", None)
    try:
        manifest = Manifest.load(args.manifest, trusted_public_hex=trusted_key)
    except ManifestIntegrityError as exc:
        # A manifest that claims integrity protection but cannot prove it is a
        # tampering signal, not a generic parse failure — say so plainly.
        log.error("MANIFEST INTEGRITY FAILURE: %s", exc)
        print(
            "HATA: Manifest imzası doğrulanamadı — bu manifest kurcalanmış "
            "olabilir. Doğrulama yapılmadı.",
            file=sys.stderr,
        )
        return EXIT_UNTRUSTED_REFERENCE
    except ManifestError as exc:
        log.error("Could not load manifest: %s", exc)
        # Distinguish "no such manifest" from "this file is not a usable
        # manifest": a caller script reacts differently to each.
        if not Path(args.manifest).exists():
            print(f"HATA: Manifest bulunamadı: {args.manifest}", file=sys.stderr)
            return EXIT_FAILURE
        print(f"HATA: Manifest okunamadı/geçersiz: {exc}", file=sys.stderr)
        return EXIT_MANIFEST_INVALID

    reference_trusted = manifest.signature_state is SignatureState.TRUSTED
    allow_unsigned = bool(getattr(args, "allow_unsigned", False))

    if reference_trusted:
        print("Manifest imzası güvenilen anahtarla doğrulandı.")
    elif manifest.signature_state is SignatureState.VALID_EMBEDDED:
        print(
            "UYARI: Manifest imzası geçerli ama yalnızca kendi gömülü "
            "anahtarıyla doğrulandı — kaynağı doğrulanmadı. "
            "Dış güven için --trusted-key kullanın."
        )
    else:
        print(
            "UYARI: Bu manifest imzasız — referans veriler bir saldırgan "
            "tarafından değiştirilmiş olabilir."
        )

    if not reference_trusted and not allow_unsigned:
        # Matching an unverifiable reference proves consistency, not
        # integrity. Rather than quietly returning success for backwards
        # compatibility, require the caller to say they accept that.
        print(
            "HATA: Referansın kaynağı doğrulanamadı. Karşılaştırma yapılmadı.\n"
            "      İmzalı bir manifesti --trusted-key ile doğrulayın veya "
            "bilinçli olarak --allow-unsigned kullanın.",
            file=sys.stderr,
        )
        return EXIT_UNTRUSTED_REFERENCE

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
        result = Verifier(manifest, trusted_public_hex=trusted_key).verify(
            args.folder,
            on_progress=_on_verify_progress,
            # The manifest (and any report we write into the tree) is not part
            # of the data being verified.
            exclude=[args.manifest] + ([args.report] if args.report else []),
        )
    except ManifestIntegrityError as exc:
        log.error("MANIFEST INTEGRITY FAILURE: %s", exc)
        print(f"HATA: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except (FileNotFoundError, HashError) as exc:
        log.error("%s", exc)
        return EXIT_FAILURE

    # Record that the caller consciously accepted an unverifiable reference,
    # so the JSON report says how this result was reached.
    result.policy_accepted = allow_unsigned and not reference_trusted

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

    # Derive the exit code from the typed outcome rather than the ambiguous
    # is_clean flag: a scan that could not observe the whole folder is not a
    # pass, even when every file it did see matched.
    if not result.scan_complete:
        print(
            "HATA: Klasör tarama sırasında değişti "
            f"({len(result.changed_during_scan)} yol); sonuç tek bir ana ait "
            "değil.",
            file=sys.stderr,
        )
        return EXIT_INCOMPLETE
    if not result.files_match:
        return EXIT_DIFFERENCES
    return EXIT_OK


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
    _apply_output_encoding_contract()
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
