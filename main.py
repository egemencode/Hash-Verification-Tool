"""
Hash Verification Tool — command-line entry point.

Subcommands:
  hash     Compute hashes for a single file or every file under a folder
           and write a JSON manifest (optionally signed).
  verify   Re-scan a folder and compare it against a previously-saved
           manifest, reporting unchanged / modified / new / missing.
  keygen   Create an Ed25519 signing keypair.
  sign     Sign an existing manifest with a private key.
  inspect  Describe a manifest (schema, coverage, signature) without scanning.
  report   Convert a JSON verification report to another format (CSV / JSON).

Run ``python main.py --help`` to see the full option list.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from core import __version__
from core.hash_utils import (
    DEFAULT_ALGORITHM,
    SUPPORTED_ALGORITHMS,
    HashError,
    ProgressEvent,
    hash_file_with_snapshot,
    is_collision_prone,
)
from core.key_files import KeyFileError, create_keypair, storage_backend
from core import key_files
from core.manifest_manager import (
    Manifest,
    ManifestError,
    ManifestIntegrityError,
    SignatureState,
    build_manifest_for_folder,
    manifest_from_hashed_file,
)
from core.reporter import (
    ReportError,
    convert_report,
    report_to_console,
    report_to_csv,
    report_to_json,
)
from core.scan_policy import (
    confirmations,
    evaluate_hash_request,
    first_blocking,
    is_inside,
    resolved as _resolved,
    warnings as policy_warnings,
)
from core import manifest_signing
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
EXIT_CANCELLED = 7          # the user stopped the run


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
        "--allow-insecure-algorithm",
        action="store_true",
        help=(
            "Required to build a manifest with MD5 or SHA-1. Collisions under "
            "these algorithms are practically constructible, so a later match "
            "shows the digests agree — not that the file was not replaced."
        ),
    )
    hash_p.add_argument(
        "--follow-symlinks",
        action="store_true",
        help=(
            "Descend into symlinks and Windows junctions. Targets that resolve "
            "outside the scanned folder are still skipped, so a link cannot "
            "smuggle foreign files into the manifest."
        ),
    )
    hash_p.add_argument(
        "--sign-key",
        type=str,
        default=None,
        help=(
            "Private key file (see `keygen`) used to sign the manifest. The "
            "key must not live inside the scanned folder or next to the "
            "manifest — publishing it there would let anyone forge manifests."
        ),
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
        "--follow-symlinks",
        action="store_true",
        help="Descend into symlinks/junctions that stay inside the folder.",
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
            "Ed25519 public key to verify a signed manifest against — a .pub "
            "file from `keygen`, or the raw hex. Without it a signed manifest "
            "can only be checked against its own embedded key, which proves "
            "consistency but not external trust."
        ),
    )

    # ----- keygen ------------------------------------------------------
    keygen_p = subparsers.add_parser(
        "keygen", help="Create an Ed25519 signing keypair."
    )
    keygen_p.add_argument(
        "--out", type=str, required=True,
        help="Where to write the private key. The public half goes to <out>.pub.",
    )
    keygen_p.add_argument(
        "--portable",
        action="store_true",
        help=(
            "Store the private key as plain hex instead of protecting it with "
            "DPAPI. Needed to move the key to another account or machine; "
            "anyone who can read the file can then sign as you."
        ),
    )

    # ----- sign --------------------------------------------------------
    sign_p = subparsers.add_parser(
        "sign", help="Sign an existing manifest."
    )
    sign_p.add_argument("--manifest", type=str, required=True, help="Manifest to sign.")
    sign_p.add_argument("--key", type=str, required=True, help="Private key file.")
    sign_p.add_argument(
        "--output", type=str, default=None,
        help="Write the signed manifest here instead of in place.",
    )
    sign_p.add_argument(
        "--force", action="store_true",
        help="Replace an existing signature.",
    )

    # ----- inspect -----------------------------------------------------
    inspect_p = subparsers.add_parser(
        "inspect",
        help="Describe a manifest's coverage and signature without scanning.",
    )
    inspect_p.add_argument("--manifest", type=str, required=True)
    inspect_p.add_argument(
        "--trusted-key", type=str, default=None,
        help="Public key (.pub file or hex) to check the signature against.",
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
# Key helpers
# ----------------------------------------------------------------------
def load_public_key(reference: str) -> str:
    """Public wrapper so callers/tests can resolve a key the way the CLI does."""
    return key_files.load_public_key(reference)


def load_private_key(path: str) -> str:
    """Return the private key hex stored at *path*."""
    return key_files.load_private_key(path).private_hex


# ----------------------------------------------------------------------
# Subcommand handlers
# ----------------------------------------------------------------------
def _cmd_hash(args: argparse.Namespace) -> int:
    algo = args.algo
    signing_key_path = getattr(args, "sign_key", None)
    allow_insecure = bool(getattr(args, "allow_insecure_algorithm", False))
    mode = "file" if args.file else "folder"
    target = args.file or args.folder
    # For folders the manifest has a default location, so the policy must see
    # the path that will actually be written.
    effective_output = args.output or (None if args.file else "manifest.json")

    # Every rule is evaluated before a single byte is read: a refusal must not
    # leave a half-written manifest behind.
    notices = evaluate_hash_request(
        mode=mode,
        target=target,
        output=effective_output,
        algorithm=algo,
        allow_insecure_algorithm=allow_insecure,
        sign_key=signing_key_path,
    )
    blocking = first_blocking(notices)
    if blocking is not None:
        print(f"HATA: {blocking.message}", file=sys.stderr)
        return EXIT_USAGE
    for notice in confirmations(notices):
        # There is no prompt in a non-interactive CLI: the "yes" is the flag.
        print(
            f"HATA: {notice.message}\n"
            "      Bilinçli olarak devam etmek için "
            "--allow-insecure-algorithm ekleyin.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    for notice in policy_warnings(notices):
        print(f"UYARI: {notice.message}", file=sys.stderr)

    # ---- single file --------------------------------------------------
    if args.file:
        if signing_key_path:
            print(
                "HATA: --sign-key yalnız klasör manifestleri için geçerli.",
                file=sys.stderr,
            )
            return EXIT_USAGE

        try:
            # One read, one point in time. Strict only when the result becomes
            # a stored reference; printing a checksum of a live file stays
            # tolerant, as it always was.
            digest, snapshot = hash_file_with_snapshot(
                args.file, algorithm=algo, ensure_stable=bool(args.output)
            )
        except HashError as exc:
            log.error("%s", exc)
            return EXIT_FAILURE

        print(f"{algo}  {digest}  {args.file}")
        if args.output:
            try:
                manifest = manifest_from_hashed_file(
                    args.file, algo, digest, snapshot
                )
                manifest.save(args.output)
            except (HashError, ManifestError) as exc:
                log.error("%s", exc)
                return EXIT_FAILURE
            print(f"Manifest saved: {args.output}")
        return EXIT_OK

    # ---- folder -------------------------------------------------------
    output = effective_output
    folder = args.folder
    follow_symlinks = bool(getattr(args, "follow_symlinks", False))

    private_hex = None
    if signing_key_path:
        try:
            private_hex = load_private_key(signing_key_path)
        except KeyFileError as exc:
            print(f"HATA: {exc}", file=sys.stderr)
            return EXIT_USAGE

    log.info("Hashing folder %s with %s", folder, algo)

    def _on_error(rel_path: str, exc: Exception) -> None:
        log.warning("Skipped %s: %s", rel_path, exc)

    def _on_progress(event: ProgressEvent) -> None:
        log.debug(
            "hashed [%d/%d] %s (%s)", event.done, event.total, event.path,
            event.state.value,
        )

    try:
        build = build_manifest_for_folder(
            folder,
            algorithm=algo,
            on_error=_on_error,
            on_progress=_on_progress,
            follow_symlinks=follow_symlinks,
            # Never let the manifest we are about to write become part of its
            # own inventory.
            exclude=[output],
        )
    except (HashError, ManifestError) as exc:
        log.error("%s", exc)
        return EXIT_FAILURE

    if build.complete:
        if private_hex is not None:
            try:
                build.manifest.sign(private_hex)
            except (ManifestError, manifest_signing.SigningError) as exc:
                print(f"HATA: Manifest imzalanamadı: {exc}", file=sys.stderr)
                return EXIT_FAILURE
        try:
            build.save(output)
        except ManifestError as exc:
            log.error("%s", exc)
            return EXIT_FAILURE
        print(f"Manifest written to {output} ({build.file_count} files hashed).")
        if private_hex is not None:
            print(
                "Manifest imzalandı. Doğrularken: "
                f"verify --trusted-key {key_files.public_path_for(signing_key_path)}"
            )
        return EXIT_OK

    # A partial manifest is NOT a success: it records a folder we could not
    # fully read, so anything it misses would silently verify as "unchanged".
    # Nothing is written to the expected path — only, on request, a clearly
    # named .partial.json artefact. It is never signed: a signature would
    # attest to a description that knowingly has holes in it.
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
    raw_key = getattr(args, "trusted_key", None)
    trusted_key = None
    if raw_key:
        try:
            trusted_key = load_public_key(raw_key)
        except KeyFileError as exc:
            print(f"HATA: --trusted-key okunamadı: {exc}", file=sys.stderr)
            return EXIT_USAGE

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
        log.debug(
            "verified [%d/%d] %s (%s)", event.done, event.total, event.path,
            event.state.value,
        )

    try:
        result = Verifier(manifest, trusted_public_hex=trusted_key).verify(
            args.folder,
            on_progress=_on_verify_progress,
            follow_symlinks=bool(getattr(args, "follow_symlinks", False)),
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
    if result.cancelled:
        return EXIT_CANCELLED
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


def _cmd_keygen(args: argparse.Namespace) -> int:
    if not manifest_signing.is_available():
        print(
            "HATA: İmzalama için 'cryptography' paketi gerekli "
            "(pip install cryptography).",
            file=sys.stderr,
        )
        return EXIT_FAILURE
    try:
        priv_path, pub_path, public_hex = create_keypair(
            args.out, portable=bool(getattr(args, "portable", False))
        )
    except KeyFileError as exc:
        print(f"HATA: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except manifest_signing.SigningError as exc:
        print(f"HATA: Anahtar üretilemedi: {exc}", file=sys.stderr)
        return EXIT_FAILURE

    portable = bool(getattr(args, "portable", False))
    print(f"Özel anahtar : {priv_path}")
    print(f"Genel anahtar: {pub_path}")
    print(f"Genel anahtar (hex): {public_hex}")
    print(
        "Saklama: "
        + ("korumasız düz metin (--portable)" if portable else storage_backend())
    )
    print()
    print("Sonraki adımlar:")
    print(f"  hash   --folder <klasör> --output <manifest> --sign-key {priv_path}")
    print(f"  verify --folder <klasör> --manifest <manifest> --trusted-key {pub_path}")
    print(
        "Genel anahtarı doğrulayacak kişilere manifestten AYRI bir kanalla "
        "iletin; manifestle birlikte gelen bir anahtar hiçbir şey kanıtlamaz."
    )
    if portable:
        print(
            "UYARI: Özel anahtar korumasız yazıldı; bu dosyayı okuyabilen "
            "herkes sizin adınıza imzalayabilir.",
            file=sys.stderr,
        )
    return EXIT_OK


def _cmd_sign(args: argparse.Namespace) -> int:
    try:
        private_hex = load_private_key(args.key)
    except KeyFileError as exc:
        print(f"HATA: {exc}", file=sys.stderr)
        return EXIT_USAGE

    output = args.output or args.manifest
    if _resolved(args.key).parent == _resolved(output).parent:
        print(
            f"HATA: Özel anahtar imzalanan manifestle aynı klasörde "
            f"({args.key}). Özel anahtar, imzaladığı belgeyle birlikte "
            "dağıtılmamalı.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    try:
        manifest = Manifest.load(args.manifest, verify_integrity=False)
    except ManifestError as exc:
        print(f"HATA: Manifest okunamadı: {exc}", file=sys.stderr)
        return EXIT_MANIFEST_INVALID

    # `hash --sign-key` refuses a key stored inside the folder being scanned.
    # Signing afterwards is the obvious way round that, so the same rule has to
    # hold here — otherwise the guard is decoration and the published folder
    # still ships the key that signs manifests for it.
    if manifest.root_path and is_inside(args.key, manifest.root_path):
        print(
            f"HATA: Özel anahtar, manifestin tarif ettiği klasörün içinde "
            f"({args.key} -> {manifest.root_path}). Klasörü alan herkes "
            "anahtarı da alır ve sizin adınıza manifest imzalayabilir.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    if manifest.is_signed:
        if not getattr(args, "force", False):
            print(
                "HATA: Bu manifest zaten imzalı. Mevcut imzayı değiştirmek için "
                "--force kullanın.",
                file=sys.stderr,
            )
            return EXIT_USAGE
        try:
            # --force means "replace this signature", not "vouch for whatever
            # the file says now". A signature that no longer verifies means the
            # content changed after it was signed; re-signing would put the
            # operator's real key behind that change, and the routine habit of
            # re-signing would become the step that launders tampering.
            manifest.check_integrity(None)
        except ManifestIntegrityError as exc:
            print(
                f"HATA: Mevcut imza doğrulanmıyor: {exc}\n"
                "      Bu, manifest imzalandıktan SONRA değiştirildiği "
                "anlamına gelir; yeniden imzalamak bu değişikliği onaylamak "
                "olurdu. Manifesti klasörden yeniden üretin.",
                file=sys.stderr,
            )
            return EXIT_MANIFEST_INVALID

    try:
        manifest.sign(private_hex)
    except (ManifestError, manifest_signing.SigningError) as exc:
        print(f"HATA: İmzalanamadı: {exc}", file=sys.stderr)
        return EXIT_FAILURE

    try:
        manifest.save(output)
    except ManifestError as exc:
        print(f"HATA: Yazılamadı: {exc}", file=sys.stderr)
        return EXIT_FAILURE

    print(f"İmzalandı: {output}")
    print(f"Doğrulama için genel anahtar: {key_files.public_path_for(args.key)}")
    return EXIT_OK


def _cmd_inspect(args: argparse.Namespace) -> int:
    """
    Describe a manifest without scanning anything.

    Deliberately separate from `verify`: verify fails closed and refuses to
    speak about a manifest whose signature is broken, which is exactly the
    manifest a user most needs explained.
    """
    raw_key = getattr(args, "trusted_key", None)
    trusted_key = None
    if raw_key:
        try:
            trusted_key = load_public_key(raw_key)
        except KeyFileError as exc:
            print(f"HATA: --trusted-key okunamadı: {exc}", file=sys.stderr)
            return EXIT_USAGE

    try:
        manifest = Manifest.load(
            args.manifest, verify_integrity=False, allow_incomplete=True
        )
    except ManifestError as exc:
        print(f"HATA: Manifest okunamadı: {exc}", file=sys.stderr)
        return EXIT_MANIFEST_INVALID

    print(f"Manifest    : {args.manifest}")
    print(f"Şema        : {manifest.schema_version} (araç {manifest.tool_version})")
    print(f"Oluşturma   : {manifest.created_at}")
    print(f"Kök         : {manifest.root_path}")
    print(f"Algoritma   : {manifest.algorithm}")
    print(f"Dosya sayısı: {len(manifest.entries)}")
    print(f"Kapsam      : {'tam' if manifest.complete else 'KISMİ'}"
          + (f" ({len(manifest.skipped)} dosya atlanmış)" if manifest.skipped else ""))

    if is_collision_prone(manifest.algorithm):
        print(
            f"UYARI       : {manifest.algorithm.upper()} çakışmaya açıktır; "
            "eşleşme kurcalama kanıtı sayılmaz."
        )

    try:
        state = manifest.check_integrity(trusted_key)
    except ManifestIntegrityError as exc:
        print(f"İmza durumu : BOZUK — {exc}")
        return EXIT_MANIFEST_INVALID

    print(f"İmza durumu : {state.value}")
    if state is SignatureState.TRUSTED:
        print("Bu manifest verdiğiniz güvenilen anahtarla doğrulandı.")
        return EXIT_OK
    if state is SignatureState.VALID_EMBEDDED:
        print(
            "İmza geçerli ama yalnızca manifestin kendi gömülü anahtarıyla "
            "doğrulandı; kaynağı kanıtlanmadı. Dış güven için --trusted-key "
            "ile ayrı kanaldan aldığınız genel anahtarı verin."
        )
    else:
        print(
            "Manifest imzasız (unsigned): referans verinin kendisi "
            "değiştirilmiş olabilir."
        )
    return EXIT_UNTRUSTED_REFERENCE


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
        "keygen": _cmd_keygen,
        "sign": _cmd_sign,
        "inspect": _cmd_inspect,
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
        print("İptal edildi.", file=sys.stderr)
        return EXIT_CANCELLED
    except Exception as exc:  # last-resort safety net
        log.exception("Unexpected error: %s", exc)
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
