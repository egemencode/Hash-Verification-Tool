"""
Manifest read/write layer.

A manifest is a JSON document that records, for every scanned file,
its relative path, hash, algorithm, size and last-modified timestamp.
Keeping the format explicit (rather than pickling a dataclass) makes
the file portable and easily diffable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from core import __version__
from core.atomic_io import write_json_atomic
from core.hash_utils import (
    DEFAULT_ALGORITHM,
    HashError,
    ProgressEvent,
    ScanState,
    enumerate_files,
    hash_file_with_snapshot,
    inventory_for_paths,
    snapshot_inventory,
)
from core import manifest_signing

MANIFEST_SCHEMA_VERSION: str = "1.0"
# Schema versions this build knows how to read. An unknown (e.g. future)
# version must be rejected loudly rather than silently mis-parsed.
SUPPORTED_SCHEMA_VERSIONS: frozenset[str] = frozenset({"1.0"})

# Integrity modes recorded in the manifest metadata.
INTEGRITY_NONE = "none"
INTEGRITY_ED25519 = "ed25519"
SUPPORTED_INTEGRITY_MODES: frozenset[str] = frozenset({INTEGRITY_NONE, INTEGRITY_ED25519})


class ManifestError(Exception):
    """Raised for manifest serialisation / parsing problems."""


# Schema versions that predate the `complete` field. They asserted
# completeness by omission, so they are parsed down a separate, explicit
# legacy path rather than by guessing inside the current one.
_LEGACY_SCHEMA_VERSIONS: frozenset[str] = frozenset()


def _parse_completeness(metadata: dict[str, Any]) -> tuple[bool, list[str], list[str]]:
    """
    Read and validate the completeness block.

    ``complete`` must be a genuine JSON boolean. Python would happily accept
    ``"false"`` as truthy, which is exactly how a partial manifest could be
    laundered into a complete-looking one by editing four characters. Numbers,
    strings, null and containers are all rejected outright.

    The counts and lists must also agree with each other, so a manifest cannot
    claim completeness while carrying skipped entries.
    """
    schema_version = str(metadata.get("schema_version", ""))
    if "complete" not in metadata:
        if schema_version in _LEGACY_SCHEMA_VERSIONS:
            return True, [], []
        raise ManifestError(
            "Manifest metadata is missing the required 'complete' field."
        )

    complete = metadata["complete"]
    if not isinstance(complete, bool):
        raise ManifestError(
            f"Manifest 'complete' must be a JSON boolean, got {type(complete).__name__}"
        )

    raw_skipped = metadata.get("skipped", [])
    raw_errors = metadata.get("errors", [])
    if not isinstance(raw_skipped, list) or not isinstance(raw_errors, list):
        raise ManifestError("Manifest 'skipped'/'errors' must be arrays")
    skipped = [str(s) for s in raw_skipped]
    build_errors = [str(e) for e in raw_errors]

    declared = metadata.get("skipped_count", len(skipped))
    if not isinstance(declared, int) or isinstance(declared, bool):
        raise ManifestError("Manifest 'skipped_count' must be an integer")
    if declared != len(skipped):
        raise ManifestError(
            f"Manifest 'skipped_count' ({declared}) disagrees with the "
            f"'skipped' list ({len(skipped)} entries)"
        )

    if complete and (skipped or build_errors):
        raise ManifestError(
            "Manifest claims complete=true but lists skipped files or build "
            "errors — inconsistent metadata."
        )
    return complete, skipped, build_errors


class ManifestIntegrityError(ManifestError):
    """
    Raised when a manifest's *signature* cannot be trusted: the signature is
    malformed, does not verify, is missing while the manifest claims to be
    signed, or cannot be checked at all (missing crypto backend).

    Kept distinct from a plain :class:`ManifestError` so callers can tell
    "this file is not a manifest" from "this manifest may have been
    tampered with".
    """


class SignatureState(str, Enum):
    """How much trust the manifest's signature earns."""

    UNSIGNED = "unsigned"                # legacy/unsigned manifest (allowed)
    VALID_EMBEDDED = "valid_embedded"    # verified against its own embedded key
    TRUSTED = "trusted"                  # verified against an out-of-band key
    INVALID = "invalid"                  # present but does not verify

    @property
    def is_usable(self) -> bool:
        """False only for a signature that exists but fails to verify."""
        return self is not SignatureState.INVALID


@dataclass
class FileEntry:
    """Single file record stored inside a manifest."""

    hash: str
    algorithm: str
    size: int
    mtime: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FileEntry":
        try:
            return cls(
                hash=str(data["hash"]),
                algorithm=str(data["algorithm"]),
                size=int(data["size"]),
                mtime=float(data["mtime"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ManifestError(f"Invalid file entry: {data!r}") from exc


@dataclass
class Manifest:
    """In-memory representation of a manifest file."""

    root_path: str
    algorithm: str = DEFAULT_ALGORITHM
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    schema_version: str = MANIFEST_SCHEMA_VERSION
    tool_version: str = __version__
    integrity_mode: str = INTEGRITY_NONE
    # False when the build that produced this manifest could not cover the
    # whole folder. Part of the signed payload so it cannot be edited away.
    complete: bool = True
    skipped: list[str] = field(default_factory=list)
    build_errors: list[str] = field(default_factory=list)
    entries: dict[str, FileEntry] = field(default_factory=dict)
    # Populated only for signed manifests: {algorithm, public_key, signature}.
    signature: Optional[dict[str, Any]] = None
    # Set by load()/check_integrity(); None means "not checked yet".
    signature_state: Optional[SignatureState] = field(default=None, compare=False)

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------
    def add(self, relative_path: str, entry: FileEntry) -> None:
        # Always store with forward slashes so manifests are portable
        # between Windows and POSIX.
        self.entries[relative_path.replace("\\", "/")] = entry

    @property
    def is_signed(self) -> bool:
        return self.integrity_mode == INTEGRITY_ED25519 and bool(self.signature)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------
    def canonical_payload(self) -> dict[str, Any]:
        """
        The signed portion of the manifest (metadata + entries) — everything
        except the signature block itself. Signing and verification both run
        over exactly this structure.
        """
        return {
            "metadata": {
                "schema_version": self.schema_version,
                "tool_version": self.tool_version,
                "created_at": self.created_at,
                "algorithm": self.algorithm,
                "root_path": self.root_path,
                "integrity_mode": self.integrity_mode,
                "file_count": len(self.entries),
                # Signed along with everything else, so an incomplete manifest
                # cannot be laundered into a complete-looking one.
                "complete": self.complete,
                "skipped_count": len(self.skipped),
                "skipped": list(self.skipped),
                "errors": list(self.build_errors),
            },
            "entries": {
                path: entry.to_dict() for path, entry in self.entries.items()
            },
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self.canonical_payload()
        if self.signature is not None:
            payload["signature"] = self.signature
        return payload

    def sign(self, private_key_hex: str) -> None:
        """
        Sign this manifest with an Ed25519 private key (hex).

        Sets ``integrity_mode`` to ed25519 and stores the signature block.
        Requires the optional ``cryptography`` dependency.

        Refuses an incomplete manifest: signing it would attest to a folder
        description that is knowingly missing files.
        """
        if not self.complete:
            raise ManifestError(
                "Eksik (kısmi) bir manifest imzalanamaz: klasörün tamamı "
                "taranamadı, imza yanıltıcı bir bütünlük iddiası olurdu."
            )
        self.integrity_mode = INTEGRITY_ED25519
        self.signature = None
        # Sign over the payload that now advertises the ed25519 mode.
        self.signature = manifest_signing.sign_payload(
            self.canonical_payload(), private_key_hex
        )

    def verify_signature(
        self, trusted_public_hex: Optional[str] = None
    ) -> "manifest_signing.VerifyResult":
        """Verify the embedded signature (optionally against a trusted key)."""
        return manifest_signing.verify_payload(
            self.canonical_payload(), self.signature, trusted_public_hex
        )

    def check_integrity(
        self, trusted_public_hex: Optional[str] = None
    ) -> SignatureState:
        """
        Fail-closed integrity gate used by the normal verification flow.

        Returns the :class:`SignatureState` for an unsigned or successfully
        verified manifest, and raises :class:`ManifestIntegrityError` for a
        manifest that claims integrity protection but cannot prove it —
        including one whose signature simply cannot be checked because the
        crypto backend is missing. "Unsigned" and "signature broken" are
        therefore never conflated.
        """
        mode = self.integrity_mode or INTEGRITY_NONE
        if mode not in SUPPORTED_INTEGRITY_MODES:
            raise ManifestIntegrityError(
                f"Bilinmeyen manifest bütünlük modu: {mode!r}. "
                f"Desteklenen: {', '.join(sorted(SUPPORTED_INTEGRITY_MODES))}"
            )

        if mode == INTEGRITY_NONE:
            if self.signature:
                # A signature block with mode=none is internally inconsistent:
                # either the metadata or the signature was tampered with.
                raise ManifestIntegrityError(
                    "Manifest imza bloğu içeriyor ama bütünlük modu 'none' — "
                    "tutarsız/kurcalanmış manifest."
                )
            return SignatureState.UNSIGNED

        # mode == ed25519 from here on: a signature is mandatory.
        if not self.signature:
            raise ManifestIntegrityError(
                "Manifest 'ed25519' bütünlük modunda ama imza bloğu yok."
            )

        try:
            result = self.verify_signature(trusted_public_hex)
        except manifest_signing.SigningUnavailableError as exc:
            # Cannot check → cannot trust. Fail closed.
            raise ManifestIntegrityError(
                f"İmzalı manifest doğrulanamıyor: {exc}"
            ) from exc
        except manifest_signing.SigningError as exc:
            raise ManifestIntegrityError(f"İmza doğrulanamadı: {exc}") from exc

        if not result.valid:
            raise ManifestIntegrityError(
                f"Manifest imzası geçersiz: {result.reason} "
                "Manifest kurcalanmış olabilir."
            )
        return SignatureState.TRUSTED if result.trusted else SignatureState.VALID_EMBEDDED

    def save(self, output_path: str | Path) -> Path:
        """Write the manifest to *output_path* atomically as JSON."""
        path = Path(output_path)
        try:
            write_json_atomic(path, self.to_dict())
        except OSError as exc:
            raise ManifestError(f"Cannot write manifest to {path}: {exc}") from exc
        return path

    @classmethod
    def load(
        cls,
        manifest_path: str | Path,
        *,
        trusted_public_hex: Optional[str] = None,
        verify_integrity: bool = True,
        allow_incomplete: bool = False,
    ) -> "Manifest":
        """
        Read a manifest from disk and rehydrate it.

        By default the signature is checked here, so the ordinary
        ``load() -> Verifier.verify()`` flow can never proceed with a
        manifest whose signature is broken: a tampered manifest raises
        :class:`ManifestIntegrityError` instead of quietly verifying.

        Pass ``verify_integrity=False`` only for tooling that deliberately
        wants to inspect an untrusted manifest (e.g. printing why it failed).
        """
        path = Path(manifest_path)
        if not path.exists():
            raise ManifestError(f"Manifest not found: {path}")
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ManifestError(f"Manifest is not valid JSON: {exc}") from exc
        except OSError as exc:
            raise ManifestError(f"Cannot read manifest {path}: {exc}") from exc

        if not isinstance(data, dict) or "metadata" not in data or "entries" not in data:
            raise ManifestError("Manifest is missing required sections")

        metadata = data["metadata"]
        entries_raw = data["entries"]
        if not isinstance(metadata, dict):
            raise ManifestError("Manifest 'metadata' must be an object")
        if not isinstance(entries_raw, dict):
            raise ManifestError("Manifest 'entries' must be an object")

        schema_version = str(metadata.get("schema_version", ""))
        if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            # Never silently accept an unknown/future schema — the entries may
            # mean something different than we assume.
            raise ManifestError(
                f"Unsupported manifest schema version: {schema_version!r}. "
                f"Supported: {', '.join(sorted(SUPPORTED_SCHEMA_VERSIONS))}"
            )

        signature = data.get("signature")
        if signature is not None and not isinstance(signature, dict):
            raise ManifestError("Manifest 'signature' must be an object")

        complete, skipped, build_errors = _parse_completeness(metadata)

        manifest = cls(
            root_path=str(metadata.get("root_path", "")),
            algorithm=str(metadata.get("algorithm", DEFAULT_ALGORITHM)),
            created_at=str(metadata.get("created_at", "")),
            schema_version=schema_version,
            tool_version=str(metadata.get("tool_version", __version__)),
            integrity_mode=str(metadata.get("integrity_mode", INTEGRITY_NONE)),
            signature=signature,
            complete=complete,
            skipped=skipped,
            build_errors=build_errors,
        )
        for rel_path, raw_entry in entries_raw.items():
            if not isinstance(raw_entry, dict):
                raise ManifestError(f"Invalid entry for {rel_path!r}")
            manifest.add(rel_path, FileEntry.from_dict(raw_entry))

        if not manifest.complete and not allow_incomplete:
            raise ManifestError(
                f"Bu manifest eksik (kısmi): {len(manifest.skipped)} dosya "
                "taranamadı. Doğrulama için kullanılamaz — eksik dosyalar "
                "sessizce 'değişmemiş' görünürdü. İncelemek için "
                "allow_incomplete=True kullanın."
            )

        # Integrity gate: entries are only trustworthy once the signature
        # (when the manifest claims one) has actually been verified.
        if verify_integrity:
            manifest.signature_state = manifest.check_integrity(trusted_public_hex)
        return manifest


# ----------------------------------------------------------------------
# High-level builder used by the CLI
# ----------------------------------------------------------------------
def manifest_from_hashed_file(
    file_path: str | Path,
    algorithm: str,
    digest: str,
    snapshot: Any,
) -> Manifest:
    """
    Wrap an *already computed* digest + handle-bound snapshot in a manifest.

    Lets a caller that has just hashed a file record it without opening the
    file a second time. A second read is a second point in time: the digest
    shown to the user and the one stored in the manifest could then describe
    different bytes.
    """
    path = Path(file_path).resolve()
    manifest = Manifest(root_path=str(path.parent), algorithm=algorithm)
    manifest.add(
        path.name,
        FileEntry(
            hash=digest,
            algorithm=algorithm,
            size=snapshot.size,
            mtime=snapshot.mtime,
        ),
    )
    return manifest


def build_manifest_for_file(
    file_path: str | Path,
    algorithm: str = DEFAULT_ALGORITHM,
) -> Manifest:
    """Build a manifest containing just one file."""
    path = Path(file_path).resolve()
    # Capture size/mtime from the same handle used to hash so the recorded
    # metadata is consistent with the exact bytes we digested. Strict mode:
    # a file mutated mid-read must not produce a manifest entry.
    digest, snap = hash_file_with_snapshot(
        path, algorithm=algorithm, ensure_stable=True
    )
    return manifest_from_hashed_file(path, algorithm, digest, snap)


@dataclass
class BuildResult:
    """
    Outcome of a manifest build.

    ``complete`` is the field callers must gate on: it is True only when every
    file discovered was hashed successfully *and* the tree did not change
    underneath us. A manifest with skipped files is a partial record of the
    folder, and presenting it as a successful baseline would silently create a
    blind spot exactly where the trouble is.
    """

    manifest: Manifest
    complete: bool = True
    skipped: list[str] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
    inventory: dict[str, Any] = field(default_factory=dict)
    changed_during_scan: list[str] = field(default_factory=list)
    # True when the caller stopped the scan. A cancelled build describes only
    # the part of the folder it got to, so it is never complete.
    cancelled: bool = False

    def __post_init__(self) -> None:
        # Stamp the document itself immediately, not at save time: a caller
        # that signs or inspects the manifest directly must see the same
        # completeness the build determined.
        self._stamp_manifest()

    def _stamp_manifest(self) -> None:
        self.manifest.complete = self.complete
        self.manifest.skipped = list(self.skipped)
        self.manifest.build_errors = [f"{rel}: {msg}" for rel, msg in self.errors]

    @property
    def file_count(self) -> int:
        return len(self.manifest.entries)

    def save(self, output_path: str | Path, *, allow_partial: bool = False) -> Path:
        """
        Persist the manifest.

        An incomplete build refuses to write to *output_path* at all: a file
        sitting there under the expected name would be taken as a full
        description of the folder, and everything it missed would verify as
        "unchanged" forever after. With ``allow_partial=True`` the data is
        written to a clearly distinct ``*.partial.json`` artefact instead.
        """
        target = Path(output_path)
        self._stamp_manifest()   # re-assert in case the caller mutated it

        if self.complete:
            return self.manifest.save(target)

        if self.cancelled:
            # Not a policy choice the caller can override: a cancelled scan
            # stopped at an arbitrary file, so the "manifest" is a prefix of
            # the folder with no marker saying where it stops.
            raise ManifestError(
                "Tarama iptal edildi; yarım kalan sonuç manifest olarak "
                "kaydedilmez."
            )

        if not allow_partial:
            raise ManifestError(
                f"Tarama tamamlanamadı ({len(self.skipped)} dosya atlandı, "
                f"{len(self.changed_during_scan)} dosya tarama sırasında "
                "değişti); kısmi sonuç normal manifest olarak kaydedilmedi. "
                "Bilinçli olarak istiyorsanız allow_partial=True kullanın."
            )
        partial_target = target.with_suffix("")
        partial_target = partial_target.with_name(partial_target.name + ".partial.json")
        return self.manifest.save(partial_target)

    def summary(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "cancelled": self.cancelled,
            "hashed": self.file_count,
            "skipped": len(self.skipped),
            "errors": len(self.errors),
            "changed_during_scan": len(self.changed_during_scan),
        }


def build_manifest_for_folder(
    folder_path: str | Path,
    algorithm: str = DEFAULT_ALGORITHM,
    on_error: Optional[Callable[[str, Exception], None]] = None,
    on_progress: Optional[Callable[[ProgressEvent], None]] = None,
    *,
    follow_symlinks: bool = False,
    exclude: Optional[Sequence[str | Path]] = None,
    cancel: Optional[Callable[[], bool]] = None,
) -> BuildResult:
    """
    Build a manifest for every file under *folder_path*.

    Returns a :class:`BuildResult` rather than a bare manifest so a partial
    build cannot be mistaken for a successful one. Reparse points are not
    followed by default, and *exclude* keeps the manifest/report we are about
    to write out of its own inventory.

    *cancel* is polled before each file; when it returns True the scan stops
    and the result is marked cancelled (and therefore never complete).
    """
    root = Path(folder_path).resolve()
    manifest = Manifest(root_path=str(root), algorithm=algorithm)
    excluded = list(exclude or ())

    walk_kwargs = {"follow_symlinks": follow_symlinks, "exclude": excluded}

    skipped: list[str] = []
    errors: list[tuple[str, str]] = []
    cancelled = False
    processed = 0
    total = 0
    announced = False

    def _announce(state: ScanState) -> None:
        """Emit the single terminal event. Safe to call from any exit path."""
        nonlocal announced
        if on_progress is None or announced:
            return
        announced = True
        on_progress(
            ProgressEvent(done=processed, total=total, path="", state=state)
        )

    try:
        # ONE enumeration drives both the progress denominator and the work, so
        # `done` can never overshoot `total`. The before/after inventories below
        # are what detect a tree that shifted mid-scan.
        paths = enumerate_files(root, **walk_kwargs)
        before = inventory_for_paths(root, paths)
        total = len(paths)

        for index, file_path in enumerate(paths, start=1):
            if cancel is not None and cancel():
                cancelled = True
                break
            rel = file_path.relative_to(root).as_posix()
            try:
                # ensure_stable: a file that changes mid-read raises
                # FileChangedDuringScanError (a HashError), so it is reported
                # and deliberately left OUT of the manifest rather than
                # recorded with a digest that may match neither version.
                digest, snap = hash_file_with_snapshot(
                    file_path, algorithm=algorithm, ensure_stable=True
                )
                manifest.add(
                    rel,
                    FileEntry(
                        hash=digest, algorithm=algorithm,
                        size=snap.size, mtime=snap.mtime,
                    ),
                )
            except (HashError, OSError) as exc:
                skipped.append(rel)
                errors.append((rel, str(exc)))
                if on_error is not None:
                    on_error(rel, exc)
            processed = index
            if on_progress is not None:
                on_progress(ProgressEvent(done=index, total=total, path=rel))

        after = snapshot_inventory(root, **walk_kwargs)
        changed = sorted(
            set(before) ^ set(after)
            | {k for k in (set(before) & set(after)) if not before[k].is_same(after[k])}
        )
        if cancelled:
            # The tail of the folder was never looked at, so "did it change
            # while we scanned?" has no answer for it. Reporting drift here
            # would be an assertion about files we never read.
            changed = []
    except BaseException:
        # The tree can vanish underneath us — removable media, a temp folder
        # another process cleans up — and the re-walk above then raises. A
        # caller that stops its spinner on a terminal event would wait forever,
        # so say the run ended before letting the error out.
        _announce(ScanState.FAILED)
        raise

    # Always the last word, even for an empty folder: without it a UI has no
    # event that tells it to stop showing progress.
    _announce(ScanState.CANCELLED if cancelled else ScanState.COMPLETED)

    return BuildResult(
        manifest=manifest,
        complete=not cancelled and not skipped and not errors and not changed,
        skipped=skipped,
        errors=errors,
        inventory={k: {"size": v.size, "mtime": v.mtime} for k, v in after.items()},
        changed_during_scan=changed,
        cancelled=cancelled,
    )
