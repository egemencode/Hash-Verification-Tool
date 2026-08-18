"""
On-disk format for Ed25519 signing keys.

A signing key is the one piece of this tool whose loss is unrecoverable: every
manifest ever signed with it becomes unverifiable, and anyone who obtains it
can forge manifests that verify as trusted. So the rules here are deliberately
unforgiving:

* a private key file is **never** overwritten implicitly;
* the private half is protected with Windows DPAPI when that is available, so
  a copied file is useless on another machine or under another account —
  ``--portable-key`` opts out explicitly for the case where the user really
  does need to move it, and says so in the file itself;
* the public half is written to a separate ``.pub`` file, because that is the
  part meant to be handed around, and a format that mixes the two invites
  publishing the wrong one;
* nothing in this module ever writes private key material to a log or to
  stdout.

Storage protection is reported honestly: on a platform without DPAPI the key
is plain hex on disk with the file itself saying so, rather than a claim of
protection we do not provide.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from core import manifest_signing, secret_store

PRIVATE_KEY_TYPE = "hash-tool-ed25519-private-key"
PUBLIC_KEY_TYPE = "hash-tool-ed25519-public-key"
KEY_FILE_VERSION = 1


class KeyFileError(Exception):
    """Raised for missing, malformed or unreadable key files."""


@dataclass(frozen=True)
class PrivateKeyFile:
    """A loaded private key plus how it was stored."""

    private_hex: str
    public_hex: str
    protected: bool


def public_path_for(private_path: str | Path) -> Path:
    """The companion ``.pub`` path for a private key file."""
    path = Path(private_path)
    return path.with_name(path.name + ".pub")


def _write_restricted(path: Path, text: str, created: Optional[list[Path]] = None) -> None:
    """
    Create *path* with owner-only permissions, failing if it already exists.

    ``O_EXCL`` is what makes "do not overwrite" a property of the filesystem
    call rather than a check with a race in front of it.

    *created* is appended to the moment the file exists — before anything is
    written into it. The caller's cleanup must key off that, not off this
    function returning: a failure in ``write``/``fsync`` (a flaky volume,
    ENOSPC, a network redirector) would otherwise leave a file behind that the
    caller never learns about, and in portable mode that file holds the
    plaintext private key while the CLI reports nothing was written.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    binary = getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags | binary, 0o600)
    if created is not None:
        created.append(path)
    try:
        payload = text.encode("utf-8")
        written = 0
        while written < len(payload):
            count = os.write(fd, payload[written:])
            if count <= 0:
                raise OSError(f"Yazma ilerlemedi: {path}")
            written += count
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        # On POSIX this is the real protection. On Windows the mode bits only
        # control the read-only attribute; the ACL inherited from the parent
        # directory is what matters, which is why DPAPI protection above is
        # not optional there.
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def storage_backend() -> str:
    """Human-readable description of how a new key would be protected."""
    if secret_store.is_available():
        return f"DPAPI ({secret_store.backend_name()})"
    return "korumasız düz metin"


def create_keypair(
    private_path: str | Path, *, portable: bool = False
) -> tuple[Path, Path, str]:
    """
    Generate a keypair and write both halves.

    Returns ``(private_path, public_path, public_hex)``. Raises
    :class:`KeyFileError` if either file already exists — replacing a signing
    key silently would invalidate every manifest signed with the old one.
    """
    priv_path = Path(private_path)
    pub_path = public_path_for(priv_path)
    for existing in (priv_path, pub_path):
        if existing.exists():
            raise KeyFileError(
                f"Dosya zaten var: {existing}. Mevcut bir imzalama anahtarının "
                "üzerine yazmak, onunla imzalanmış tüm manifestleri "
                "doğrulanamaz hâle getirir. Farklı bir yol seçin veya eski "
                "anahtarı bilinçli olarak kendiniz taşıyın/silin."
            )
    try:
        priv_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise KeyFileError(f"Anahtar klasörü oluşturulamadı: {exc}") from exc

    private_hex, public_hex = manifest_signing.generate_keypair()

    document: dict[str, Any] = {
        "type": PRIVATE_KEY_TYPE,
        "version": KEY_FILE_VERSION,
        "algorithm": manifest_signing.SIGNATURE_ALGORITHM,
        "public_key": public_hex,
    }
    if portable or not secret_store.is_available():
        document["protected"] = False
        document["private_key"] = private_hex
        document["warning"] = (
            "Bu dosyadaki özel anahtar korumasızdır; dosyayı okuyabilen "
            "herkes sizin adınıza manifest imzalayabilir."
        )
    else:
        document["protected"] = True
        document["private_key_dpapi"] = secret_store.protect(private_hex)
        document["warning"] = (
            "Özel anahtar DPAPI ile bu kullanıcı hesabına bağlıdır; başka bir "
            "hesapta veya makinede çözülemez."
        )

    # The two halves are written one after the other, and either write can fail
    # part-way. Anything this call brought into existence is removed on the way
    # out: a private key with no public key beside it is unusable, a key the
    # user was told was never written would never be shredded, and — because
    # keygen refuses to overwrite — either would block the obvious recovery of
    # simply running the command again. `created` is appended by
    # _write_restricted as soon as the file exists, not when the write succeeds.
    created: list[Path] = []
    try:
        _write_restricted(
            priv_path, json.dumps(document, indent=2) + "\n", created
        )
        _write_restricted(
            pub_path,
            json.dumps(
                {
                    "type": PUBLIC_KEY_TYPE,
                    "version": KEY_FILE_VERSION,
                    "algorithm": manifest_signing.SIGNATURE_ALGORITHM,
                    "public_key": public_hex,
                },
                indent=2,
            )
            + "\n",
            created,
        )
    except Exception as exc:
        for path in created:
            try:
                os.unlink(path)
            except OSError:
                # Say so rather than reporting a clean failure: the caller
                # needs to know a key file is lying around.
                raise KeyFileError(
                    f"Anahtar yazılamadı ({exc}) ve yarım kalan {path} "
                    "silinemedi. Devam etmeden bu dosyayı elle kaldırın."
                ) from exc
        if isinstance(exc, FileExistsError):
            raise KeyFileError(f"Dosya zaten var: {exc.filename}") from exc
        if isinstance(exc, OSError):
            raise KeyFileError(f"Anahtar yazılamadı: {exc}") from exc
        raise

    return priv_path, pub_path, public_hex


def _load_document(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise KeyFileError(f"Anahtar dosyası bulunamadı: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise KeyFileError(f"Anahtar dosyası okunamadı ({path}): {exc}") from exc
    except OSError as exc:
        raise KeyFileError(f"Anahtar dosyası açılamadı ({path}): {exc}") from exc
    if not isinstance(data, dict):
        raise KeyFileError(f"Anahtar dosyası beklenen biçimde değil: {path}")
    return data


def load_private_key(path: str | Path) -> PrivateKeyFile:
    """Read a private key file, decrypting it when it is DPAPI-protected."""
    key_path = Path(path)
    data = _load_document(key_path)
    if data.get("type") != PRIVATE_KEY_TYPE:
        raise KeyFileError(
            f"{key_path} bir özel anahtar dosyası değil "
            f"(type={data.get('type')!r})."
        )

    protected = bool(data.get("protected"))
    if protected:
        token = str(data.get("private_key_dpapi", ""))
        if not token:
            raise KeyFileError(f"{key_path}: korumalı anahtar verisi eksik.")
        try:
            private_hex = secret_store.unprotect(token)
        except secret_store.SecretStoreError as exc:
            raise KeyFileError(
                f"{key_path} çözülemedi: {exc} Bu anahtar başka bir kullanıcı "
                "hesabında veya makinede oluşturulmuş olabilir."
            ) from exc
    else:
        private_hex = str(data.get("private_key", ""))
        if not private_hex:
            raise KeyFileError(f"{key_path}: özel anahtar verisi eksik.")

    try:
        derived = manifest_signing.public_key_for(private_hex)
    except manifest_signing.SigningError as exc:
        raise KeyFileError(f"{key_path}: geçersiz özel anahtar ({exc}).") from exc

    recorded = str(data.get("public_key", "")).strip().lower()
    if recorded and recorded != derived:
        # The two halves disagreeing means the file was edited or corrupted;
        # signing with it would produce a manifest nobody can verify.
        raise KeyFileError(
            f"{key_path}: dosyadaki genel anahtar özel anahtarla uyuşmuyor."
        )
    return PrivateKeyFile(
        private_hex=private_hex, public_hex=derived, protected=protected
    )


def load_public_key(reference: str | Path) -> str:
    """
    Resolve a trusted public key from a ``.pub`` file, a private key file, or
    a raw hex string.

    Accepting all three is what makes ``--trusted-key`` usable: people copy
    whichever artefact they have to hand. Anything that is not 32 raw bytes is
    rejected rather than passed on to the crypto layer as a mystery.
    """
    text = str(reference).strip()
    candidate = Path(text)
    if candidate.exists() and candidate.is_file():
        data = _load_document(candidate)
        kind = data.get("type")
        if kind not in (PUBLIC_KEY_TYPE, PRIVATE_KEY_TYPE):
            raise KeyFileError(
                f"{candidate} bir anahtar dosyası değil (type={kind!r})."
            )
        if kind == PRIVATE_KEY_TYPE:
            # A private key file carries both halves, so the public one can be
            # *derived* rather than believed. Taking the stored field at face
            # value discards the only free integrity check on this file:
            # editing that one field — without ever touching the protected
            # private blob — would silently substitute an attacker's key for
            # the operator's, and a manifest signed with it would verify as
            # trusted. load_private_key already refuses such a file; the
            # trusted-key path must not be the lenient one.
            return load_private_key(candidate).public_hex
        text = str(data.get("public_key", "")).strip()
        if not text:
            raise KeyFileError(f"{candidate}: genel anahtar alanı boş.")

    try:
        raw = bytes.fromhex(text)
    except ValueError as exc:
        raise KeyFileError(
            f"Genel anahtar hex olarak çözülemedi: {exc}"
        ) from exc
    if len(raw) != 32:
        raise KeyFileError(
            f"Ed25519 genel anahtarı 32 bayt olmalı, {len(raw)} bayt verildi."
        )
    return raw.hex()


def describe_protection(path: str | Path) -> Optional[str]:
    """One line about how the key at *path* is stored (None if unreadable)."""
    try:
        data = _load_document(Path(path))
    except KeyFileError:
        return None
    if data.get("type") != PRIVATE_KEY_TYPE:
        return None
    return "DPAPI ile korunuyor" if data.get("protected") else "korumasız (portable)"
