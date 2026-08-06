"""
Ed25519 manifest signing (optional feature).

Signing/verification needs the third-party ``cryptography`` package. The
rest of the tool works without it, so this module imports the backend
lazily and raises a clear :class:`SigningUnavailableError` when a signing
or verification operation is attempted without it installed.

Security model
--------------
* The **private key never lives next to the manifest or the app settings**
  — the caller passes a key file path the user controls.
* Verification against an **out-of-band trusted public key** is the only
  thing that yields ``trusted=True``. Verifying against the key embedded in
  the manifest itself proves internal consistency only (``trusted=False``):
  an attacker who rewrote the manifest could also embed their own key, so a
  self-signed manifest must never be treated as externally trustworthy.
* Signing/verification is computed over a **canonical** JSON encoding
  (sorted keys, no insignificant whitespace) so it is stable across
  save/load round-trips.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

SIGNATURE_ALGORITHM = "ed25519"


class SigningError(Exception):
    """Base class for signing/verification problems."""


class SigningUnavailableError(SigningError):
    """Raised when the optional ``cryptography`` dependency is missing."""


def _backend():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover - exercised only w/o dep
        raise SigningUnavailableError(
            "İmzalama/doğrulama için 'cryptography' paketi gerekli. "
            "Kurulum: pip install cryptography"
        ) from exc
    return Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature, serialization


def is_available() -> bool:
    """True when the ``cryptography`` backend can be imported."""
    try:
        _backend()
        return True
    except SigningUnavailableError:
        return False


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Deterministic UTF-8 encoding used as the signed message."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def generate_keypair() -> tuple[str, str]:
    """Return ``(private_hex, public_hex)`` for a fresh Ed25519 key."""
    PrivK, _PubK, _Inv, serialization = _backend()
    priv = PrivK.generate()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_raw.hex(), pub_raw.hex()


def public_key_for(private_hex: str) -> str:
    """Derive the public key (hex) from a private key (hex)."""
    PrivK, _PubK, _Inv, serialization = _backend()
    try:
        priv = PrivK.from_private_bytes(bytes.fromhex(private_hex.strip()))
    except (ValueError, TypeError) as exc:
        raise SigningError(f"Geçersiz özel anahtar: {exc}") from exc
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return pub_raw.hex()


def sign_payload(payload: dict[str, Any], private_hex: str) -> dict[str, str]:
    """Sign *payload* and return a signature block suitable for embedding."""
    PrivK, _PubK, _Inv, _ser = _backend()
    try:
        priv = PrivK.from_private_bytes(bytes.fromhex(private_hex.strip()))
    except (ValueError, TypeError) as exc:
        raise SigningError(f"Geçersiz özel anahtar: {exc}") from exc
    signature = priv.sign(canonical_bytes(payload))
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "public_key": public_key_for(private_hex),
        "signature": signature.hex(),
    }


@dataclass
class VerifyResult:
    """Outcome of verifying a manifest signature."""

    valid: bool
    reason: str = ""
    # trusted is True ONLY when the signature verified against an
    # out-of-band public key the caller explicitly trusts.
    trusted: bool = False


def verify_payload(
    payload: dict[str, Any],
    signature_block: Optional[dict[str, Any]],
    trusted_public_hex: Optional[str] = None,
) -> VerifyResult:
    """
    Verify a signature block against *payload*.

    If *trusted_public_hex* is given, verification uses that key and a
    success is ``trusted=True``. Otherwise it falls back to the key embedded
    in the signature block — a success there only proves internal
    consistency (``trusted=False``).
    """
    _PrivK, PubK, InvalidSignature, _ser = _backend()

    if not signature_block:
        return VerifyResult(False, "Manifestte imza yok.")
    if signature_block.get("algorithm") != SIGNATURE_ALGORITHM:
        return VerifyResult(
            False, f"Desteklenmeyen imza algoritması: {signature_block.get('algorithm')!r}"
        )

    embedded_pub = str(signature_block.get("public_key", "")).strip()
    sig_hex = str(signature_block.get("signature", "")).strip()
    verify_key_hex = (trusted_public_hex or embedded_pub).strip()
    if not verify_key_hex:
        return VerifyResult(False, "Doğrulama için genel anahtar yok.")

    try:
        pub = PubK.from_public_bytes(bytes.fromhex(verify_key_hex))
        pub.verify(bytes.fromhex(sig_hex), canonical_bytes(payload))
    except InvalidSignature:
        return VerifyResult(False, "İmza doğrulanamadı (içerik veya anahtar uyuşmuyor).")
    except (ValueError, TypeError) as exc:
        return VerifyResult(False, f"İmza/anahtar biçimi geçersiz: {exc}")

    if trusted_public_hex:
        return VerifyResult(True, "İmza, güvenilen genel anahtarla doğrulandı.", trusted=True)
    return VerifyResult(
        True,
        "İmza geçerli, ancak yalnızca manifestin kendi gömülü anahtarıyla "
        "doğrulandı — dışarıdan güven sağlanmadı.",
        trusted=False,
    )
