"""
Per-user secret storage backed by Windows DPAPI.

The VirusTotal API key must not sit in a plaintext JSON file. On Windows we
encrypt it with DPAPI (``CryptProtectData`` / ``CryptUnprotectData``) tied to
the current user account — no third-party dependency, just ``ctypes``. The
ciphertext is base64-encoded so it can live inside the settings JSON.

DPAPI is Windows-only. On other platforms :func:`is_available` returns
``False`` and :func:`protect` / :func:`unprotect` raise
:class:`SecretStoreUnavailable`, so the caller can decide (e.g. refuse to
save, or fall back to an explicit portable-mode plaintext with a warning)
rather than silently writing an unprotected secret.
"""

from __future__ import annotations

import base64
import sys

# A DPAPI "entropy"/description string — namespaces our blobs.
_DESCRIPTION = "HashTool VirusTotal API key"
_CRYPTPROTECT_UI_FORBIDDEN = 0x01


class SecretStoreError(Exception):
    """Raised when a secret cannot be protected/unprotected."""


class SecretStoreUnavailable(SecretStoreError):
    """Raised when no secure backend exists on this platform."""


def is_available() -> bool:
    """True when a secure backend (DPAPI) is usable on this platform."""
    return sys.platform.startswith("win")


def backend_name() -> str:
    return "windows-dpapi" if is_available() else "none"


# ----------------------------------------------------------------------
# Windows DPAPI via ctypes
# ----------------------------------------------------------------------
def _dpapi():
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    return ctypes, DATA_BLOB, crypt32, kernel32


def _to_blob(ctypes_mod, DATA_BLOB, data: bytes):
    buf = ctypes_mod.create_string_buffer(data, len(data))
    blob = DATA_BLOB()
    blob.cbData = len(data)
    blob.pbData = ctypes_mod.cast(buf, ctypes_mod.POINTER(ctypes_mod.c_char))
    # Keep a reference to buf alive by returning it alongside the blob.
    return blob, buf


def protect(plaintext: str) -> str:
    """Encrypt *plaintext* for the current user; return a base64 token."""
    if not is_available():
        raise SecretStoreUnavailable(
            "Bu platformda güvenli anahtar deposu (DPAPI) yok."
        )
    ctypes_mod, DATA_BLOB, crypt32, kernel32 = _dpapi()
    data = plaintext.encode("utf-8")
    blob_in, _keep = _to_blob(ctypes_mod, DATA_BLOB, data)
    blob_out = DATA_BLOB()
    ok = crypt32.CryptProtectData(
        ctypes_mod.byref(blob_in),
        _DESCRIPTION,
        None,
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes_mod.byref(blob_out),
    )
    if not ok:
        raise SecretStoreError("CryptProtectData başarısız oldu.")
    try:
        raw = ctypes_mod.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)
    return base64.b64encode(raw).decode("ascii")


def unprotect(token: str) -> str:
    """Decrypt a base64 token produced by :func:`protect`."""
    if not is_available():
        raise SecretStoreUnavailable(
            "Bu platformda güvenli anahtar deposu (DPAPI) yok."
        )
    ctypes_mod, DATA_BLOB, crypt32, kernel32 = _dpapi()
    try:
        raw = base64.b64decode(token.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise SecretStoreError(f"Bozuk gizli anahtar verisi: {exc}") from exc
    blob_in, _keep = _to_blob(ctypes_mod, DATA_BLOB, raw)
    blob_out = DATA_BLOB()
    ok = crypt32.CryptUnprotectData(
        ctypes_mod.byref(blob_in),
        None,
        None,
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes_mod.byref(blob_out),
    )
    if not ok:
        raise SecretStoreError("CryptUnprotectData başarısız oldu.")
    try:
        out = ctypes_mod.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)
    return out.decode("utf-8", errors="replace")


def redact(secret: str, text: str) -> str:
    """Replace *secret* wherever it appears in *text* (for safe logging)."""
    if secret and secret in text:
        return text.replace(secret, "***REDACTED***")
    return text
