"""
Authenticode digital-signature check (Windows only).

We shell out to PowerShell's ``Get-AuthenticodeSignature`` cmdlet so we
do not need to ship a native PE parser. The result is reduced to a
small enum (:class:`SignatureStatus`) plus an optional signer name —
that is everything the user-facing summary needs.

On non-Windows platforms the function returns
:attr:`SignatureStatus.UNSUPPORTED` instead of raising.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class SignatureStatus(str, Enum):
    """Reduced view of an Authenticode result."""

    SIGNED_VALID = "signed_valid"            # signed AND valid
    SIGNED_INVALID = "signed_invalid"        # signed but cert problem
    UNSIGNED = "unsigned"                    # no signature at all
    UNKNOWN = "unknown"                      # PowerShell returned something we don't recognise
    UNSUPPORTED = "unsupported"              # not on Windows
    ERROR = "error"                          # could not invoke PowerShell


@dataclass
class SignatureResult:
    status: SignatureStatus
    signer: Optional[str] = None
    raw_status: Optional[str] = None
    message: str = ""

    @property
    def is_valid(self) -> bool:
        return self.status == SignatureStatus.SIGNED_VALID

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"status": self.status.value}


# PowerShell maps its SignatureStatus enum to these strings. We bucket
# them into the three values the GUI actually cares about.
_VALID_STATUSES = {"Valid"}
_UNSIGNED_STATUSES = {"NotSigned"}
_INVALID_STATUSES = {
    "HashMismatch",
    "NotTrusted",
    "UnknownError",
    "Incompatible",
    "NotSupportedFileFormat",
}


def _is_windows() -> bool:
    return sys.platform.startswith("win")


def check_signature(file_path: str | Path, timeout: float = 15.0) -> SignatureResult:
    """
    Return the Authenticode verdict for *file_path*.

    Non-Windows hosts get :attr:`SignatureStatus.UNSUPPORTED`. PowerShell
    failures (missing, blocked execution policy, timeout) collapse to
    :attr:`SignatureStatus.ERROR` with the underlying message attached.
    """
    if not _is_windows():
        return SignatureResult(
            status=SignatureStatus.UNSUPPORTED,
            message="Dijital imza kontrolü yalnızca Windows üzerinde desteklenir.",
        )

    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return SignatureResult(
            status=SignatureStatus.ERROR,
            message=f"Dosya bulunamadı: {path}",
        )

    # -OutputFormat is more reliable than | ConvertTo-Json on some
    # locales; we still parse JSON to read SignerCertificate.Subject
    # safely on paths with quotes / spaces.
    ps_command = (
        "$ErrorActionPreference='Stop';"
        f"$s = Get-AuthenticodeSignature -LiteralPath '{_escape_for_powershell(str(path))}';"
        "$o = [ordered]@{"
        "Status=$s.Status.ToString();"
        "StatusMessage=$s.StatusMessage;"
        "Signer = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { $null }"
        "};"
        "$o | ConvertTo-Json -Compress"
    )

    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-Command", ps_command,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return SignatureResult(
            status=SignatureStatus.ERROR,
            message="PowerShell bu sistemde bulunamadı.",
        )
    except subprocess.TimeoutExpired:
        return SignatureResult(
            status=SignatureStatus.ERROR,
            message="İmza kontrolü zaman aşımına uğradı.",
        )

    if completed.returncode != 0:
        # ExecutionPolicy or a parsing error — surface the message but
        # do not treat the file as 'unsigned' (which would be a lie).
        err = (completed.stderr or completed.stdout or "").strip().splitlines()
        return SignatureResult(
            status=SignatureStatus.ERROR,
            message=f"PowerShell hatası: {err[0] if err else 'bilinmiyor'}",
        )

    stdout = (completed.stdout or "").strip()
    if not stdout:
        return SignatureResult(
            status=SignatureStatus.UNKNOWN,
            message="PowerShell boş yanıt döndü.",
        )

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return SignatureResult(
            status=SignatureStatus.UNKNOWN,
            message="PowerShell çıktısı çözümlenemedi.",
            raw_status=stdout[:120],
        )

    raw_status = str(data.get("Status", "")).strip()
    signer = _clean_signer(data.get("Signer"))
    status_message = str(data.get("StatusMessage") or "")

    if raw_status in _VALID_STATUSES:
        return SignatureResult(
            status=SignatureStatus.SIGNED_VALID,
            signer=signer,
            raw_status=raw_status,
            message=status_message,
        )
    if raw_status in _UNSIGNED_STATUSES:
        return SignatureResult(
            status=SignatureStatus.UNSIGNED,
            signer=None,
            raw_status=raw_status,
            message=status_message,
        )
    if raw_status in _INVALID_STATUSES:
        return SignatureResult(
            status=SignatureStatus.SIGNED_INVALID,
            signer=signer,
            raw_status=raw_status,
            message=status_message,
        )
    return SignatureResult(
        status=SignatureStatus.UNKNOWN,
        signer=signer,
        raw_status=raw_status or None,
        message=status_message,
    )


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _escape_for_powershell(value: str) -> str:
    # PowerShell single-quoted strings: only ' needs to be doubled.
    return value.replace("'", "''")


def _clean_signer(raw: Any) -> Optional[str]:
    if not raw:
        return None
    text = str(raw).strip()
    # Subject usually looks like 'CN=Microsoft Corporation, O=Microsoft…'
    # Surface just the CN= bit for the friendly summary.
    for part in text.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:].strip().strip('"')
    return text
