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
import os
import subprocess
import sys
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class SignatureStatus(str, Enum):
    """Reduced view of an Authenticode result.

    The buckets are intentionally distinct so the risk engine can treat
    them very differently: a broken-integrity signature (``HASH_MISMATCH``)
    is a strong danger signal, whereas ``NOT_APPLICABLE`` (a file type that
    simply cannot carry an Authenticode signature, e.g. a ``.txt``) and
    ``UNKNOWN`` (the check itself failed) are *neutral* — they must never be
    presented to the user as "signed but invalid".
    """

    SIGNED_VALID = "signed_valid"          # signed AND valid
    HASH_MISMATCH = "hash_mismatch"        # signed, but content changed after signing
    UNTRUSTED = "untrusted"                # signed, but certificate chain not trusted
    UNSIGNED = "unsigned"                  # no signature at all
    NOT_APPLICABLE = "not_applicable"      # this file type cannot carry a signature
    UNKNOWN = "unknown"                    # check ran but result not recognised
    UNSUPPORTED = "unsupported"            # not on Windows
    ERROR = "error"                        # could not invoke PowerShell


@dataclass
class SignatureResult:
    status: SignatureStatus
    signer: Optional[str] = None
    raw_status: Optional[str] = None
    message: str = ""

    @property
    def is_valid(self) -> bool:
        return self.status == SignatureStatus.SIGNED_VALID

    @property
    def is_signed(self) -> bool:
        """True when a signature is present, regardless of trust/integrity."""
        return self.status in (
            SignatureStatus.SIGNED_VALID,
            SignatureStatus.HASH_MISMATCH,
            SignatureStatus.UNTRUSTED,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"status": self.status.value}


# PowerShell maps its SignatureStatus enum to these strings. We keep the
# security-relevant ones in separate buckets instead of collapsing them all
# into a single "invalid" state.
_VALID_STATUSES = {"Valid"}
_UNSIGNED_STATUSES = {"NotSigned"}
_HASH_MISMATCH_STATUSES = {"HashMismatch"}
_UNTRUSTED_STATUSES = {"NotTrusted"}
# Formats/results that must NOT be shown as "signed but invalid":
_NOT_APPLICABLE_STATUSES = {"NotSupportedFileFormat", "Incompatible"}
# "UnknownError" and anything unrecognised fall through to UNKNOWN — unless
# the file type simply cannot carry an Authenticode signature (see below).

# Extensions Authenticode can actually sign. Windows reports plain data files
# (e.g. a .txt) as the generic "UnknownError" rather than
# "NotSupportedFileFormat", which would otherwise be presented to the user as
# an inconclusive *security* check on a file that was never signable in the
# first place. We only downgrade UnknownError -> NOT_APPLICABLE for
# extensions outside this set, so genuine check failures on a real PE keep
# surfacing as UNKNOWN.
_SIGNABLE_EXTENSIONS = frozenset(
    {
        ".exe", ".dll", ".sys", ".ocx", ".efi", ".scr", ".cpl", ".drv",
        ".msi", ".msp", ".msm", ".cab", ".cat", ".appx", ".appxbundle",
        ".msix", ".msixbundle", ".ps1", ".psm1", ".psd1", ".ps1xml",
        ".vbs", ".js", ".wsf", ".jar", ".xap", ".stl",
    }
)


def _is_signable_extension(path: Path) -> bool:
    return path.suffix.lower() in _SIGNABLE_EXTENSIONS


def _is_windows() -> bool:
    return sys.platform.startswith("win")


def _windows_directory() -> Optional[str]:
    """
    Resolve the real Windows directory via ``GetWindowsDirectoryW``.

    ``%SystemRoot%`` / ``%windir%`` are ordinary environment variables: any
    code that can set them for this process could point us at a directory it
    controls and have us execute its own ``powershell.exe``. The Win32 API
    answers from the OS, not from the environment block.

    **Fail closed on Windows**: if the API call fails we return ``None``
    rather than falling back to the environment, because an attacker able to
    make the call fail could otherwise choose the fallback path. The env vars
    are consulted only on non-Windows platforms, where this whole code path
    is unreachable in practice.
    """
    if sys.platform.startswith("win"):
        try:
            import ctypes
            from ctypes import wintypes

            buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
            length = ctypes.windll.kernel32.GetWindowsDirectoryW(buf, wintypes.MAX_PATH)
        except Exception:
            return None
        return buf.value if length else None
    return os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"


def _system_directory() -> Optional[str]:
    """Resolve System32 via ``GetSystemDirectoryW`` (bitness-correct)."""
    if not sys.platform.startswith("win"):
        return None
    import ctypes
    from ctypes import wintypes

    buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buf, wintypes.MAX_PATH)
    return buf.value if length else None


#: Where PowerShell stops explaining and starts quoting itself. Everything
#: from here on is the offending line, the caret art and the CategoryInfo /
#: FullyQualifiedErrorId block — console furniture, not a reason.
_PS_NOISE_PREFIXES = ("At line:", "At char:", "+", "CategoryInfo",
                      "FullyQualifiedErrorId")

#: The message is rendered in a status bar and written into a report field,
#: so it has to stay one bounded line.
_ERROR_SUMMARY_LIMIT = 500


def _error_summary(completed) -> str:
    """One readable line out of PowerShell's multi-line complaint.

    This used to keep ``stderr.splitlines()[0]`` and nothing else, which is
    where PowerShell happens to break the *first* sentence, not where the
    sentence ends. A CI run produced

        PowerShell hatası: Get-AuthenticodeSignature : The
        'Get-AuthenticodeSignature' command was found in the module

    and stopped — the clause naming why the module could not be loaded, the
    only part that identified the machine's problem, was discarded here rather
    than by the log that carried it.
    """
    raw = (getattr(completed, "stderr", "") or getattr(completed, "stdout", "")
           or "")
    kept: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith(_PS_NOISE_PREFIXES):
            break
        kept.append(line)
    summary = " ".join(kept)
    if not summary:
        return "bilinmiyor"
    if len(summary) > _ERROR_SUMMARY_LIMIT:
        summary = summary[:_ERROR_SUMMARY_LIMIT - 1].rstrip() + "…"
    return summary


def _powershell_executable() -> str:
    """
    Return a verified, absolute path to the *system* ``powershell.exe``.

    We never launch PowerShell by bare name and deliberately do **not** fall
    back to a ``PATH`` lookup: PATH is attacker-influenceable, and this process
    runs the result against user-supplied file paths. The directory comes from
    the Win32 API rather than ``%SystemRoot%`` so a spoofed environment cannot
    redirect us. If the trusted location is missing we return a controlled
    error instead of executing something we cannot vouch for.
    """
    candidates: list[Path] = []
    system_dir = _system_directory()
    if system_dir:
        candidates.append(Path(system_dir) / "WindowsPowerShell" / "v1.0" / "powershell.exe")

    windows_dir = _windows_directory()
    if windows_dir:
        root = Path(windows_dir)
        candidates += [
            root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
            # 32-bit process on 64-bit Windows: System32 is redirected, the
            # real one is behind SysNative.
            root / "SysNative" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
            root / "SysWOW64" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
        ]

    for candidate in candidates:
        try:
            if candidate.is_file():
                return str(candidate)
        except OSError:
            continue
    # Fail closed: no PATH lookup, and no environment-variable fallback.
    raise FileNotFoundError(
        "Güvenilir sistem PowerShell yolu belirlenemedi (Win32 API yanıt "
        "vermedi veya dosya yok). Güvenlik nedeniyle PATH ya da ortam "
        "değişkeni üzerinden PowerShell çalıştırılmaz."
    )


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
        powershell = _powershell_executable()
    except FileNotFoundError as exc:
        return SignatureResult(status=SignatureStatus.ERROR, message=str(exc))

    try:
        completed = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                # NOTE: -ExecutionPolicy Bypass intentionally removed. We run a
                # single -Command string (not a script file), which execution
                # policy does not gate, so Bypass only widened the attack
                # surface for no functional benefit.
                "-Command", ps_command,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return SignatureResult(
            status=SignatureStatus.ERROR,
            message="PowerShell bu sistemde bulunamadı.",
        )
    except subprocess.TimeoutExpired:
        # subprocess.run kills the child process on timeout before re-raising,
        # so no orphaned powershell.exe is left behind.
        return SignatureResult(
            status=SignatureStatus.ERROR,
            message="İmza kontrolü zaman aşımına uğradı.",
        )

    if completed.returncode != 0:
        # A policy, environment or parsing problem — surface it, but do not
        # treat the file as 'unsigned', which would be a lie.
        return SignatureResult(
            status=SignatureStatus.ERROR,
            message=f"PowerShell hatası: {_error_summary(completed)}",
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
    if raw_status in _HASH_MISMATCH_STATUSES:
        return SignatureResult(
            status=SignatureStatus.HASH_MISMATCH,
            signer=signer,
            raw_status=raw_status,
            message=status_message,
        )
    if raw_status in _UNTRUSTED_STATUSES:
        return SignatureResult(
            status=SignatureStatus.UNTRUSTED,
            signer=signer,
            raw_status=raw_status,
            message=status_message,
        )
    if raw_status in _NOT_APPLICABLE_STATUSES:
        # A file type that cannot carry a signature is NOT a risk signal.
        return SignatureResult(
            status=SignatureStatus.NOT_APPLICABLE,
            signer=None,
            raw_status=raw_status,
            message=status_message,
        )
    # Windows answers "UnknownError" both for a failed check AND for a file
    # type that can never carry a signature (a .txt, .png, …). Separate the
    # two: an unsignable extension is NOT_APPLICABLE (informational), while a
    # real check failure on a signable file stays UNKNOWN (inconclusive).
    if raw_status == "UnknownError" and not _is_signable_extension(path):
        return SignatureResult(
            status=SignatureStatus.NOT_APPLICABLE,
            signer=None,
            raw_status=raw_status,
            message=status_message
            or "Bu dosya türü dijital imza taşıyamaz.",
        )

    # Anything else we don't recognise: the check itself is inconclusive.
    # Never dress this up as "signed but invalid".
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
