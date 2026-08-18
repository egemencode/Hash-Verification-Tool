"""
One decision table for "may this hash request proceed, and on what terms?"

The CLI and the GUI reach the same core functions. When each carries its own
checks they drift, and they drift in the worst direction: the expert interface
gets the guard rails and the default one silently does the dangerous thing.
So the rules live here, in one Tk-free place, and both front ends render the
same notices — as exit codes and stderr in one, as dialogs and log lines in
the other.

Nothing in this module touches the filesystem beyond resolving paths, so it
is cheap to call before any work starts. That matters: a refusal must not
leave a half-written manifest behind.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, Sequence

from core.hash_utils import INSECURE_ALGORITHMS, SUPPORTED_ALGORITHMS, is_collision_prone


class PolicyLevel(str, Enum):
    """How a front end must treat a notice."""

    BLOCK = "block"      # refuse; there is no safe way to continue
    CONFIRM = "confirm"  # proceed only on an explicit, informed "yes"
    WARN = "warn"        # proceed, but the user must be told


@dataclass(frozen=True)
class PolicyNotice:
    """A single decision, with the text a user should actually read."""

    level: PolicyLevel
    code: str
    message: str

    @property
    def blocking(self) -> bool:
        return self.level is PolicyLevel.BLOCK


SAFE_ALGORITHMS = tuple(a for a in SUPPORTED_ALGORITHMS if a not in INSECURE_ALGORITHMS)


_EXTENDED_PREFIX = "\\\\?\\"
_EXTENDED_UNC_PREFIX = "\\\\?\\UNC\\"


def resolved(path: str | Path) -> Path:
    """
    Absolute, comparable form of *path* — works for files that do not exist yet.

    Two spellings of the same file must compare equal, or every containment
    check below silently answers "no" for the one case somebody bothered to
    spell differently. ``Path.resolve()`` alone is not enough on Windows:

    * it *keeps* a caller-supplied ``\\\\?\\`` extended-length prefix while the
      operand it is compared against has none, so ``\\\\?\\C:\\d\\k.key`` is not
      "inside" ``C:\\d`` — and ``\\\\?\\`` is the ordinary remedy for long
      paths, not an exotic input;
    * the filesystem is case-insensitive, so ``C:\\Data`` and ``c:\\data`` are
      the same directory but different strings.

    Both are normalised away here.
    """
    try:
        absolute = Path(path).resolve()
    except OSError:  # pragma: no cover - exotic paths
        absolute = Path(os.path.abspath(str(path)))

    text = str(absolute)
    if text.startswith(_EXTENDED_UNC_PREFIX):
        text = "\\\\" + text[len(_EXTENDED_UNC_PREFIX):]
    elif text.startswith(_EXTENDED_PREFIX):
        text = text[len(_EXTENDED_PREFIX):]
    return Path(os.path.normcase(text))


# Kept as a private alias so the existing call sites read unchanged.
_resolved = resolved


def same_file(a: str | Path, b: str | Path) -> bool:
    """True when two path strings name the same file on disk."""
    pa, pb = Path(a), Path(b)
    try:
        if pa.exists() and pb.exists():
            return os.path.samefile(pa, pb)
    except OSError:
        pass
    return _resolved(pa) == _resolved(pb)


def is_inside(path: str | Path, folder: str | Path) -> bool:
    """True when *path* resolves to somewhere under *folder*."""
    try:
        return _resolved(path).is_relative_to(_resolved(folder))
    except (OSError, ValueError):
        return False


def evaluate_hash_request(
    *,
    mode: str,
    target: str | Path,
    output: Optional[str | Path] = None,
    algorithm: str = "sha256",
    allow_insecure_algorithm: bool = False,
    sign_key: Optional[str | Path] = None,
) -> list[PolicyNotice]:
    """
    Decide what must happen before hashing *target*.

    *mode* is ``"file"`` or ``"folder"``. Returns the notices in the order a
    user should see them, blocking ones first. An empty list means "go ahead,
    nothing to say".
    """
    notices: list[PolicyNotice] = []
    writes_reference = bool(output)

    # --- the manifest must not destroy what it describes ---------------
    if writes_reference and mode == "file" and same_file(target, output):
        notices.append(PolicyNotice(
            PolicyLevel.BLOCK,
            "output_overwrites_input",
            f"Kaydetme hedefi özetlenecek dosyanın kendisi ({target}). "
            "Manifest yazılsaydı özetlenen dosya yok olurdu. Farklı bir hedef "
            "seçin.",
        ))

    # --- the signing key must not travel with what it signs ------------
    if sign_key:
        if mode == "folder" and is_inside(sign_key, target):
            notices.append(PolicyNotice(
                PolicyLevel.BLOCK,
                "sign_key_inside_folder",
                f"İmzalama anahtarı taranan klasörün içinde ({sign_key}). "
                "Klasörü alan herkes anahtarı da alır ve sizin adınıza "
                "manifest imzalayabilir.",
            ))
        elif writes_reference and _resolved(sign_key).parent == _resolved(output).parent:
            notices.append(PolicyNotice(
                PolicyLevel.BLOCK,
                "sign_key_beside_manifest",
                f"İmzalama anahtarı manifestle aynı klasörde ({sign_key}). "
                "Özel anahtar, imzaladığı belgeyle birlikte dağıtılmamalı.",
            ))

    # --- collision-prone algorithms ------------------------------------
    if writes_reference and is_collision_prone(algorithm):
        algo = str(algorithm).upper()
        explanation = (
            f"{algo} ile bütünlük manifesti üretiliyor. Bu algoritmada aynı "
            "özeti veren farklı bir dosya üretmek pratiktir; sonradan eşleşen "
            "bir özet, dosyanın değiştirilmediğini KANITLAMAZ. Yalnız eski "
            "checksum listeleriyle uyum için kullanın. "
            f"Güvenli seçenekler: {', '.join(SAFE_ALGORITHMS)}."
        )
        notices.append(PolicyNotice(
            PolicyLevel.WARN if allow_insecure_algorithm else PolicyLevel.CONFIRM,
            "insecure_algorithm",
            explanation,
        ))

    # --- writing into the tree being scanned ---------------------------
    if writes_reference and mode == "folder" and is_inside(output, target):
        notices.append(PolicyNotice(
            PolicyLevel.WARN,
            "manifest_inside_folder",
            f"Manifest taranan klasörün içine yazılıyor ({output}); kendi "
            "envanterinden hariç tutuldu. Doğrularken aynı yolu manifest "
            "olarak verin, aksi hâlde 'yeni dosya' görünür.",
        ))

    notices.sort(key=lambda n: 0 if n.blocking else 1)
    return notices


def first_blocking(notices: Sequence[PolicyNotice]) -> Optional[PolicyNotice]:
    """The notice that must stop the run, if any."""
    for notice in notices:
        if notice.blocking:
            return notice
    return None


def confirmations(notices: Sequence[PolicyNotice]) -> list[PolicyNotice]:
    """Notices requiring an explicit yes before proceeding."""
    return [n for n in notices if n.level is PolicyLevel.CONFIRM]


def warnings(notices: Sequence[PolicyNotice]) -> list[PolicyNotice]:
    """Notices to show but not to stop on."""
    return [n for n in notices if n.level is PolicyLevel.WARN]
