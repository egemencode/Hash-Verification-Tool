"""
Presentation logic for manifest trust + verification outcome.

Deliberately free of any Tk import so the *wording and the decision rules*
can be unit-tested without a display. The GUI only renders what these
functions return.

The core rule this module enforces: **"files match" is not the same as
"trustworthy"**. A manifest that is unsigned, or signed only with a key that
travelled inside the manifest itself, does not establish where the reference
hashes came from — so the UI must never present that outcome as a bare
"Temiz".
"""

from __future__ import annotations

from dataclasses import dataclass

from core.manifest_manager import SignatureState

# Severity buckets the GUI maps to colours. Colour is never the only carrier
# of meaning — every state also has an icon and explicit text.
SEV_GOOD = "good"
SEV_INFO = "info"
SEV_WARN = "warn"
SEV_BAD = "bad"


@dataclass(frozen=True)
class TrustBadge:
    """How to render the manifest's own trust level."""

    state: SignatureState
    icon: str
    label: str
    detail: str
    severity: str
    # False when the manifest's provenance is not established, so the caller
    # must not claim a plain "clean" result.
    provenance_established: bool


_BADGES: dict[SignatureState, TrustBadge] = {
    SignatureState.UNSIGNED: TrustBadge(
        state=SignatureState.UNSIGNED,
        icon="○",
        label="Manifest imzasız",
        detail=(
            "Bu manifest imzalanmamış. Referans hash'lerin kaynağı "
            "doğrulanamaz; manifest dosyası değiştirilmiş olabilir."
        ),
        severity=SEV_WARN,
        provenance_established=False,
    ),
    SignatureState.VALID_EMBEDDED: TrustBadge(
        state=SignatureState.VALID_EMBEDDED,
        icon="◐",
        label="İmza geçerli — kaynak anahtar güvenilmiyor",
        detail=(
            "İmza, manifestin kendi içindeki anahtarla doğrulandı. Bu yalnızca "
            "manifestin kendi içinde tutarlı olduğunu gösterir: manifesti "
            "değiştiren biri kendi anahtarını da gömebilirdi. Kaynağı "
            "doğrulamak için güvendiğiniz genel anahtarı kullanın."
        ),
        severity=SEV_WARN,
        provenance_established=False,
    ),
    SignatureState.TRUSTED: TrustBadge(
        state=SignatureState.TRUSTED,
        icon="✔",
        label="Güvenilen anahtarla doğrulandı",
        detail=(
            "Manifest imzası, sağladığınız güvenilen genel anahtarla "
            "doğrulandı; içeriği imzalandığından beri değişmemiş."
        ),
        severity=SEV_GOOD,
        provenance_established=True,
    ),
    SignatureState.INVALID: TrustBadge(
        state=SignatureState.INVALID,
        icon="✖",
        label="Manifest imzası geçersiz",
        detail=(
            "Manifestin imzası doğrulanamadı. Manifest kurcalanmış olabilir; "
            "karşılaştırma sonuçlarına güvenmeyin."
        ),
        severity=SEV_BAD,
        provenance_established=False,
    ),
}


def trust_badge(state: SignatureState) -> TrustBadge:
    """Return the badge for *state* (falls back to the INVALID badge)."""
    return _BADGES.get(state, _BADGES[SignatureState.INVALID])


@dataclass(frozen=True)
class VerificationHeadline:
    """The single sentence shown above the verification summary."""

    icon: str
    text: str
    severity: str


def verification_headline(
    *, files_match: bool, state: SignatureState
) -> VerificationHeadline:
    """
    Combine "did the files match?" with "can we trust the manifest?".

    A match against an unverified manifest is reported as a *qualified*
    result, never as an unconditional "Temiz".
    """
    if state is SignatureState.INVALID:
        return VerificationHeadline(
            "✖",
            "Manifest imzası geçersiz — karşılaştırma sonucu güvenilir değil.",
            SEV_BAD,
        )

    if not files_match:
        return VerificationHeadline(
            "✖", "Farklılıklar bulundu — dosyalar manifestle eşleşmiyor.", SEV_BAD
        )

    if state is SignatureState.TRUSTED:
        return VerificationHeadline(
            "✔",
            "Dosyalar, güvenilen anahtarla doğrulanmış manifestle eşleşiyor.",
            SEV_GOOD,
        )

    if state is SignatureState.VALID_EMBEDDED:
        return VerificationHeadline(
            "◐",
            "Dosyalar manifestle eşleşiyor; ancak manifestin kaynağı doğrulanmadı.",
            SEV_WARN,
        )

    # UNSIGNED
    return VerificationHeadline(
        "◐",
        "Dosyalar manifestle eşleşiyor; ancak manifest imzasız olduğu için "
        "referans veriler değiştirilmiş olabilir.",
        SEV_WARN,
    )


@dataclass(frozen=True)
class StartupWarning:
    """A one-off notice shown when the app starts."""

    title: str
    body: str


def collect_startup_warnings(
    *,
    settings_warnings: list[str] | None = None,
    history_warning: str | None = None,
    local_store_warning: str | None = None,
) -> StartupWarning | None:
    """
    Fold every "your data was not in the state we expected" notice into one
    dialog payload, or ``None`` when there is nothing to report.

    Kept separate from the Tk layer so the wording and the
    show-once/nothing-to-show decisions are unit-testable.
    """
    lines: list[str] = []
    lines.extend(settings_warnings or [])
    for warning in (history_warning, local_store_warning):
        if warning:
            lines.append(warning)
    if not lines:
        return None

    return StartupWarning(
        title="Veri Uyarısı",
        body=(
            "Uygulama başlarken bazı kayıtlar beklenen durumda değildi:\n\n"
            + "\n\n".join(f"• {line}" for line in lines)
        ),
    )


def describe_result(result) -> tuple[VerificationHeadline, TrustBadge]:
    """Convenience wrapper for a :class:`core.verifier.VerificationResult`."""
    state = result.signature_state
    # is_clean already returns False for INVALID; compare on the file findings
    # so the headline can distinguish "files differ" from "manifest untrusted".
    files_match = not (
        result.modified or result.new or result.missing or result.errors
    )
    return verification_headline(files_match=files_match, state=state), trust_badge(state)
