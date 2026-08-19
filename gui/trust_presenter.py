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

from dataclasses import dataclass, field
from typing import Optional

from core.manifest_manager import SignatureState
from core.phrases import Phrase
from gui.i18n import t


# ======================================================================
# Rendering the core's verdict
# ======================================================================
# core/risk_engine.py and core/smart_summary.py decide *which* sentence is
# true and hand back a Phrase — a key plus the values that belong in it. The
# words are chosen here, because this is the layer that already knows which
# language the user picked. See tests/test_verdict_language.py.


def render(phrase: Optional[Phrase]) -> str:
    """One phrase as words. ``None`` renders as the empty string."""
    if phrase is None:
        return ""
    return t(phrase.key, **dict(phrase.params))


@dataclass(frozen=True)
class RenderedSummary:
    """The result card, in words."""

    headline: str
    bullets: list[str] = field(default_factory=list)
    advice: str = ""

    def as_text(self) -> str:
        lines = [self.headline]
        for bullet in self.bullets:
            lines.append(f"• {bullet}")
        if self.advice:
            lines.append("")
            lines.append(self.advice)
        return "\n".join(lines)


@dataclass(frozen=True)
class RenderedFactor:
    """One evidence row, in words. Weight and severity are not language."""

    label: str
    detail: str
    weight: int
    severity: str


def render_summary(summary) -> RenderedSummary:
    return RenderedSummary(
        headline=render(summary.headline),
        bullets=[render(b) for b in summary.bullets],
        advice=render(summary.advice),
    )


def render_factor(factor) -> RenderedFactor:
    return RenderedFactor(
        label=render(factor.label),
        detail=render(factor.detail),
        weight=factor.weight,
        severity=factor.severity,
    )

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


# state -> (icon, i18n key stem, severity, does this establish provenance?)
#
# Keys rather than sentences: this table is built once at import, and a label
# resolved here would be fixed in whichever language happened to be active
# when Python first read the file.
_BADGES: dict[SignatureState, tuple[str, str, str, bool]] = {
    SignatureState.UNSIGNED: ("○", "manifest.badge.unsigned", SEV_WARN, False),
    SignatureState.VALID_EMBEDDED: ("◐", "manifest.badge.embedded", SEV_WARN, False),
    SignatureState.TRUSTED: ("✔", "manifest.badge.trusted", SEV_GOOD, True),
    SignatureState.INVALID: ("✖", "manifest.badge.invalid", SEV_BAD, False),
}


def trust_badge(state: SignatureState) -> TrustBadge:
    """Return the badge for *state* (falls back to the INVALID badge)."""
    if state not in _BADGES:
        state = SignatureState.INVALID
    icon, key, severity, established = _BADGES[state]
    return TrustBadge(
        state=state,
        icon=icon,
        label=t(key),
        detail=t(f"{key}.detail"),
        severity=severity,
        provenance_established=established,
    )


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
        return VerificationHeadline("✖", t("manifest.result.invalid"), SEV_BAD)

    if not files_match:
        return VerificationHeadline("✖", t("manifest.result.mismatch"), SEV_BAD)

    if state is SignatureState.TRUSTED:
        return VerificationHeadline("✔", t("manifest.result.trusted"), SEV_GOOD)

    if state is SignatureState.VALID_EMBEDDED:
        return VerificationHeadline("◐", t("manifest.result.embedded"), SEV_WARN)

    # UNSIGNED
    return VerificationHeadline("◐", t("manifest.result.unsigned"), SEV_WARN)


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
        title=t("startup.warning.title"),
        body=t(
            "startup.warning.body",
            lines="\n\n".join(f"• {line}" for line in lines),
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
