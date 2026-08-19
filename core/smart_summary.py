"""
Friendly Turkish-first summary builder.

Turns the raw outputs of the other modules into a short, no-jargon
paragraph for the main "Güven Kontrolü" screen. The hard rule the
product asks for: **özet önce, teknik sonra.**
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from core.local_verify import LocalVerifyResult, LocalVerifyStatus
from core.phrases import Phrase, phrase
from core.risk_engine import RiskAssessment, RiskLevel
from core.signature_checker import SignatureResult, SignatureStatus
from core.vt_client import VTLookupResult, VTStatus


@dataclass
class SmartSummary:
    """
    Headline + 1–3 supporting sentences + an optional advice line.

    Every field is a :class:`core.phrases.Phrase`: which sentence, and the
    values that go in it. There is deliberately no ``as_text`` here any more.
    Flattening a summary to a string requires choosing a language, and this
    module is the one place that must not — see ``gui/trust_presenter.py`` for
    the rendering, and ``tests/test_verdict_language.py`` for why.
    """

    headline: Phrase
    risk_level: RiskLevel
    bullets: list[Phrase] = field(default_factory=list)
    advice: Optional[Phrase] = None

    def to_dict(self) -> dict:
        return {
            "headline": self.headline.to_dict(),
            "risk_level": self.risk_level.value,
            "bullets": [b.to_dict() for b in self.bullets],
            "advice": self.advice.to_dict() if self.advice else None,
        }


def build_summary(
    assessment: RiskAssessment,
    vt: Optional[VTLookupResult] = None,
    sig: Optional[SignatureResult] = None,
    local: Optional[LocalVerifyResult] = None,
) -> SmartSummary:
    """Choose the sentences that describe *assessment* and its inputs."""
    bullets: list[Phrase] = []

    # --- VirusTotal sentence -----------------------------------------
    if vt is not None:
        if vt.status == VTStatus.OK:
            m, s = vt.stats.malicious, vt.stats.suspicious
            # Base the wording on engines that actually produced a verdict.
            # A result made up entirely of timeouts must never be narrated as
            # "no engine flagged it" — nothing was analysed at all.
            if vt.analysing_engines <= 0 or vt.stats_malformed:
                bullets.append(phrase("summary.vt.no_usable_analysis"))
            elif m == 0 and s == 0 and not vt.is_fresh:
                # Never let an undatable/old "0 detections" read as reassurance.
                # Two complete sentences rather than one with a word swapped
                # into it: "stale" and "undated" are different claims, and a
                # translation must be free to phrase each on its own terms.
                bullets.append(phrase(
                    "summary.vt.clean_but_stale" if vt.is_stale
                    else "summary.vt.clean_but_undated"
                ))
            elif m == 0 and s == 0:
                bullets.append(phrase("summary.vt.clean"))
            elif m == 0:
                bullets.append(phrase("summary.vt.suspicious_only", count=s))
            else:
                bullets.append(phrase("summary.vt.malicious", count=m))
        elif vt.status == VTStatus.NOT_FOUND:
            bullets.append(phrase("summary.vt.not_found"))
        elif vt.status == VTStatus.NO_API_KEY:
            bullets.append(phrase("summary.vt.no_key"))
        elif vt.status == VTStatus.UNAUTHORIZED:
            bullets.append(phrase("summary.vt.unauthorized"))
        elif vt.status == VTStatus.RATE_LIMITED:
            bullets.append(phrase("summary.vt.rate_limited"))
        elif vt.status == VTStatus.NETWORK_ERROR:
            bullets.append(phrase("summary.vt.network_error"))
        else:
            bullets.append(phrase("summary.vt.failed"))

    # --- Signature sentence ------------------------------------------
    if sig is not None:
        if sig.status == SignatureStatus.SIGNED_VALID:
            if sig.signer:
                bullets.append(
                    phrase("summary.sig.signed_valid_by", signer=sig.signer)
                )
            else:
                bullets.append(phrase("summary.sig.signed_valid"))
        elif sig.status == SignatureStatus.HASH_MISMATCH:
            bullets.append(phrase("summary.sig.hash_mismatch"))
        elif sig.status == SignatureStatus.UNTRUSTED:
            bullets.append(phrase("summary.sig.untrusted"))
        elif sig.status == SignatureStatus.UNSIGNED:
            bullets.append(phrase("summary.sig.unsigned"))
        elif sig.status == SignatureStatus.NOT_APPLICABLE:
            bullets.append(phrase("summary.sig.not_applicable"))

    # --- Local fingerprint sentence ----------------------------------
    if local is not None:
        if local.status == LocalVerifyStatus.SAME:
            bullets.append(phrase("summary.local.same"))
        elif local.status == LocalVerifyStatus.CHANGED:
            bullets.append(phrase("summary.local.changed"))
        elif local.status == LocalVerifyStatus.NEW:
            bullets.append(phrase("summary.local.new"))

    advice = _advice_for(assessment.level)

    return SmartSummary(
        headline=assessment.headline,
        risk_level=assessment.level,
        bullets=bullets,
        advice=advice,
    )


def _advice_for(level: RiskLevel) -> Phrase:
    # Cautious by design: even the "Low" advice never says "safe", and that
    # constraint is written into every translation rather than left to the
    # next person who adds a language.
    return phrase(f"summary.advice.{level.value}")
