"""
Risk scoring engine.

Combines the verdicts produced by the other modules
(:mod:`core.vt_client`, :mod:`core.signature_checker`,
:mod:`core.local_verify`) into a single user-facing risk level:
``LOW`` / ``MEDIUM`` / ``HIGH`` / ``UNKNOWN``.

Design principles (v2 policy)
-----------------------------
* **Risk signal and evidence sufficiency are separate.** A low numeric
  score only means "no strong risk signal". It becomes ``LOW`` *only* when
  we actually have malware evidence (a real VirusTotal verdict). Otherwise
  the result is ``UNKNOWN`` — "not enough data" — never a reassuring LOW.
* **Some signals are hard overrides.** A malicious VirusTotal hit, a
  changed local fingerprint, or a broken-integrity signature
  (``HASH_MISMATCH``) force ``HIGH`` regardless of the numeric score.
* **A valid signature is not proof of safety**, and a matching local
  fingerprint only means "same as last time" — neither is malware evidence.
* The numeric ``score`` is an internal, auditable weight. It is clamped to
  a defined range and is **never** presented to the user as a probability
  or a confidence level.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional

from core.local_verify import LocalVerifyResult, LocalVerifyStatus
from core.signature_checker import SignatureResult, SignatureStatus
from core.vt_client import VTLookupResult, VTStatus


# Bump this whenever the decision logic changes so that reports produced by
# an older policy can be flagged in the UI/history.
RISK_POLICY_VERSION = "2.0"

# The score is an internal weight, clamped to this symmetric range. It is
# NOT a probability and NOT a confidence percentage.
SCORE_MIN = -100
SCORE_MAX = 100

# Documented minimum evidence for a LOW verdict. A handful of engines
# agreeing tells us very little; below this the honest answer is "not enough
# data" rather than a reassuring "low risk". VirusTotal routinely returns
# 60-75 engines, so this is a low bar that only filters degenerate responses.
MIN_ENGINES_FOR_LOW = 10


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


# Severity ordering, used only to apply a "minimum level" floor. UNKNOWN is
# deliberately lowest so that a genuine MEDIUM/HIGH floor always wins over
# an "insufficient evidence" result.
_LEVEL_ORDER = {
    RiskLevel.UNKNOWN: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
}


@dataclass
class RiskFactor:
    """Single contribution to the final score (auditable & UI-renderable)."""

    label: str
    detail: str
    weight: int          # positive = riskier, negative = safer
    severity: str        # "info" | "good" | "warn" | "bad"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RiskAssessment:
    level: RiskLevel
    score: int
    headline: str
    policy_version: str = RISK_POLICY_VERSION
    # True only when we have real malware evidence (a VirusTotal verdict).
    # Kept separate from ``level`` so the UI can say "not enough data"
    # instead of implying safety.
    evidence_sufficient: bool = False
    factors: list[RiskFactor] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.value,
            "score": self.score,
            "headline": self.headline,
            "policy_version": self.policy_version,
            "evidence_sufficient": self.evidence_sufficient,
            "factors": [f.to_dict() for f in self.factors],
        }


# Tunable thresholds. Kept at module scope so unit tests can reference them
# without poking at constants inside a function.
_THRESHOLD_HIGH = 60
_THRESHOLD_MEDIUM = 25


def assess(
    vt_result: Optional[VTLookupResult] = None,
    signature_result: Optional[SignatureResult] = None,
    local_result: Optional[LocalVerifyResult] = None,
) -> RiskAssessment:
    """Produce a :class:`RiskAssessment` from the three independent checks."""
    factors: list[RiskFactor] = []
    score = 0

    score += _score_virustotal(vt_result, factors)
    score += _score_signature(signature_result, factors)
    score += _score_local(local_result, factors)

    # Clamp: the score is a bounded internal weight, not an open-ended number.
    score = max(SCORE_MIN, min(SCORE_MAX, score))

    floor = _security_floor(vt_result, signature_result, local_result)
    evidence = _has_malware_evidence(vt_result)

    level = _decide(score, evidence=evidence, floor=floor)
    return RiskAssessment(
        level=level,
        score=score,
        headline=_headline_for(level),
        policy_version=RISK_POLICY_VERSION,
        evidence_sufficient=evidence,
        factors=factors,
    )


# ----------------------------------------------------------------------
# Decision helpers
# ----------------------------------------------------------------------
def _security_floor(
    vt: Optional[VTLookupResult],
    sig: Optional[SignatureResult],
    local: Optional[LocalVerifyResult],
) -> RiskLevel:
    """
    The decision table: the **minimum** level each signal mandates.

    This is deliberately not additive. A detection is a fact about the file;
    positive context (a valid signature, a matching fingerprint) explains
    *who* shipped it, never that the detection was wrong. Scores are only
    allowed to raise the result above this floor, never below it.
    """
    floor = RiskLevel.UNKNOWN

    def raise_to(level: RiskLevel) -> None:
        nonlocal floor
        if _LEVEL_ORDER[level] > _LEVEL_ORDER[floor]:
            floor = level

    if vt is not None and vt.status == VTStatus.OK:
        # Note: this deliberately runs even when `stats_malformed` is set. A
        # counter we *did* parse successfully is still a real detection; a
        # broken sibling field must not make it disappear. Malformation only
        # blocks the reassuring direction (see _has_malware_evidence).
        if vt.stats.malicious >= 1:
            raise_to(RiskLevel.HIGH)
        elif vt.stats.suspicious >= 1:
            # Even a single suspicious verdict among many clean ones must be
            # surfaced for review — it may not be flattened into LOW.
            raise_to(RiskLevel.MEDIUM)

    if local is not None and local.status == LocalVerifyStatus.CHANGED:
        raise_to(RiskLevel.HIGH)

    if sig is not None:
        if sig.status == SignatureStatus.HASH_MISMATCH:
            raise_to(RiskLevel.HIGH)
        elif sig.status == SignatureStatus.UNTRUSTED:
            raise_to(RiskLevel.MEDIUM)

    return floor


def _has_malware_evidence(vt: Optional[VTLookupResult]) -> bool:
    """
    True only when we have a *real* verdict about maliciousness.

    Only a VirusTotal response backed by at least one engine counts. A
    valid signature or a matching local fingerprint says nothing about
    malware, so they never make the evidence "sufficient". A NOT_FOUND,
    network/quota error, missing key, or a zero-engine response are all
    "no evidence".
    """
    # Requires an OK verdict, well-formed stats, established freshness, and
    # enough engines behind it to be meaningful. A handful of engines is not
    # a basis for reassuring the user.
    # The quorum counts only engines that actually returned a verdict —
    # timeouts and unsupported types analysed nothing and must not pad it.
    return bool(
        vt is not None
        and vt.is_usable_verdict
        and vt.analysing_engines >= MIN_ENGINES_FOR_LOW
    )


def _decide(score: int, *, evidence: bool, floor: RiskLevel) -> RiskLevel:
    """
    Combine the additive score with the mandatory security floor.

    The score may only *raise* the outcome. This is what makes the model
    monotonic: no accumulation of reassuring signals can push a result below
    what the decision table requires.
    """
    if score >= _THRESHOLD_HIGH:
        level = RiskLevel.HIGH
    elif score >= _THRESHOLD_MEDIUM:
        level = RiskLevel.MEDIUM
    else:
        # Below the medium threshold we only call it LOW when we actually
        # have sufficient evidence. Otherwise it is "not enough data".
        level = RiskLevel.LOW if evidence else RiskLevel.UNKNOWN

    if _LEVEL_ORDER[floor] > _LEVEL_ORDER[level]:
        level = floor
    return level


# ----------------------------------------------------------------------
# Scoring sub-routines
# ----------------------------------------------------------------------
def _score_virustotal(vt: Optional[VTLookupResult], out: list[RiskFactor]) -> int:
    if vt is None:
        out.append(RiskFactor("VirusTotal", "Sorgu yapılmadı.", 0, "info"))
        return 0

    if vt.status == VTStatus.OK:
        # A verdict with no *analysing* engines behind it is not usable
        # evidence, even if plenty of engines timed out.
        if vt.analysing_engines <= 0:
            out.append(
                RiskFactor(
                    "VirusTotal",
                    "Sonuç döndü ama hiçbir motor veri vermedi; güven sinyali sayılmadı.",
                    0,
                    "info",
                )
            )
            return 0

        malicious = vt.stats.malicious
        suspicious = vt.stats.suspicious
        if malicious >= 5:
            weight, severity = 80, "bad"
            detail = f"{malicious} güvenlik motoru zararlı olarak işaretledi."
        elif malicious >= 1:
            weight, severity = 50, "bad"
            detail = f"{malicious} güvenlik motoru zararlı olarak işaretledi."
        elif suspicious >= 3:
            weight, severity = 25, "warn"
            detail = f"{suspicious} motor şüpheli olarak işaretledi."
        elif suspicious >= 1:
            weight, severity = 12, "warn"
            detail = f"{suspicious} motor şüpheli olarak işaretledi."
        else:
            # A clean verdict is only a positive signal when we can establish
            # that it is current and well-formed. Malicious/suspicious hits
            # above are scored regardless of age — a stale detection is still
            # a detection; only the *reassuring* direction needs freshness.
            if not vt.is_fresh:
                reason = (
                    "VirusTotal sonucu çok eski"
                    if vt.is_stale
                    else "VirusTotal sonucunun tarihi belirlenemedi"
                )
                out.append(
                    RiskFactor(
                        "VirusTotal",
                        f"{reason}; güncel bir güven sinyali sayılmadı.",
                        0,
                        "info",
                    )
                )
                return 0
            if vt.stats_malformed:
                out.append(
                    RiskFactor(
                        "VirusTotal",
                        "VirusTotal motor istatistikleri okunamadı; güven sinyali sayılmadı.",
                        0,
                        "info",
                    )
                )
                return 0
            # Context, not negative risk: a clean sweep is recorded with zero
            # weight so it cannot offset a detection from another signal.
            weight, severity = 0, "good"
            detail = f"{vt.analysing_engines} motorda zararlı/şüpheli işareti yok."
        out.append(RiskFactor("VirusTotal", detail, weight, severity))
        return weight

    if vt.status == VTStatus.NOT_FOUND:
        out.append(
            RiskFactor(
                "VirusTotal",
                "Bu hash VirusTotal'da yok — dosya yeni veya nadir olabilir; "
                "temiz olduğu anlamına gelmez.",
                10,
                "warn",
            )
        )
        return 10

    # No key / unauthorized / rate-limited / network / other error: these are
    # NOT clean evidence, and they carry no weight.
    detail = {
        VTStatus.NO_API_KEY: "API anahtarı ayarlanmadığı için sorgu yapılamadı.",
        VTStatus.UNAUTHORIZED: vt.message or "API anahtarı reddedildi.",
        VTStatus.RATE_LIMITED: vt.message or "Hız limitine takıldı.",
        VTStatus.NETWORK_ERROR: vt.message or "VirusTotal'a ulaşılamadı.",
    }.get(vt.status, vt.message or "Sorgu tamamlanamadı.")
    out.append(RiskFactor("VirusTotal", detail, 0, "info"))
    return 0


def _score_signature(sig: Optional[SignatureResult], out: list[RiskFactor]) -> int:
    if sig is None:
        out.append(RiskFactor("Dijital İmza", "Kontrol yapılmadı.", 0, "info"))
        return 0

    status = sig.status
    if status == SignatureStatus.SIGNED_VALID:
        detail = (
            f"Geçerli dijital imza: {sig.signer}"
            if sig.signer
            else "Dosyanın geçerli bir dijital imzası var."
        )
        # Weight 0 on purpose: a signature tells us who published the file,
        # not that it is harmless. Signed malware is routine, so this must
        # never subtract from a detection.
        out.append(RiskFactor("Dijital İmza", detail, 0, "good"))
        return 0

    if status == SignatureStatus.HASH_MISMATCH:
        out.append(
            RiskFactor(
                "Dijital İmza",
                "İmza var ama dosya içeriği imzalandıktan sonra değişmiş (hash uyuşmuyor).",
                60,
                "bad",
            )
        )
        return 60

    if status == SignatureStatus.UNTRUSTED:
        out.append(
            RiskFactor(
                "Dijital İmza",
                "İmza var ama sertifika zinciri doğrulanamadı (güvenilir değil).",
                30,
                "bad",
            )
        )
        return 30

    if status == SignatureStatus.UNSIGNED:
        out.append(
            RiskFactor("Dijital İmza", "Dosyada dijital imza yok.", 8, "warn")
        )
        return 8

    if status == SignatureStatus.NOT_APPLICABLE:
        out.append(
            RiskFactor(
                "Dijital İmza",
                "Bu dosya türü için imza kontrolü uygulanamaz.",
                0,
                "info",
            )
        )
        return 0

    if status == SignatureStatus.UNSUPPORTED:
        out.append(
            RiskFactor(
                "Dijital İmza", "Bu işletim sisteminde desteklenmiyor.", 0, "info"
            )
        )
        return 0

    # UNKNOWN / ERROR: inconclusive check — neutral, never "invalid".
    out.append(
        RiskFactor(
            "Dijital İmza", sig.message or "İmza durumu belirlenemedi.", 0, "info"
        )
    )
    return 0


def _score_local(local: Optional[LocalVerifyResult], out: list[RiskFactor]) -> int:
    if local is None:
        return 0

    if local.status == LocalVerifyStatus.SAME:
        # Weight 0: the fingerprint store is a plain, user-writable JSON file,
        # so it is not a trust root. "Same as last time" is context only and
        # must never lower the risk produced by an engine detection.
        out.append(
            RiskFactor(
                "Yerel Kayıt",
                "Daha önce kaydedilen sürümle birebir aynı (zararlılık kanıtı değil).",
                0,
                "good",
            )
        )
        return 0

    if local.status == LocalVerifyStatus.CHANGED:
        out.append(
            RiskFactor(
                "Yerel Kayıt",
                "Dosya daha önce kaydedilen sürümden farklı!",
                40,
                "bad",
            )
        )
        return 40

    if local.status == LocalVerifyStatus.NEW:
        out.append(
            RiskFactor(
                "Yerel Kayıt", "Bu dosyanın hash'i yerel kayda eklendi.", 0, "info"
            )
        )
        return 0

    return 0


# ----------------------------------------------------------------------
# Headline
# ----------------------------------------------------------------------
def _headline_for(level: RiskLevel) -> str:
    # We intentionally avoid words like "güvenli" / "safe". No tool can
    # guarantee a file is harmless — we only report what the signals say.
    return {
        RiskLevel.LOW: "Güçlü bir risk işareti bulunamadı.",
        RiskLevel.MEDIUM: "Dikkatli olun — bazı şüpheli işaretler var.",
        RiskLevel.HIGH: "Bu dosya şüpheli olabilir.",
        RiskLevel.UNKNOWN: "Bu dosya hakkında yeterli veri yok.",
    }[level]
