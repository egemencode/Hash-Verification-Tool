"""
Risk scoring engine.

Combines the verdicts produced by the other modules
(:mod:`core.vt_client`, :mod:`core.signature_checker`,
:mod:`core.local_verify`) into a single user-facing risk level:
``LOW`` / ``MEDIUM`` / ``HIGH`` / ``UNKNOWN``.

The scoring is intentionally simple — the goal is *defensible* and
*explainable*, not academically optimal. Every signal contributes a
positive (riskier) or negative (safer) integer; the engine clamps the
total and maps it onto a bucket.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional

from core.local_verify import LocalVerifyResult, LocalVerifyStatus
from core.signature_checker import SignatureResult, SignatureStatus
from core.vt_client import VTLookupResult, VTStatus


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


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
    factors: list[RiskFactor] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.value,
            "score": self.score,
            "headline": self.headline,
            "factors": [f.to_dict() for f in self.factors],
        }


# Tunable thresholds. Kept at module scope so unit tests can reference
# them without poking at constants inside a function.
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

    level = _bucket(score, vt_result, local_result)
    headline = _headline_for(level)
    return RiskAssessment(level=level, score=score, headline=headline, factors=factors)


# ----------------------------------------------------------------------
# Scoring sub-routines
# ----------------------------------------------------------------------
def _score_virustotal(vt: Optional[VTLookupResult], out: list[RiskFactor]) -> int:
    if vt is None:
        out.append(
            RiskFactor(
                label="VirusTotal",
                detail="Sorgu yapılmadı.",
                weight=0,
                severity="info",
            )
        )
        return 0

    if vt.status == VTStatus.OK:
        malicious = vt.stats.malicious
        suspicious = vt.stats.suspicious
        if malicious >= 5:
            weight = 80
            severity = "bad"
            detail = f"{malicious} güvenlik motoru zararlı olarak işaretledi."
        elif malicious >= 1:
            weight = 50
            severity = "bad"
            detail = f"{malicious} güvenlik motoru zararlı olarak işaretledi."
        elif suspicious >= 3:
            weight = 25
            severity = "warn"
            detail = f"{suspicious} motor şüpheli olarak işaretledi."
        elif suspicious >= 1:
            weight = 12
            severity = "warn"
            detail = f"{suspicious} motor şüpheli olarak işaretledi."
        else:
            weight = -15
            severity = "good"
            engines_text = (
                f"{vt.total_engines} motorda" if vt.total_engines else "motorlarda"
            )
            detail = f"VirusTotal {engines_text} zararlı/şüpheli işareti yok."
        out.append(
            RiskFactor(
                label="VirusTotal",
                detail=detail,
                weight=weight,
                severity=severity,
            )
        )
        return weight

    if vt.status == VTStatus.NOT_FOUND:
        out.append(
            RiskFactor(
                label="VirusTotal",
                detail="Bu hash VirusTotal veritabanında yok — dosya yeni veya nadir olabilir.",
                weight=10,
                severity="warn",
            )
        )
        return 10

    if vt.status == VTStatus.NO_API_KEY:
        out.append(
            RiskFactor(
                label="VirusTotal",
                detail="API anahtarı ayarlanmadığı için sorgu yapılamadı.",
                weight=0,
                severity="info",
            )
        )
        return 0

    if vt.status in (VTStatus.UNAUTHORIZED, VTStatus.RATE_LIMITED):
        out.append(
            RiskFactor(
                label="VirusTotal",
                detail=vt.message or "Sorgu reddedildi.",
                weight=0,
                severity="info",
            )
        )
        return 0

    out.append(
        RiskFactor(
            label="VirusTotal",
            detail=vt.message or "Sorgu sırasında bir sorun oluştu.",
            weight=0,
            severity="info",
        )
    )
    return 0


def _score_signature(sig: Optional[SignatureResult], out: list[RiskFactor]) -> int:
    if sig is None:
        out.append(
            RiskFactor(
                label="Dijital İmza",
                detail="Kontrol yapılmadı.",
                weight=0,
                severity="info",
            )
        )
        return 0

    if sig.status == SignatureStatus.SIGNED_VALID:
        detail = (
            f"Geçerli dijital imza: {sig.signer}"
            if sig.signer
            else "Dosya geçerli bir dijital imzaya sahip."
        )
        out.append(
            RiskFactor(label="Dijital İmza", detail=detail, weight=-20, severity="good")
        )
        return -20

    if sig.status == SignatureStatus.SIGNED_INVALID:
        out.append(
            RiskFactor(
                label="Dijital İmza",
                detail="İmza var ama doğrulanamadı (sertifika güvenilir değil veya hash uyumsuz).",
                weight=30,
                severity="bad",
            )
        )
        return 30

    if sig.status == SignatureStatus.UNSIGNED:
        out.append(
            RiskFactor(
                label="Dijital İmza",
                detail="Dosyada dijital imza yok.",
                weight=8,
                severity="warn",
            )
        )
        return 8

    if sig.status == SignatureStatus.UNSUPPORTED:
        out.append(
            RiskFactor(
                label="Dijital İmza",
                detail="Bu işletim sisteminde desteklenmiyor.",
                weight=0,
                severity="info",
            )
        )
        return 0

    out.append(
        RiskFactor(
            label="Dijital İmza",
            detail=sig.message or "İmza durumu belirsiz.",
            weight=0,
            severity="info",
        )
    )
    return 0


def _score_local(local: Optional[LocalVerifyResult], out: list[RiskFactor]) -> int:
    if local is None:
        return 0

    if local.status == LocalVerifyStatus.SAME:
        out.append(
            RiskFactor(
                label="Yerel Kayıt",
                detail="Daha önce kaydedilen sürümle birebir aynı.",
                weight=-10,
                severity="good",
            )
        )
        return -10

    if local.status == LocalVerifyStatus.CHANGED:
        out.append(
            RiskFactor(
                label="Yerel Kayıt",
                detail="Dosya daha önce kaydedilen sürümden farklı!",
                weight=40,
                severity="bad",
            )
        )
        return 40

    if local.status == LocalVerifyStatus.NEW:
        out.append(
            RiskFactor(
                label="Yerel Kayıt",
                detail="Bu dosyanın hash'i yerel kayda eklendi.",
                weight=0,
                severity="info",
            )
        )
        return 0

    return 0


# ----------------------------------------------------------------------
# Bucketing & headline
# ----------------------------------------------------------------------
def _bucket(
    score: int,
    vt: Optional[VTLookupResult],
    local: Optional[LocalVerifyResult],
) -> RiskLevel:
    # Strong signals override the numeric bucket so the user does not
    # see "Low risk" right after a 40-engine red flag.
    if vt and vt.status == VTStatus.OK and vt.stats.malicious >= 1:
        return RiskLevel.HIGH
    if local and local.status == LocalVerifyStatus.CHANGED:
        return RiskLevel.HIGH
    if score >= _THRESHOLD_HIGH:
        return RiskLevel.HIGH
    if score >= _THRESHOLD_MEDIUM:
        return RiskLevel.MEDIUM
    # If we have basically no signal at all (no VT key, no signature
    # support, no local record), call it Unknown instead of pretending
    # everything is fine.
    has_any_evidence = (
        (vt is not None and vt.status in (VTStatus.OK, VTStatus.NOT_FOUND))
        or (local is not None and local.status != LocalVerifyStatus.NOT_TRACKED)
    )
    if not has_any_evidence and score <= 0:
        return RiskLevel.UNKNOWN
    return RiskLevel.LOW


def _headline_for(level: RiskLevel) -> str:
    # We intentionally avoid words like "güvenli" / "safe". No tool can
    # guarantee a file is harmless — we only report what the available
    # signals say.
    return {
        RiskLevel.LOW: "Güçlü bir risk işareti bulunamadı.",
        RiskLevel.MEDIUM: "Dikkatli olun — bazı şüpheli işaretler var.",
        RiskLevel.HIGH: "Bu dosya şüpheli olabilir.",
        RiskLevel.UNKNOWN: "Bu dosya hakkında yeterli veri yok.",
    }[level]
