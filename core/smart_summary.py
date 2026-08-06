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
from core.risk_engine import RiskAssessment, RiskLevel
from core.signature_checker import SignatureResult, SignatureStatus
from core.vt_client import VTLookupResult, VTStatus


@dataclass
class SmartSummary:
    """Headline + 1–3 supporting sentences + an optional advice line."""

    headline: str
    risk_level: RiskLevel
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


def build_summary(
    assessment: RiskAssessment,
    vt: Optional[VTLookupResult] = None,
    sig: Optional[SignatureResult] = None,
    local: Optional[LocalVerifyResult] = None,
) -> SmartSummary:
    """Render *assessment* (plus its inputs) as friendly Turkish prose."""
    bullets: list[str] = []

    # --- VirusTotal sentence -----------------------------------------
    if vt is not None:
        if vt.status == VTStatus.OK:
            m, s = vt.stats.malicious, vt.stats.suspicious
            # Base the wording on engines that actually produced a verdict.
            # A result made up entirely of timeouts must never be narrated as
            # "no engine flagged it" — nothing was analysed at all.
            if vt.analysing_engines <= 0 or vt.stats_malformed:
                bullets.append(
                    "VirusTotal sonucu alındı ancak kullanılabilir motor "
                    "analizi bulunamadı; bu bir güven işareti sayılamaz."
                )
            elif m == 0 and s == 0 and not vt.is_fresh:
                # Never let an undatable/old "0 detections" read as reassurance.
                when = "çok eski" if vt.is_stale else "tarihi belirsiz"
                bullets.append(
                    f"VirusTotal'da zararlı işareti yok, ancak bu sonuç {when}; "
                    "dosyanın şu anki hâli için güncel bir kanıt sayılmaz."
                )
            elif m == 0 and s == 0:
                bullets.append(
                    "VirusTotal'daki güvenlik motorlarından zararlı veya "
                    "şüpheli işareti gelmedi."
                )
            elif m == 0:
                bullets.append(
                    f"{s} motor bu dosyayı şüpheli buldu, ama zararlı olarak "
                    "işaretleyen yok."
                )
            else:
                bullets.append(
                    f"{m} güvenlik motoru bu dosyayı zararlı olarak işaretledi."
                )
        elif vt.status == VTStatus.NOT_FOUND:
            bullets.append(
                "VirusTotal bu dosyayı daha önce görmemiş — yeni veya nadir bir "
                "dosya olabilir."
            )
        elif vt.status == VTStatus.NO_API_KEY:
            bullets.append(
                "VirusTotal sorgusu yapılmadı (API anahtarı ayarlanmamış)."
            )
        elif vt.status == VTStatus.UNAUTHORIZED:
            bullets.append("VirusTotal anahtarınız reddedildi.")
        elif vt.status == VTStatus.RATE_LIMITED:
            bullets.append("VirusTotal hız limitine ulaşıldı, biraz sonra tekrar deneyin.")
        elif vt.status == VTStatus.NETWORK_ERROR:
            bullets.append("İnternet bağlantısı kurulamadığı için VirusTotal sorgusu başarısız.")
        else:
            bullets.append("VirusTotal sorgusu tamamlanamadı.")

    # --- Signature sentence ------------------------------------------
    if sig is not None:
        if sig.status == SignatureStatus.SIGNED_VALID:
            if sig.signer:
                bullets.append(
                    f"Dosya {sig.signer} tarafından imzalanmış (imza geçerli); "
                    "bu, dosyanın zararsız olduğunu kanıtlamaz."
                )
            else:
                bullets.append(
                    "Dosyanın geçerli bir dijital imzası var; bu, zararsız "
                    "olduğunu kanıtlamaz."
                )
        elif sig.status == SignatureStatus.HASH_MISMATCH:
            bullets.append(
                "Dikkat: dosyanın imzası var ama içeriği imzalandıktan sonra "
                "değişmiş görünüyor (hash uyuşmuyor)."
            )
        elif sig.status == SignatureStatus.UNTRUSTED:
            bullets.append(
                "Dosyanın imzası var ama sertifika zinciri doğrulanamadı — "
                "imza güvenilir kabul edilemez."
            )
        elif sig.status == SignatureStatus.UNSIGNED:
            bullets.append("Dosyanın dijital imzası yok.")
        elif sig.status == SignatureStatus.NOT_APPLICABLE:
            bullets.append("Bu dosya türü dijital imza taşıyamıyor.")

    # --- Local fingerprint sentence ----------------------------------
    if local is not None:
        if local.status == LocalVerifyStatus.SAME:
            bullets.append("Daha önce kaydettiğiniz sürümle birebir aynı.")
        elif local.status == LocalVerifyStatus.CHANGED:
            bullets.append(
                "Dikkat: bu dosya daha önce kaydettiğiniz sürümden farklı görünüyor."
            )
        elif local.status == LocalVerifyStatus.NEW:
            bullets.append("Bu dosyanın hash'i yerel kayda eklendi.")

    advice = _advice_for(assessment.level)

    return SmartSummary(
        headline=assessment.headline,
        risk_level=assessment.level,
        bullets=bullets,
        advice=advice,
    )


def _advice_for(level: RiskLevel) -> str:
    # Cautious by design: even the "Low" advice never says "safe".
    return {
        RiskLevel.LOW: (
            "Bu, dosyanın kesinlikle güvenli olduğu anlamına gelmez — yalnızca "
            "güvendiğiniz kaynaklardan indirdiğiniz dosyaları açın."
        ),
        RiskLevel.MEDIUM: (
            "Dosyayı açmadan önce kaynağını ve indirme adresini bir kez daha "
            "doğrulamanızı öneririz."
        ),
        RiskLevel.HIGH: (
            "Bu dosyayı çalıştırmamanızı öneririz. Şüpheli görünüyorsa silin "
            "ve indirildiği kaynağı tekrar incelemeden kullanmayın."
        ),
        RiskLevel.UNKNOWN: (
            "Daha net bir sonuç için Ayarlar'dan VirusTotal API anahtarınızı "
            "ekleyebilir veya dosyayı kaydederek ileride değişip değişmediğini "
            "izleyebilirsiniz."
        ),
    }[level]
