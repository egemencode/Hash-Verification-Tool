"""
Baseline ("remember this version") policy.

Saving a fingerprint is the one action in the tool that *destroys* prior
evidence: after it, the next scan compares against the new bytes and the old
ones are forgotten. So it must never happen implicitly.

This module holds the decision alone — no I/O, no UI — so the policy can be
tested and reasoned about directly.
"""

from __future__ import annotations

from enum import Enum

from core.local_verify import LocalVerifyStatus
from core.risk_engine import RiskLevel


class BaselineDecision(str, Enum):
    """What the caller must do before touching the stored baseline."""

    SAVE = "save"                      # no prior baseline: just record it
    ALREADY_CURRENT = "already_current"  # identical to the stored one: no-op
    CONFIRM_REPLACE = "confirm_replace"  # file changed: needs explicit consent
    CONFIRM_RISKY = "confirm_risky"      # some risk signals: needs consent
    BLOCKED = "blocked"                  # refuse: this must not become a baseline


def evaluate_baseline_request(
    *,
    local_status: LocalVerifyStatus,
    risk_level: RiskLevel,
    signature_broken: bool = False,
    vt_malicious: int = 0,
    vt_suspicious: int = 0,
) -> BaselineDecision:
    """
    Decide whether the current file may be recorded as the baseline.

    Blocking beats confirming: a file that looks actively bad must not be
    promoted to "the known-good version" even with a confirmation click,
    because that would erase the only record of what the file used to be.

    The decision takes the **actual detection counts**, not just the summarised
    risk level: a single suspicious verdict lands at MEDIUM, and MEDIUM alone
    used to be merely "confirm". Recording a flagged file as known-good is how
    a detection gets normalised away, so any detection blocks outright.
    """
    if vt_malicious >= 1 or vt_suspicious >= 1:
        return BaselineDecision.BLOCKED
    if signature_broken or risk_level is RiskLevel.HIGH:
        return BaselineDecision.BLOCKED

    if local_status is LocalVerifyStatus.SAME:
        return BaselineDecision.ALREADY_CURRENT

    if local_status is LocalVerifyStatus.CHANGED:
        # The stored baseline no longer matches: replacing it silently would
        # hide exactly the change the user should be looking at.
        return BaselineDecision.CONFIRM_REPLACE

    if risk_level is RiskLevel.MEDIUM:
        return BaselineDecision.CONFIRM_RISKY

    return BaselineDecision.SAVE


# User-facing copy, kept next to the policy so the two cannot drift apart.
DECISION_PROMPTS: dict[BaselineDecision, str] = {
    BaselineDecision.SAVE: "Bu sürümü hatırla",
    BaselineDecision.ALREADY_CURRENT: (
        "Bu dosya zaten kayıtlı sürümle aynı; yapılacak bir şey yok."
    ),
    BaselineDecision.CONFIRM_REPLACE: (
        "Bu dosya daha önce kaydettiğiniz sürümden FARKLI.\n\n"
        "Yeni sürümü temel sürüm yaparsanız, önceki sürümle karşılaştırma "
        "yapamazsınız. Değişikliği beklediğinizden emin misiniz?"
    ),
    BaselineDecision.CONFIRM_RISKY: (
        "Bu taramada dikkat edilmesi gereken işaretler var.\n\n"
        "Yine de bu sürümü temel sürüm olarak kaydetmek istiyor musunuz?"
    ),
    BaselineDecision.BLOCKED: (
        "Bu dosya temel sürüm olarak kaydedilemez: tarama bir güvenlik "
        "tespiti, yüksek risk ya da bozuk imza bildiriyor. Bir motorun "
        "işaretlediği dosyayı 'bilinen iyi sürüm' yapmak, tespiti kalıcı "
        "olarak görünmez kılar. Önce dosyanın kaynağını doğrulayın."
    ),
}
