"""
Trust-check orchestration.

Glues together the individual modules (hashing, VirusTotal lookup,
signature check, local fingerprint compare, risk engine, smart summary)
into one ``run_trust_check()`` function. The GUI runs this on a worker
thread; the pipeline emits progress callbacks for the status bar.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from core.file_info import FileInfo, FileInfoError, collect_file_info
from core.hash_utils import (
    FileChangedDuringScanError,
    HashError,
    compute_file_hashes_with_snapshot,
    snapshot_file,
)
from core.local_verify import LocalVerifyResult, LocalVerifyStore
from core.risk_engine import RiskAssessment, assess
from core.signature_checker import SignatureResult, check_signature
from core.smart_summary import SmartSummary, build_summary
from core.trust_report import TrustReport
from core.vt_client import VirusTotalClient, VTLookupResult


# Algorithms the GUI displays in the detail panel. Kept narrow on purpose:
# we still expose SHA-512 in the legacy hash tab via SUPPORTED_ALGORITHMS,
# but the "trust check" surface area is intentionally the three names
# end-users actually look for on download pages.
TRUST_ALGORITHMS: tuple[str, ...] = ("md5", "sha1", "sha256")


ProgressCallback = Callable[[str], None]


def resolve_online_checks(
    *, autoquery: bool, has_key: bool, online_allowed: bool = True
) -> bool:
    """
    The single place that decides whether this scan may contact VirusTotal.

    All three must hold: the user enabled online checks, a key is configured,
    and nothing else (e.g. an explicit offline mode) has vetoed it. Callers
    must route through here instead of testing ``client.has_key`` alone —
    that was the defect where a saved "do not query" preference was ignored.
    """
    return bool(autoquery) and bool(has_key) and bool(online_allowed)


# What we send, stated plainly enough to put in the UI verbatim.
PRIVACY_NOTICE = (
    "Dosyanız yüklenmez. Yalnızca dosyanın SHA-256 özeti VirusTotal'a "
    "gönderilir; bu istek IP adresiniz ve API hesabınızla ilişkilendirilebilir."
)


@dataclass
class TrustResult:
    """Everything the GUI needs to render one scan."""

    file_info: FileInfo
    hashes: dict[str, str] = field(default_factory=dict)
    vt: Optional[VTLookupResult] = None
    signature: Optional[SignatureResult] = None
    local: Optional[LocalVerifyResult] = None
    assessment: Optional[RiskAssessment] = None
    summary: Optional[SmartSummary] = None

    @property
    def sha256(self) -> str:
        return self.hashes.get("sha256", "")

    def to_report(self) -> TrustReport:
        return TrustReport(
            file_info=self.file_info,
            hashes=dict(self.hashes),
            vt_result=self.vt,
            signature_result=self.signature,
            local_result=self.local,
            assessment=self.assessment,
            summary=self.summary,
        )


# ----------------------------------------------------------------------
def run_trust_check(
    file_path: str,
    *,
    vt_client: VirusTotalClient,
    local_store: Optional[LocalVerifyStore] = None,
    check_signature_flag: bool = True,
    query_virustotal: bool = True,
    on_progress: Optional[ProgressCallback] = None,
    cancel_check: Optional[Callable[[], None]] = None,
) -> TrustResult:
    """
    Run the full trust pipeline against *file_path*.

    Raises :class:`FileInfoError` or :class:`HashError` for unrecoverable
    early failures (file missing, unreadable). Network / VT errors do
    **not** raise — they become a :class:`VTLookupResult` with the
    appropriate status, so the rest of the report can still render.
    """

    def report(step: str) -> None:
        # Cancellation is checked at every stage boundary: the VirusTotal and
        # signature stages can each take seconds, and a user who cancelled
        # should not wait for them to finish.
        if cancel_check is not None:
            cancel_check()
        if on_progress is not None:
            on_progress(step)

    report("Dosya bilgileri okunuyor…")
    file_info = collect_file_info(file_path)

    report("Hash değerleri hesaplanıyor…")
    # One pass over the file for MD5 / SHA-1 / SHA-256 so every digest comes
    # from the exact same bytes. The snapshot is read with fstat() from that
    # same descriptor — taking it with a separate stat() afterwards would
    # leave a window where the file could be swapped between the hashing and
    # the metadata read. If the file changes mid-read this raises
    # FileChangedDuringScanError and we do NOT produce a trust verdict.
    hashes, snapshot_after_hash = compute_file_hashes_with_snapshot(
        file_info.path, TRUST_ALGORITHMS, ensure_stable=True
    )

    result = TrustResult(file_info=file_info, hashes=hashes)

    # --- VirusTotal --------------------------------------------------
    if query_virustotal:
        report("VirusTotal sorgulanıyor…")
        sha256 = hashes.get("sha256") or ""
        result.vt = vt_client.lookup_hash(sha256)
    else:
        result.vt = None

    # --- Digital signature ------------------------------------------
    if check_signature_flag:
        report("Dijital imza kontrol ediliyor…")
        result.signature = check_signature(file_info.path)
    else:
        result.signature = None

    # --- Local fingerprint compare ----------------------------------
    if local_store is not None and hashes.get("sha256"):
        report("Yerel kayıt karşılaştırılıyor…")
        result.local = local_store.compare(file_info.path, hashes["sha256"])
    else:
        result.local = None

    # --- Re-verify the file did not change mid-scan -----------------
    # VirusTotal / signature checks can take seconds; a verdict about a file
    # that was swapped underneath us in the meantime would be misleading.
    #
    # The cheap size/mtime comparison runs first, but we do NOT stop there: an
    # active attacker can rewrite content and restore both the size and the
    # mtime. The authoritative check is therefore content-based — we re-read
    # the file and recompute SHA-256, which no metadata forgery can defeat.
    report("Dosya bütünlüğü yeniden doğrulanıyor…")
    try:
        snapshot_final = snapshot_file(file_info.path)
    except HashError as exc:
        raise FileChangedDuringScanError(
            f"Dosya tarama sırasında erişilemez oldu: {file_info.path}"
        ) from exc
    if not snapshot_after_hash.is_same(snapshot_final):
        raise FileChangedDuringScanError(
            f"Dosya tarama sırasında değişti: {file_info.path}"
        )

    recheck, _snap = compute_file_hashes_with_snapshot(
        file_info.path, ("sha256",), ensure_stable=True
    )
    if recheck.get("sha256") != hashes.get("sha256"):
        raise FileChangedDuringScanError(
            f"Dosya içeriği tarama sırasında değişti: {file_info.path}"
        )

    # --- Risk + summary ---------------------------------------------
    report("Risk değerlendiriliyor…")
    result.assessment = assess(
        vt_result=result.vt,
        signature_result=result.signature,
        local_result=result.local,
    )
    result.summary = build_summary(
        result.assessment,
        vt=result.vt,
        sig=result.signature,
        local=result.local,
    )

    report("Tamamlandı.")
    return result
