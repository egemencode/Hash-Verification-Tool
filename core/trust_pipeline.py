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
from core.hash_utils import HashError, compute_file_hash
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
) -> TrustResult:
    """
    Run the full trust pipeline against *file_path*.

    Raises :class:`FileInfoError` or :class:`HashError` for unrecoverable
    early failures (file missing, unreadable). Network / VT errors do
    **not** raise — they become a :class:`VTLookupResult` with the
    appropriate status, so the rest of the report can still render.
    """

    def report(step: str) -> None:
        if on_progress is not None:
            on_progress(step)

    report("Dosya bilgileri okunuyor…")
    file_info = collect_file_info(file_path)

    report("Hash değerleri hesaplanıyor…")
    hashes: dict[str, str] = {}
    # Compute all three in one pass-per-algo to keep the code simple;
    # the cost is at most 2x I/O which is dominated by disk on big files.
    # If that ever becomes a bottleneck we can switch to a one-pass
    # multi-hasher.
    for algo in TRUST_ALGORITHMS:
        report(f"{algo.upper()} hesaplanıyor…")
        try:
            hashes[algo] = compute_file_hash(file_info.path, algorithm=algo)
        except HashError:
            # Surface as empty so we never lie about a hash we don't have.
            hashes[algo] = ""

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
