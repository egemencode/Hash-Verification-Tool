"""
Trust-report exporter.

Bundles everything a single "Güven Kontrolü" scan produced into one
payload and writes it out as either JSON (machine-readable) or HTML
(human-friendly, single file you can share).

Kept separate from the legacy :mod:`core.reporter` so the manifest
verification pipeline stays untouched.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from core.file_info import FileInfo
from core.local_verify import LocalVerifyResult
from core.risk_engine import RiskAssessment, RiskLevel
from core.signature_checker import SignatureResult
from core.smart_summary import SmartSummary
from core.vt_client import VTLookupResult


class TrustReportError(Exception):
    """Raised when a trust report cannot be written."""


@dataclass
class TrustReport:
    """Aggregated payload for a single file scan."""

    file_info: FileInfo
    hashes: dict[str, str]
    vt_result: Optional[VTLookupResult] = None
    signature_result: Optional[SignatureResult] = None
    local_result: Optional[LocalVerifyResult] = None
    assessment: Optional[RiskAssessment] = None
    summary: Optional[SmartSummary] = None
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc)
        .astimezone()
        .isoformat(timespec="seconds")
    )

    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "trust-report/1.0",
            "generated_at": self.generated_at,
            "file": self.file_info.to_dict(),
            "hashes": dict(self.hashes),
            "virustotal": self.vt_result.to_dict() if self.vt_result else None,
            "signature": self.signature_result.to_dict() if self.signature_result else None,
            "local_record": self.local_result.to_dict() if self.local_result else None,
            "risk": self.assessment.to_dict() if self.assessment else None,
            "summary": {
                "headline": self.summary.headline if self.summary else "",
                "risk_level": self.summary.risk_level.value if self.summary else "",
                "bullets": list(self.summary.bullets) if self.summary else [],
                "advice": self.summary.advice if self.summary else "",
            },
        }


# ----------------------------------------------------------------------
# JSON
# ----------------------------------------------------------------------
def export_json(report: TrustReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            json.dump(report.to_dict(), fh, indent=2, ensure_ascii=False)
    except OSError as exc:
        raise TrustReportError(f"JSON rapor yazılamadı: {exc}") from exc
    return path


# ----------------------------------------------------------------------
# HTML
# ----------------------------------------------------------------------
# A third copy of the risk palette. It cannot import gui.theme without
# inverting the layering, so the two are kept in step by
# tests/test_gui_theme_contrast.py instead: the copies existing is tolerable,
# the copies drifting apart is not — and they did, the moment the on-screen
# colours were repaired for contrast and this one was left behind, so the same
# verdict rendered in two shades depending on where you looked at it.
_RISK_COLOR = {
    RiskLevel.LOW.value:    "#2b742f",
    RiskLevel.MEDIUM.value: "#a74b00",
    RiskLevel.HIGH.value:   "#c62828",
    RiskLevel.UNKNOWN.value: "#616161",
}

_RISK_TR = {
    RiskLevel.LOW.value:    "Düşük Risk",
    RiskLevel.MEDIUM.value: "Orta Risk",
    RiskLevel.HIGH.value:   "Yüksek Risk",
    RiskLevel.UNKNOWN.value: "Bilinmiyor",
}


def export_html(report: TrustReport, output_path: str | Path) -> Path:
    """Render the report as a single, self-contained HTML page."""
    data = report.to_dict()
    risk_level = (data.get("risk") or {}).get("level") or RiskLevel.UNKNOWN.value
    risk_color = _RISK_COLOR.get(risk_level, _RISK_COLOR[RiskLevel.UNKNOWN.value])
    risk_label_tr = _RISK_TR.get(risk_level, "Bilinmiyor")

    summary = data.get("summary") or {}
    bullets_html = "".join(
        f"<li>{html.escape(str(b))}</li>" for b in (summary.get("bullets") or [])
    )

    hashes = data.get("hashes") or {}
    hashes_rows = "".join(
        f"<tr><th>{html.escape(name.upper())}</th><td><code>{html.escape(value)}</code></td></tr>"
        for name, value in hashes.items()
    )

    file_info = data.get("file") or {}
    file_rows = "".join(
        f"<tr><th>{html.escape(label)}</th><td>{html.escape(str(file_info.get(key, '')))}</td></tr>"
        for key, label in (
            ("name", "Dosya Adı"),
            ("path", "Tam Yol"),
            ("size_human", "Boyut"),
            ("extension", "Uzantı"),
            ("created_at", "Oluşturulma"),
            ("modified_at", "Son Değişiklik"),
        )
    )

    vt = data.get("virustotal") or {}
    vt_html = _render_vt_html(vt)
    sig = data.get("signature") or {}
    sig_html = _render_signature_html(sig)
    local = data.get("local_record") or {}
    local_html = _render_local_html(local)

    factors = ((data.get("risk") or {}).get("factors") or [])
    factors_html = "".join(
        f"<li class='sev-{html.escape(str(f.get('severity', 'info')))}'>"
        f"<strong>{html.escape(str(f.get('label', '')))}</strong>: "
        f"{html.escape(str(f.get('detail', '')))} "
        f"<span class='weight'>({int(f.get('weight') or 0):+d})</span></li>"
        for f in factors
    )

    html_doc = f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>Dosya Güven Raporu — {html.escape(str(file_info.get('name', '')))}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 0; padding: 32px; background:#f5f6f8; color:#222; }}
  .card {{ background:#fff; border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,.06); padding:24px; margin-bottom:20px; }}
  h1 {{ margin:0 0 6px 0; font-size: 22px; }}
  h2 {{ margin:0 0 12px 0; font-size: 16px; color:#444; }}
  .headline {{ font-size:18px; font-weight:600; margin: 8px 0 16px; }}
  .risk-badge {{
    display:inline-block; padding:6px 14px; border-radius:999px;
    color:#fff; font-weight:600; background:{risk_color};
  }}
  ul {{ margin: 8px 0 0 18px; padding:0; }}
  ul li {{ margin: 4px 0; }}
  table {{ width:100%; border-collapse: collapse; }}
  th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #eee; vertical-align: top; }}
  th {{ width:160px; color:#666; font-weight:500; }}
  code {{ font-family: Consolas, monospace; font-size: 13px; word-break: break-all; }}
  .advice {{ background:#fff8e1; border-left:4px solid #ffb300; padding:10px 14px; border-radius:6px; }}
  .muted {{ color:#666; font-size:13px; }}
  .sev-good {{ color:#2b742f; }}
  .sev-warn {{ color:#a74b00; }}
  .sev-bad  {{ color:#c62828; }}
  .sev-info {{ color:#555; }}
  .weight {{ color:#6f6f6f; font-weight:400; }}
</style>
</head>
<body>
<div class="card">
  <h1>Dosya Güven Raporu</h1>
  <p class="muted">Oluşturulma: {html.escape(str(data.get('generated_at', '')))}</p>
  <p class="risk-badge">{html.escape(risk_label_tr)}</p>
  <p class="headline">{html.escape(str(summary.get('headline', '')))}</p>
  <ul>{bullets_html}</ul>
  <p class="advice">{html.escape(str(summary.get('advice', '')))}</p>
</div>

<div class="card">
  <h2>Dosya Bilgileri</h2>
  <table>{file_rows}</table>
</div>

<div class="card">
  <h2>Hash Değerleri</h2>
  <table>{hashes_rows}</table>
</div>

<div class="card">
  <h2>VirusTotal</h2>
  {vt_html}
</div>

<div class="card">
  <h2>Dijital İmza</h2>
  {sig_html}
</div>

<div class="card">
  <h2>Yerel Kayıt</h2>
  {local_html}
</div>

<div class="card">
  <h2>Risk Faktörleri</h2>
  <ul>{factors_html or '<li class="muted">Faktör listesi boş.</li>'}</ul>
</div>
</body>
</html>
"""

    path = Path(output_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            fh.write(html_doc)
    except OSError as exc:
        raise TrustReportError(f"HTML rapor yazılamadı: {exc}") from exc
    return path


def _render_vt_html(vt: dict[str, Any]) -> str:
    if not vt:
        return "<p class='muted'>Sorgu yapılmadı.</p>"
    stats = vt.get("stats") or {}
    rows = [
        ("Durum", html.escape(str(vt.get("status", "")))),
        ("Zararlı (malicious)", str(stats.get("malicious", 0))),
        ("Şüpheli (suspicious)", str(stats.get("suspicious", 0))),
        ("Temiz (harmless)", str(stats.get("harmless", 0))),
        ("Algılanmadı (undetected)", str(stats.get("undetected", 0))),
        ("Toplam motor", str(vt.get("total_engines", 0))),
        ("Son analiz", html.escape(str(vt.get("last_analysis_date") or "—"))),
        ("İtibar (reputation)", str(vt.get("reputation") if vt.get("reputation") is not None else "—")),
        ("Dosya türü tahmini", html.escape(str(vt.get("type_description") or "—"))),
        ("Bilinen isim", html.escape(str(vt.get("meaningful_name") or "—"))),
        ("Mesaj", html.escape(str(vt.get("message") or ""))),
    ]
    return "<table>" + "".join(
        f"<tr><th>{label}</th><td>{value}</td></tr>" for label, value in rows
    ) + "</table>"


def _render_signature_html(sig: dict[str, Any]) -> str:
    if not sig:
        return "<p class='muted'>Kontrol yapılmadı.</p>"
    rows = [
        ("Durum", html.escape(str(sig.get("status", "")))),
        ("İmzalayan", html.escape(str(sig.get("signer") or "—"))),
        ("Açıklama", html.escape(str(sig.get("message") or "—"))),
    ]
    return "<table>" + "".join(
        f"<tr><th>{label}</th><td>{value}</td></tr>" for label, value in rows
    ) + "</table>"


def _render_local_html(local: dict[str, Any]) -> str:
    if not local:
        return "<p class='muted'>Yerel kayıt yok.</p>"
    rows = [
        ("Durum", html.escape(str(local.get("status", "")))),
        ("Açıklama", html.escape(str(local.get("message") or ""))),
        ("Önceki hash", html.escape(str(local.get("previous_hash") or "—"))),
        ("Şimdiki hash", html.escape(str(local.get("current_hash") or "—"))),
    ]
    return "<table>" + "".join(
        f"<tr><th>{label}</th><td>{value}</td></tr>" for label, value in rows
    ) + "</table>"
