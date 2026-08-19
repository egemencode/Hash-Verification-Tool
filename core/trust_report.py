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
from typing import Any, Callable, Optional

from core.file_info import FileInfo
from core.local_verify import LocalVerifyResult
from core.phrases import Phrase
from core.risk_engine import RiskAssessment, RiskLevel
from core.signature_checker import SignatureResult
from core.smart_summary import SmartSummary
from core.vt_client import VTLookupResult


# A ``t``-shaped callable: key plus values, in, words out. Passed in rather
# than imported so this module keeps no opinion about which language is
# current — the caller already knows, and a report written in the wrong one is
# not something the reader can fix.
Translate = Callable[..., str]


def _say(translate: Translate, phrase: Optional[Phrase]) -> str:
    if phrase is None:
        return ""
    return translate(phrase.key, **dict(phrase.params))


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
    def to_dict(self, translate: Translate) -> dict[str, Any]:
        """
        The report as data. *translate* turns the core's phrase keys into
        words, because a report is read by a person and has to be in the
        language they were working in.

        Required rather than defaulted on purpose: a report quietly full of
        ``risk.headline.high`` would still be a valid document, and nothing
        would notice until somebody opened it.
        """
        return {
            "schema": "trust-report/1.0",
            "generated_at": self.generated_at,
            "file": self.file_info.to_dict(),
            "hashes": dict(self.hashes),
            "virustotal": self.vt_result.to_dict() if self.vt_result else None,
            "signature": self.signature_result.to_dict() if self.signature_result else None,
            "local_record": self.local_result.to_dict() if self.local_result else None,
            "risk": self._risk_dict(translate),
            "summary": {
                "headline": _say(translate, self.summary.headline) if self.summary else "",
                "risk_level": self.summary.risk_level.value if self.summary else "",
                "bullets": [
                    _say(translate, b) for b in (self.summary.bullets if self.summary else [])
                ],
                "advice": _say(translate, self.summary.advice) if self.summary else "",
            },
        }

    def _risk_dict(self, translate: Translate) -> Optional[dict[str, Any]]:
        """
        The level, the score and the evidence behind them.

        Both spellings of each finding are kept: the words a reader needs, and
        the key a program can match on. A translated sentence is not a stable
        identifier, and dropping the key would make the JSON report useless to
        anything but a human.
        """
        if self.assessment is None:
            return None
        return {
            "level": self.assessment.level.value,
            "score": self.assessment.score,
            "headline": _say(translate, self.assessment.headline),
            "headline_key": self.assessment.headline.key,
            "policy_version": self.assessment.policy_version,
            "evidence_sufficient": self.assessment.evidence_sufficient,
            "factors": [
                {
                    "label": _say(translate, f.label),
                    "detail": _say(translate, f.detail),
                    "detail_key": f.detail.key,
                    "weight": f.weight,
                    "severity": f.severity,
                }
                for f in self.assessment.factors
            ],
        }


# ----------------------------------------------------------------------
# JSON
# ----------------------------------------------------------------------
def export_json(
    report: TrustReport, output_path: str | Path, *, translate: Translate
) -> Path:
    path = Path(output_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            json.dump(report.to_dict(translate), fh, indent=2, ensure_ascii=False)
    except OSError as exc:
        raise TrustReportError(translate("report.err.json", error=exc)) from exc
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

def export_html(
    report: TrustReport,
    output_path: str | Path,
    *,
    translate: Translate,
    language: str = "tr",
) -> Path:
    """
    Render the report as a single, self-contained HTML page.

    *language* only sets the document's ``lang`` attribute. It is separate
    from *translate* because the two answer different questions — what the
    words are, and what a screen reader should be told they are — and getting
    the second wrong is invisible to everyone who can see the page.
    """
    data = report.to_dict(translate)
    risk_level = (data.get("risk") or {}).get("level") or RiskLevel.UNKNOWN.value
    risk_color = _RISK_COLOR.get(risk_level, _RISK_COLOR[RiskLevel.UNKNOWN.value])
    risk_label = translate(f"risk.badge.{risk_level}")

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
        f"<tr><th>{html.escape(translate(label_key))}</th>"
        f"<td>{html.escape(str(file_info.get(key, '')))}</td></tr>"
        for key, label_key in (
            ("name", "trust.file.name"),
            ("path", "trust.file.path"),
            ("size_human", "trust.file.size"),
            ("extension", "trust.file.extension"),
            ("created_at", "trust.file.created"),
            ("modified_at", "trust.file.modified"),
        )
    )

    vt = data.get("virustotal") or {}
    vt_html = _render_vt_html(vt, translate)
    sig = data.get("signature") or {}
    sig_html = _render_signature_html(sig, translate)
    local = data.get("local_record") or {}
    local_html = _render_local_html(local, translate)

    empty_factors = (
        f'<li class="muted">{html.escape(translate("report.doc.no_factors"))}</li>'
    )
    factors = ((data.get("risk") or {}).get("factors") or [])
    factors_html = "".join(
        f"<li class='sev-{html.escape(str(f.get('severity', 'info')))}'>"
        f"<strong>{html.escape(str(f.get('label', '')))}</strong>: "
        f"{html.escape(str(f.get('detail', '')))} "
        f"<span class='weight'>({int(f.get('weight') or 0):+d})</span></li>"
        for f in factors
    )

    html_doc = f"""<!doctype html>
<html lang="{html.escape(language)}">
<head>
<meta charset="utf-8">
<title>{html.escape(translate("report.doc.title"))} — {html.escape(str(file_info.get('name', '')))}</title>
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
  <h1>{html.escape(translate("report.doc.title"))}</h1>
  <p class="muted">{html.escape(translate("report.doc.generated"))}: {html.escape(str(data.get('generated_at', '')))}</p>
  <p class="risk-badge">{html.escape(risk_label)}</p>
  <p class="headline">{html.escape(str(summary.get('headline', '')))}</p>
  <ul>{bullets_html}</ul>
  <p class="advice">{html.escape(str(summary.get('advice', '')))}</p>
</div>

<div class="card">
  <h2>{html.escape(translate("report.doc.section.file"))}</h2>
  <table>{file_rows}</table>
</div>

<div class="card">
  <h2>{html.escape(translate("report.doc.section.hashes"))}</h2>
  <table>{hashes_rows}</table>
</div>

<div class="card">
  <h2>{html.escape(translate("report.doc.section.vt"))}</h2>
  {vt_html}
</div>

<div class="card">
  <h2>{html.escape(translate("report.doc.section.signature"))}</h2>
  {sig_html}
</div>

<div class="card">
  <h2>{html.escape(translate("report.doc.section.local"))}</h2>
  {local_html}
</div>

<div class="card">
  <h2>{html.escape(translate("report.doc.section.factors"))}</h2>
  <ul>{factors_html or empty_factors}</ul>
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
        raise TrustReportError(translate("report.err.html", error=exc)) from exc
    return path


def _render_vt_html(vt: dict[str, Any], translate: Translate) -> str:
    if not vt:
        return f"<p class='muted'>{html.escape(translate('report.doc.not_queried'))}</p>"
    stats = vt.get("stats") or {}
    rows = [
        (translate("kv.status"), html.escape(str(vt.get("status", "")))),
        (translate("trust.vt.malicious"), str(stats.get("malicious", 0))),
        (translate("trust.vt.suspicious"), str(stats.get("suspicious", 0))),
        (translate("trust.vt.harmless"), str(stats.get("harmless", 0))),
        (translate("trust.vt.undetected"), str(stats.get("undetected", 0))),
        (translate("trust.vt.total_engines"), str(vt.get("total_engines", 0))),
        (translate("trust.vt.last_analysis"), html.escape(str(vt.get("last_analysis_date") or "—"))),
        (translate("trust.vt.reputation"), str(vt.get("reputation") if vt.get("reputation") is not None else "—")),
        (translate("trust.vt.type_description"), html.escape(str(vt.get("type_description") or "—"))),
        (translate("trust.vt.meaningful_name"), html.escape(str(vt.get("meaningful_name") or "—"))),
        (translate("report.doc.message"), html.escape(str(vt.get("message") or ""))),
    ]
    return "<table>" + "".join(
        f"<tr><th>{html.escape(label)}</th><td>{value}</td></tr>"
        for label, value in rows
    ) + "</table>"


def _render_signature_html(sig: dict[str, Any], translate: Translate) -> str:
    if not sig:
        return f"<p class='muted'>{html.escape(translate('report.doc.not_checked'))}</p>"
    rows = [
        (translate("kv.status"), html.escape(str(sig.get("status", "")))),
        (translate("trust.sig.signer"), html.escape(str(sig.get("signer") or "—"))),
        (translate("kv.detail"), html.escape(str(sig.get("message") or "—"))),
    ]
    return "<table>" + "".join(
        f"<tr><th>{html.escape(label)}</th><td>{value}</td></tr>"
        for label, value in rows
    ) + "</table>"


def _render_local_html(local: dict[str, Any], translate: Translate) -> str:
    if not local:
        return f"<p class='muted'>{html.escape(translate('report.doc.no_local'))}</p>"
    rows = [
        (translate("kv.status"), html.escape(str(local.get("status", "")))),
        (translate("kv.detail"), html.escape(str(local.get("message") or ""))),
        (translate("trust.local.previous_hash"), html.escape(str(local.get("previous_hash") or "—"))),
        (translate("trust.local.current_hash"), html.escape(str(local.get("current_hash") or "—"))),
    ]
    return "<table>" + "".join(
        f"<tr><th>{html.escape(label)}</th><td>{value}</td></tr>"
        for label, value in rows
    ) + "</table>"
