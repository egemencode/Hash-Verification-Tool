"""
The verdict itself must read in the language the user chose.

§5A translated everything the three default screens *write*. It did not touch
what they *report*: the headline above the risk badge, the bullets under it,
the advice line, and the evidence rows in the exported report are composed by
``core/risk_engine.py`` and ``core/smart_summary.py``. So an English user got
an English interface and a Turkish judgement — the sentence the whole tool
exists to produce.

The shape chosen here, and why
------------------------------
The core does not translate. It returns a :class:`core.phrases.Phrase` — the
identity of a sentence plus the values that go in it — and the presentation
layer turns that into words. This follows the grain the codebase already has:
``gui/trust_presenter.py`` exists so that "the wording and the decision rules"
can be tested apart, and ``core/risk_engine.py`` is a decision table rather
than a score. Having the core call ``t()`` would put presentation back inside
it, and would make an exported report's language depend on a global that the
core has no business reading.

These tests therefore render twice and require the two to differ. Comparing
the Phrases themselves would prove nothing: the same decision produces the
same key in both languages, which is the point of the key.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from core.local_verify import LocalVerifyResult, LocalVerifyStatus
from core.risk_engine import assess
from core.signature_checker import SignatureResult, SignatureStatus
from core.smart_summary import build_summary
from core.vt_client import VTAnalysisStats, VTLookupResult, VTStatus

from tests.support import DiagnosticTempDir


def _vt(stats: VTAnalysisStats, status: VTStatus = VTStatus.OK) -> VTLookupResult:
    return VTLookupResult(
        status=status, hash_value="a" * 64, stats=stats,
        total_engines=70, analysing_engines=70,
    )


def _inputs():
    """One scan with something to say about all three checks."""
    vt = _vt(VTAnalysisStats(malicious=3, suspicious=1, harmless=60))
    sig = SignatureResult(status=SignatureStatus.HASH_MISMATCH, signer="Acme Ltd")
    local = LocalVerifyResult(
        status=LocalVerifyStatus.CHANGED, previous_hash="x", current_hash="y"
    )
    return vt, sig, local


class VerdictLanguageTests(unittest.TestCase):
    def tearDown(self) -> None:
        from gui.i18n import set_language

        set_language("tr")

    def _rendered(self, language: str):
        from gui.i18n import set_language
        from gui.trust_presenter import render_summary

        set_language(language)
        vt, sig, local = _inputs()
        assessment = assess(vt_result=vt, signature_result=sig, local_result=local)
        summary = build_summary(assessment, vt=vt, sig=sig, local=local)
        return assessment, render_summary(summary)

    def test_the_headline_reads_in_the_chosen_language(self) -> None:
        _, turkish = self._rendered("tr")
        _, english = self._rendered("en")
        self.assertTrue(turkish.headline, "no headline was produced")
        self.assertNotEqual(
            turkish.headline, english.headline,
            "the sentence above the risk badge is the same in both languages",
        )

    def test_every_bullet_reads_in_the_chosen_language(self) -> None:
        _, turkish = self._rendered("tr")
        _, english = self._rendered("en")
        self.assertEqual(
            len(turkish.bullets), len(english.bullets),
            "the two languages disagree about how many things to say",
        )
        self.assertGreaterEqual(
            len(turkish.bullets), 3,
            "this scan should have something to say about all three checks",
        )
        for tr_line, en_line in zip(turkish.bullets, english.bullets):
            with self.subTest(bullet=tr_line):
                self.assertNotEqual(tr_line, en_line)

    def test_the_advice_reads_in_the_chosen_language(self) -> None:
        _, turkish = self._rendered("tr")
        _, english = self._rendered("en")
        self.assertTrue(turkish.advice, "no advice line was produced")
        self.assertNotEqual(turkish.advice, english.advice)

    def test_the_evidence_rows_read_in_the_chosen_language(self) -> None:
        """
        The factors are the *why* behind the level, and they are what an
        exported report shows someone who was not at the machine.
        """
        from gui.trust_presenter import render_factor

        assessment, _ = self._rendered("tr")
        turkish = [render_factor(f) for f in assessment.factors]
        assessment, _ = self._rendered("en")
        english = [render_factor(f) for f in assessment.factors]

        self.assertTrue(turkish, "the assessment recorded no factors")
        self.assertEqual(len(turkish), len(english))
        for tr_factor, en_factor in zip(turkish, english):
            with self.subTest(factor=tr_factor.detail):
                self.assertNotEqual(tr_factor.detail, en_factor.detail)


class ExportedReportLanguageTests(unittest.TestCase):
    """
    A report is the artefact that leaves the machine.

    It is what the user sends to somebody else, so it must be readable in the
    language they were working in — not in whichever one the core happens to
    have been written in.
    """

    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()

    def tearDown(self) -> None:
        from gui.i18n import set_language

        try:
            set_language("tr")
        finally:
            self._tmp.cleanup()

    def _export(self, language: str) -> dict:
        from core.file_info import FileInfo
        from core.trust_report import TrustReport, export_json
        from gui.i18n import set_language, t

        set_language(language)
        vt, sig, local = _inputs()
        assessment = assess(vt_result=vt, signature_result=sig, local_result=local)
        summary = build_summary(assessment, vt=vt, sig=sig, local=local)
        report = TrustReport(
            file_info=FileInfo(
                name="setup.exe", path=r"C:\tmp\setup.exe",
                size_bytes=10, size_human="10 B", extension=".exe",
                created_at="2026-08-19T10:00:00+03:00",
                modified_at="2026-08-19T10:00:00+03:00",
            ),
            hashes={"sha256": "a" * 64},
            vt_result=vt,
            signature_result=sig,
            local_result=local,
            assessment=assessment,
            summary=summary,
        )
        out = Path(self._tmp.name) / f"report-{language}.json"
        export_json(report, out, translate=t)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_the_exported_summary_is_in_the_chosen_language(self) -> None:
        turkish = self._export("tr")
        english = self._export("en")
        self.assertTrue(turkish["summary"]["headline"])
        self.assertNotEqual(
            turkish["summary"]["headline"], english["summary"]["headline"]
        )
        self.assertNotEqual(
            turkish["summary"]["bullets"], english["summary"]["bullets"]
        )

    def test_the_exported_report_carries_words_not_keys(self) -> None:
        """
        Guards the test above against agreeing with a report full of
        ``risk.headline.high`` — two different keys are also "not equal".
        """
        english = self._export("en")
        headline = english["summary"]["headline"]
        self.assertNotIn(".", headline.split(" ")[0].rstrip("."),
                         f"the report seems to contain a key: {headline!r}")
        self.assertIn(" ", headline, "the headline is not a sentence")


if __name__ == "__main__":
    unittest.main()
