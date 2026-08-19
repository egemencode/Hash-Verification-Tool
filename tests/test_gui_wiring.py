"""
GUI wiring regression suite (no display required).

These tests assert that the GUI *actually consumes* the signals the core
layer produces — the previous gap was that `load_warning` was generated but
never read, so the "visible warning" claim was untrue. Rather than launching
Tk, we drive the real startup sequence used by `HashToolApp.__init__` and the
real result-rendering helper, and assert on the text that would be shown.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.support import DiagnosticTempDir
from core.history_manager import HistoryManager
from core.local_verify import LocalVerifyStore
from core.manifest_manager import SignatureState
from core.verifier import VerificationResult
from gui import app as gui_app
from gui.trust_presenter import collect_startup_warnings, describe_result

CORRUPT = b"not json at all \x00\xff"


class StartupWarningWiringTests(unittest.TestCase):
    """The app must read load_warning from BOTH stores at startup."""

    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _startup(self, *, corrupt_history: bool, corrupt_store: bool):
        hpath = self.root / "history.json"
        spath = self.root / "known_files.json"
        hpath.write_bytes(
            CORRUPT if corrupt_history
            else json.dumps({"entries": []}).encode("utf-8")
        )
        spath.write_bytes(
            CORRUPT if corrupt_store
            else json.dumps({"records": {}}).encode("utf-8")
        )
        history = HistoryManager(hpath)
        store = LocalVerifyStore(spath)
        # Mirror exactly what HashToolApp.__init__ does.
        history.all()
        store.all()
        return collect_startup_warnings(
            settings_warnings=[],
            history_warning=history.load_warning,
            local_store_warning=store.load_warning,
        )

    def test_corrupt_history_produces_a_warning(self) -> None:
        warning = self._startup(corrupt_history=True, corrupt_store=False)
        self.assertIsNotNone(warning)
        self.assertIn("Geçmiş", warning.body)

    def test_corrupt_fingerprint_store_produces_a_warning(self) -> None:
        warning = self._startup(corrupt_history=False, corrupt_store=True)
        self.assertIsNotNone(warning)
        self.assertIn("parmak izi", warning.body.lower())

    def test_warning_names_the_quarantine_file(self) -> None:
        warning = self._startup(corrupt_history=True, corrupt_store=False)
        self.assertIn(".corrupt", warning.body)
        self.assertIn("yeni bir geçmiş başlatıldı", warning.body)

    def test_both_corrupt_reports_both(self) -> None:
        warning = self._startup(corrupt_history=True, corrupt_store=True)
        self.assertIn("Geçmiş", warning.body)
        self.assertIn("parmak izi", warning.body.lower())

    def test_healthy_stores_produce_no_warning(self) -> None:
        self.assertIsNone(self._startup(corrupt_history=False, corrupt_store=False))


class StartupWarningDeliveryTests(unittest.TestCase):
    """
    Behaviour, not source text: drive the real ``_show_startup_warning``
    against a stub dialog and assert what the user would actually see.
    """

    def _app_stub(self, warning):
        """A minimal object bound to the real method under test."""

        class _Stub:
            def __init__(self) -> None:
                self._startup_warning = warning
                self._migration_warnings = ["stale"]
                self.shown: list[tuple[str, str]] = []

            _show_startup_warning = gui_app.HashToolApp._show_startup_warning

        return _Stub()

    def test_warning_is_shown_once_and_then_suppressed(self) -> None:
        warning = collect_startup_warnings(history_warning="geçmiş bozuktu")
        stub = self._app_stub(warning)
        shown: list[tuple[str, str]] = []
        with mock.patch.object(
            gui_app.messagebox, "showwarning",
            side_effect=lambda title, body: shown.append((title, body)),
        ):
            stub._show_startup_warning()
            stub._show_startup_warning()   # second call must be a no-op
        self.assertEqual(len(shown), 1, "the notice was shown more than once")
        self.assertIn("geçmiş bozuktu", shown[0][1])
        self.assertIsNone(stub._startup_warning)
        self.assertEqual(stub._migration_warnings, [])

    def test_no_dialog_when_there_is_nothing_to_report(self) -> None:
        stub = self._app_stub(None)
        shown: list = []
        with mock.patch.object(
            gui_app.messagebox, "showwarning", side_effect=lambda *a: shown.append(a)
        ):
            stub._show_startup_warning()
        self.assertEqual(shown, [])


class HistoryFailureSurfacedTests(unittest.TestCase):
    """A history write failure must reach the user, not just the log."""

    def test_history_store_error_produces_a_warning_dialog(self) -> None:
        from core.history_manager import HistoryStoreError
        from gui.views import trust_check_view

        class _Stub:
            _record_in_history = trust_check_view.TrustCheckView._record_in_history

            def __init__(self) -> None:
                class _History:
                    def add(self, entry):
                        raise HistoryStoreError("disk dolu")

                self._history = _History()
                self._on_scan_recorded = None

        from core.phrases import phrase
        from core.risk_engine import RiskLevel
        from core.smart_summary import SmartSummary

        result = mock.Mock()
        # A real summary, not a Mock: the view renders it through the presenter
        # now, and a Mock would iterate as one more Mock rather than as the
        # bullets a scan actually produced.
        result.summary = SmartSummary(
            headline=phrase("risk.headline.unknown"),
            risk_level=RiskLevel.UNKNOWN,
            bullets=[],
            advice=phrase("summary.advice.unknown"),
        )
        result.assessment = mock.Mock()
        result.file_info.name = "f.exe"
        result.file_info.path = "C:/f.exe"
        result.sha256 = "a" * 64
        result.vt = None
        result.signature = None

        shown: list = []
        with mock.patch.object(
            trust_check_view.messagebox, "showwarning",
            side_effect=lambda title, body: shown.append((title, body)),
        ):
            _Stub()._record_in_history(result)

        self.assertEqual(len(shown), 1, "the user was not told the scan was not recorded")
        self.assertIn("disk dolu", shown[0][1])


class RenderedTrustTextTests(unittest.TestCase):
    """The exact user-facing strings for each manifest trust state."""

    def _texts(self, state: SignatureState) -> tuple[str, str]:
        result = VerificationResult(
            folder="C:/x", algorithm="sha256", signature_state=state
        )
        result.unchanged.append("a.txt")
        headline, badge = describe_result(result)
        return headline.text, f"{badge.label} — {badge.detail}"

    def test_unsigned_text(self) -> None:
        headline, badge = self._texts(SignatureState.UNSIGNED)
        self.assertIn("imzasız", headline)
        self.assertIn("imzasız", badge.lower())

    def test_valid_embedded_text_is_explicitly_qualified(self) -> None:
        headline, badge = self._texts(SignatureState.VALID_EMBEDDED)
        self.assertEqual(
            headline,
            "Dosyalar manifestle eşleşiyor; ancak manifestin kaynağı doğrulanmadı.",
        )
        self.assertIn("güvenilmiyor", badge)

    def test_trusted_text(self) -> None:
        headline, badge = self._texts(SignatureState.TRUSTED)
        self.assertIn("güvenilen anahtarla", headline.lower())
        self.assertIn("Güvenilen anahtarla doğrulandı", badge)

    def test_invalid_text(self) -> None:
        headline, badge = self._texts(SignatureState.INVALID)
        self.assertIn("geçersiz", headline.lower())
        self.assertIn("kurcalanmış", badge.lower())


if __name__ == "__main__":
    unittest.main()
