"""
The language menu offers English. Most of the interface never asked for it.

``gui/app.py`` calls ``t()`` in 99 places, so the menu, the tab captions and
the three Advanced tabs translate. The three view modules that make up the
default experience — Trust Check, History, Settings — contain zero ``t()``
calls between them. Choosing English therefore leaves the screen the user
actually works on entirely in Turkish.

That is not a missing feature. The menu *states* that English is available,
and a control that describes something the application does not do is the same
defect class as the settings warning that once told users to press a "Remove
key" button which did not exist.

How this is tested
------------------
Not by counting ``t()`` calls — a module can call ``t()`` a hundred times and
still hard-code the one label that matters. The test builds the real window,
harvests every string on screen, switches the language through the same code
path the menu uses, and harvests again.

**The two harvests must not share a single word.** Any string present in both
is a string the language switch could not move, which is precisely the defect.
A hard-coded label appears in both sets and fails here regardless of whether
it happens to contain a Turkish diacritic — which matters, because "Kopyala",
"Yenile", "Tarih" and "Risk" contain none and a character-based check would
wave all four through.

The handful of strings that are legitimately identical in both languages are
listed in :data:`ALLOWED_IDENTICAL`, each with the reason it is there.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from tests.support import DiagnosticTempDir

try:
    import tkinter as tk
    from tkinter import ttk

    _probe = tk.Tk()
    _probe.destroy()
    TK_AVAILABLE = True
    TK_SKIP = ""
except Exception as exc:  # pragma: no cover - depends on the machine
    TK_AVAILABLE = False
    TK_SKIP = f"Tk unavailable: {exc}"


# Strings a translation is not supposed to change. Kept short and explicit:
# every entry is a claim that this text is correct in both languages, and an
# entry added merely to silence a failure would be a lie about the interface.
ALLOWED_IDENTICAL = {
    "VirusTotal",              # product name
    "Türkçe",                  # language names are shown in their own language
    "English",                 #   so a user can find theirs without reading
    "MD5:",                    # algorithm names
    "SHA1:",
    "Manifest JSON:",          # already a key; both tables give the same words
    "Risk",                    # the same word in both, and the column is narrow
}

# Widgets that hold user data rather than interface language: a path, a hash,
# an API key, a record limit, an algorithm id. Their contents must not be
# translated, and reading them would compare the user's data against itself.
# ttk's entry family also answers ``cget("text")`` with the *name* of its text
# variable, which is neither language nor data.
_DATA_WIDGET_CLASSES = {
    "TEntry", "TCombobox", "TSpinbox", "Entry", "Spinbox",
}


def _has_letters(text: str) -> bool:
    """Ignore separators, digits, dashes and the em-dash placeholder."""
    return any(ch.isalpha() for ch in text)


def harvest_texts(widget) -> set[str]:
    """
    Every string this widget subtree puts in front of the user.

    Covers the ways text reaches the screen in this application: a widget's
    own ``-text``, the variable behind ``-textvariable``, notebook tab
    captions, Treeview headings and rows, canvas text items, and the contents
    of a Text area. Entry *values* are deliberately excluded — those hold user
    data (paths, hashes), not interface language.
    """
    found: set[str] = set()

    def add(value) -> None:
        text = str(value).strip()
        if text and _has_letters(text):
            found.add(text)

    def walk(w) -> None:
        if w.winfo_class() not in _DATA_WIDGET_CLASSES:
            try:
                add(w.cget("text"))
            except (tk.TclError, TypeError):
                pass
            try:
                var_name = str(w.cget("textvariable"))
                if var_name:
                    add(w.getvar(var_name))
            except (tk.TclError, TypeError):
                pass

        if isinstance(w, ttk.Notebook):
            for tab_id in w.tabs():
                add(w.tab(tab_id, "text"))
        elif isinstance(w, ttk.Treeview):
            for column in w.cget("columns") or ():
                add(w.heading(column, "text"))
            for item in w.get_children():
                for value in w.item(item, "values") or ():
                    add(value)
        elif isinstance(w, tk.Canvas):
            for item in w.find_all():
                if w.type(item) == "text":
                    add(w.itemcget(item, "text"))
        elif isinstance(w, tk.Text):
            add(w.get("1.0", "end-1c"))

        for child in w.winfo_children():
            walk(child)

    walk(widget)
    return found


@unittest.skipUnless(TK_AVAILABLE, TK_SKIP or "Tk unavailable")
class LanguageSwitchTests(unittest.TestCase):
    """The window, before and after the switch the menu offers."""

    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self._env = mock.patch.dict(
            os.environ, {"LOCALAPPDATA": str(Path(self._tmp.name) / "profile")}
        )
        self._env.start()

        from gui.i18n import set_language

        set_language("tr")
        from gui.app import HashToolApp

        self.app = HashToolApp()
        self.app.update_idletasks()

    def tearDown(self) -> None:
        from gui.i18n import set_language

        try:
            self.app.destroy()
        finally:
            set_language("tr")
            self._env.stop()
            self._tmp.cleanup()

    def test_switching_to_english_leaves_no_turkish_on_screen(self) -> None:
        turkish = harvest_texts(self.app)
        self.assertTrue(turkish, "harvested nothing — the walk is broken")

        self.app._switch_language("en")     # noqa: SLF001 - the menu's own path
        self.app.update_idletasks()
        english = harvest_texts(self.app)
        self.assertTrue(english, "harvested nothing after the switch")

        stuck = sorted((turkish & english) - ALLOWED_IDENTICAL)
        self.assertEqual(
            stuck, [],
            "these strings survived a switch to English, so they are written "
            "into a view rather than looked up:\n  "
            + "\n  ".join(repr(s) for s in stuck),
        )

    def test_the_switch_actually_reached_the_main_screen(self) -> None:
        """
        Guards the test above against passing for the wrong reason.

        Disjoint sets would also be produced by a switch that rebuilt nothing
        and harvested nothing twice, or by a window whose main screen went
        missing. This pins the assertion to the screen the complaint is about.
        """
        self.app._switch_language("en")     # noqa: SLF001
        self.app.update_idletasks()

        from gui.i18n import t

        texts = harvest_texts(self.app.trust_view)
        self.assertIn(t("trust.section.pick"), texts)
        self.assertIn(t("btn.cancel"), texts)

    def test_no_label_on_the_main_screen_is_cut_off(self) -> None:
        """
        A translated sentence is longer or shorter than the original.

        The screen was laid out around one language, so the switch is what
        surfaced this — but the check runs on both, because the sentence that
        loses its last word is not necessarily the translated one. Here it was
        the Turkish original that lost the most.

        Only mapped labels count: a widget inside the collapsed details panel
        reports a width of one pixel, which would read as a 400-pixel overflow
        that no user could ever see.
        """
        def offenders() -> list[str]:
            self.app.update()
            found: list[str] = []

            def walk(w) -> None:
                if isinstance(w, ttk.Label) and w.winfo_ismapped():
                    try:
                        var = str(w.cget("textvariable"))
                        text = str(w.getvar(var) if var else w.cget("text"))
                    except tk.TclError:
                        text = ""
                    if text.strip():
                        short = w.winfo_reqwidth() - w.winfo_width()
                        if short > 1:
                            found.append(f"cut by {short}px: {text[:50]!r}")
                for child in w.winfo_children():
                    walk(child)

            walk(self.app.trust_view)
            return found

        with self.subTest(language="tr"):
            self.assertEqual(offenders(), [])
        self.app._switch_language("en")          # noqa: SLF001
        with self.subTest(language="en"):
            self.assertEqual(offenders(), [])

    def test_the_end_state_cards_translate(self) -> None:
        """
        The screen after a scan stops, which the harvest above never sees.

        A freshly built window is idle, so the cancelled and failed cards are
        not on it. They are also where the one string with a *default* lives:
        the "what to do next" sentence. Written as a default argument it would
        be evaluated once at import and then never change language again, so
        the failed card is checked as well as the cancelled one.
        """
        def cards() -> tuple[str, str, str]:
            view = self.app.trust_view
            view._show_cancelled_end_state()            # noqa: SLF001
            cancelled = (view.headline_var.get(), view.advice_var.get())
            # No advice argument: this is the call that takes the default.
            view._show_terminal_failure(                # noqa: SLF001
                "headline", "detail",
            )
            return cancelled[0], cancelled[1], view.advice_var.get()

        turkish = cards()
        self.app._switch_language("en")                 # noqa: SLF001
        self.app.update_idletasks()
        english = cards()

        for label, tr_text, en_text in zip(
            ("cancelled headline", "cancelled advice", "failure advice"),
            turkish, english,
        ):
            with self.subTest(text=label):
                self.assertNotEqual(
                    tr_text, en_text, f"the {label} reads the same in both"
                )


@unittest.skipUnless(TK_AVAILABLE, TK_SKIP or "Tk unavailable")
@unittest.skipUnless(TK_AVAILABLE, TK_SKIP or "Tk unavailable")
class SummaryFitTests(unittest.TestCase):
    """
    None of the verdict may be hidden, at any window size the app allows.

    The bullets are the evidence for the risk level. A Text widget with a
    fixed height does not report the lines that do not fit — it stops drawing
    them, with nothing to say so — and at the 880-pixel minimum this window
    permits, the longest summary lost a line in Turkish and two in English.

    The longest summary is constructed here rather than waited for: one bullet
    may come from each of the three checks, so the worst case is the longest
    sentence in each group, and picking them from the table means a sentence
    added later is covered without anyone remembering to update this.
    """

    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self._env = mock.patch.dict(
            os.environ, {"LOCALAPPDATA": str(Path(self._tmp.name) / "profile")}
        )
        self._env.start()

        from gui.i18n import set_language

        set_language("tr")
        from gui.app import HashToolApp

        self.app = HashToolApp()
        # The smallest size the application lets a user drag it to.
        self.app.geometry("880x600")
        self.app.update()

    def tearDown(self) -> None:
        from gui.i18n import set_language

        try:
            self.app.destroy()
        finally:
            set_language("tr")
            self._env.stop()
            self._tmp.cleanup()

    @staticmethod
    def _longest_bullets() -> list[str]:
        from gui.i18n import _TRANSLATIONS, get_language, t  # noqa: SLF001

        table = _TRANSLATIONS[get_language()]
        out = []
        for group in ("summary.vt.", "summary.sig.", "summary.local."):
            keys = [k for k in table if k.startswith(group)]
            longest = max(
                keys, key=lambda k: len(t(k, count=99, signer="Some Publisher Ltd"))
            )
            out.append(t(longest, count=99, signer="Some Publisher Ltd"))
        return out

    def _hidden_lines(self) -> int:
        box = self.app.trust_view.bullets_text
        box.configure(state="normal")
        box.delete("1.0", "end")
        for bullet in self._longest_bullets():
            box.insert("end", f"• {bullet}\n")
        box.configure(state="disabled")
        self.app.trust_view._fit_bullets()          # noqa: SLF001
        self.app.update()
        counted = box.count("1.0", "end", "displaylines")
        wrapped = counted[0] if counted else 0
        return max(0, wrapped - int(box.cget("height")))

    def test_the_longest_verdict_is_fully_visible(self) -> None:
        with self.subTest(language="tr"):
            self.assertEqual(self._hidden_lines(), 0)
        self.app._switch_language("en")             # noqa: SLF001
        self.app.geometry("880x600")
        self.app.update()
        with self.subTest(language="en"):
            self.assertEqual(self._hidden_lines(), 0)


@unittest.skipUnless(TK_AVAILABLE, TK_SKIP or "Tk unavailable")
class HistoryRowTests(unittest.TestCase):
    """
    Rows only exist once something has been scanned.

    An empty History tab renders no risk level, no signature state and no
    VirusTotal verdict, so the language switch above never sees them. They are
    the column values a returning user reads first.

    Only the three computed columns are compared. The other three hold the
    entry's own data — a timestamp, a file name, a path — which must not be
    translated, and comparing them would also be flaky: two views built in the
    same second carry the same timestamp and in the next second they do not.
    """

    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self._root = tk.Tk()
        self._root.withdraw()

    def tearDown(self) -> None:
        from gui.i18n import set_language

        try:
            self._root.destroy()
        finally:
            set_language("tr")
            self._tmp.cleanup()

    def _view(self, language: str):
        from core.history_manager import HistoryManager, make_entry
        from gui.i18n import set_language
        from gui.views.history_view import HistoryView

        set_language(language)
        store = Path(self._tmp.name) / f"history-{language}.json"
        manager = HistoryManager(store_path=str(store), limit=10)
        manager.add(
            make_entry(
                file_name="setup.exe",
                file_path=r"C:\tmp\setup.exe",
                sha256="a" * 64,
                risk_level="medium",
                headline="",
                vt_malicious=2,
                vt_suspicious=1,
                vt_status="ok",
                signature_status="signed_valid",
            )
        )
        view = HistoryView(self._root, manager)
        view.update_idletasks()
        return view

    @staticmethod
    def _computed_cells(view) -> set[str]:
        tree = view.tree
        columns = list(tree.cget("columns"))
        item = tree.get_children()[0]
        cells = dict(zip(columns, tree.item(item, "values")))
        return {cells["risk"], cells["vt"], cells["signature"]}

    def test_a_history_row_reads_in_the_chosen_language(self) -> None:
        turkish = self._computed_cells(self._view("tr"))
        english = self._computed_cells(self._view("en"))
        self.assertEqual(len(turkish), 3, "the row did not render three verdicts")

        stuck = sorted((turkish & english) - ALLOWED_IDENTICAL)
        self.assertEqual(
            stuck, [],
            "these history-row verdicts do not translate:\n  "
            + "\n  ".join(repr(s) for s in stuck),
        )


class ViewAuthoredLabelTests(unittest.TestCase):
    """
    The labels the views compute rather than lay out.

    A risk badge, a signature verdict and a risk-level column value are chosen
    at render time from a mapping, so no widget carries them until a scan has
    finished. They need no display to check.
    """

    def tearDown(self) -> None:
        from gui.i18n import set_language

        set_language("tr")

    def _both(self, produce):
        from gui.i18n import set_language

        set_language("tr")
        turkish = produce()
        set_language("en")
        english = produce()
        return turkish, english

    def test_the_risk_badge_label_translates(self) -> None:
        from core.risk_engine import RiskLevel
        from gui.views import trust_check_view

        for level in RiskLevel:
            with self.subTest(level=level.value):
                tr, en = self._both(
                    lambda lv=level: trust_check_view.risk_presentation(lv.value)[1]
                )
                self.assertNotEqual(
                    tr, en, f"the {level.value} badge reads the same in both"
                )

    def test_the_signature_column_translates(self) -> None:
        from gui.views import history_view

        for raw in ("signed_valid", "signed_invalid", "unsigned", "error", "unknown"):
            with self.subTest(status=raw):
                tr, en = self._both(lambda r=raw: history_view.signature_label(r))
                self.assertNotEqual(tr, en, f"{raw} reads the same in both")

    def test_the_risk_level_column_translates(self) -> None:
        from core.risk_engine import RiskLevel
        from gui.views import history_view

        for level in RiskLevel:
            with self.subTest(level=level.value):
                tr, en = self._both(lambda lv=level: history_view.level_label(lv.value))
                self.assertNotEqual(tr, en, f"{level.value} reads the same in both")


class TranslationTableTests(unittest.TestCase):
    """
    The two tables must describe the same interface.

    ``t()`` falls back quietly in both directions, and both fallbacks are
    worse than a crash would be: a key missing from ``tr`` shows a Turkish
    user an English sentence, and a key missing from ``en`` puts the raw key
    — ``trust.btn.scan`` — on a button. Neither raises, so nothing else in
    the suite would notice.
    """

    def test_both_languages_define_the_same_keys(self) -> None:
        from gui.i18n import _TRANSLATIONS  # noqa: SLF001

        turkish = set(_TRANSLATIONS["tr"])
        english = set(_TRANSLATIONS["en"])
        self.assertEqual(
            sorted(english - turkish), [],
            "defined in English only — a Turkish user gets the English text",
        )
        self.assertEqual(
            sorted(turkish - english), [],
            "defined in Turkish only — an English user gets the raw key",
        )

    def test_a_translation_keeps_every_placeholder_it_was_given(self) -> None:
        """
        A dropped ``{placeholder}`` loses a fact, silently.

        ``t()`` substitutes with ``str.format`` and swallows a KeyError, so a
        translation that forgot ``{path}`` does not raise — it renders the
        sentence without the path, and the dialog that was supposed to say
        *which* file is invalid simply stops naming one.
        """
        import re

        from gui.i18n import _TRANSLATIONS  # noqa: SLF001

        def fields(text: str) -> set[str]:
            return set(re.findall(r"\{(\w+)\}", text))

        english = _TRANSLATIONS["en"]
        for language, table in _TRANSLATIONS.items():
            if language == "en":
                continue
            for key, value in table.items():
                with self.subTest(language=language, key=key):
                    self.assertEqual(
                        fields(value), fields(english[key]),
                        "the two versions of this string do not take the "
                        "same values",
                    )

    def test_no_key_is_left_as_its_own_placeholder(self) -> None:
        """A value equal to its key means the entry was never written."""
        from gui.i18n import _TRANSLATIONS  # noqa: SLF001

        for language, table in _TRANSLATIONS.items():
            for key, value in table.items():
                with self.subTest(language=language, key=key):
                    self.assertNotEqual(value, key)
                    self.assertTrue(value.strip(), "empty translation")


class PrivacyNoticeTests(unittest.TestCase):
    """
    The privacy sentence is stated in :mod:`core.trust_pipeline` and shown on
    two screens. Translating it means the interface now carries a second copy,
    and two statements about what leaves the machine may not drift apart.
    """

    def tearDown(self) -> None:
        from gui.i18n import set_language

        set_language("tr")

    def test_the_turkish_notice_is_the_one_the_pipeline_states(self) -> None:
        from core.trust_pipeline import PRIVACY_NOTICE
        from gui.i18n import set_language, t

        set_language("tr")
        self.assertEqual(t("privacy.notice"), PRIVACY_NOTICE)

    def test_the_english_notice_is_a_translation_not_a_copy(self) -> None:
        from core.trust_pipeline import PRIVACY_NOTICE
        from gui.i18n import set_language, t

        set_language("en")
        self.assertNotEqual(t("privacy.notice"), PRIVACY_NOTICE)


if __name__ == "__main__":
    unittest.main()
