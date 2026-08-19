"""
Every colour the interface renders text in must be legible.

Three of them were not. The worst was the neutral badge at 2.68:1 — the
"Taranıyor…" state, which is on screen during every single scan — followed by
the medium-risk orange at 3.08:1 and the modified-file orange at 3.79:1. WCAG
AA asks 4.5:1 for normal-size text. A risk indicator nobody can read is worse
than no indicator: it occupies the place where the warning was supposed to be.

The colours also lived as literals in four files, with the risk palette defined
twice, so "fix the contrast" had no single place to happen and the two copies
could drift apart without anything noticing.

The ratios here are computed from the WCAG formula directly rather than through
any helper the application ships, so a mistake in that helper cannot make these
pass.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from core.risk_engine import RiskLevel

try:
    import tkinter as tk

    _probe = tk.Tk()
    _probe.destroy()
    TK_AVAILABLE = True
    TK_SKIP = ""
except Exception as exc:  # pragma: no cover
    TK_AVAILABLE = False
    TK_SKIP = f"Tk unavailable: {exc}"

# WCAG 2.1 relative luminance / contrast, implemented independently.
AA_NORMAL_TEXT = 4.5


def _relative_luminance(hex_colour: str) -> float:
    raw = hex_colour.lstrip("#")
    if len(raw) == 3:
        raw = "".join(c * 2 for c in raw)
    channels = [int(raw[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [
        c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
        for c in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast_ratio(foreground: str, background: str) -> float:
    a, b = _relative_luminance(foreground), _relative_luminance(background)
    lighter, darker = max(a, b), min(a, b)
    return (lighter + 0.05) / (darker + 0.05)


class ContrastFormulaTests(unittest.TestCase):
    """The yardstick itself, against values fixed by the specification."""

    def test_known_ratios(self) -> None:
        self.assertAlmostEqual(contrast_ratio("#000000", "#ffffff"), 21.0, places=2)
        self.assertAlmostEqual(contrast_ratio("#ffffff", "#ffffff"), 1.0, places=2)
        self.assertAlmostEqual(contrast_ratio("#767676", "#ffffff"), 4.54, places=2)


class ThemeContrastTests(unittest.TestCase):
    def test_every_text_colour_is_legible_on_the_surface(self) -> None:
        from gui import theme

        colours = theme.text_colours()
        self.assertTrue(colours, "the theme exposes no text colours to check")
        for name, colour in sorted(colours.items()):
            with self.subTest(token=name):
                ratio = contrast_ratio(colour, theme.SURFACE)
                self.assertGreaterEqual(
                    ratio, AA_NORMAL_TEXT,
                    f"{name} ({colour}) is {ratio:.2f}:1 on {theme.SURFACE}, "
                    f"below the {AA_NORMAL_TEXT}:1 WCAG AA needs for body text",
                )

    def test_every_risk_level_has_a_legible_colour(self) -> None:
        from gui import theme

        for level in RiskLevel:
            with self.subTest(level=level.value):
                colour = theme.risk_colour(level.value)
                ratio = contrast_ratio(colour, theme.SURFACE)
                self.assertGreaterEqual(
                    ratio, AA_NORMAL_TEXT,
                    f"risk level {level.value} renders {colour} at {ratio:.2f}:1",
                )


class ReportPaletteTests(unittest.TestCase):
    """
    The exported HTML report is a third copy of the palette.

    It lives in ``core`` and cannot import the GUI theme without inverting the
    layering, so the two are kept in step by this test rather than by a shared
    import. That is the whole point: the copies existing is tolerable, the
    copies drifting silently is not — and they did drift, the moment the GUI
    colours were repaired and this one was not.
    """

    def test_the_report_colours_a_verdict_like_the_screen_does(self) -> None:
        from core import trust_report
        from gui import theme

        for level in RiskLevel:
            with self.subTest(level=level.value):
                self.assertEqual(
                    trust_report._RISK_COLOR[level.value],     # noqa: SLF001
                    theme.risk_colour(level.value),
                    f"a {level.value} verdict is one colour on screen and "
                    f"another in the report exported from that same screen",
                )

    def test_every_colour_the_report_sets_text_in_is_legible(self) -> None:
        # The report is its own HTML document, so it is measured against its
        # own grounds: the page tint for `body`, an explicit `background:` when
        # the rule sets one, and the white card otherwise. Every `color:` rule
        # is walked, not just the severity classes — a de-emphasised label is
        # still text somebody has to read.
        import re

        source = Path("core/trust_report.py").read_text(encoding="utf-8")
        PAGE, CARD = "#f5f6f8", "#ffffff"

        checked = 0
        for rule, body in re.findall(r"([.\w-]+)\s*\{\{([^}]*)\}\}", source):
            found = re.search(r"\bcolor:\s*(#[0-9a-fA-F]{3,6})", body)
            if not found:
                continue
            foreground = found.group(1)
            own_bg = re.search(r"background:\s*(#[0-9a-fA-F]{3,6})", body)
            ground = own_bg.group(1) if own_bg else (PAGE if rule == "body" else CARD)
            checked += 1
            with self.subTest(rule=rule):
                ratio = contrast_ratio(foreground, ground)
                self.assertGreaterEqual(
                    ratio, AA_NORMAL_TEXT,
                    f"{rule} draws {foreground} on {ground} at {ratio:.2f}:1",
                )
        self.assertGreater(checked, 5, "the CSS walk found almost nothing")


class PaletteAgreementTests(unittest.TestCase):
    def test_the_two_screens_colour_a_risk_level_the_same(self) -> None:
        # The same verdict must not look different depending on which screen
        # the user is standing on. These were two independent literals, and
        # nothing would have reported it if one of them had been edited.
        from gui.views import history_view, trust_check_view

        for level in RiskLevel:
            with self.subTest(level=level.value):
                self.assertEqual(
                    history_view._LEVEL_COLOR[level.value],          # noqa: SLF001
                    trust_check_view.RISK_PRESENTATION[level.value][0],
                    f"{level.value} is drawn in two different colours",
                )



class RenderedColourTests(unittest.TestCase):
    """
    What the screens actually draw, not what the theme merely offers.

    A token module everything ignores fixes nothing. These read the mappings
    the views hand to their widgets, so a literal left behind in a view is a
    failure here even while the theme itself is spotless.
    """

    def _rendered(self):
        from gui import app as app_module
        from gui.views import history_view, trust_check_view

        for level in RiskLevel:
            yield (
                f"history:{level.value}",
                history_view._LEVEL_COLOR[level.value],          # noqa: SLF001
            )
            yield (
                f"trust:{level.value}",
                trust_check_view.RISK_PRESENTATION[level.value][0],
            )
        for status, colour in app_module.STATUS_COLORS.items():
            yield f"verify-row:{status}", colour

    def test_every_colour_a_screen_renders_is_legible(self) -> None:
        from gui import theme

        for where, colour in self._rendered():
            with self.subTest(where=where):
                ratio = contrast_ratio(colour, theme.SURFACE)
                self.assertGreaterEqual(
                    ratio, AA_NORMAL_TEXT,
                    f"{where} draws {colour} at {ratio:.2f}:1 on "
                    f"{theme.SURFACE}",
                )

    def test_the_screens_take_their_colours_from_the_theme(self) -> None:
        from gui import theme

        known = set(theme.text_colours().values())
        for where, colour in self._rendered():
            with self.subTest(where=where):
                self.assertIn(
                    colour, known,
                    f"{where} uses {colour}, which is not one of the theme's "
                    f"colours — a literal that the contrast check cannot see",
                )



@unittest.skipUnless(TK_AVAILABLE, TK_SKIP or "Tk unavailable")
class BadgeCanvasTests(unittest.TestCase):
    """
    The risk badge draws its own text straight onto a canvas.

    It never went through the risk palette — the colour is an argument at the
    call site — so the mapping checks above cannot see it. This was the worst
    of the three failures at 2.68:1, and it is the state the user looks at
    during every scan.
    """

    def setUp(self) -> None:
        import os
        import tempfile
        from unittest import mock

        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(
            os.environ, {"LOCALAPPDATA": str(Path(self._tmp.name) / "profile")}
        )
        self._env.start()

        from gui.app import HashToolApp

        self.app = HashToolApp()
        self.app.update_idletasks()

    def tearDown(self) -> None:
        try:
            self.app.destroy()
        finally:
            self._env.stop()
            self._tmp.cleanup()

    def _hex(self, name: str) -> str:
        """Resolve a Tk colour name (``SystemButtonFace``) to a hex value."""
        r, g, b = self.app.winfo_rgb(name)
        return "#%02x%02x%02x" % (r // 257, g // 257, b // 257)

    def test_the_theme_knows_what_the_toolkit_actually_paints(self) -> None:
        # The whole palette is derived against these two values. The first
        # version of this module simply asserted white, and ttk paints
        # SystemButtonFace behind almost everything — so every ratio it
        # reported was an upper bound and two colours shipped under AA. Read
        # the surfaces back from the live style instead of trusting a constant.
        import tkinter.ttk as ttk

        from gui import theme

        style = ttk.Style(self.app)
        chrome = style.lookup("TFrame", "background")
        field = style.lookup("Treeview", "background")
        self.assertTrue(chrome and field, "ttk reported no background colours")

        self.assertEqual(
            self._hex(chrome), theme.SURFACE,
            "theme.SURFACE is not what ttk paints behind frames and labels",
        )
        self.assertEqual(
            self._hex(field), theme.SURFACE_FIELD,
            "theme.SURFACE_FIELD is not what ttk paints behind field widgets",
        )

    def test_the_badge_is_legible_in_every_state_it_draws(self) -> None:
        from core.risk_engine import RiskLevel as _Level

        from gui import theme
        from gui.views import trust_check_view

        canvas = self.app.trust_view.badge_canvas
        ground = self._hex(canvas.cget("bg"))

        def check(state: str) -> None:
            self.app.update_idletasks()
            drawn_any = False
            for item in canvas.find_all():
                if canvas.type(item) != "text":
                    continue
                drawn_any = True
                colour = canvas.itemcget(item, "fill")
                shown = canvas.itemcget(item, "text")
                ratio = contrast_ratio(colour, ground)
                self.assertGreaterEqual(
                    ratio, AA_NORMAL_TEXT,
                    f"in state {state!r} the badge draws {shown!r} in "
                    f"{colour} at {ratio:.2f}:1 on {ground}",
                )
            self.assertTrue(drawn_any, f"state {state!r} drew no badge text")

        # As built, before anything redraws it. Checking this first matters:
        # _clear_summary immediately overwrites the canvas, so a test that
        # drives the other states first never sees the colour the window
        # actually opens with — and stops holding that call site at all.
        with self.subTest(state="idle"):
            check("idle")

        # The scanning badge and each verdict are separate call sites that
        # pass their colour as an argument, so none of them goes through the
        # risk palette the mapping tests walk.
        with self.subTest(state="scanning"):
            self.app.trust_view._clear_summary()          # noqa: SLF001
            check("scanning")

        for level in _Level:
            with self.subTest(state=level.value):
                colour, text = trust_check_view.RISK_PRESENTATION[level.value]
                self.app.trust_view._draw_badge(colour, text)   # noqa: SLF001
                check(level.value)


if __name__ == "__main__":
    unittest.main()
