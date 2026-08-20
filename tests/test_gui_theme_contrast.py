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


class _PaletteCase(unittest.TestCase):
    """
    Runs its assertions once per palette.

    Not a loop inside one test: a failure has to name which theme it is
    talking about, and a light-only failure must not be hidden by a dark-only
    pass. Every subclass restores the palette afterwards, because it is module
    state and a test that leaves it switched would decide the next one.
    """

    def tearDown(self) -> None:
        from gui import theme

        theme.use(theme.DEFAULT_MODE)

    def palettes(self):
        from gui import theme

        for mode in theme.MODES:
            theme.use(mode)
            yield mode, theme


class ThemeContrastTests(_PaletteCase):
    def test_every_text_colour_is_legible_on_the_hard_ground(self) -> None:
        """
        Measured against each palette's *hardest* ground, not against a fixed
        one. Which surface that is flips with the theme — dark text struggles
        on the darker surface, light text on the lighter one — and assuming it
        was always the darker one is how two colours shipped under AA.
        """
        for mode, theme in self.palettes():
            ground = theme.hard_ground()
            colours = theme.text_colours()
            self.assertTrue(colours, f"{mode}: the theme exposes no text colours")
            for name, colour in sorted(colours.items()):
                with self.subTest(mode=mode, token=name):
                    ratio = contrast_ratio(colour, ground)
                    self.assertGreaterEqual(
                        ratio, AA_NORMAL_TEXT,
                        f"[{mode}] {name} ({colour}) is {ratio:.2f}:1 on "
                        f"{ground}, below the {AA_NORMAL_TEXT}:1 WCAG AA needs",
                    )

    def test_every_text_colour_is_legible_on_both_surfaces(self) -> None:
        """The hard ground should imply the easy one — assert it rather than trust it."""
        for mode, theme in self.palettes():
            for name, colour in sorted(theme.text_colours().items()):
                for ground in (theme.SURFACE, theme.SURFACE_FIELD):
                    with self.subTest(mode=mode, token=name, ground=ground):
                        self.assertGreaterEqual(
                            contrast_ratio(colour, ground), AA_NORMAL_TEXT
                        )

    def test_every_risk_level_has_a_legible_colour(self) -> None:
        for mode, theme in self.palettes():
            ground = theme.hard_ground()
            for level in RiskLevel:
                with self.subTest(mode=mode, level=level.value):
                    colour = theme.risk_colour(level.value)
                    ratio = contrast_ratio(colour, ground)
                    self.assertGreaterEqual(
                        ratio, AA_NORMAL_TEXT,
                        f"[{mode}] risk level {level.value} renders {colour} "
                        f"at {ratio:.2f}:1",
                    )

    def test_every_verify_row_has_a_legible_colour(self) -> None:
        for mode, theme in self.palettes():
            ground = theme.hard_ground()
            for status in theme.RESULT_STATUSES:
                with self.subTest(mode=mode, status=status):
                    colour = theme.result_colour(status)
                    self.assertGreaterEqual(
                        contrast_ratio(colour, ground), AA_NORMAL_TEXT,
                        f"[{mode}] a {status} row renders {colour}",
                    )

    def test_the_two_palettes_are_actually_different(self) -> None:
        """
        Guards every test above against agreeing with a dark theme that is
        just the light one under another name — which would pass all of them.
        """
        from gui import theme

        light = theme.PALETTES["light"]
        dark = theme.PALETTES["dark"]
        self.assertEqual(sorted(light), sorted(dark), "the palettes differ in shape")
        shared = [name for name in light if light[name] == dark[name]]
        self.assertEqual(
            shared, [],
            f"these are the same colour in both themes: {shared}",
        )


class ChromeContrastTests(_PaletteCase):
    """
    The accent is text in one direction and a ground in the other.

    ``text_colours()`` only walks the palette the views draw *with*, so a
    colour introduced by the chrome — the accent on the primary button and on
    the selected tab — would be invisible to every check above. That is the
    same blind spot that let three illegible colours ship, one layer up.
    """

    def test_the_accent_is_legible_in_both_directions(self) -> None:
        """
        The accent carries a label in one direction and is one in the other.

        Its foreground comes from the palette rather than being assumed white.
        That assumption held on light and is catastrophic on dark: white on
        the dark accent measures 2.01:1, so a test written against a literal
        "#ffffff" would have passed the light theme and shipped an unreadable
        primary button in the other one.
        """
        for mode, theme in self.palettes():
            pairs = [
                ("label on the primary button", theme.ACCENT_TEXT, theme.ACCENT),
                ("label while hovered", theme.ACCENT_TEXT, theme.ACCENT_ACTIVE),
                ("selected tab label", theme.ACCENT, theme.SURFACE_FIELD),
                ("accent on the chrome ground", theme.ACCENT, theme.SURFACE),
            ]
            for what, foreground, ground in pairs:
                with self.subTest(mode=mode, pair=what):
                    ratio = contrast_ratio(foreground, ground)
                    self.assertGreaterEqual(
                        ratio, AA_NORMAL_TEXT,
                        f"[{mode}] {what}: {foreground} on {ground} is "
                        f"{ratio:.2f}:1",
                    )

    def test_a_selected_row_is_still_readable(self) -> None:
        # Selection paints the accent behind a Treeview row, so the row's text
        # stops sitting on the field ground and lands on the accent instead.
        for mode, theme in self.palettes():
            with self.subTest(mode=mode):
                self.assertGreaterEqual(
                    contrast_ratio(theme.ACCENT_TEXT, theme.ACCENT),
                    AA_NORMAL_TEXT,
                )

    def test_body_text_survives_the_button_face(self) -> None:
        # Buttons are painted a shade off the surface, so the label sits on a
        # ground none of the palette ratios were measured against.
        for mode, theme in self.palettes():
            for name, ground in (("button", theme._BUTTON),          # noqa: SLF001
                                 ("button hovered", theme._BUTTON_ACTIVE)):  # noqa: SLF001
                with self.subTest(mode=mode, ground=name):
                    ratio = contrast_ratio(theme.TEXT, ground)
                    self.assertGreaterEqual(ratio, AA_NORMAL_TEXT)


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
        # Against the light palette specifically. The report is its own
        # document on its own white page, so it does not follow the window
        # into dark mode — but it must still agree with the screen a user
        # exported it from, and "the screen" for this purpose is the light one.
        from core import trust_report
        from gui import theme

        try:
            theme.use("light")
            for level in RiskLevel:
                with self.subTest(level=level.value):
                    self.assertEqual(
                        trust_report._RISK_COLOR[level.value],     # noqa: SLF001
                        theme.risk_colour(level.value),
                        f"a {level.value} verdict is one colour on screen and "
                        f"another in the report exported from that same screen",
                    )
        finally:
            theme.use(theme.DEFAULT_MODE)

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


@unittest.skipUnless(TK_AVAILABLE, TK_SKIP or "Tk unavailable")
class RenderedColourTests(unittest.TestCase):
    """
    What the screens actually hand their widgets, in each theme.

    The earlier version of this read two module-level tables and compared them
    to each other. Once both screens started asking the theme for the colour,
    that comparison answered itself — the same tautology the ground check fell
    into in §4B. So this builds the widgets and reads back what they were
    configured with, which is the only version that can still catch a screen
    that stopped following the palette.
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

    def tearDown(self) -> None:
        from gui import theme

        try:
            theme.use(theme.DEFAULT_MODE)
        finally:
            self._env.stop()
            self._tmp.cleanup()

    def _built(self, mode: str):
        """The colours a real window configured, with *mode* forced."""
        from unittest import mock

        from gui import theme

        with mock.patch("gui.theme.detect_mode", return_value=mode):
            from gui.app import HashToolApp

            app = HashToolApp()
            app.update_idletasks()
            try:
                self.assertEqual(
                    theme.current_mode(), mode,
                    "the window did not take the theme it was told to",
                )
                drawn = {}
                tree = app.history_view.tree
                for level in RiskLevel:
                    drawn[f"history:{level.value}"] = str(
                        tree.tag_configure(f"risk-{level.value}", "foreground")
                    )
                from gui.views import trust_check_view
                for level in RiskLevel:
                    drawn[f"trust:{level.value}"] = trust_check_view.risk_presentation(
                        level.value
                    )[0]
                verify_tree = app.verify_tab.tree
                for status in theme.RESULT_STATUSES:
                    drawn[f"verify-row:{status}"] = str(
                        verify_tree.tag_configure(status, "foreground")
                    )
                return drawn
            finally:
                app.destroy()

    def test_every_colour_a_screen_renders_is_legible(self) -> None:
        from gui import theme

        for mode in theme.MODES:
            drawn = self._built(mode)
            ground = theme.hard_ground()
            self.assertTrue(drawn, f"[{mode}] nothing was drawn to check")
            for where, colour in sorted(drawn.items()):
                with self.subTest(mode=mode, where=where):
                    self.assertTrue(colour, f"[{mode}] {where} has no colour at all")
                    ratio = contrast_ratio(colour, ground)
                    self.assertGreaterEqual(
                        ratio, AA_NORMAL_TEXT,
                        f"[{mode}] {where} draws {colour} at {ratio:.2f}:1 on {ground}",
                    )

    def test_the_screens_take_their_colours_from_the_theme(self) -> None:
        from gui import theme

        for mode in theme.MODES:
            drawn = self._built(mode)
            known = set(theme.text_colours().values())
            for where, colour in sorted(drawn.items()):
                with self.subTest(mode=mode, where=where):
                    self.assertIn(
                        colour, known,
                        f"[{mode}] {where} uses {colour}, which is not one of "
                        f"this theme's colours — a literal the contrast check "
                        f"cannot see",
                    )

    def test_the_two_screens_colour_a_risk_level_the_same(self) -> None:
        # The same verdict must not look different depending on which screen
        # the user is standing on.
        from gui import theme

        for mode in theme.MODES:
            drawn = self._built(mode)
            for level in RiskLevel:
                with self.subTest(mode=mode, level=level.value):
                    self.assertEqual(
                        drawn[f"history:{level.value}"],
                        drawn[f"trust:{level.value}"],
                        f"[{mode}] {level.value} is drawn in two different colours",
                    )



@unittest.skipUnless(TK_AVAILABLE, TK_SKIP or "Tk unavailable")
class RenderedLegibilityTests(unittest.TestCase):
    """
    Every widget on screen, in both themes: is its text readable on its own
    background?

    This exists because a defect got through by hand. The summary box took its
    ground from the theme and its foreground from Tk's default, which is
    black — invisible luck on the light palette, black-on-charcoal on the
    dark one, in the box that holds the reason for the risk verdict. Nothing
    caught it: the palette was spotless, the grounds were all known, and no
    check had ever compared a widget's two ends to each other.

    The mode is forced rather than detected. Otherwise this machine's Windows
    setting decides which half of the palette the suite exercises, and the
    other half ships unmeasured.
    """

    # Widgets that carry no text of their own. Listed rather than inferred:
    # a class that turns up here later should be a decision, not a silent skip.
    NO_TEXT = {
        "TFrame", "Frame", "TNotebook", "TSeparator", "TProgressbar",
        "TScrollbar", "Scrollbar", "Canvas", "TSizegrip", "Toplevel", "Tk",
    }

    def setUp(self) -> None:
        import os
        import tempfile
        from unittest import mock

        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(
            os.environ, {"LOCALAPPDATA": str(Path(self._tmp.name) / "profile")}
        )
        self._env.start()

    def tearDown(self) -> None:
        from gui import theme

        try:
            theme.use(theme.DEFAULT_MODE)
        finally:
            self._env.stop()
            self._tmp.cleanup()

    def _pairs(self, app, style):
        """
        (where, foreground, background) for everything that shows text.

        The ttk/plain split is decided by ``isinstance``, not by whether the
        class name starts with a T. That shortcut is wrong for exactly the
        widget this test exists to protect: ``Text`` starts with a T, so the
        first version of this looked its colours up in the ttk style, found
        nothing, and skipped the box whose black-on-charcoal defect prompted
        the test in the first place. The coverage harness reported it as
        toothless, which is what that harness is for.
        """
        import tkinter as tk
        import tkinter.ttk as ttk

        def resolve(widget, option, tk_option):
            if isinstance(widget, ttk.Widget):
                return style.lookup(widget.winfo_class(), option)
            try:
                return widget.cget(tk_option)
            except tk.TclError:
                return ""

        def hexify(value):
            if not value:
                return ""
            try:
                r, g, b = app.winfo_rgb(value)
            except tk.TclError:
                return ""
            return "#%02x%02x%02x" % (r // 257, g // 257, b // 257)

        found = []

        def walk(widget):
            cls = widget.winfo_class()
            if cls not in self.NO_TEXT:
                fg = hexify(resolve(widget, "foreground", "fg"))
                bg = hexify(resolve(widget, "background", "bg"))
                if fg and bg:
                    found.append((cls, fg, bg))
            for child in widget.winfo_children():
                walk(child)

        walk(app)
        return found

    def test_no_widget_draws_text_it_cannot_be_read_against(self) -> None:
        from unittest import mock
        import tkinter.ttk as ttk

        from gui import theme

        for mode in theme.MODES:
            with mock.patch("gui.theme.detect_mode", return_value=mode):
                from gui.app import HashToolApp

                app = HashToolApp()
                app.update_idletasks()
                try:
                    style = ttk.Style(app)
                    pairs = self._pairs(app, style)
                    self.assertTrue(
                        pairs, f"[{mode}] no widget reported both a fg and a bg"
                    )
                    offenders = sorted({
                        f"{cls}: {fg} on {bg} ({contrast_ratio(fg, bg):.2f}:1)"
                        for cls, fg, bg in pairs
                        if contrast_ratio(fg, bg) < AA_NORMAL_TEXT
                    })
                    self.assertEqual(
                        offenders, [],
                        f"[{mode}] these widgets draw text nobody can read",
                    )
                finally:
                    app.destroy()


@unittest.skipUnless(TK_AVAILABLE, TK_SKIP or "Tk unavailable")
class BadgeCanvasTests(unittest.TestCase):
    """
    The risk badge draws its own text straight onto a canvas.

    It never went through the risk palette — the colour is an argument at the
    call site — so the mapping checks above cannot see it. This was the worst
    of the three failures at 2.68:1, and it is the state the user looks at
    during every scan.
    """

    # Pinned rather than detected. Left to Windows, this suite exercises
    # whichever palette the machine happens to be wearing and the other one
    # ships unmeasured — which is not hypothetical: the badge's grey passes on
    # a dark ground, so a revert that made it illegible on light went
    # unnoticed on a dark-mode machine until the coverage harness said so.
    MODE = "light"

    def setUp(self) -> None:
        import os
        import tempfile
        from unittest import mock

        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(
            os.environ, {"LOCALAPPDATA": str(Path(self._tmp.name) / "profile")}
        )
        self._env.start()
        self._theme = mock.patch("gui.theme.detect_mode", return_value=self.MODE)
        self._theme.start()

        from gui.app import HashToolApp

        self.app = HashToolApp()
        self.app.update_idletasks()

    def tearDown(self) -> None:
        from gui import theme

        try:
            self.app.destroy()
        finally:
            self._theme.stop()
            theme.use(theme.DEFAULT_MODE)
            self._env.stop()
            self._tmp.cleanup()

    def _hex(self, name: str) -> str:
        """Resolve a Tk colour name (``SystemButtonFace``) to a hex value."""
        r, g, b = self.app.winfo_rgb(name)
        return "#%02x%02x%02x" % (r // 257, g // 257, b // 257)

    def test_every_widget_sits_on_a_ground_the_palette_knows(self) -> None:
        # The palette's ratios only mean anything against the grounds they
        # were computed on. Once the application styles its own theme, asking
        # "does SURFACE match what ttk reports?" answers itself — the constant
        # *is* what ttk reports, because the constant configured it.
        #
        # What still has teeth is the other direction: is every widget on
        # screen sitting on a ground somebody measured? The root style gives
        # ttk classes a safe default, so this is not about forgetting to style
        # one; it catches a widget deliberately put on a colour that was picked
        # without checking it — including the plain tk widgets (canvases, text
        # areas) that the ttk theme never touches.
        import tkinter as tk
        import tkinter.ttk as ttk

        from gui import theme

        style = ttk.Style(self.app)
        known = {v.lower() for v in theme.text_grounds().values()}
        # The progress bar is a filled indicator, not a text ground.
        known.add(theme.ACCENT.lower())

        offenders: list[str] = []

        def walk(widget) -> None:
            cls = widget.winfo_class()
            # isinstance, not a name prefix: "Text", "Toplevel" and "Tk" all
            # start with a T and none of them is a ttk widget.
            if isinstance(widget, ttk.Widget):
                raw = style.lookup(cls, "background")
            else:
                try:
                    raw = widget.cget("bg")
                except tk.TclError:
                    raw = ""
            if raw:
                try:
                    ground = self._hex(raw).lower()
                except tk.TclError:
                    ground = raw
                if ground not in known:
                    offenders.append(f"{cls} on {ground}")
            for child in widget.winfo_children():
                walk(child)

        walk(self.app)
        self.assertEqual(
            sorted(set(offenders)), [],
            "these widgets sit on a ground no contrast ratio was measured "
            "against, so the text on them is unchecked",
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
                # Through the accessor, not the raw table: the table stores an
                # i18n key, and drawing that instead of the label would check
                # the contrast of a string no user ever sees.
                colour, text = trust_check_view.risk_presentation(level.value)
                self.app.trust_view._draw_badge(colour, text)   # noqa: SLF001
                check(level.value)


@unittest.skipUnless(TK_AVAILABLE, TK_SKIP or "Tk unavailable")
class DarkBadgeCanvasTests(BadgeCanvasTests):
    """
    Every check the light theme gets, the dark theme gets too.

    Subclassed rather than parametrised so a dark-only failure is named as
    one in the output, and so adding a check to the light class cannot
    accidentally leave the other palette without it.
    """

    MODE = "dark"


if __name__ == "__main__":
    unittest.main()
