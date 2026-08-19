"""
One place for the colours and fonts the interface draws with.

Why this exists
---------------
These were literals scattered over four view modules — eleven distinct colours
in twenty-eight places, with the risk palette written out twice. That had two
consequences, and the second is the one that mattered:

* the two copies of the risk palette could drift apart, and nothing would have
  said so;
* three of the colours were illegible, and there was no single place for
  "fix the contrast" to happen.

The illegible ones were the neutral badge at 2.68:1 — the "Taranıyor…" state,
on screen during every scan — and two oranges at 3.08:1 and 3.79:1, where WCAG
AA asks 4.5:1 for body text. A risk indicator that cannot be read is worse than
none: it occupies the place where the warning was meant to be.

Choosing the replacements
-------------------------
Each failing colour was darkened along its own hue until it cleared 5.0:1 —
AA plus enough headroom that a later nudge does not silently drop it under.

The first attempt measured all of this against white and was wrong about the
one thing it was most confident of. ttk paints most of the window with
SystemButtonFace (#f0f0f0), and against that ground the repaired orange came
out at 4.39:1 — still under AA — while the green sat exactly on 4.50. White is
the lightest ground there is, so every ratio computed against it is an upper
bound on what the user sees. The palette is now derived against the darker of
the two real surfaces, and the surfaces themselves are read back from the live
ttk style by a test rather than asserted here.
The two near-identical oranges became one token: they meant different things
(a risk level, a changed file) but no eye could tell them apart, and three
greys collapsed into one for the same reason.

Four values changed, not three. The greys were ``#9e9e9e`` (the illegible one),
``#616161`` and ``#666666`` — that last was already legible at 5.74:1 and still
moved, because it sat five units from ``#616161`` and the difference was a
distinction only a colour picker could see. Everything else keeps the value it
had; this round consolidates the palette and repairs the contrast, it does not
restyle the application.

``tests/test_gui_theme_contrast.py`` recomputes every ratio from the WCAG
formula, so this docstring cannot quietly become false.

Scope
-----
Light surface only. The palette is tuned against white and most of it falls
under 3.5:1 on a dark ground, so supporting a dark theme is a separate piece of
work, not a switch to flip here — see docs/P1-BACKLOG.md.
"""

from __future__ import annotations

from core.risk_engine import RiskLevel

# --- Surfaces ---------------------------------------------------------
# There are two, and assuming there was one is how the first attempt at this
# module shipped colours that still failed. ttk paints frames, labels and the
# badge canvas with SystemButtonFace, not white; only field widgets — Treeview
# rows, entries — get SystemWindow. On Windows 11 those resolve to #f0f0f0 and
# #ffffff, and #f0f0f0 is the harder ground, so every ratio below is measured
# against SURFACE and therefore holds on SURFACE_FIELD as well.
#
# These are not decoration: a test looks them up from the live ttk style and
# fails if they have drifted from what the toolkit actually paints.
SURFACE = "#f0f0f0"        # SystemButtonFace — frames, labels, canvases
SURFACE_FIELD = "#ffffff"  # SystemWindow — Treeview rows, entry fields

# --- Text -------------------------------------------------------------
# Ratios are against SURFACE (the darker ground); the value on SURFACE_FIELD
# follows in brackets.
TEXT = "#444444"        # 8.55:1 [9.74] — body copy
MUTED = "#616161"       # 5.43:1 [6.19] — hints, secondary detail, neutral states

# --- Semantic ---------------------------------------------------------
OK = "#2b742f"          # 5.06:1 [5.77] — low risk, unchanged
ATTENTION = "#a74b00"   # 5.05:1 [5.75] — medium risk, modified
DANGER = "#c62828"      # 4.93:1 [5.62] — high risk, missing
INFO = "#1565c0"        # 5.04:1 [5.75] — new
TRACE = "#6a1b9a"       # 8.24:1 [9.39] — errors in a result listing

# --- Typography -------------------------------------------------------
# The same six definitions the views were already using, named rather than
# repeated. Sizes are unchanged: this round centralises them, it does not
# redesign the type.
FONT_UI = ("Segoe UI", 10)
FONT_UI_BOLD = ("Segoe UI", 10, "bold")
FONT_LABEL_BOLD = ("Segoe UI", 9, "bold")
FONT_HEADING = ("Segoe UI", 11, "bold")
FONT_MONO = ("Consolas", 10)
FONT_MONO_SMALL = ("Consolas", 9)

# --- Mappings ---------------------------------------------------------
_RISK_COLOUR = {
    RiskLevel.LOW.value: OK,
    RiskLevel.MEDIUM.value: ATTENTION,
    RiskLevel.HIGH.value: DANGER,
    RiskLevel.UNKNOWN.value: MUTED,
}

# Verify-tab result rows. "modified" shares ATTENTION with medium risk: they
# are never on screen together and two oranges nobody can tell apart is not a
# distinction, it is noise.
RESULT_COLOUR = {
    "unchanged": OK,
    "modified": ATTENTION,
    "new": INFO,
    "missing": DANGER,
    "errors": TRACE,
}


def risk_colour(level: str) -> str:
    """Colour for a risk level, falling back to the neutral tone."""
    return _RISK_COLOUR.get(level, MUTED)


def text_colours() -> dict[str, str]:
    """
    Every colour that is drawn as text, for the contrast test to walk.

    Anything added here is checked; anything a view keeps to itself is not,
    which is the argument for not keeping any.
    """
    return {
        "TEXT": TEXT,
        "MUTED": MUTED,
        "OK": OK,
        "ATTENTION": ATTENTION,
        "DANGER": DANGER,
        "INFO": INFO,
        "TRACE": TRACE,
    }
