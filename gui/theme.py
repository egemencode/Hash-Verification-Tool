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
bound on what the user sees. The palette is therefore derived against the
*hardest* ground each theme has, and the grounds themselves are read back from
the live ttk style by a test rather than asserted here.

Two palettes
------------
Light and dark are separate tables, not one table with a switch. Almost none
of the light palette survives on a dark ground — measured, most of it lands
under 3.5:1 — so a dark theme is a second set of decisions rather than an
inversion.

Which ground is the hard one flips with the theme. On light, text is dark and
the *darker* surface is the difficult one; on dark, text is light and the
*lighter* surface is. Both directions are measured, in both palettes, by
``tests/test_gui_theme_contrast.py``.

The accent flips something else, and it is the kind of assumption that shipped
three illegible colours the first time. The light accent carries white text at
5.38:1. The dark accent carries white at **2.01:1** — unreadable — and black at
10.47:1. So the foreground the accent takes is part of the palette, not a
constant, and the test checks each accent against the foreground its own theme
actually pairs with it.

Scope
-----
The exported HTML report is a separate surface with its own white page, so it
keeps the light values regardless of which theme the application is wearing —
see ``core/trust_report.py`` and the test that holds the two in step.
"""

from __future__ import annotations

from typing import Any, Optional

from core.risk_engine import RiskLevel


# ======================================================================
# The two palettes
# ======================================================================
# Every ratio in the comments is against that palette's *hardest* ground:
# SURFACE on light (the darker of the two), SURFACE_FIELD on dark (the
# lighter). A colour that clears the hard ground clears the easy one.
PALETTES: dict[str, dict[str, str]] = {
    "light": {
        "SURFACE": "#f0f0f0",        # SystemButtonFace — frames, labels, canvases
        "SURFACE_FIELD": "#ffffff",  # SystemWindow — Treeview rows, entries

        "TEXT": "#444444",           # 8.55:1 — body copy
        "MUTED": "#616161",          # 5.43:1 — hints, secondary detail
        "OK": "#2b742f",             # 5.06:1 — low risk, unchanged
        "ATTENTION": "#a74b00",      # 5.05:1 — medium risk, modified
        "DANGER": "#c62828",         # 4.93:1 — high risk, missing
        "INFO": "#1565c0",           # 5.04:1 — new
        "TRACE": "#6a1b9a",          # 8.24:1 — errors in a result listing

        "BORDER": "#e1e1e1",
        "BUTTON": "#fbfbfb",
        "BUTTON_ACTIVE": "#f0f0f0",
        "TROUGH": "#e6e6e6",
        # WCAG 1.4.3 exempts inactive controls, deliberately: a disabled
        # button that reads as crisply as an enabled one stops looking
        # disabled. Recorded rather than left unexplained — it is the one
        # value in each palette below 4.5:1.
        "DISABLED_TEXT": "#9a9a9a",  # 2.47:1

        "ACCENT": "#0f6cbd",         # 5.38:1 as text on the field ground
        "ACCENT_ACTIVE": "#115ea3",
        "ACCENT_TEXT": "#ffffff",    # 5.38:1 on ACCENT
    },
    "dark": {
        "SURFACE": "#202020",
        "SURFACE_FIELD": "#2b2b2b",

        "TEXT": "#f0f0f0",           # 12.42:1
        "MUTED": "#b8b8b8",          # 7.14:1
        "OK": "#8ed48e",             # 8.06:1
        "ATTENTION": "#f5bb70",      # 8.24:1
        "DANGER": "#f79b94",         # 6.79:1
        "INFO": "#9ac8f0",           # 8.02:1
        "TRACE": "#d4b3e8",          # 7.69:1

        "BORDER": "#3d3d3d",
        "BUTTON": "#323232",
        "BUTTON_ACTIVE": "#3d3d3d",
        "TROUGH": "#3d3d3d",
        "DISABLED_TEXT": "#6e6e6e",  # 2.78:1 — same exemption as above

        "ACCENT": "#4cc2ff",         # 7.06:1 as text on the field ground
        "ACCENT_ACTIVE": "#6ccdff",
        # Black, not white: white on this accent is 2.01:1. The light theme's
        # answer does not transfer, which is the whole reason this is a
        # palette entry rather than a literal in apply().
        "ACCENT_TEXT": "#000000",    # 10.47:1 on ACCENT
    },
}

MODES = tuple(PALETTES)
DEFAULT_MODE = "light"

_mode = DEFAULT_MODE

# --- Active palette ---------------------------------------------------
# These are module attributes rather than dictionary lookups because every
# view reads them as ``theme.TEXT`` while it builds, and a view is always
# built after `apply` has chosen a palette. `use` rebinds them.
SURFACE = PALETTES[DEFAULT_MODE]["SURFACE"]
SURFACE_FIELD = PALETTES[DEFAULT_MODE]["SURFACE_FIELD"]
TEXT = PALETTES[DEFAULT_MODE]["TEXT"]
MUTED = PALETTES[DEFAULT_MODE]["MUTED"]
OK = PALETTES[DEFAULT_MODE]["OK"]
ATTENTION = PALETTES[DEFAULT_MODE]["ATTENTION"]
DANGER = PALETTES[DEFAULT_MODE]["DANGER"]
INFO = PALETTES[DEFAULT_MODE]["INFO"]
TRACE = PALETTES[DEFAULT_MODE]["TRACE"]
ACCENT = PALETTES[DEFAULT_MODE]["ACCENT"]
ACCENT_ACTIVE = PALETTES[DEFAULT_MODE]["ACCENT_ACTIVE"]
ACCENT_TEXT = PALETTES[DEFAULT_MODE]["ACCENT_TEXT"]
_BORDER = PALETTES[DEFAULT_MODE]["BORDER"]
_BUTTON = PALETTES[DEFAULT_MODE]["BUTTON"]
_BUTTON_ACTIVE = PALETTES[DEFAULT_MODE]["BUTTON_ACTIVE"]
_TROUGH = PALETTES[DEFAULT_MODE]["TROUGH"]
_DISABLED_TEXT = PALETTES[DEFAULT_MODE]["DISABLED_TEXT"]

# --- Typography -------------------------------------------------------
# The same six definitions the views were already using, named rather than
# repeated. Type does not change with the theme.
FONT_UI = ("Segoe UI", 10)
FONT_UI_BOLD = ("Segoe UI", 10, "bold")
FONT_LABEL_BOLD = ("Segoe UI", 9, "bold")
FONT_HEADING = ("Segoe UI", 11, "bold")
FONT_MONO = ("Consolas", 10)
FONT_MONO_SMALL = ("Consolas", 9)


def use(mode: str) -> None:
    """
    Make *mode* the active palette.

    Must run before any view is built. Everything on screen reads these as
    module attributes while it lays itself out, so switching afterwards
    changes the constants without repainting anything that already used them
    — which is why the application chooses once, at startup, and rebuilds the
    window if that ever needs to change.
    """
    global _mode, SURFACE, SURFACE_FIELD, TEXT, MUTED, OK, ATTENTION, DANGER
    global INFO, TRACE, ACCENT, ACCENT_ACTIVE, ACCENT_TEXT
    global _BORDER, _BUTTON, _BUTTON_ACTIVE, _TROUGH, _DISABLED_TEXT

    palette = PALETTES.get(mode)
    if palette is None:
        return
    _mode = mode
    SURFACE = palette["SURFACE"]
    SURFACE_FIELD = palette["SURFACE_FIELD"]
    TEXT = palette["TEXT"]
    MUTED = palette["MUTED"]
    OK = palette["OK"]
    ATTENTION = palette["ATTENTION"]
    DANGER = palette["DANGER"]
    INFO = palette["INFO"]
    TRACE = palette["TRACE"]
    ACCENT = palette["ACCENT"]
    ACCENT_ACTIVE = palette["ACCENT_ACTIVE"]
    ACCENT_TEXT = palette["ACCENT_TEXT"]
    _BORDER = palette["BORDER"]
    _BUTTON = palette["BUTTON"]
    _BUTTON_ACTIVE = palette["BUTTON_ACTIVE"]
    _TROUGH = palette["TROUGH"]
    _DISABLED_TEXT = palette["DISABLED_TEXT"]


def current_mode() -> str:
    return _mode


def detect_mode() -> str:
    """
    Which theme Windows is wearing, or ``"light"`` when it will not say.

    Reads the same value Explorer does. Anything unexpected — another
    platform, a missing key, a policy that blocks the read — falls back to
    light rather than guessing: a wrong guess here paints the whole window,
    and the light palette is the one this application was designed against.
    """
    try:
        import winreg
    except ImportError:
        return DEFAULT_MODE
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        ) as key:
            apps_use_light, _kind = winreg.QueryValueEx(key, "AppsUseLightTheme")
    except OSError:
        return DEFAULT_MODE
    return "light" if apps_use_light else "dark"


# --- Mappings ---------------------------------------------------------
def risk_colour(level: str) -> str:
    """
    Colour for a risk level, in the active palette.

    A function, not a table: a dictionary built at import time captures
    whichever palette was active when Python first read this file, which is
    before the application has looked at what theme Windows is using.
    """
    return {
        RiskLevel.LOW.value: OK,
        RiskLevel.MEDIUM.value: ATTENTION,
        RiskLevel.HIGH.value: DANGER,
        RiskLevel.UNKNOWN.value: MUTED,
    }.get(level, MUTED)


# Verify-tab result rows. "modified" shares ATTENTION with medium risk: they
# are never on screen together and two oranges nobody can tell apart is not a
# distinction, it is noise.
RESULT_STATUSES = ("unchanged", "modified", "new", "missing", "errors")


def result_colour(status: str) -> str:
    """Colour for a verify-result row, in the active palette."""
    return {
        "unchanged": OK,
        "modified": ATTENTION,
        "new": INFO,
        "missing": DANGER,
        "errors": TRACE,
    }.get(status, MUTED)


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


def text_grounds() -> dict[str, str]:
    """
    Every ground the interface draws text on.

    Buttons are painted a shade off the surface, so a label on one sits on a
    third colour that neither SURFACE nor SURFACE_FIELD describes. A widget
    class nobody styled falls back to clam's default beige, which is not in
    here — which is the point: a test walks the built window and fails on any
    ground this does not name.
    """
    return {
        "SURFACE": SURFACE,
        "SURFACE_FIELD": SURFACE_FIELD,
        "BUTTON": _BUTTON,
        "BUTTON_ACTIVE": _BUTTON_ACTIVE,
    }


def hard_ground() -> str:
    """
    The ground a colour has the most trouble on, in the active palette.

    On light that is the darker surface; on dark it is the lighter one. The
    first version of this module assumed the answer was always "the darker
    one" and shipped two colours under AA because of it.
    """
    return max(
        (SURFACE, SURFACE_FIELD),
        key=lambda ground: _relative_luminance(ground) if _mode == "dark"
        else -_relative_luminance(ground),
    )


def _relative_luminance(hex_colour: str) -> float:
    raw = hex_colour.lstrip("#")
    channels = [int(raw[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [
        c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
        for c in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


# ======================================================================
# Chrome
# ======================================================================
def apply(root: Any, mode: Optional[str] = None) -> None:
    """
    Put the window on the ``clam`` base, flatten it, and paint the palette.

    ``vista`` is the theme Tk reaches for on Windows, and it draws Windows
    7-era chrome: cramped tabs, buttons with no real padding, and a primary
    action distinguishable from the rest only by bold text. ``clam`` is the
    one built-in base that takes styling, so the look is built on it rather
    than inherited. It is also the only one that will accept a dark palette at
    all — ``vista`` draws its own bitmaps and ignores the colours it is given,
    which is why the fallback below stays light no matter what Windows says.

    *mode* defaults to whatever Windows is using.
    """
    import tkinter as tk
    from tkinter import ttk

    style = ttk.Style(root)
    # Not `theme`: that name is this module in the caller's namespace, and
    # shadowing it once made every token lookup read off a string instead.
    for theme_name in ("clam", "vista", "default"):
        try:
            style.theme_use(theme_name)
            break
        except tk.TclError:
            continue

    if style.theme_use() != "clam":
        # Nothing below is meaningful on a theme that ignores it, and a dark
        # palette half-applied is worse than none: the parts vista draws
        # itself would stay light and the text over them would be light too.
        use("light")
        style.configure("Status.TLabel", padding=(8, 4))
        style.configure("Accent.TButton", font=FONT_UI_BOLD)
        return

    use(mode or detect_mode())

    # The window itself is a plain Tk widget and keeps SystemButtonFace
    # whatever the ttk style says. Anywhere a ttk frame does not cover it —
    # padding, the strip behind the notebook, a moment during a resize — that
    # is a light grey rectangle in a dark window.
    try:
        root.configure(background=SURFACE)
    except tk.TclError:  # pragma: no cover - not a real toplevel
        pass

    style.configure(".", background=SURFACE, foreground=TEXT, font=FONT_UI,
                    borderwidth=0, focuscolor=ACCENT)
    style.configure("TFrame", background=SURFACE)
    style.configure("TLabel", background=SURFACE, foreground=TEXT)
    style.configure("TCheckbutton", background=SURFACE, foreground=TEXT)
    style.map("TCheckbutton",
              background=[("active", SURFACE)],
              foreground=[("disabled", _DISABLED_TEXT)],
              indicatorcolor=[("selected", ACCENT)])
    style.configure("TRadiobutton", background=SURFACE, foreground=TEXT)
    style.map("TRadiobutton",
              background=[("active", SURFACE)],
              foreground=[("disabled", _DISABLED_TEXT)],
              indicatorcolor=[("selected", ACCENT)])
    style.configure("TLabelframe", background=SURFACE, bordercolor=_BORDER,
                    relief="solid", borderwidth=1)
    style.configure("TLabelframe.Label", background=SURFACE, foreground=MUTED,
                    font=FONT_LABEL_BOLD)

    style.configure("TButton", background=_BUTTON, foreground=TEXT,
                    bordercolor=_BORDER, relief="solid", borderwidth=1,
                    padding=(14, 7))
    style.map("TButton",
              background=[("active", _BUTTON_ACTIVE), ("disabled", SURFACE)],
              foreground=[("disabled", _DISABLED_TEXT)])
    # Exactly one accented control per screen: an emphasis everything shares
    # is not an emphasis.
    style.configure("Accent.TButton", background=ACCENT, foreground=ACCENT_TEXT,
                    bordercolor=ACCENT, padding=(14, 7), font=FONT_UI_BOLD)
    style.map("Accent.TButton",
              background=[("active", ACCENT_ACTIVE), ("disabled", SURFACE)],
              foreground=[("disabled", _DISABLED_TEXT)])

    style.configure("TEntry", fieldbackground=SURFACE_FIELD, foreground=TEXT,
                    insertcolor=TEXT, bordercolor=_BORDER, lightcolor=_BORDER,
                    darkcolor=_BORDER, padding=5)
    style.map("TEntry", foreground=[("disabled", _DISABLED_TEXT)])
    style.configure("TCombobox", fieldbackground=SURFACE_FIELD, foreground=TEXT,
                    background=_BUTTON, arrowcolor=TEXT,
                    bordercolor=_BORDER, padding=4)
    # A readonly combobox keeps clam's grey field unless the map overrides it,
    # which made the algorithm picker read as a disabled control.
    style.map("TCombobox",
              fieldbackground=[("readonly", SURFACE_FIELD)],
              selectbackground=[("readonly", SURFACE_FIELD)],
              selectforeground=[("readonly", TEXT)],
              foreground=[("readonly", TEXT)])
    style.configure("TSpinbox", fieldbackground=SURFACE_FIELD, foreground=TEXT,
                    background=_BUTTON, arrowcolor=TEXT,
                    bordercolor=_BORDER, padding=4)

    style.configure("TNotebook", background=SURFACE, borderwidth=0,
                    tabmargins=(0, 6, 0, 0))
    style.configure("TNotebook.Tab", background=SURFACE, bordercolor=SURFACE,
                    foreground=TEXT, padding=(18, 9), font=FONT_UI)
    style.map("TNotebook.Tab",
              background=[("selected", SURFACE_FIELD)],
              foreground=[("selected", ACCENT)])

    style.configure("Treeview", background=SURFACE_FIELD, foreground=TEXT,
                    fieldbackground=SURFACE_FIELD, bordercolor=_BORDER,
                    rowheight=26)
    style.map("Treeview",
              background=[("selected", ACCENT)],
              foreground=[("selected", ACCENT_TEXT)])
    style.configure("Treeview.Heading", background=SURFACE, foreground=TEXT,
                    relief="flat", font=FONT_LABEL_BOLD, padding=(6, 6))

    style.configure("TScrollbar", background=_BUTTON, troughcolor=SURFACE,
                    bordercolor=_BORDER, arrowcolor=TEXT)
    style.configure("Status.TLabel", background=SURFACE, padding=(10, 6))
    style.configure("TProgressbar", background=ACCENT, troughcolor=_TROUGH,
                    bordercolor=_TROUGH, lightcolor=ACCENT, darkcolor=ACCENT)


def style_text_area(widget: Any) -> None:
    """
    Paint a plain Tk text area, which the ttk style cannot reach.

    ``ScrolledText`` is not a ttk widget: it is a Text inside a plain Frame
    with a plain Scrollbar, and all three keep the Windows defaults no matter
    what the theme says. On light that is invisible — the defaults happen to
    match. On dark it is three light rectangles in a dark window, and the
    caret and the selection are unreadable on top of them.

    Only what the widget actually has is set, so this works for a bare Text as
    well as for a ScrolledText.
    """
    try:
        widget.configure(
            background=SURFACE_FIELD, foreground=TEXT,
            insertbackground=TEXT,
            selectbackground=ACCENT, selectforeground=ACCENT_TEXT,
            highlightthickness=0, borderwidth=0,
        )
    except Exception:  # pragma: no cover - a widget without those options
        pass
    frame = getattr(widget, "frame", None)
    if frame is not None:
        try:
            frame.configure(background=SURFACE, highlightthickness=0)
        except Exception:  # pragma: no cover
            pass
    vbar = getattr(widget, "vbar", None)
    if vbar is not None:
        try:
            vbar.configure(
                background=_BUTTON, troughcolor=SURFACE,
                activebackground=_BUTTON_ACTIVE, highlightthickness=0,
                borderwidth=0,
            )
        except Exception:  # pragma: no cover
            pass


def style_menu(menu: Any) -> None:
    """
    Paint a menu, as far as Windows allows.

    The dropdowns take these colours. The menu *bar* on Windows is drawn by
    the OS and ignores them — a limitation worth naming rather than papering
    over, because it means a dark window keeps a light strip along its top
    until Tk grows native dark menu support.
    """
    try:
        menu.configure(
            background=SURFACE, foreground=TEXT,
            activebackground=ACCENT, activeforeground=ACCENT_TEXT,
            disabledforeground=_DISABLED_TEXT,
            borderwidth=0, relief="flat",
        )
    except Exception:  # pragma: no cover
        pass
