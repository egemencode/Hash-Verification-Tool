"""
Where the GUI reaches for translations. The table itself lives in
:mod:`core.i18n`.

It was here first, and moving it was not tidying. ``core/scan_policy.py``
holds the rules both front ends obey, and its notices are text the
application chose to say — so they have to be translatable. A core module
importing ``gui`` to get at ``t()`` would have inverted the dependency the
whole point of that file is to avoid.

The GUI keeps importing ``gui.i18n`` because that is what a view should be
asking for. Nothing here holds state: the language, the table and the lookup
are all one module deep, so ``set_language`` called through this name is the
same call, on the same state, as one made from the core side.
"""

from __future__ import annotations

from core.i18n import (  # noqa: F401  (re-exported on purpose)
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    _TRANSLATIONS,
    get_language,
    set_language,
    t,
)

__all__ = [
    "DEFAULT_LANGUAGE",
    "SUPPORTED_LANGUAGES",
    "get_language",
    "set_language",
    "t",
]
