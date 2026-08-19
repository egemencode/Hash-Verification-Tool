"""
What the core decided to say, before anybody says it in a language.

The risk engine and the summary builder used to return Turkish prose. That
made the verdict — the sentence this whole tool exists to produce —
untranslatable, and it put presentation inside the layer that is supposed to
hold only decisions.

A :class:`Phrase` is the identity of a sentence plus the values that belong in
it. The core chooses which one is true; something above it chooses the words.
That is the split ``gui/trust_presenter.py`` was already built around, and it
is why the risk engine is a decision table rather than a score.

Deliberately not a translation mechanism. This module has no table, no
language and no lookup: it names sentences and carries their parameters, and
nothing more. The lookup lives in the presentation layer, where the choice of
language already lives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional


@dataclass(frozen=True)
class Phrase:
    """One sentence the core selected, not yet in any language."""

    key: str
    params: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """
        Serialised form, for a report that wants the decision as well as the
        wording. Kept separate from the rendered text: the words are what a
        person reads, the key is what another program can act on.
        """
        return {"key": self.key, "params": dict(self.params)}


def phrase(key: str, **params: Any) -> Phrase:
    """Shorthand so call sites read as sentences rather than constructions."""
    return Phrase(key=key, params=params)


def is_phrase(value: Any) -> bool:
    return isinstance(value, Phrase)


def key_of(value: Optional[Phrase]) -> str:
    """The key, or the empty string — for tests and logs, never for display."""
    return value.key if value is not None else ""
