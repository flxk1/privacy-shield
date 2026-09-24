"""Person names, found by evidence rather than by capitalisation.

THE MODULE MOVED. The rules now live one language per module under
`privacy_shield.name_layer`, because the reasoning that produced them is a
fact about ONE language and not about names: German capitalises every noun, so
capitalisation is not evidence there, while in English it is the candidate
generator. See `name_layer/shared.py` for the split that makes several
languages possible (evidence per language and additive, exclusions shared and
union), `name_layer/de.py` and `name_layer/en.py` for the two that are
measured, and `name_layer/detect.py` for how the language is decided.

The German rules in `name_layer/de.py` are this module's rules unchanged,
including probe A's withdrawal and the wider-claim rule. This module stays as
the callable surface, `find_names(text)`, and re-exports the German tables it
used to define, because they are cited by name in `docs/limits.md` and in the
tests. It is a shim, not a second implementation.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Union

from .name_layer import (
    Span,
    find_names as _find_names,
    find_names_by_language,
    find_names_by_probe as _find_names_by_probe,
    languages,
    register_recogniser,
    registry,
)
from .name_layer.de import (
    ADDRESSEE_MARKER,
    CLOSING,
    GIVEN_NAMES,
    NAME_LINE,
    ORGANISATIONAL,
    PERSON_COLUMN_HEADERS,
    POSTCODE_LINE,
    PROBES,
    SINGLE_WORD,
    STREET_LINE,
    TITLE_ANCHORED,
)

__all__ = [
    "ADDRESSEE_MARKER",
    "CLOSING",
    "GIVEN_NAMES",
    "NAME_LINE",
    "ORGANISATIONAL",
    "PERSON_COLUMN_HEADERS",
    "POSTCODE_LINE",
    "PROBES",
    "SINGLE_WORD",
    "STREET_LINE",
    "Span",
    "TITLE_ANCHORED",
    "find_names",
    "find_names_by_language",
    "find_names_by_probe",
    "languages",
    "register_recogniser",
    "registry",
]

Language = Optional[Union[str, Iterable[str]]]


def find_names(text: str, language: Language = None) -> List[Span]:
    """Every person name in *text* that the surrounding text evidences.

    `language` is the caller's declaration when it has one. Without it the
    document is offered to every ruleset whose markers appear, and to all of
    them when none do - see `name_layer/detect.py`.
    """
    return _find_names(text, language)


def find_names_by_probe(text: str, language: Language = None):
    """What each probe claims, for diagnosis and for the precision tests."""
    return _find_names_by_probe(text, language)
