"""The name layer, per language.

    find_names(text)              every language the document evidences
    find_names(text, "en")        one declared language
    find_names_by_language(text)  the same claims, attributed
    find_names_by_probe(text)     the same claims, attributed to a rule

One language is one module registering one `Ruleset` (see registry.py). The
rules inside a ruleset are that language's own; only the exclusion union and
the two structural probes are shared, and shared.py says why that split and
not another.

Shipped and measured: German (`de`), English (`en`). Everything else is
`unmeasured` in `docs/limits.md` and says so rather than being called
supported.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Union

from . import de as _de  # noqa: F401  (registers the German ruleset)
from . import detect, en as _en, recogniser, registry  # noqa: F401
from .recogniser import register_recogniser
from .shared import Exclusions, Ruleset, Span

__all__ = [
    "Exclusions",
    "Ruleset",
    "Span",
    "detect",
    "find_names",
    "find_names_by_language",
    "find_names_by_probe",
    "languages",
    "recogniser",
    "register_recogniser",
    "registry",
]

Language = Optional[Union[str, Iterable[str]]]


def languages() -> List[str]:
    """Languages with rules in this package."""
    return registry.languages()


def find_names(text: str, language: Language = None) -> List[Span]:
    """Every person name in *text* that some language's evidence supports.

    Claim order is the resolved language order (detect.py), so the language a
    document is mostly in wins any overlap, and a first claim wins over a
    later one.
    """
    spans: List[Span] = []
    from .shared import claim

    for code in detect.resolve(text, language):
        ruleset = registry.ruleset(code)
        if ruleset is None:
            continue
        for start, end, _value in ruleset.find(text):
            claim(spans, start, end, text)
        for start, end, _value in recogniser.recognise(text, code):
            claim(spans, start, end, text)
    spans.sort(key=lambda span: span[0])
    return spans


def find_names_by_language(text: str, language: Language = None) -> Dict[str, List[Span]]:
    """What each resolved language claims, unmerged - for diagnosis."""
    out: Dict[str, List[Span]] = {}
    for code in detect.resolve(text, language):
        ruleset = registry.ruleset(code)
        if ruleset is not None:
            out[code] = ruleset.find(text)
    return out


def find_names_by_probe(text: str, language: Language = None) -> Dict[str, List[Span]]:
    """What each probe claims, merged across the resolved languages.

    Probe names are shared where the probe is shared (`label`, `table`), so a
    diagnosis reads the same in every language.
    """
    out: Dict[str, List[Span]] = {}
    for code in detect.resolve(text, language):
        ruleset = registry.ruleset(code)
        if ruleset is None:
            continue
        for name, probe in ruleset.probes.items():
            out.setdefault(name, []).extend(probe(text))
    return out
