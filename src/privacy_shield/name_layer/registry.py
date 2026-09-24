"""Which languages the name layer has rules for, and their shared exclusions.

The registry is the mechanism the twenty-five-language claim rests on: a
language is a `Ruleset` registered here, nothing imports another language, and
adding one cannot change what an existing one claims EXCEPT by contributing to
the exclusion union, which can only narrow. `docs/limits.md` reports covered
and uncovered positions per language, and `LANGUAGES` below is what that table
is allowed to list.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .shared import Exclusions, Ruleset

_RULESETS: Dict[str, Ruleset] = {}
_EXCLUSIONS: Optional[Exclusions] = None


def register(ruleset: Ruleset) -> None:
    global _EXCLUSIONS
    _RULESETS[ruleset.language] = ruleset
    _EXCLUSIONS = None


def ruleset(language: str) -> Optional[Ruleset]:
    return _RULESETS.get(language)


def languages() -> List[str]:
    return sorted(_RULESETS)


def rulesets() -> Dict[str, Ruleset]:
    return dict(_RULESETS)


def exclusions() -> Exclusions:
    """The union over every registered language.

    Union, not per-language, because a reason not to claim is language-safe
    while a reason to claim is not. See shared.py.

    """
    global _EXCLUSIONS
    if _EXCLUSIONS is None:
        merged = Exclusions()
        for entry in _RULESETS.values():
            merged = merged.merged_with(entry.exclusions)
        _EXCLUSIONS = merged
    return _EXCLUSIONS
