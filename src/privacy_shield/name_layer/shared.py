"""The language-independent half of the name layer.

Two things live here, and nothing else: the span bookkeeping and the exclusion
union. The table probe is NOT here even though it is the one rule whose shape
transfers across languages - German's is main's repaired implementation and
English's is modelled on it, and a shared parameterised third copy bought
nothing but a place for the two to drift apart.

WHY THE EXCLUSIONS ARE SHARED AND THE EVIDENCE IS NOT. A language's evidence -
its address forms, its closing formulae, its person-role labels - licenses a
claim, and it is the one thing that cannot be transferred: `Herrn` means a
person is next in German and nothing at all in Finnish. The exclusions are the
opposite. `GmbH`, `Ltd`, `Abteilung`, `Accounts Payable`, `Monday` and
`Dezember` are reasons NOT to claim, and a reason not to claim is safe in every
language: adding one can only reduce what the layer takes, never widen it.

So evidence is per-language and additive across the languages a document is
in, and exclusions are the union over every REGISTERED language regardless of
what the document is in. That is what makes a mixed-language document - the
normal case in EU correspondence, not the exception - behave: a German letter
with an English closing gets both sets of evidence and both sets of
exclusions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, List, Tuple

Span = Tuple[int, int, str]
Probe = Callable[[str], List[Span]]


@dataclass(frozen=True)
class Exclusions:
    """Reasons a capitalised sequence is not a person, by class.

    Kept as named classes rather than one bag so that a false negative can be
    traced to the class that caused it, and so a language can add to one class
    without touching the others.

    TWO MECHANISMS WERE HERE AND ARE GONE, because with the fail-open label
    probe withdrawn they bought nothing measurable. A 410-entry ISO 20275
    legal-form table (`Oy`, `Kft`, `OU`, `SIA`) and a six-character stem match
    (`Automatische` refusing `Automatischer`) were built to close the holes
    that sank probe A - and ablated against 69 clean English and 42 clean
    German documents they changed the false-positive count by ZERO in each
    direction, because the position that needed them no longer ships. The
    exposure was a property of the POSITION, not of the length of the list.
    Recorded in tests/test_name_layer_enumeration_limit.py so that restoring
    the label probe restores them with it.
    """

    legal_forms: FrozenSet[str] = frozenset()
    organisational: FrozenSet[str] = frozenset()
    non_person_values: FrozenSet[str] = frozenset()
    temporal: FrozenSet[str] = frozenset()

    def blocks(self, words) -> bool:
        return any(
            word in self.legal_forms
            or word in self.organisational
            or word in self.non_person_values
            or word in self.temporal
            for word in words
        )

    def merged_with(self, other: "Exclusions") -> "Exclusions":
        return Exclusions(
            legal_forms=self.legal_forms | other.legal_forms,
            organisational=self.organisational | other.organisational,
            non_person_values=self.non_person_values | other.non_person_values,
            temporal=self.temporal | other.temporal,
        )


@dataclass(frozen=True)
class Ruleset:
    """One language's name layer.

    `find` is the language's own composition of its own rules, not a template
    filled in: German takes names where a title, a signature, an addressee
    position or a known given name says a person is named, and English takes
    them where capitalisation plus a frame says so. Forcing both through one
    parameterised rule is what produces a design that is worse than the rules
    it replaced in the language that has measurements.
    """

    language: str
    find: Callable[[str], List[Span]]
    probes: Dict[str, Probe]
    exclusions: Exclusions
    #: Lowercased closed-class tokens that evidence this language. Used only
    #: to decide which rulesets a document is offered to (see detect.py).
    markers: FrozenSet[str] = frozenset()
    #: Measured but NOT shipped, with the cost recorded in the test file.
    candidate_probes: Dict[str, Probe] = field(default_factory=dict)


def line_spans(text: str) -> List[Tuple[int, int, str]]:
    spans: List[Tuple[int, int, str]] = []
    start = 0
    for line in text.splitlines(keepends=True):
        stripped = line.rstrip("\r\n")
        spans.append((start, start + len(stripped), stripped))
        start += len(line)
    return spans


def claim(spans: List[Span], start: int, end: int, text: str) -> None:
    """Add a claim, preferring the WIDER of two overlapping ones.

    Main's rule, adopted here for the dispatcher and for English. It used to
    be all-or-nothing: any overlap and the new claim was dropped. So when the
    title rule claimed the given names of a four-part name, the wider claim
    that would have included the surname was refused and the surname egressed.
    A narrower claim is now replaced rather than defended.
    """
    for index, (existing_start, existing_end, _value) in enumerate(spans):
        if start < existing_end and existing_start < end:
            if start <= existing_start and end >= existing_end:
                spans[index] = (start, end, text[start:end])
            return
    spans.append((start, end, text[start:end]))
