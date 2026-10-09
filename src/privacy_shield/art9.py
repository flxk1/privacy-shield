"""Special-category evidence tied to a person.

Art. 9 GDPR covers data concerning a natural person: "Diabetes ist eine
Volkskrankheit" names a disease and concerns nobody. A term from the ICD-10-GM
index, and a hit the optional model makes on its own, therefore count only in
a sentence that also refers to a person: a name the scanner finds, an
honorific, a third- or first-person pronoun, or a person noun (Patientin,
Mitarbeiter, Sohn).

A sentence ends at ., ! or ? before a capital, except after an abbreviation,
or at a blank line; a form block with no full stops is one sentence.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Sequence, Tuple

_ABBREVIATIONS = frozenset("dr prof nr str hr fr ca bzw vgl ggf z.b u.a abs art bzw.".split())
_BOUNDARY = re.compile(r"(?<=[.!?])\s+(?=[A-ZÄÖÜ\"„(])|\n\s*\n")
_HONORIFIC = re.compile(r"\b(?:Herrn?|Frau|Dr\.|Prof\.)\s+[A-ZÄÖÜ]")
# case-sensitive: "Sie" and "Ihr" are the formal you of a letter's reader
_PRONOUN = re.compile(
    r"\b(?:[Ee]r|[Ii]hm|[Ii]hn|[Ss]eine[mnrs]?|sie|ihr|ihre[mnrs]?|[Ii]ch|[Mm]ein|[Mm]eine[mnrs]?|[Mm]ir|[Mm]ich)\b")
# "Sie hat", "Sie leidet": the formal you takes plural verbs ("Sie haben",
# "Sie sind"), so a singular verb after "Sie" is the third person
_SHE = re.compile(r"\bSie\s+(?!sind\b)(?![a-zäöüß]+en\b)[a-zäöüß]+\b")
_PERSON_NOUN = re.compile(
    r"\b(?:Patient(?:in|en|innen)?|Mitarbeiter(?:in|innen|s)?|Arbeitnehmer(?:in|innen|s)?|"
    r"Beschäftigte[nr]?|Angestellte[nr]?|Bewerber(?:in|innen|s)?|Mandant(?:in|en|innen)?|"
    r"Versicherte[nr]?|Kind(?:es)?|Sohn(?:es)?|Tochter|Ehefrau|Ehemann|Ehegatte|Mutter|Vater|"
    r"Kollegin|Kollegen?|Schüler(?:in|innen)?|Mieter(?:in|innen|s)?|Kundin|Kunden?|Klient(?:in|en)?)\b"
)


def sentences(text: str) -> List[Tuple[int, int]]:
    """(start, end) of each sentence in *text*."""
    spans, start = [], 0
    for m in _BOUNDARY.finditer(text):
        before = text[start:m.start()].rstrip()
        last = before.rsplit(None, 1)[-1].lower().rstrip(".") if before.split() else ""
        if m.group(0).strip() == "" and "\n" not in m.group(0) and last in _ABBREVIATIONS:
            continue
        spans.append((start, m.start()))
        start = m.end()
    spans.append((start, len(text)))
    return [(s, e) for s, e in spans if text[s:e].strip()]


def sentence_of(spans: Sequence[Tuple[int, int]], at: int) -> Tuple[int, int]:
    for s, e in spans:
        if s <= at < e:
            return s, e
    return (0, 0)


def refers_to_person(text: str, span: Tuple[int, int], names: Iterable[Tuple[int, int]] = ()) -> bool:
    s, e = span
    sentence = text[s:e]
    if (_HONORIFIC.search(sentence) or _PRONOUN.search(sentence) or _SHE.search(sentence)
            or _PERSON_NOUN.search(sentence)):
        return True
    return any(s <= ns < e for ns, _ne in names)
