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

_ABBREVIATIONS = frozenset(
    "dr prof nr str hr fr ca bzw vgl ggf z.b u.a abs art med jur rer nat phil dipl ing univ habil".split())
_BOUNDARY = re.compile(r"(?<=[.!?])\s+(?=[A-ZÄÖÜ\"„(])|\n\s*\n")
_HONORIFIC = re.compile(r"\b(?:Herrn?|Frau|Hr\.|Fr\.|Dr\.|Prof\.)\s+[A-ZÄÖÜ]")
# only people say "ich"
_FIRST_PERSON = re.compile(r"\b(?:[Ii]ch|[Mm]ein|[Mm]eine[mnrs]?|[Mm]ir|[Mm]ich)\b")
# a third-person pronoun can be a pipe, a company or "they"; it counts only
# where the text names a person somewhere. "Sie"/"Ihr" with a capital inside a
# sentence is the letter's formal you; at the start, "Sie hat" is she
_THIRD_PERSON = re.compile(r"\b(?:[Ee]r|[Ii]hm|[Ii]hn|[Ss]eine[mnrs]?|sie|ihr|ihre[mnrs]?)\b")
_SHE = re.compile(
    r"^\W*Sie\s+(?:hat|ist|war|wird|kann|muss|soll|will|darf|mag|"
    r"(?!nicht\b|jetzt\b|erst\b|selbst\b|oft\b|gut\b|bereits\b|bitte\b)[a-zäöüß]+t)\b")
# singular only: "die Mitarbeiter erhalten eine Schulung" is staff as a group
_SINGULAR = r"(?:[Dd]er|[Dd]em|[Dd]en|[Dd]es|[Ee]in|[Ee]inem|[Ee]inen|[Ee]ines|[Uu]nser(?:em|en)?|Ihr(?:em|en)?|[Dd]ieser|[Dd]iesem|[Dd]iesen)"
_PERSON_NOUN = re.compile(
    r"\b(?:Patientin|Mitarbeiterin|Arbeitnehmerin|Bewerberin|Mandantin|Versicherte|Kollegin|"
    r"Schülerin|Mieterin|Kundin|Klientin|Beschäftigte|Angestellte|Sohn|Tochter|Ehefrau|Ehemann|"
    r"Ehegatte|Mutter|Vater)\b|\b" + _SINGULAR + r"\s+(?:\w+e[nrms]?\s+)?"
    r"(?:Patienten?|Mitarbeiters?|Arbeitnehmers?|Bewerbers?|Mandanten?|Versicherten?|Kollegen?|"
    r"Schülers?|Mieters?|Kunden?|Klienten?|Beschäftigten?|Angestellten?|Kind(?:es)?)\b"
)


def sentences(text: str) -> List[Tuple[int, int]]:
    """(start, end) of each sentence in *text*."""
    spans, start = [], 0
    for m in _BOUNDARY.finditer(text):
        before = text[start:m.start()].rstrip()
        last = before.rsplit(None, 1)[-1].lower().split("-")[-1].rstrip(".") if before.split() else ""
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


def _anchor(text: str, span: Tuple[int, int], names: Sequence[Tuple[int, int]]) -> bool:
    s, e = span
    sentence = text[s:e]
    return bool(_HONORIFIC.search(sentence) or _FIRST_PERSON.search(sentence) or _PERSON_NOUN.search(sentence)
                or any(s <= ns < e for ns, _ne in names))


def refers_to_person(text: str, spans: Sequence[Tuple[int, int]], at: int,
                     names: Sequence[Tuple[int, int]] = ()) -> bool:
    """Whether the sentence holding *at*, or the one before it, is about a person.

    A name, an honorific, "ich" or a singular person noun counts in the
    sentence or the one before ("Herr Dahl fehlt. Ursache: Hepatitis."); a
    third-person pronoun counts in the sentence itself, and only when such an
    anchor stands somewhere in the text.
    """
    current = sentence_of(spans, at)
    index = list(spans).index(current) if current in spans else -1
    if _anchor(text, current, names) or (index > 0 and _anchor(text, spans[index - 1], names)):
        return True
    sentence = text[current[0]:current[1]]
    if not (_THIRD_PERSON.search(sentence) or _SHE.search(sentence)):
        return False
    return any(_anchor(text, span, names) for span in spans)
