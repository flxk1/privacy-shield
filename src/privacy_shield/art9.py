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
_HONORIFIC = re.compile(r"\b(?:Herrn?|Frau|Hr\.|Fr\.|Dr\.|Prof\.|Mr\.?|Mrs\.?|Ms\.?)\s+[A-ZÄÖÜ]")
# only people say "ich"
_FIRST_PERSON = re.compile(r"\b(?:[Ii]ch|[Mm]ein|[Mm]eine[mnrs]?|[Mm]ir|[Mm]ich|I|[Mm]y|[Mm]e)\b")
# a third-person pronoun can be a pipe, a company or "they"; it counts only
# where the text names a person somewhere. "Sie"/"Ihr" with a capital inside a
# sentence is the letter's formal you; at the start, "Sie hat" is she
_THIRD_PERSON = re.compile(
    r"\b(?:[Ee]r|[Ii]hm|[Ii]hn|[Ss]eine[mnrs]?|sie|ihr|ihre[mnrs]?|[Hh]e|[Hh]im|[Hh]is|[Ss]he|[Hh]er)\b")
_SHE = re.compile(
    r"^\W*Sie\s+(?:hat|ist|war|wird|kann|muss|soll|will|darf|mag|"
    r"(?!nicht\b|jetzt\b|erst\b|selbst\b|oft\b|gut\b|bereits\b|bitte\b)[a-zäöüß]+t)\b")
# singular only: "die Mitarbeiter erhalten eine Schulung" is staff as a group
# definite or possessive only: "ein Mitarbeiter" in a policy is anyone
_SINGULAR = r"(?:[Dd]er|[Dd]em|[Dd]en|[Dd]es|[Uu]nser(?:em|en)?|Ihr(?:em|en)?|[Dd]ieser|[Dd]iesem|[Dd]iesen)"
_PERSON_NOUN = re.compile(
    r"\b(?:Patientin|Mitarbeiterin|Arbeitnehmerin|Bewerberin|Mandantin|Versicherte|Kollegin|"
    r"Schülerin|Mieterin|Kundin|Klientin|Beschäftigte|Angestellte|Sohn|Tochter|Ehefrau|Ehemann|"
    r"Ehegatte|Mutter|Vater)\b|\b" + _SINGULAR + r"\s+(?:\w+e[nrms]?\s+)?"
    r"(?:Patienten?|Mitarbeiters?|Arbeitnehmers?|Bewerbers?|Mandanten?|Versicherten?|Kollegen?|"
    r"Schülers?|Mieters?|Kunden?|Klienten?|Beschäftigten?|Angestellten?|Kind(?:es)?)\b"
    # a form's field label, and the English record and staff nouns
    r"|\bPatient(?:in)?\s*:|\b[Pp]atient(?:'s)?\b(?=\s+[a-z])"
    r"|\b(?:[Tt]he|[Oo]ur|[Tt]his)\s+(?:employee|applicant|client|tenant|customer|child)\b"
)


_FOLLOW_UP_WORDS = 6


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


# a record's field ("Befund: HIV-positiv") or a diagnosis code ("F32.1") is
# about the record's subject even where the name stands elsewhere in the file
_RECORD_FIELD = re.compile(
    r"(?im)^[ \t]*(?:Diagnosen?|Befund|Therapie(?:plan)?|Medikation|Vorerkrankungen|Anamnese|Laborwerte?|"
    r"Krankheitsbild|Religion|Konfession|Religionszugehörigkeit|Sexuelle Orientierung|Vorstrafen?|"
    r"Diagnosis|Findings?|Treatment|Medication|Medical history|Lab results?|Religion|Criminal record)"
    # "Befund vom 12.03.:" - the field word, then at most a date or a short qualifier
    r"\b[^:\n]{0,24}:"
    # "Diagnose Morbus Crohn seit 2019." - the field word opening a line before a term
    r"|^[ \t]*(?:Diagnose|Diagnosis)[ \t]+[A-ZÄÖÜ]")
_ICD_CODE = re.compile(r"\b[A-TV-Z]\d{2}\.\d{1,2}\b|\([A-TV-Z]\d{2}(?:\.\d{1,2})?\)")


def _anchor(text: str, span: Tuple[int, int], names: Sequence[Tuple[int, int]]) -> bool:
    s, e = span
    sentence = text[s:e]
    return bool(_HONORIFIC.search(sentence) or _FIRST_PERSON.search(sentence) or _PERSON_NOUN.search(sentence)
                or _RECORD_FIELD.search(sentence) or _ICD_CODE.search(sentence)
                or any(s <= ns < e for ns, _ne in names))


# A document that names itself as a record about one person: every sentence in
# it is about that person, though clinical prose drops the subject
# ("Vorbekannt sind ein Typ-2-Diabetes und eine Hypertonie.")
# a person's name, not an article or quantifier and a noun ("Die
# Antragstellerin", "Alle Beschäftigten")
_NOT_A_NAME = r"(?!(?:Die|Der|Das|Den|Dem|Des|Ein|Eine|Einen|Einem|Alle|Jede|Jeder|Jedes|Kein|Keine|Unsere|Unser|Ihre|Ihr|Diese|Dieser|Sämtliche|Beide|Siehe)\b)"
_NAMED = (
    r"(?:(?:Herrn?|Frau|Hr\.|Fr\.)[ \t]+[A-ZÄÖÜ][a-zäöüß]+|"
    + _NOT_A_NAME + r"[A-ZÄÖÜ][a-zäöüß]+[ \t]+[A-ZÄÖÜ][a-zäöüß]+)"
)
_RECORD_ANCHOR = re.compile(
    # a label whose value is a person: not "Mitarbeiter:" left empty, "Patient:
    # siehe Anlage" or "Versicherte Person: die im Antrag genannte Person"
    r"(?m)^[ \t]*(?i:Patient(?:in)?|Versicherte(?:r)?|Versicherte[ \t]+Person|Betroffene(?:r)?|"
    r"Bewerber(?:in)?|Mitarbeiter(?:in)?|Arbeitnehmer(?:in)?)[ \t]*:[ \t]*" + _NAMED
    # a record word as the heading of a line: not "Arztbrief-Software", and not
    # "Überweisung", which is also a bank transfer
    + r"|^[ \t]*(?:Arztbrief|Entlass(?:ungs)?brief|Befundbericht|Überweisungsschein|Krankmeldung|"
    r"Arbeitsunfähigkeitsbescheinigung|AU-Bescheinigung|Ärztliches[ \t]+Attest|Attest|Anamnese|Epikrise|"
    r"Pflegebericht)[ \t]*(?::|$|[ \t]\d{1,2}\.\d{1,2}\.)"
)


def is_record(text: str) -> bool:
    return bool(_RECORD_ANCHOR.search(text))


def refers_to_person(text: str, spans: Sequence[Tuple[int, int]], at: int,
                     names: Sequence[Tuple[int, int]] = ()) -> bool:
    """Whether the sentence holding *at*, or the one before it, is about a person.

    A name, an honorific, "ich" or a singular person noun counts in the
    sentence, or in the one before when this one is a short follow-up
    ("Herr Dahl fehlt. Ursache: Hepatitis."); a
    third-person pronoun counts in the sentence itself, and only when such an
    anchor stands somewhere in the text.
    """
    if is_record(text):
        return True
    current = sentence_of(spans, at)
    index = list(spans).index(current) if current in spans else -1
    if _anchor(text, current, names):
        return True
    # the sentence before counts for a short follow-up ("Ursache: Hepatitis.",
    # "Grund ist eine Gehirnerschütterung."), not for a sentence of its own
    # ("Herr Kraus hat angerufen. Die Grippe geht um, bitte …")
    follow_up = len(text[current[0]:current[1]].split()) <= _FOLLOW_UP_WORDS
    if follow_up and index > 0 and _anchor(text, spans[index - 1], names):
        return True
    sentence = text[current[0]:current[1]]
    if not (_THIRD_PERSON.search(sentence) or _SHE.search(sentence)):
        return False
    return any(_anchor(text, span, names) for span in spans)
