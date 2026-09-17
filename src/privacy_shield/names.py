"""Person names, found by evidence rather than by capitalisation.

German capitalises every noun. "Sehr geehrte Damen und Herren", "bezugnehmend
auf Ihr Schreiben vom", "Interne Mitteilung", "Leistungszeitraum Maerz" - all
of it is capitalised, and a rule that takes capitalised sequences takes the
document. Measured on twenty ordinary German business letters, invoices and
memos containing no personal data at all, the two capitalisation patterns this
module replaces claimed 75% of every character and 121 separate spans; on one
memo, 90%. The overlay is what the cloud model receives, so that is not
over-redaction, it is deletion.

Capitalisation is the `\\b` of this layer: a property the identifier happens to
have, which almost everything else has too.

So a name is claimed here only where something in the text says a person is
being named:

  TITLE      an address form or academic title in front of it - Herr, Frau,
             Herrn, Dr., Prof., Dipl.-Ing. Titles are not claimed themselves,
             only the name after them.
  SIGNATURE  the first name-shaped line after a closing formula. That line is
             the signer by convention; the lines after it are the role and the
             department, and are not claimed.
  ADDRESS    a name-shaped line that sits where an addressee sits - directly
             above a street or a postal code and city, or directly below a
             bare "An".
  GIVEN      a known given name followed by a surname. This is the only rule
             that fires in running prose, and it is deliberately the narrowest:
             it needs a name from the list to start.

What this cannot do is find a bare surname in running prose with nothing around
it - "die Pruefung durch Weber ergab" is invisible here. That is the recall
this buys the precision with, and it is measured in
tests/test_name_layer_precision.py rather than asserted.
"""

from __future__ import annotations

import re
from typing import List, Tuple

Span = Tuple[int, int, str]

#: A capitalised word, including hyphenated surnames (Mueller-Lang).
_WORD = r"[A-ZÄÖÜ][a-zäöüß]+(?:-[A-ZÄÖÜ][a-zäöüß]+)?"

#: Address forms and titles. Not claimed - they are the evidence, not the data.
_TITLE = r"(?:Herrn|Herr|Frau|Fr\.|Hr\.|Dr\.|Prof\.|Dipl\.-[A-Za-zÄÖÜäöü]+\.?|Mag\.|Ing\.)"

TITLE_ANCHORED = re.compile(
    rf"\b(?:{_TITLE}[ \t]+)+({_WORD}(?:[ \t]+{_WORD}){{0,2}})"
)

#: A line that is nothing but a name: one to three capitalised words, with any
#: titles in front.
NAME_LINE = re.compile(
    rf"^[ \t]*(?:{_TITLE}[ \t]+)*({_WORD}(?:[ \t]+{_WORD}){{0,2}})[ \t]*$"
)

CLOSING = re.compile(
    r"^[ \t]*(?:Mit[ \t]+(?:freundlichen|besten|herzlichen)[ \t]+"
    r"Gr(?:ü|ue)(?:ß|ss)en|(?:Viele|Beste|Freundliche|Herzliche)[ \t]+"
    r"Gr(?:ü|ue)(?:ß|ss)e|(?:Best|Kind|Warm)[ \t]+regards|"
    r"Yours[ \t]+(?:sincerely|faithfully|truly))[ \t]*,?[ \t]*$",
    re.IGNORECASE,
)

STREET_LINE = re.compile(
    r"^[ \t]*[A-ZÄÖÜ][a-zäöüß]+(?:stra(?:ß|ss)e|str\.|weg|platz|allee|gasse|"
    r"ring|damm|ufer)[ \t]+\d+[a-z]?[ \t]*$",
    re.IGNORECASE,
)

POSTCODE_LINE = re.compile(r"^[ \t]*\d{5}[ \t]+[A-ZÄÖÜ][a-zäöüß]+", re.UNICODE)

ADDRESSEE_MARKER = re.compile(r"^[ \t]*(?:An|An:|z\.\s?H\.|z\.\s?Hd\.)[ \t]*$")

#: Common German and international given names. A data table, not a heuristic:
#: the rule is "a known given name followed by a surname", and this is the
#: list of known given names. Short and conservative on purpose - every entry
#: is a licence for the word after it to be claimed.
GIVEN_NAMES = frozenset("""
Alexander Andrea Andreas Angelika Anna Anne Annette Antje Barbara Bernd Birgit
Brigitte Christian Christiane Christina Christine Christoph Claudia Daniel
Daniela David Dieter Dirk Dorothea Elke Erika Eva Felix Frank Franziska Gabriele
Georg Gerd Gisela Hannah Hans Heike Heinz Helga Helmut Henning Ines Ingrid Jan
Jens Joachim Johanna Johannes Jonas Jörg Julia Jutta Karin Karl Katharina
Katrin Kerstin Klaus Kristina Lara Laura Leon Lena Lisa Lukas Manfred Manuela
Marc Marcel Maria Marie Mario Marion Markus Martin Martina Mathias Matthias
Max Michael Michaela Monika Nadine Nicole Niklas Norbert Olaf Oliver Patrick
Paul Peter Petra Philipp Rainer Ralf Regina Renate Robert Roland Rolf Ruth
Sabine Sandra Sarah Sebastian Silke Simon Sofia Sophie Stefan Stefanie Steffen
Stephan Susanne Sven Tanja Thomas Tim Tobias Ulrich Ulrike Ursula Ute Uwe
Vanessa Verena Volker Walter Werner Wolfgang Yvonne
""".split())

#: A single capitalised word, located so the GIVEN rule can anchor on the
#: given name itself. Matching "given name plus surname" as one greedy
#: expression does not work: in "Aussendienstmitarbeiter Thomas Fischer" the
#: match starts at the job title, its first word is not a given name, and the
#: real name is consumed and never offered.
SINGLE_WORD = re.compile(rf"\b{_WORD}\b")


#: Words that make a line a ROLE or a DEPARTMENT rather than a person. The
#: signature rule claimed "Abteilung Vertrieb", which its own docstring said it
#: would not: titles, roles and departments are evidence, not data.
ORGANISATIONAL = frozenset("""
Abteilung Bereich Referat Sachgebiet Team Gruppe Stabsstelle Sekretariat
Geschaeftsfuehrung Geschäftsführung Vorstand Buchhaltung Einkauf Vertrieb
Verkauf Marketing Personal Personalabteilung Rechnungswesen Controlling
Logistik Lager Versand Produktion Technik Entwicklung Konstruktion Qualitaet
Qualität Service Kundendienst Support Innendienst Aussendienst Außendienst
Recht Rechtsabteilung Datenschutz Compliance Revision Leitung Leiter Leiterin
Direktion Niederlassung Zentrale Filiale Werk Standort Poststelle Empfang
Verwaltung Organisation Projektbuero Projektbüro Veranstaltungsbuero
Veranstaltungsbüro Beschaffung Disposition Fuhrpark Werkstatt
""".split())


def _is_organisational(candidate: str) -> bool:
    return any(word in ORGANISATIONAL for word in candidate.split())


def _line_spans(text: str) -> List[Tuple[int, int, str]]:
    spans: List[Tuple[int, int, str]] = []
    start = 0
    for line in text.splitlines(keepends=True):
        stripped = line.rstrip("\r\n")
        spans.append((start, start + len(stripped), stripped))
        start += len(line)
    return spans


def _claim(spans: List[Span], start: int, end: int, text: str) -> None:
    for existing_start, existing_end, _value in spans:
        if start < existing_end and existing_start < end:
            return
    spans.append((start, end, text[start:end]))


def find_names(text: str) -> List[Span]:
    """Every person name in *text* that the surrounding text evidences."""
    spans: List[Span] = []

    # TITLE - the strongest signal, so it runs first and wins any overlap.
    for match in TITLE_ANCHORED.finditer(text):
        _claim(spans, match.start(1), match.end(1), text)

    lines = _line_spans(text)

    # SIGNATURE - the first name-shaped line after a closing formula, and only
    # the first: the lines below it are the role and the department.
    for index, (_start, _end, line) in enumerate(lines):
        if not CLOSING.match(line):
            continue
        for following in range(index + 1, min(index + 5, len(lines))):
            line_start, _line_end, candidate = lines[following]
            if not candidate.strip():
                continue
            match = NAME_LINE.match(candidate)
            if (
                match
                and len(match.group(1).split()) >= 2
                and not _is_organisational(match.group(1))
            ):
                _claim(
                    spans,
                    line_start + match.start(1),
                    line_start + match.end(1),
                    text,
                )
            break

    # ADDRESS - a name-shaped line where an addressee sits.
    for index, (line_start, _line_end, line) in enumerate(lines):
        match = NAME_LINE.match(line)
        if not match:
            continue
        below = lines[index + 1][2] if index + 1 < len(lines) else ""
        above = lines[index - 1][2] if index > 0 else ""
        if (
            STREET_LINE.match(below)
            or POSTCODE_LINE.match(below)
            or ADDRESSEE_MARKER.match(above)
        ):
            _claim(
                spans, line_start + match.start(1), line_start + match.end(1), text
            )

    # GIVEN - a known given name followed by a surname. The only rule that
    # fires in running prose, and it needs a name from the list to start.
    words = list(SINGLE_WORD.finditer(text))
    for index, word in enumerate(words):
        if word.group() not in GIVEN_NAMES:
            continue
        # A SURNAME IS REQUIRED. The first version claimed the given name
        # whether or not one followed, so the shipped rule was "a known given
        # name, optionally followed by capitalised words" - not what its own
        # docstring said. "Max." for maximal and "Jan" for Januar are in every
        # German offer, invoice and specification, and both came back as
        # [NAME]. A bare given name on its own is not claimed at all.
        end = None
        following = index + 1
        while following < len(words) and following - index <= 2:
            gap = text[(end if end is not None else word.end()):words[following].start()]
            if gap not in (" ", "\t"):
                break
            end = words[following].end()
            following += 1
        if end is None:
            continue
        _claim(spans, word.start(), end, text)

    # Probes A and D, last so the evidence-stronger rules above win any
    # overlap. See PROBES below.
    for probe in PROBES.values():
        for start, end, _value in probe(text):
            _claim(spans, start, end, text)

    spans.sort(key=lambda span: span[0])
    return spans

# ---------------------------------------------------------------------------
# Probes A and D. Separable by construction: each is one function in PROBES
# below, and find_names_by_probe() reports which one claimed what, so a
# regression names its cause and either can be dropped without touching the
# other.
# ---------------------------------------------------------------------------

#: Labels whose value IS a person, always. "Sachbearbeiter" means a case
#: worker; there is no non-person answer to it.
PERSON_ROLE_LABELS = frozenset("""
Sachbearbeiter Sachbearbeiterin Bearbeiter Bearbeiterin Ansprechpartner
Ansprechpartnerin Berater Beraterin Betreuer Betreuerin Pruefer Prueferin
Prüfer Prüferin Verfasser Verfasserin Unterzeichner Unterzeichnerin
Antragsteller Antragstellerin Zeichnungsberechtigt Zeichnungsberechtigte
Vorgesetzter Vorgesetzte Erfasser Erfasserin
""".split())

#: Labels whose value is USUALLY a person but may be a list or a department.
#: These carry less evidence, so a value after them is held to the same test.
CONTACT_LABELS = frozenset("""
Von An CC Cc Kontakt Teilnehmer Anwesend Verteiler
""".split())

#: Multi-word labels, matched before the single words above.
PHRASE_LABELS = ("Rueckfragen an", "Rückfragen an", "Im Auftrag von", "i. A.")

#: Legal forms. A value carrying one of these is an organisation, whatever its
#: shape - and "Nordstern GmbH" has exactly the shape the rule wants.
LEGAL_FORMS = frozenset("""
GmbH mbH AG KG OHG GbR UG SE KGaA eG e.V. eV gGmbH Co Ltd Inc SA SARL BV NV
Stiftung Verein Genossenschaft
""".split())

#: Collective and placeholder words that stand where a person's name would.
#: BOUNDED and position-specific - it applies only to a value after a label,
#: and it is about thirty words. It is NOT the stoplist inversion, which is a
#: general frequency list over all prose and is a separate piece of work.
NON_PERSON_VALUES = frozenset("""
Alle Mitarbeiter Mitarbeiterinnen Beschaeftigte Beschäftigte Kollegen Kolleginnen
Verteiler Hotline Noch Unbesetzt Automatische Zuweisung Abteilungsleiter
Abteilungsleiterin Offen Keine Keiner Niemand Intern Extern Unbekannt
Ausstehend Entfaellt Entfällt Nicht Vakant Nachtrag Siehe Diverse Verschiedene
Interessenten Kunden Lieferanten Gaeste Gäste Anwesende Personalrat Betriebsrat
""".split())

_LABEL_LINE = re.compile(
    rf"^[ \t]*(?P<label>[A-ZÄÖÜ][A-Za-zÄÖÜäöüß. ]{{1,24}}?)[ \t]*:[ \t]*(?P<value>.+?)[ \t]*$",
    re.MULTILINE,
)

_VALUE_NAME = re.compile(rf"^(?:{_TITLE}[ \t]+)*({_WORD}(?:[ \t]+{_WORD}){{0,2}})$")


def _label_is_a_person_role(label: str) -> bool:
    cleaned = label.strip().rstrip(".")
    if cleaned in PERSON_ROLE_LABELS or cleaned in CONTACT_LABELS:
        return True
    return any(cleaned.lower() == phrase.lower() for phrase in PHRASE_LABELS)


def value_is_a_person(value: str) -> bool:
    """THE RULE, in one sentence.

    A value after a person-role label is a name only if it is one to three
    capitalised words, carries no legal-form suffix, and contains no
    organisational or collective word.

    A label and a colon are evidence that a VALUE follows, not that the value
    is a person: measured against twenty-two documents written to break it,
    the unnarrowed probe claimed "Zentrale Verwaltung", "Alle Mitarbeiter",
    "Verteiler Technik", "Zentrale Hotline", "Noch" and "Unbesetzt".
    """
    match = _VALUE_NAME.match(value.strip())
    if not match:
        return False
    words = match.group(1).split()
    if any(word in LEGAL_FORMS for word in words):
        return False
    if any(word in ORGANISATIONAL for word in words):
        return False
    if any(word in NON_PERSON_VALUES for word in words):
        return False
    return True


def _label_names(text: str) -> List[Span]:
    """Probe A - a label that names a person's role, then a colon."""
    spans: List[Span] = []
    for match in _LABEL_LINE.finditer(text):
        if not _label_is_a_person_role(match.group("label")):
            continue
        value_start = match.start("value")
        # A contact label may carry a comma-separated list.
        offset = 0
        for part in match.group("value").split(","):
            stripped = part.strip()
            if stripped and value_is_a_person(stripped):
                begin = value_start + offset + part.index(stripped)
                spans.append((begin, begin + len(stripped), stripped))
            offset += len(part) + 1
    return spans


_TABLE_ROW = re.compile(r"^[ \t]*\|(?P<body>.+)\|[ \t]*$", re.MULTILINE)


def _table_names(text: str) -> List[Span]:
    """Probe D - a table cell whose COLUMN is a person column.

    The header is what carries the evidence. "| Osterloh |" and
    "| Dichtungsring |" are the same shape; the difference is that one sits
    under "Bearbeiter" and the other under "Produkt".
    """
    spans: List[Span] = []
    person_columns: set = set()
    seen_header = False
    for row in _TABLE_ROW.finditer(text):
        body = row.group("body")
        cells = body.split("|")
        starts = []
        position = row.start("body")
        for cell in cells:
            starts.append(position)
            position += len(cell) + 1

        if not seen_header:
            for index, cell in enumerate(cells):
                if _label_is_a_person_role(cell.strip()):
                    person_columns.add(index)
            seen_header = True
            continue

        for index in person_columns:
            if index >= len(cells):
                continue
            cell = cells[index]
            stripped = cell.strip()
            if stripped and value_is_a_person(stripped):
                begin = starts[index] + cell.index(stripped)
                spans.append((begin, begin + len(stripped), stripped))
    return spans


#: Named and separable, so a regression reports which probe caused it and the
#: owner can drop one without touching the other.
PROBES = {
    "label": _label_names,
    "table": _table_names,
}


def find_names_by_probe(text: str) -> "dict[str, List[Span]]":
    """What each probe claims, for diagnosis and for the precision tests."""
    return {name: probe(text) for name, probe in PROBES.items()}

