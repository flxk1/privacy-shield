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

#: Up to FIVE words after a title. Three was the cap, and
#: "Frau Anna Maria Luise Schmidt" then claimed "Anna Maria Luise" and left
#: the surname - the most identifying token of the five - in the overlay,
#: while pii_detected said True.
TITLE_ANCHORED = re.compile(
    rf"\b(?:{_TITLE}[ \t]+)+({_WORD}(?:[ \t]+{_WORD}){{0,4}})"
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
    """Add a claim, preferring the WIDER of two overlapping ones.

    This used to be all-or-nothing: any overlap and the new claim was dropped.
    So when the title rule claimed the given names of a four-part name, the
    wider claim that would have included the surname was refused and the
    surname egressed. A narrower claim is now replaced rather than defended.
    """
    for index, (existing_start, existing_end, _value) in enumerate(spans):
        if start < existing_end and existing_start < end:
            if start <= existing_start and end >= existing_end:
                spans[index] = (start, end, text[start:end])
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

#: Column headers that declare a column of people. "Sachbearbeiter" means a
#: case worker; a column under it holds people because the table says so.
#:
#: This enumeration FAILS CLOSED, which is why it is acceptable where probe A's
#: were not: a header word missing from this list means a column of names is
#: not claimed - a recall loss. A value word missing from probe A's lists meant
#: a false positive on a clean document. Same kind of list, opposite
#: consequence, because of the position it sits in.
PERSON_COLUMN_HEADERS = frozenset("""
Sachbearbeiter Sachbearbeiterin Bearbeiter Bearbeiterin Ansprechpartner
Ansprechpartnerin Berater Beraterin Betreuer Betreuerin Pruefer Prueferin
Prüfer Prüferin Verfasser Verfasserin Unterzeichner Unterzeichnerin
Antragsteller Antragstellerin Erfasser Erfasserin Zustaendig Zuständig
Zustaendige Zuständige Mitarbeitername Name Nachname Vorname Kunde Kundin
Teilnehmer Teilnehmerin Empfaenger Empfänger Absender Unterschrift
""".split())

_CELL_NAME = re.compile(
    rf"\A(?:{_TITLE}[ \t]+)*({_WORD}(?:[ \t]+{_WORD}){{0,3}})\Z"
)


def _is_a_person_column(header: str) -> bool:
    return header.strip().rstrip(".:") in PERSON_COLUMN_HEADERS


# PROBE A DOES NOT SHIP.
#
# It was approved on a measured zero, an independent corpus produced 18
# false-positive spans on 20 documents, and the owner had already made a
# shipping decision on that zero. This is the record of why it cannot be
# narrowed rather than widened.
#
# Both of its enumerations are short in the way every enumeration in this
# programme has been short. LEGAL_FORMS listed Ltd, SARL, BV and NV and missed
# Oy, Kft and Asa, so "An: Nordica Oy" was a person. NON_PERSON_VALUES held
# "Automatische" and German inflects, so "Von: Automatischer Rechnungslauf"
# walked past it; it held "Keine" and not "Ohne Zuordnung". Systems, queues,
# person-shaped places, streets, statuses and companies with no legal form at
# all are the rest.
#
# The lists are not the defect. The defect is that A's ONLY unique
# contribution is the undecidable case. Measured against the other rules:
# where the value is a full name with a known given name ("Von: Petra
# Ullrich"), GIVEN already claims it; where a title is present
# ("Sachbearbeiter: Herr Osterloh"), TITLE already claims it. What is left over
# - and the entire reason to want A - is the BARE SURNAME after a label:
# "Sachbearbeiter: Osterloh". That is structurally identical to
# "Sachbearbeiter: Unbesetzt", "An: Nordica Oy" and "Bearbeiter: Workflow
# Engine". A label and a colon are evidence that a value follows; nothing in
# the text says whether the value is a person, and no amount of narrowing
# invents that evidence.
#
# Deciding it needs a lexicon - which is the stoplist inversion, deferred by
# the owner to separate work. Until then this position is NOT covered, and
# that is recorded in docs/limits.md beside the others.
#
# The asymmetry that lets D ship while A does not: D enumerates LABELS in a
# table header, and a label missing from that list costs a missed name -
# recall, failing closed. A enumerated VALUES, and a value missing from those
# lists costs a false positive on a clean document - precision, failing open.
# The same kind of list has opposite consequences in the two positions.

_TABLE_ROW = re.compile(r"^[ \t]*\|(?P<body>.+)\|[ \t]*$", re.MULTILINE)


def _table_names(text: str) -> List[Span]:
    """Probe D - a table cell whose COLUMN is a person column.

    The header is what carries the evidence. "| Osterloh |" and
    "| Dichtungsring |" are the same shape; the difference is that one sits
    under "Bearbeiter" and the other under "Produkt".
    """
    spans: List[Span] = []
    # The header is tracked PER TABLE. It used to be a single flag over the
    # whole document, so a handler table followed by a parts table reused
    # column 0 as a person column and claimed every product in it - which is
    # verbatim the failure that got the unnarrowed probe rejected. And the
    # converse: with the tables the other way round the person column was
    # never learned and the name egressed untouched. The only difference
    # between leaking and destroying the document was the order of two tables.
    #
    # A table ends at the first line that is not a table row, and the next one
    # starts by learning its own header.
    rows = list(_TABLE_ROW.finditer(text))
    person_columns: set = set()
    previous_end = None
    for row in rows:
        gap = text[previous_end:row.start()] if previous_end is not None else None
        # EXACTLY one line terminator. A blank line between two tables strips
        # to the empty string, so "nothing but whitespace between the rows"
        # made two tables look like one and the second reused the first's
        # person column.
        contiguous = gap is not None and gap.count("\n") == 1 and not gap.strip()
        previous_end = row.end()

        body = row.group("body")
        cells = body.split("|")
        starts = []
        position = row.start("body")
        for cell in cells:
            starts.append(position)
            position += len(cell) + 1

        declared = {
            index for index, cell in enumerate(cells) if _is_a_person_column(cell)
        }
        # A row that names a person column IS a header, wherever it sits. Two
        # tables concatenated with no blank line between them are otherwise
        # one table with a stray row in the middle, and the second table's
        # names went out untouched.
        if not contiguous or declared:
            person_columns = declared
            continue

        for index in sorted(person_columns):
            if index >= len(cells):
                continue
            cell = cells[index]
            stripped = cell.strip()
            if not stripped:
                continue
            # SHAPE only. The header already declared this column to hold
            # people, so there is nothing left to decide about the value - and
            # judging it would need exactly the value vocabulary that sank
            # probe A. A status word sitting in a person column is redacted,
            # which is what the table says it is.
            match = _CELL_NAME.match(stripped)
            if not match:
                continue
            begin = starts[index] + cell.index(stripped) + match.start(1)
            spans.append((begin, begin + len(match.group(1)), match.group(1)))
    return spans


#: Named and separable, so a regression reports which probe caused it and the
#: owner can drop one without touching the other.
PROBES = {
    "table": _table_names,
}


def find_names_by_probe(text: str) -> "dict[str, List[Span]]":
    """What each probe claims, for diagnosis and for the precision tests."""
    return {name: probe(text) for name, probe in PROBES.items()}

