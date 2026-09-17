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
            if match and len(match.group(1).split()) >= 2:
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
        end = word.end()
        following = index + 1
        while following < len(words) and following - index <= 2:
            gap = text[end:words[following].start()]
            if gap not in (" ", "\t"):
                break
            end = words[following].end()
            following += 1
        _claim(spans, word.start(), end, text)

    spans.sort(key=lambda span: span[0])
    return spans
