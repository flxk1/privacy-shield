"""Documents that break the exclusion union by being outside its enumeration.

THE POINT OF THIS FILE. The name layer decides "this value is not a person"
from word lists - legal forms, organisational words, collective placeholders,
months. A word list is an ENUMERATION, and two things are always outside it:

  1. A legal form from a member state nobody wrote down. A 37-word hand list
     holds `Ltd`, `SARL`, `BV` and `NV` and not `Oy`, `Kft`, `OÜ`, `SIA`,
     `UAB`, `Zrt`, `ApS` or `d.o.o.` - so `An: Nordica Oy` is a person.
  2. An inflected form of a word that IS on the list. `Automatische` is on it
     and `Automatischer Rechnungslauf` walks past. German inflects; Finnish,
     Hungarian, Polish and the Baltic languages inflect far more.

Neither is a corner. Both are the mechanism failing in exactly the direction
that a list can never fix by growing, which is why they are a corpus and not a
paragraph: the numbers they produce are in
tests/test_name_layer_enumeration_limit.py and in `docs/limits.md`, and they
are the argument for replacing the hand list with ISO 20275 rather than for
adding eight more words.

Every company name here is invented. No real entity's data is in this file.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# One member state's legal form per line, after a label whose value the layer
# treats as a person. None of these is personal data.
# ---------------------------------------------------------------------------

EU_LEGAL_FORM_VALUES = [
    ("fi", "An: Nordica Oy\n"),
    ("fi", "Contact: Pohjola Oyj\n"),
    ("hu", "CC: Mediatech Kft\n"),
    ("hu", "From: Budapest Zrt\n"),
    ("ee", "Attn: Tallinn OÜ\n"),
    ("lv", "From: Baltic SIA\n"),
    ("lt", "Prepared by: Vilnius UAB\n"),
    ("dk", "To: Aarhus ApS\n"),
    ("se", "Contact: Stockholm AB\n"),
    ("cz", "Approved by: Praha a.s.\n"),
    ("sk", "Reviewed by: Bratislava s.r.o.\n"),
    ("si", "Handler: Zagreb d.o.o.\n"),
    ("it", "Signed by: Milano SpA\n"),
    ("pt", "From: Lisboa Lda\n"),
    ("bg", "Contact: Sofia EOOD\n"),
    ("pl", "An: Warszawa Sp. z o.o.\n"),
    ("ro", "To: Bucuresti SRL\n"),
    ("gr", "Contact: Athina AE\n"),
    ("es", "Approved by: Madrid SL\n"),
    ("fr", "Signed by: Lyon SAS\n"),
    ("be", "From: Brussel BVBA\n"),
    ("nl", "Attn: Utrecht VOF\n"),
    ("ie", "Contact: Dublin Teoranta\n"),
    ("mt", "To: Valletta Kumpanija\n"),
    ("hr", "From: Split d.d.\n"),
    ("at", "Kontakt: Wien OG\n"),
    ("lu", "Contact: Luxembourg SCS\n"),
]

# ---------------------------------------------------------------------------
# Inflected and derived forms of words the exclusion union already holds.
# ---------------------------------------------------------------------------

INFLECTED_NON_PERSON_VALUES = [
    ("de", "Bearbeiter: Automatischer Rechnungslauf\n", "Automatische"),
    ("de", "Ansprechpartner: Zentrales Sekretariat\n", "Zentrale"),
    ("de", "Sachbearbeiter: Vakante Stelle\n", "Vakant"),
    ("de", "An: Verwaltungsgebaeude Nord\n", "Verwaltung"),
    ("de", "Kontakt: Technische Leitstelle\n", "Technik"),
    ("de", "Teilnehmer: Diverse Interessenten\n", "Diverse"),
    ("en", "Caseworker: Vacancies Open\n", "Vacant"),
    ("en", "Handler: Automated Routing\n", "Automatic"),
    ("en", "Contact: Accountancy Payables\n", "Payable"),
    ("en", "Attn: Dispatching Office\n", "Dispatch"),
    ("en", "Reviewed by: Auditors Panel\n", "Audit"),
    ("en", "From: Administrative Services\n", "Administration"),
]

CLEAN_ENUMERATION = [text for _code, text in EU_LEGAL_FORM_VALUES] + [
    text for _code, text, _root in INFLECTED_NON_PERSON_VALUES
]


# ---------------------------------------------------------------------------
# A measurement corpus, not a shipped list. Every exclusion mechanism can
# refuse a real name by accident - the stem match refuses anything beginning
# with a six-character entry, and the ISO 20275 table holds two-letter
# abbreviations that are also given names - so the cost has to be counted
# against names rather than argued about.
#
# Roughly the most common surnames of each member state, written out so that
# the number in tests/test_name_layer_enumeration_limit.py is checkable.
# ---------------------------------------------------------------------------

COMMON_EU_SURNAMES = sorted(set("""
Mueller Schmidt Schneider Fischer Weber Meyer Wagner Becker Schulz Hoffmann
Schaefer Koch Bauer Richter Klein Wolf Schroeder Neumann Schwarz Zimmermann
Braun Krueger Hofmann Hartmann Lange Schmitt Werner Schmitz Krause Meier
Lehmann Schmid Schulze Maier Koehler Herrmann Koenig Walter Mayer Huber Kaiser
Fuchs Peters Lang Scholz Moeller Weiss Jung Hahn Schubert Vogel Friedrich Keller
Guenther Frank Berger Winkler Roth Beck Lorenz Baumann Franke Albrecht Schuster
Simon Ludwig Boehm Winter Kraus Martin Schumacher Kraemer Vogt Stein Jaeger
Otto Sommer Gross Seidel Heinrich Brandt Haas Schreiber Graf Dietrich Ziegler
Kuhn Kuehn Pohl Engel Horn Busch Bergmann Thomas Voigt Sauer Arnold Wolff Pfeiffer
Smith Jones Taylor Brown Wilson Evans Johnson Roberts Walker Wright
Robinson Thompson White Hughes Edwards Green Lewis Wood Harris Jackson
Clarke Clark Turner Hill Scott Cooper Morris Ward Moore King Watson Baker Harrison
Morgan Patel Young Allen Mitchell James Anderson Phillips Lee Bell Parker Davies
Nowak Kowalski Wisniewski Dabrowski Lewandowski Wojcik Kaminski Kowalczyk
Zielinski Szymanski Wozniak Kozlowski Jankowski Mazur Kwiatkowski Krawczyk
Virtanen Korhonen Makinen Nieminen Hamalainen Heikkinen Laine Koskinen
Nagy Kovacs Toth Szabo Horvath Varga Kiss Molnar Nemeth Farkas
Rossi Russo Ferrari Esposito Bianchi Romano Colombo Ricci Marino Greco
Garcia Rodriguez Martinez Lopez Sanchez Perez Gomez Fernandez Diaz Moreno
Silva Santos Ferreira Pereira Oliveira Costa Rodrigues Martins Jesus Sousa
Jansen Vries Berg Dijk Bakker Visser Smit Meijer Boer Mulder
Andersson Johansson Karlsson Nilsson Eriksson Larsson Olsson Persson Svensson
Petrov Ivanov Dimitrov Georgiev Todorov Hristov Stoyanov Kolev Angelov
Popescu Ionescu Popa Radu Dumitru Stan Stoica Gheorghe Marin Tudor
Novak Svoboda Dvorak Cerny Prochazka Kucera Vesely Horak Nemec Pokorny
Berzins Kalnins Ozols Jansons Krumins Balodis Liepins Petersons
Kazlauskas Jankauskas Petrauskas Stankevicius Vasiliauskas Butkus
Tamm Saar Sepp Magi Kask Kukk Rebane Ilves Koppel
Murphy Kelly Sullivan Walsh Byrne Ryan Connor Neill Reilly Doyle McCarthy
Borg Camilleri Vella Farrugia Zammit Galea Micallef Attard Spiteri Azzopardi
Papadopoulos Georgiou Nikolaou Christodoulou Ioannou Konstantinou Vasileiou
""".split()))
