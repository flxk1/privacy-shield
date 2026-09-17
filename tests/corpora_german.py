"""German business documents for measuring the name layer.

Two axes, and a development / held-out split on each.

The names in the NAMED corpora are marked inline with guillemets and stripped
at import, so a document and its ground truth cannot drift apart: there is no
second list of offsets to maintain.

The HELD_OUT halves exist so that precision and recall can be reported on
documents the rule was not shaped against. They are written first and not
looked at again while the rule is being designed.

Every name used is a documentation placeholder (Mustermann, Musterfrau) or an
ordinary German surname in the way a textbook uses one. No real person's data
is in this file.
"""

from __future__ import annotations

import re

_MARK = re.compile(r"«([^»]*)»")


def strip_marks(marked: str) -> tuple[str, list[tuple[int, int, str]]]:
    """Return the plain document and the ground-truth name spans."""
    spans: list[tuple[int, int, str]] = []
    out: list[str] = []
    position = 0
    for match in _MARK.finditer(marked):
        out.append(marked[position:match.start()])
        start = sum(len(part) for part in out)
        name = match.group(1)
        out.append(name)
        spans.append((start, start + len(name), name))
        position = match.end()
    out.append(marked[position:])
    return "".join(out), spans


# ---------------------------------------------------------------------------
# CLEAN: ordinary German business documents containing NO personal data.
# Every NAME finding on these is a false positive.
# ---------------------------------------------------------------------------

CLEAN_DEV = [
    "Sehr geehrte Damen und Herren,\n\nbezugnehmend auf Ihr Schreiben vom "
    "14.03.2026 teilen wir Ihnen mit, dass\ndie Lieferung fristgerecht erfolgt "
    "ist.\n\nMit freundlichen Gruessen",

    "Rechnung\n\nRechnungsnummer 2026-004871\nLeistungszeitraum Maerz 2026\n"
    "Zahlungsziel 30 Tage netto ohne Abzug\nGesamtbetrag 1.349,00 EUR",

    "Auftragsbestaetigung\n\nWir bestaetigen Ihren Auftrag ueber die Lieferung "
    "von Ersatzteilen.\nDer Versand erfolgt per Spedition.\nDie Allgemeinen "
    "Geschaeftsbedingungen gelten in der aktuellen Fassung.",

    "Interne Mitteilung\n\nBetreff: Umstellung der Ablage\n\nAb dem kommenden "
    "Quartal werden alle Vorgaenge digital erfasst.\nDie Papierablage entfaellt. "
    "Bitte beachten Sie die neue Ordnerstruktur.",

    "Protokoll der Bereichsbesprechung\n\nBeschlossen wurde die Anschaffung "
    "eines weiteren Messgeraets.\nDie Beschaffung erfolgt im laufenden "
    "Haushaltsjahr.\nNaechste Sitzung im Juni.",

    "Lieferschein\n\nPosition 10 Dichtungsring Menge 200\nPosition 20 "
    "Schraubensatz Menge 50\nDie Ware wurde vollstaendig geliefert.",

    "Datenschutzhinweis\n\nDie Verarbeitung erfolgt nach Art. 6 DSGVO. "
    "Betroffene Personen haben\nein Auskunftsrecht. Weitere Angaben enthaelt "
    "unsere Datenschutzerklaerung.",

    "Angebot\n\nWir unterbreiten Ihnen folgendes Angebot fuer die Wartung der "
    "Anlage.\nDie Preise verstehen sich zuzueglich der gesetzlichen "
    "Mehrwertsteuer.\nDas Angebot ist drei Monate gueltig.",

    "Mahnung\n\nTrotz mehrfacher Erinnerung ist der offene Betrag bisher nicht "
    "eingegangen.\nWir bitten um Ausgleich innerhalb von zehn Werktagen.\n"
    "Weitere Schritte behalten wir uns vor.",

    "Betriebsanweisung\n\nVor Beginn der Arbeiten ist die Anlage "
    "spannungsfrei zu schalten.\nDie Schutzausruestung ist zu tragen. "
    "Verstoesse werden dokumentiert.",

    "Qualitaetsbericht\n\nDie Pruefung ergab keine Abweichung von der "
    "Spezifikation.\nDie Messwerte liegen innerhalb der Toleranz.\nEine "
    "Nachpruefung ist nicht erforderlich.",

    "Terminankuendigung\n\nDie Jahresinventur findet am letzten Werktag des "
    "Monats statt.\nDas Lager bleibt an diesem Tag geschlossen.\nBitte planen "
    "Sie entsprechend.",
]

CLEAN_HELD_OUT = [
    "Wartungsvertrag\n\nDer Auftragnehmer verpflichtet sich zur regelmaessigen "
    "Wartung.\nDie Verguetung erfolgt quartalsweise.\nDer Vertrag verlaengert "
    "sich stillschweigend um ein Jahr.",

    "Reisekostenrichtlinie\n\nFahrten mit dem Dienstwagen sind im Fahrtenbuch "
    "zu erfassen.\nUebernachtungskosten werden gegen Beleg erstattet.\n"
    "Verpflegungsmehraufwand richtet sich nach den gesetzlichen Pauschalen.",

    "Sehr geehrte Damen und Herren,\n\nvielen Dank fuer Ihre Anfrage. Gern "
    "senden wir Ihnen die gewuenschten\nUnterlagen zu. Bei Rueckfragen stehen "
    "wir zur Verfuegung.\n\nMit freundlichen Gruessen",

    "Inventurliste\n\nLagerort Halle Zwei\nBestand laut System 4820 Stueck\n"
    "Bestand gezaehlt 4818 Stueck\nDifferenz zwei Stueck geklaert",

    "Aushang\n\nWegen einer Betriebsversammlung bleibt die Poststelle am "
    "Freitag\nab zwoelf Uhr geschlossen. Dringende Sendungen nimmt das "
    "Sekretariat entgegen.",

    "Pruefbericht\n\nGegenstand der Pruefung war die Einhaltung der "
    "Aufbewahrungsfristen.\nDie Stichprobe umfasste zwanzig Vorgaenge.\n"
    "Beanstandungen ergaben sich nicht.",

    "Bestellanforderung\n\nBenoetigt werden zwei Bildschirme und eine "
    "Dockingstation.\nDie Beschaffung ist im Budget des laufenden Jahres "
    "vorgesehen.\nEine Begruendung liegt bei.",

    "Kuendigung des Liefervertrags\n\nHiermit kuendigen wir den bestehenden "
    "Liefervertrag fristgerecht\nzum Ende des Kalenderjahres. Die "
    "Restmengen werden wie vereinbart abgenommen.",
]

# ---------------------------------------------------------------------------
# NAMED: the same kind of document, with names where names actually occur -
# salutation, signature block, address block, after a title, beside a contact.
# ---------------------------------------------------------------------------

NAMED_DEV_MARKED = [
    "Sehr geehrte Frau «Schneider»,\n\nbezugnehmend auf Ihr Schreiben teilen "
    "wir Ihnen mit, dass die\nLieferung erfolgt ist.\n\nMit freundlichen "
    "Gruessen\n«Erika Mustermann»\nVertrieb",

    "Sehr geehrter Herr Dr. «Baumann»,\n\nanbei die angeforderten Unterlagen.\n"
    "\nMit freundlichen Gruessen\n«Klaus Weber»",

    "Mustermann GmbH\n«Erika Musterfrau»\nMusterstrasse 12\n12345 Musterstadt",

    "Protokoll\n\nAnwesend: Herr «Weber», Frau «Klein», Herr Dr. «Baumann»\n"
    "Beschluss einstimmig angenommen.",

    "Bei Rueckfragen wenden Sie sich an «Anna Schmidt», Sachbearbeiterin,\n"
    "erreichbar unter anna.schmidt@example.com.",

    "Zeichnungsberechtigt ist Frau «Maria Hoffmann».\nDie Vollmacht gilt bis "
    "auf Widerruf.",

    "Sehr geehrte Damen und Herren,\n\nunser Aussendienstmitarbeiter "
    "«Thomas Fischer» wird Sie besuchen.\n\nMit freundlichen Gruessen\n"
    "«Sabine Richter»\nInnendienst",

    "An\n«Peter Lorenz»\nBeispielweg 42\n54321 Beispielstadt\n\nBetreff: "
    "Ihre Anfrage",

    "Die Bearbeitung uebernimmt Herr «Michael Becker».\nEr meldet sich in den "
    "naechsten Tagen bei Ihnen.",

    "Mit freundlichen Gruessen\n«Laura Wagner»\nLeiterin Einkauf\n"
    "Telefon 089 12345678",
]

NAMED_HELD_OUT_MARKED = [
    "Sehr geehrter Herr «Hartmann»,\n\nwir bestaetigen den Eingang Ihrer "
    "Bestellung.\n\nMit freundlichen Gruessen\n«Sophie Brandt»",

    "Teilnehmer der Besprechung waren Frau «Keller» und Herr «Lindner».\n"
    "Das Ergebnis wird schriftlich festgehalten.",

    "Beispiel AG\n«Martin Kuehn»\nTestplatz 7\n98765 Probestadt",

    "Ihre Ansprechpartnerin ist «Julia Neumann», Telefon 030 90212345.",

    "Sehr geehrte Frau Prof. «Vogel»,\n\nvielen Dank fuer Ihren Vortrag.\n\n"
    "Mit freundlichen Gruessen\n«Andreas Roth»\nVeranstaltungsbuero",

    "Die Pruefung wurde von Herrn «Stefan Braun» durchgefuehrt.\n"
    "Beanstandungen ergaben sich nicht.",

    "An\n«Christine Sommer»\nDemoallee 456\n11111 Musterhausen",

    "Mit freundlichen Gruessen\n«Frank Zimmermann»\nAbteilung Technik\n"
    "frank.zimmermann@example.com",
]


def _build(marked_documents):
    return [strip_marks(marked) for marked in marked_documents]


NAMED_DEV = _build(NAMED_DEV_MARKED)
NAMED_HELD_OUT = _build(NAMED_HELD_OUT_MARKED)
