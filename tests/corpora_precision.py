"""Business text with no personal data in it, shaped like the things the detectors look for.

Each entry is a sentence or short document a detector has misread at least
once, or one that sits next to such a shape: figures with units, greetings to
groups, labels with non-person values, codes and versions, decimal pairs,
policy pages that use health words. tests/test_precision_budget.py pins what
all detectors together claim here.
"""

PRECISION_DE = [
    # figures, units, counts
    "Umsatz 25000 euro netto, Gewicht 10000 kg, Lieferung von 12000 stück.",
    "Die Laufleistung liegt bei 85000 km, der Timeout nach 30000 ms.",
    "Im Jahr 2024 stieg der Umsatz um 12 Prozent.",
    "Messwerte 0.12345, 0.67890 mg/l bei 20 Grad.",
    "EUR/USD Kurs 1.08345, 1.08412 (Geld/Brief).",
    "Preis 12.5000, 3.4000 EUR je Einheit.",
    "Version 1.2345, 6.7890 wurde ausgeliefert.",
    "Die Garantie gilt 5 Jahre, die Anlage ist 15 Jahre alt.",
    "Unser Unternehmen ist 25 Jahre alt geworden.",
    "Seite 12-14 im Bericht, §§ 3-5 des Vertrags.",
    # codes, numbers, tickets
    "Ticket D-4711 Fehler beim Login, Bauteil A-1234 Teil der Lieferung.",
    "Norm DIN EN 1234 und ISO 9001 gelten.",
    "Raum A-B 12, Produkt X-Z 9000, Typ HS-A 102.",
    "Bestellnummer 4500112233, Rechnungsnummer RE-2025-0042.",
    "Das Angebot ist gültig bis 12/2025.",
    "Bahncard gültig bis 03/26, Monatskarte gültig bis 12/25.",
    "Uhrzeit 12:30:45, Beispiel-Adresse 2001:db8::1:2 in der Doku.",
    "MAC 00:00:00:00:00:00 als Platzhalter.",
    "Stream auf netflix.com/de ansehen, Tracking unter fedex.com/de-de/tracking.",
    "Siehe https://github.com/features und linkedin.com/company/acme.",
    "Die Firewall 2 blockiert den Port, der Datenmarkt 2025 wächst.",
    "Supermarkt 3 hat offen, der Lernpfad 3 beginnt.",
    "Das Postfach 250 ungelesene Mails enthält.",
    # greetings, sign-offs, labels without a person
    "Hallo Zusammen,\nbitte die Unterlagen prüfen.",
    "Liebe Eltern,\ndie Schule bleibt am Freitag geschlossen.",
    "Hallo Team,\ndas Meeting ist verschoben.",
    "Guten Morgen Deutschland!",
    "Viele Grüße\nIhr Team",
    "Grüße\nVertrieb",
    "Mitarbeiter: Alle Beschäftigten\nAbteilung: Vertrieb",
    "Anwesend: Vorstand, Abteilung Recht, Team Nord",
    "Kunde: Beispiel GmbH\nCC: Mediatech Kft",
    "Fahrer: Spedition Müller, Moderation: Agentur Blau",
    "Verfasser: Abteilung Recht",
    "Muster-Personalbogen\nMitarbeiter:\nAbteilung: Vertrieb",
    # contract and policy text with cue words
    "Jede Partei im Sinne dieses Vertrages kann kündigen.",
    "Nach Wahl des Vermieters wird die Kaution angelegt.",
    "Die Behandlung Ihres Antrags dauert zwei Wochen.",
    "Die Diagnose der Netzwerkstörung liegt vor.",
    "Der Betriebsrat wurde informiert.",
    "Die Reha-Abteilung des Herstellers ist umgezogen.",
    "Der Auftragnehmer unterliegt der Schweigepflicht nach Ziffer 9.",
    "Die Parteien vereinbaren die Geltung deutschen Rechts.",
    "Der Erblasser kann durch Testament den Erben bestimmen.",
    "Rechnung\nBitte begleichen Sie den Betrag per Überweisung bis zum 30.06.2025.",
    "Lieferung der Arztbrief-Software an das Krankenhaus Nord.",
    "Versicherte Person: Die Antragstellerin bzw. der Antragsteller.",
    "Migräne ist eine häufige Erkrankung.",
    # street-like phrases
    "Im Jahr 2024 zogen wir um. Am Montag 12 Teilnehmer. Im Kapitel 3, Seite 4.",
    "Leider Platz 4 im Gesamtranking, aber Platz 2 reicht nicht.",
    "Neuer Weg 2026 für die Firma.",
    "Breiter Straße 2 Spuren geplant.",
    "Wir treffen uns at 5, Fußnote *12.04.2024 geändert.",
    # dates and counts without a person's event
    "Lieferung am 22.03.2025, Rechnung vom 01.07.2025.",
    "Die Kündigung des Vertrags zum 30.06.2025 ist eingegangen.",
    "Aufnahme in den Katalog am 01.03.2025, Artikel (12) und Tabelle (3).",
    "10-jährige Garantie für 5 Geräte.",
    "Die Unfallversicherung gilt ab 01.01.2026, die Unfallkasse prüft seit 01.02.2025.",
    "Der stationäre Handel verzeichnet seit 01.03. steigende Umsätze.",
    "Eintritt der Bedingung am 01.04.2025; Eintritt frei am 03.10.2025.",
    "Der Austritt Großbritanniens am 31.01.2020 war folgenreich.",
    "Am Todestag des Firmengründers, dem 14.02.2025, bleibt das Werk zu.",
    "Die Maschine (12 J.) wird ersetzt. AU-Zone Nord: Lieferung am 12.06.2025.",
    "Die Entlassungswelle begann am 15.01.2024. Unser Team operiert ab 01.10. in Berlin.",
    "Eintritt: frei am 03.10.2025. Lieferung nach AU am 12.06.2025, Goldpreis (AU) am 01.10.2025.",
]
