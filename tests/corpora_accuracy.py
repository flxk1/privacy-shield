"""Personal data the detectors must find, with the value that must leave the overlay.

Each entry is (class, text, value). The class groups the recall measurement in
tests/test_precision_budget.py; the value is the part a reader must not see.
"""

ACCURACY_DE = [
    # identifiers with a check digit or a fixed format
    ("identifier", "IBAN DE89 3704 0044 0532 0130 00 für die Erstattung.", "0532 0130 00"),
    ("identifier", "Kartennummer 4111 1111 1111 1111, gültig bis 12/27.", "1111 1111 1111"),
    ("identifier", "Ihre SV-Nummer lautet 15 070649 C 103.", "C 103"),
    ("identifier", "Steuernummer: 143/123/45678", "143/123/45678"),
    ("identifier", "Personalausweis-Nr. L01X00T47", "L01X00T47"),
    ("identifier", "Krankenversichertennummer A123456780", "A123456780"),
    ("identifier", "Personalnummer 004711", "004711"),
    ("identifier", "Kennzeichen: M XY 123E", "XY 123E"),
    # contact and online
    ("contact", "Tel. (030) 123 456-78, Fax: 089 - 12 34 56", "456-78"),
    ("contact", "Mobil: +49 171 2345678", "2345678"),
    ("contact", "Mail: max.mustermann [at] example [dot] org", "mustermann"),
    ("contact", "Kontakt: j.albrecht@example.org", "albrecht@example"),
    ("contact", "Instagram: @max_mustermann", "max_mustermann"),
    ("contact", "IMEI 490154203237518", "490154203237518"),
    ("contact", "Standort 52.520008, 13.404954", "13.404954"),
    # addresses
    ("address", "Lindenweg 4, 10115 Berlin", "Lindenweg"),
    ("address", "Am Lindenhof 4, 50667 Köln", "Lindenhof"),
    ("address", "Karl-Marx-Allee 90–92, 10243 Berlin", "92"),
    ("address", "Frankfurter Straße 5, 60311 Frankfurt am Main", "Main"),
    ("address", "Seestrasse 3, CH-8640 Rapperswil", "Rapperswil"),
    ("address", "Postfach 10 20 30, 10115 Berlin", "20 30"),
    ("address", "Beispiel GmbH, Hauptstraße 5, 61348 Bad Homburg", "Homburg"),
    ("address", "schick es an 10115 berlin bitte", "berlin"),
    # names
    ("name", "Sehr geehrte Frau Weber,\nanbei die Unterlagen.", "Weber"),
    ("name", "Bitte leiten Sie die Akte an Jonas Albrecht weiter.", "Albrecht"),
    ("name", "Mit freundlichen Grüßen\nKatrin Möller", "Möller"),
    ("name", "Zeugin: Mia Kranz", "Kranz"),
    ("name", "Anwesend: S. Brandt, T. Okafor", "Okafor"),
    ("name", "Hallo Martin,\nanbei die Datei.", "Martin"),
    ("name", "Herr Łukasz Wiśniewski kommt.", "niewski"),
    ("name", "Herr Jürgen Müller kommt.", "rgen"),
    # dates and ages
    ("date", "Herr Albrecht (* 12.04.1971) ist neu.", "1971"),
    ("date", "geb. am 12. April 1971", "April"),
    ("date", "Herr Albrecht ist 54 Jahre alt.", "54"),
    ("date", "Herr Kraus war stationär vom 02.04. bis 09.04.2025 im Klinikum.", "09.04.2025"),
    ("date", "Er ist seit 02.06.2025 krankgeschrieben.", "02.06.2025"),
    ("date", "Herr Bauer ist am 09.01.2025 verstorben.", "09.01.2025"),
    ("date", "eine Radfahrerin (71) wurde verletzt", "71"),
    ("contact", "Tel. +49 711 55601-23", "55601-23"),
    # secrets
    ("secret", "export GITHUB_TOKEN=ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8", "ghp_"),
    ("secret", "Karte gültig bis 12/27, CVV 123", "CVV 123"),
    # special categories (redacted span, the verdict is in test_precision_budget)
    ("art9", "Herr Albrecht ist seit März krankgeschrieben, Diagnose: Depression.", "Depression"),
]

# texts with special-category data about a person that must not leave
ART9_MUST_BLOCK = [
    "Herr Albrecht ist seit März krankgeschrieben, Diagnose: Depression.",
    "Arztbrief\nPatientin: Elfriede Sauer\nVorbekannt sind ein Typ-2-Diabetes und eine Hypertonie; "
    "aktuelle Medikation: Metformin.",
    "Ich bin 34 Jahre alt, schwerbehindert (GdB 50).",
    "Mitarbeiterin: Lea Sommer\n\nIm weiteren Verlauf zeigte sich unter der begonnenen Therapie eine "
    "deutliche Besserung der Beschwerden.",
    "Herr Ruge ist Betriebsratsmitglied.",
    "Befund: HIV-positiv, Therapie läuft.",
    "Karte gültig bis 12/27, CVV 123",
]
