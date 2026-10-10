import pytest

from privacy_shield.runner import scan


@pytest.mark.parametrize("text, hidden", [
    ("Die AU geht bis Freitag, 16.05.", "16.05."),
    ("Herr Kraus war stationär vom 02.04. bis 09.04.2025 im Klinikum.", "09.04.2025"),
    ("Herr Engel hatte einen Unfall am 22.03.2025 auf der B27.", "22.03.2025"),
    ("Eintritt: 01.07.2025, Austritt zum 31.12.2025.", "31.12.2025"),
    ("Frau Weiß war vom 12.05.2025 bis 23.05.2025 arbeitsunfähig.", "23.05.2025"),
    ("Er ist seit 02.06.2025 krankgeschrieben.", "02.06.2025"),
    ("Herr Bauer ist am 09.01.2025 verstorben.", "09.01.2025"),
    ("Krankgemeldet seit 7. Juli 2025.", "Juli"),
    ("Herr Dahl (58 J.) kam.", "58"),
    ("eine Radfahrerin (71) wurde verletzt", "71"),
    ("den 28-jährigen Pascal Lüders", "28"),
    ("Tel. +49 711 55601-23", "55601-23"),
    ("Mobil 0176 – 2344 1987", "2344 1987"),
])
def test_person_event_dates_ages_and_phone_layouts_are_masked(text, hidden):
    assert hidden not in scan(text).documents[0].overlay


@pytest.mark.parametrize("text", [
    "Lieferung am 22.03.2025", "10-jährige Garantie für 5 Geräte", "Rechnung vom 01.07.2025",
    "Die Kündigung des Vertrags zum 30.06.2025 ist eingegangen.", "Aufnahme in den Katalog am 01.03.2025",
    "Artikel (12) und Tabelle (3)",
    "Die Unfallversicherung gilt ab 01.01.2026 für alle Beschäftigten.",
    "Die Unfallkasse prüft seit 01.02.2025 alle Anträge.",
    "Der stationäre Handel verzeichnet seit 01.03. steigende Umsätze.",
    "Eintritt der Bedingung am 01.04.2025 setzt die Frist in Gang.",
    "Kostenlos parken: Eintritt frei am 03.10.2025.",
    "Der Austritt Großbritanniens am 31.01.2020 war folgenreich.",
    "Am Todestag des Firmengründers, dem 14.02.2025, bleibt das Werk zu.",
    "Die Maschine (12 J.) wird ersetzt.",
    "AU-Zone Nord: Lieferung am 12.06.2025.",
    "Die Entlassungswelle begann am 15.01.2024.",
    "Unser Team operiert ab 01.10. in Berlin.",
])
def test_business_dates_and_counts_stay(text):
    assert scan(text).documents[0].overlay == text


@pytest.mark.parametrize("text, date", [
    ("Herr Kraus betreut die Unfallversicherung ab 01.01.2026.", "01.01.2026"),
    ("Frau Lenz kündigte die Entlassungswelle für den 15.01.2024 an.", "15.01.2024"),
])
def test_a_compound_is_not_the_anchor_even_beside_a_person(text, date):
    assert date in scan(text).documents[0].overlay
