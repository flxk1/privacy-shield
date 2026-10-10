import pytest

from privacy_shield.runner import scan


@pytest.mark.parametrize("text, hidden", [
    ("Die AU geht bis Freitag, 16.05.", "16.05."),
    ("Er war stationär vom 02.04. bis 09.04.2025 im Klinikum.", "09.04.2025"),
    ("Unfall am 22.03.2025 auf der B27.", "22.03.2025"),
    ("Eintritt 01.07.2025, Austritt zum 31.12.2025.", "31.12.2025"),
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
])
def test_business_dates_and_counts_stay(text):
    assert scan(text).documents[0].overlay == text
