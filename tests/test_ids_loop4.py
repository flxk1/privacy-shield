import pytest

from privacy_shield.identifiers import find_labelled_ids, icao_check, kvnr_valid
from privacy_shield.runner import scan


def test_the_check_digits():
    assert kvnr_valid("A123456780") and not kvnr_valid("A123456781")
    assert icao_check("L01X00T47") == 1


@pytest.mark.parametrize("text, hidden, kept", [
    ("Steuernummer: 143/123/45678", "143/123", "Steuernummer"),
    ("St.-Nr. 21/815/08150", "815", "St.-Nr."),
    ("Personalausweis-Nr. L01X00T47", "L01X00T47", "Personalausweis"),
    ("Ausweisnummer L01X00T471", "L01X00T471", "Ausweisnummer"),
    ("Krankenversichertennummer A123456780", "A123456780", "Krankenversichertennummer"),
    ("Personalnummer 004711", "004711", "Personalnummer"),
    ("Kunden-Nr.: KD-2024-118", "2024-118", "Kunden-Nr."),
    ("Herr Albrecht (* 12.04.1971) ist neu.", "1971", "ist neu"),
    ("geb. am 12. April 1971", "April", ""),
    ("Geburtsdatum: 1971-04-12", "1971", ""),
    ("Er ist 54 Jahre alt.", "54", "Er ist"),
    ("Tel. (030) 123 456-78", "-78", "Tel."),
    ("Tel. +49 (0)30 1234567", "(0)", "Tel."),
    ("Fax: 089 - 12 34 56", "34 56", "Fax"),
])
def test_loop4_identifier_is_masked_and_its_label_kept(text, hidden, kept):
    overlay = scan(text).documents[0].overlay
    assert hidden not in overlay and kept in overlay


@pytest.mark.parametrize("text", [
    "Kundennummer anbei", "Seite 089 - 12 34 im Bericht",
    "Fußnote *12.04.2024 geändert", "Die Garantie gilt 5 Jahre.", "(2024) 123 Seiten",
])
def test_loop4_look_alikes_stay(text):
    assert scan(text).documents[0].overlay == text
