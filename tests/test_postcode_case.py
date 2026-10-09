import pytest

from privacy_shield.runner import scan


@pytest.mark.parametrize("text", [
    "Messwerte 0.12345, 0.67890 mg/l", "Wir haben 50000 kunden gewonnen.", "Lieferung von 12000 stück",
    "Umsatz 25000 euro netto", "Gewicht 10000 kg",
])
def test_a_figure_and_a_lowercase_word_are_not_a_postcode_and_city(text):
    assert scan(text).documents[0].overlay == text


@pytest.mark.parametrize("text, hidden", [
    ("10115 Berlin", "Berlin"), ("60311 Frankfurt am Main", "Main"), ("Am Markt 1, 04109 Leipzig", "Leipzig"),
])
def test_a_postcode_and_city_is_still_found(text, hidden):
    assert hidden not in scan(text).documents[0].overlay
