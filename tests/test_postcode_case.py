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


@pytest.mark.parametrize("text, hidden", [
    ("Beispiel GmbH, Hauptstraße 5, 61348 Bad Homburg", "Homburg"),
    ("Anschrift: Lindenweg 2, 53757 Sankt Augustin", "Augustin"),
    ("Kurallee 4\n83646 Bad Tölz", "Tölz"),
    ("wohnhaft in 51429 Bergisch Gladbach", "Gladbach"),
    ("Am Markt 1, 15711 Königs Wusterhausen", "Wusterhausen"),
    ("Filiale 21629 Neu Wulmstorf", "Wulmstorf"),
    ("82467 Garmisch-Partenkirchen", "Partenkirchen"),
    ("15230 Frankfurt (Oder)", "Oder"),
    ("66386 St. Ingbert", "Ingbert"),
    ("34346 Hann. Münden", "Münden"),
])
def test_a_multi_word_city_is_masked_whole(text, hidden):
    assert hidden not in scan(text).documents[0].overlay


@pytest.mark.parametrize("text, hidden", [
    ("gartenweg 4, 80331 münchen", "münchen"),
    ("schick es an 10115 berlin bitte", "berlin"),
    ("wohnhaft in 50667 köln", "köln"),
    ("komme aus 04109 leipzig", "leipzig"),
])
def test_a_lowercase_city_after_a_street_or_preposition_is_found(text, hidden):
    assert hidden not in scan(text).documents[0].overlay


@pytest.mark.parametrize("text", ["nach 30000 km", "timeout in 30000 ms", "an 50000 kunden", "in 12000 fällen"])
def test_a_counted_quantity_after_a_preposition_is_not_a_city(text):
    assert scan(text).documents[0].overlay == text
