import pytest

from privacy_shield.runner import scan


@pytest.mark.parametrize("text, hidden", [
    ("Karl-Marx-Allee 90–92, 10243 Berlin", "92"),
    ("Bahnhofstraße 1-3, 90402 Nürnberg", "-3"),
    ("Jungfernstieg 7, 20354 Hamburg", "Jungfernstieg"),
    ("Am Lindenhof 4, 50667 Köln", "Lindenhof"),
    ("An der Alster 7, 20099 Hamburg", "Alster"),
    ("Unter den Linden 77, 10117 Berlin", "Linden"),
    ("Neuer Wall 50, 20354 Hamburg", "Wall"),
    ("Zur Mühle 3\n01067 Dresden", "Mühle"),
    ("Anschrift: Im Grund 5", "Grund"),
    ("Postfach 10 20 30, 10115 Berlin", "20 30"),
    ("c/o Müller, Ringstraße 5, 1010 Wien", "Wien"),
])
def test_the_address_form_is_masked_whole(text, hidden):
    assert hidden not in scan(text).documents[0].overlay


@pytest.mark.parametrize("text", [
    "Im Jahr 2024 zogen wir um.", "Am Montag 12 Teilnehmer.", "Im Kapitel 3, Seite 4.",
    "Seite 12-14 im Bericht", "Zum Termin 3 Personen.",
])
def test_a_street_shape_without_postcode_or_label_is_not_an_address(text):
    assert scan(text).documents[0].overlay == text
