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


@pytest.mark.parametrize("text, hidden", [
    ("Frankfurter Straße 5, 60311 Frankfurt am Main", "Main"),
    ("Mariahilfer Straße 45, 1060 Wien", "Wien"),
    ("Bahnhofstrasse 10, 8001 Zürich", "Zürich"),
    ("Am Markt 1 · 04109 Leipzig", "Markt"),
    ("Fischmarkt 4, 20359 Hamburg", "Fischmarkt"),
])
def test_more_address_forms(text, hidden):
    assert hidden not in scan(text).documents[0].overlay


@pytest.mark.parametrize("text", [
    "Im Kapitel 3, 2500 Wörter genügen dafür.", "Die Firewall 2 blockiert den Port.",
    "Der Datenmarkt 2025 wächst.", "Das Postfach 2 Tage nicht geleert.", "Supermarkt 3 hat offen.",
    "Unser Weg 2025 ist klar.", "Am Ende 2023, 4500 Kunden zufrieden.", "Der Lernpfad 3 beginnt.",
])
def test_compounds_and_counts_are_not_addresses(text):
    assert scan(text).documents[0].overlay == text


def test_a_count_after_a_lead_phrase_is_not_a_postcode():
    assert "Im Kapitel 3" in scan("Im Kapitel 3, 12500 Wörter genügen dafür.").documents[0].overlay
