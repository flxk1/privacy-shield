import pytest

from privacy_shield.scanner import PIIType, PrivacyScanner


def _types(text):
    return [(f.pii_type, f.value) for f in PrivacyScanner().scan(text).findings]


@pytest.mark.parametrize("street", [
    "Graf-Zeppelin-Straße 7", "Lindau-Weg-Str. 18", "Anna-Seghers-Weg 4",
    "Torstraße 112",
])
def test_street_names_including_hyphenated_ones(street):
    assert (PIIType.ADDRESS, street) in _types(f"Die Wohnung liegt in der {street}, 10115 Berlin.")


@pytest.mark.parametrize("text", [
    "Die Wohnung liegt im 4. OG links, Hinterhaus.",
    "Bitte rechts oben unterschreiben.",
    "Sie haben Variante B gewählt.",
    "Die Vertragsauslegung ist liberal.",
])
def test_directions_and_choices_are_not_political_opinions(text):
    assert PIIType.POLITICAL not in [t for t, _ in _types(text)]


@pytest.mark.parametrize("text", [
    "Er ist Parteimitglied seit 2010.",
    "Bei der Wahl hat sie links gewählt, Partei unbekannt.",
    "Seine politische Meinung ist bekannt.",
])
def test_political_opinions_with_a_political_word_are_found(text):
    assert PIIType.POLITICAL in [t for t, _ in _types(text)]


@pytest.mark.parametrize("text", [
    "UVZ-Nr. H73/2026 des Notars.",
    "Papierformat A4, Druck auf B12 Bogen.",
    "Aktenzeichen K12 und Raum E10.",
])
def test_a_letter_and_two_digits_without_a_medical_word_is_not_a_diagnosis(text):
    assert PIIType.ICD_CODE not in [t for t, _ in _types(text)]


@pytest.mark.parametrize("text, code", [
    ("Diagnose: H73, Kontrolle in vier Wochen.", "H73"),
    ("Befund unauffällig, Verdacht auf J45.", "J45"),
    ("Kodiert als F32.1.", "F32.1"),
])
def test_diagnosis_codes_are_found(text, code):
    assert (PIIType.ICD_CODE, code) in _types(text)
