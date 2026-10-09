import pytest

from privacy_shield.identifiers import find_plates, find_svnr, svnr_check_digit
from privacy_shield.runner import scan
from privacy_shield.scanner import PIIType, PrivacyScanner


def test_the_published_example_checks():
    assert svnr_check_digit("15", "070649", "C", "10") == 3


@pytest.mark.parametrize("text", [
    "Ihre SV-Nummer lautet 15 070649 C 103.",
    "Rentenversicherungsnummer: 15070649C103",
    "Rentenvers.-Nr.: 15-070649-C-103",
])
def test_a_pension_number_is_masked_whole(text):
    doc = scan(text).documents[0]
    assert "070649" not in doc.overlay and "103" not in doc.overlay and "C 1" not in doc.overlay
    hit = [f for f in PrivacyScanner().scan(text).findings if f.pii_type is PIIType.SVNR]
    assert hit and hit[0].checksum_validated


def test_a_wrong_check_digit_is_masked_but_not_validated():
    [(_, _, _, ok)] = find_svnr("15070649C104")
    assert ok is False
    assert "070649" not in scan("Nummer 15070649C104").documents[0].overlay


@pytest.mark.parametrize("text", ["Bestellnr 12 345678 A 123", "Artikel 99 999999 Z 999"])
def test_no_real_birth_date_no_pension_number(text):
    assert find_svnr(text) == []


@pytest.mark.parametrize("text, plate", [
    ("Das Fahrzeug B-AB 1234 parkte falsch.", "B-AB 1234"),
    ("Kennzeichen: M XY 123E", "M XY 123E"),
    ("Kfz-Kennzeichen KÖ-AB 12", "KÖ-AB 12"),
    ("Kennzeichen B-A 1", "B-A 1"),
])
def test_a_plate_is_found_and_masked(text, plate):
    assert [v for _s, _e, v in find_plates(text)] == [plate]
    assert plate not in scan(text).documents[0].overlay


@pytest.mark.parametrize("text", [
    "Norm DIN EN 1234 gilt.", "gemäß DIN-EN 1234", "Raum A-B 12", "Produkt X-Z 9000",
    "Bitte B AB 1234 prüfen.", "Version ISO-AB 12",
])
def test_standards_rooms_and_unlabelled_spaced_forms_are_not_plates(text):
    assert find_plates(text) == []
