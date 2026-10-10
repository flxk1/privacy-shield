import pytest

from privacy_shield import pii_model
from privacy_shield.gate import PrivacyGate


@pytest.fixture(autouse=True)
def _no_model(monkeypatch):
    monkeypatch.delenv(pii_model.ENV, raising=False)


@pytest.mark.parametrize("text", [
    "Arztbrief\nPatientin: Elfriede Sauer\nVorbekannt sind ein Typ-2-Diabetes und eine Hypertonie; "
    "aktuelle Medikation: Metformin.",
    "Hallo Team, die Ärztin vermutet bei Herrn Krause eine Gürtelrose, er ist krankgeschrieben bis Freitag.",
    "Ich bin 34 Jahre alt, schwerbehindert (GdB 50).",
    "Herr Ruge ist Betriebsratsmitglied.",
])
def test_records_and_sick_notes_are_special_category(text):
    assert PrivacyGate().check_art9(text)


@pytest.mark.parametrize("text", [
    "Der Betriebsrat wurde informiert.", "Die Reha-Abteilung des Herstellers ist umgezogen.",
    "Bitte attest the attached form.", "Die Behandlung Ihres Antrags dauert.",
])
def test_institutions_and_verbs_are_not(text):
    assert PrivacyGate().check_art9(text) == []


def test_in_a_record_the_subject_comes_from_the_document():
    text = ("Mitarbeiterin: Lea Sommer\n\nIm weiteren Verlauf zeigte sich unter der begonnenen "
            "Therapie eine deutliche Besserung der Beschwerden.")
    assert PrivacyGate().check_art9(text) == ["health"]
