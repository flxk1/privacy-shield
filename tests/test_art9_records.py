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


@pytest.mark.parametrize("text", [
    "Rechnung\nBitte begleichen Sie den Betrag per Überweisung bis zum 30.06.2025. "
    "Die Behandlung Ihrer Reklamation vom April ist abgeschlossen.",
    "Ihre Überweisung ist eingegangen. Die Diagnose unseres Technikers: Der Kompressor ist defekt.",
    "Muster-Personalbogen\nMitarbeiter:\nAbteilung: Vertrieb\nAngaben zu einer Schwerbehinderung sind freiwillig.",
    "Versicherte Person: die im Antrag genannte Person. Psychische Erkrankungen sind mitversichert.",
    "Merkblatt Entgeltfortzahlung\nArbeitnehmer: Wer krankgeschrieben ist, meldet sich.",
    "Lieferung der Arztbrief-Software an das Krankenhaus Nord. Die Therapie-Module folgen.",
])
def test_payment_templates_and_product_text_are_not_records(text):
    from privacy_shield import art9
    assert not art9.is_record(text)
    assert PrivacyGate().check_art9(text) == []


@pytest.mark.parametrize("text", [
    "Befundbericht: MRT der LWS\nPatient: Herr Kurt Lehmann\nDiagnose: Bandscheibenprotrusion.",
    "Anamnese:\nNikotinabusus, Behandlung einer Depression seit 2019.",
])
def test_a_named_label_or_a_heading_makes_a_record(text):
    from privacy_shield import art9
    assert art9.is_record(text)
