import pytest

from privacy_shield.runner import scan


@pytest.mark.parametrize("text, hidden", [
    ("Patientin: Elfriede Sauer", "Sauer"),
    ("Zeugin: Mia Kranz, Fahrer: Herr Jens Paulsen", "Paulsen"),
    ("Versicherter: Jürgen Pohl", "Pohl"),
    ("Anwesend: S. Brandt, T. Okafor, J. Wiesner", "Okafor"),
    ("Teilnehmende:\n- Svetlana Petrova\n- Ole Jansen", "Jansen"),
    ("Hallo Martin,\nanbei die Datei.", "Martin"),
    ("Viele Grüße\nLea", "Lea"),
    ("LG Petra", "Petra"),
    ("Herr Pascal Lüders kam. Später erhob die Firma Klage gegen Lüders.", "Lüders"),
])
def test_labels_lists_greetings_and_repeats_evidence_a_name(text, hidden):
    assert hidden not in scan(text).documents[0].overlay


@pytest.mark.parametrize("text", [
    "Hallo Team,\nbitte lesen.", "Viele Grüße\nIhr Team", "Mitarbeiter: Alle Beschäftigten",
    "Anwesend: Vorstand", "Kunde: Beispiel GmbH", "CC: Mediatech Kft", "Verfasser: Abteilung Recht",
    "Grüße\nVertrieb", "Mieter: Wohnbau Nord GmbH", "Der Fischer kam. Herr Peter Fischer zahlte.",
])
def test_groups_companies_and_nouns_are_not_names(text):
    overlay = scan(text).documents[0].overlay
    assert overlay.count("[NAME]") <= (1 if "Peter Fischer" in text else 0), overlay
