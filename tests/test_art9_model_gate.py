import collections

import pytest

from privacy_shield import pii_model
from privacy_shield.gate import PrivacyGate


class _Fake:
    def __init__(self, hits):
        self.hits = hits
        self.calls = 0

    def extract_entities(self, chunk, labels, **_):
        self.calls += 1
        out = {}
        for label, needle, score in self.hits:
            if needle in chunk:
                start = chunk.index(needle)
                out.setdefault(label, []).append(
                    {"text": needle, "confidence": score, "start": start, "end": start + len(needle)})
        return {"entities": out}


@pytest.fixture
def model(monkeypatch):
    def install(hits):
        fake = _Fake(hits)
        monkeypatch.setenv(pii_model.ENV, "fake")
        monkeypatch.setattr(pii_model, "_load", lambda spec: fake)
        monkeypatch.setattr(pii_model, "_model", None)
        monkeypatch.setattr(pii_model, "_cache", collections.OrderedDict())
        return fake
    return install


def _allowed(text):
    return PrivacyGate()._decide_local({"text": text}, "external_llm").allowed


@pytest.mark.parametrize("text", [
    "Jede Partei im Sinne dieses Vertrages kann kündigen.",
    "Die Behandlung Ihres Antrags dauert zwei Wochen.",
    "Nach Wahl des Vermieters wird die Kaution angelegt.",
])
def test_a_keyword_the_model_does_not_back_no_longer_blocks(model, monkeypatch, text):
    monkeypatch.delenv(pii_model.ENV, raising=False)
    assert _allowed(text) is False
    model([])
    assert _allowed(text) is True


def test_a_keyword_the_model_backs_weakly_still_blocks(model):
    model([("health condition", "Diabetes", 0.6)])
    assert _allowed("Der Patient hat Diabetes.") is False


def test_a_confident_model_hit_blocks_without_a_keyword(model):
    model([("health condition", "Chemo", 0.95)])
    assert _allowed("Herr Albrecht ist zurück. Er geht nach der Chemo wieder arbeiten.") is False


def test_a_weak_model_hit_without_a_keyword_does_not_block(model):
    model([("health condition", "Chemo", 0.6)])
    assert _allowed("Er geht nach der Chemo wieder arbeiten.") is True


@pytest.mark.parametrize("text", ["Der Befund ist genetisch bedingt.", "Der Fingerabdruck wurde erfasst."])
def test_categories_the_model_lacks_stay_keyword_only(model, text):
    model([])
    assert _allowed(text) is False


def test_without_the_model_the_keywords_decide_alone(monkeypatch):
    monkeypatch.delenv(pii_model.ENV, raising=False)
    assert _allowed("Jede Partei im Sinne dieses Vertrages kann kündigen.") is False


def test_scan_and_gate_share_one_model_run(model):
    from privacy_shield.runner import scan
    fake = model([("health condition", "Diabetes", 0.95)])
    scan("Der Mitarbeiter hat Diabetes und fehlt.")
    assert fake.calls == 1


@pytest.mark.parametrize("text", [
    "Er nimmt mehrere Medikamente gegen Bluthochdruck.",
    "Sie hat zwei Vorstrafen.",
])
def test_inflected_german_keywords_are_found(monkeypatch, text):
    monkeypatch.delenv(pii_model.ENV, raising=False)
    assert PrivacyGate().check_art9(text)


@pytest.mark.parametrize("text", [
    "Die Parteien vereinbaren Stillschweigen.", "Die Wahlen zum Aufsichtsrat finden im Mai statt.",
    "Genetische Algorithmen optimieren die Tourenplanung.", "Kirchen sind von der Grundsteuer befreit.",
    "Die Behandlungen der Reklamationen dauern an.", "Verurteilungen zur Unterlassung sind vollstreckbar.",
    "Die Diagnosen der Netzwerkanalyse liegen vor.", "Krankenhäuser sind von der Regelung ausgenommen.",
])
def test_business_plurals_of_cue_words_do_not_count(monkeypatch, text):
    monkeypatch.delenv(pii_model.ENV, raising=False)
    assert PrivacyGate().check_art9(text) == []


@pytest.mark.parametrize("text", ["Wir glauben, dass der Termin passt.", "Die Glaubensfrage stellt sich nicht."])
def test_the_verb_glauben_is_not_religion(monkeypatch, text):
    monkeypatch.delenv(pii_model.ENV, raising=False)
    assert "religious" not in PrivacyGate().check_art9(text)


def test_a_confident_hit_on_a_name_does_not_count(model):
    model([("person", "Ostendorf", 0.95), ("religion", "Ostendorf", 0.95)])
    assert PrivacyGate().check_art9("Vorname: Henrike\nNachname: Ostendorf") == []


def test_a_confident_hit_about_nobody_does_not_count(model):
    model([("religion", "Testament", 0.95)])
    assert PrivacyGate().check_art9("Der Erblasser kann durch Testament den Erben bestimmen.") == []


def test_model_support_counts_only_in_the_keywords_own_sentence(model):
    model([("health condition", "Diabetes", 0.6)])
    hits = PrivacyGate().check_art9("Die Partei tagt morgen. Herr Albrecht hat Diabetes.")
    assert "political" not in hits and "health" in hits


def test_a_confident_hit_on_a_name_in_a_sentence_about_a_person_does_not_count(model):
    model([("person", "Henrike Ostendorf", 0.95), ("religion", "Ostendorf", 0.95)])
    assert PrivacyGate().check_art9("Frau Henrike Ostendorf ist neu im Team.") == []
