import os

import pytest

from privacy_shield import pii_model
from privacy_shield.gate import PrivacyGate
from privacy_shield.runner import scan
from privacy_shield.scanner import PIIType, PrivacyScanner

TEXT = (
    "Sehr geehrte Damen und Herren,\n"
    "bitte leiten Sie die Unterlagen an Jonas Albrecht weiter, Lindenweg 4.\n"
    "Unser Geschäftsführer bestätigt den Termin. Er geht nach der Chemo wieder arbeiten.\n"
)


def _hit(text, needle, score):
    start = text.index(needle)
    return {"text": needle, "confidence": score, "start": start, "end": start + len(needle)}


class _Fake:
    def __init__(self, entities):
        self.entities = entities
        self.calls = 0

    def extract_entities(self, chunk, labels, **_):
        self.calls += 1
        out = {}
        for label, needle, score in self.entities:
            if needle in chunk:
                out.setdefault(label, []).append(_hit(chunk, needle, score))
        return {"entities": out}


@pytest.fixture
def model(monkeypatch):
    def install(entities):
        fake = _Fake(entities)
        monkeypatch.setenv(pii_model.ENV, "fake")
        monkeypatch.setattr(pii_model, "_load", lambda spec: fake)
        monkeypatch.setattr(pii_model, "_model", None)
        return fake
    return install


_ENTITIES = [
    ("person", "Jonas Albrecht", 0.95),
    ("street address", "Lindenweg 4", 0.9),
    ("person", "Geschäftsführer", 0.92),
    ("health condition", "Chemo", 0.95),
]


def test_off_without_the_variable(monkeypatch):
    monkeypatch.delenv(pii_model.ENV, raising=False)
    monkeypatch.setattr(pii_model, "_load", lambda spec: pytest.fail("loaded while off"))
    assert pii_model.find(TEXT) == []


def test_set_but_not_installed_fails_loudly(monkeypatch):
    monkeypatch.setenv(pii_model.ENV, "fastino/x")
    monkeypatch.setattr(pii_model, "_model", None)
    monkeypatch.setitem(__import__("sys").modules, "gliner2", None)
    with pytest.raises(RuntimeError, match="not installed"):
        pii_model.find(TEXT)


def test_names_addresses_and_special_categories_are_found(model):
    model(_ENTITIES)
    found = {(v, k) for _s, _e, v, k, _c in pii_model.find(TEXT)}
    assert found == {
        ("Jonas Albrecht", "name"),
        ("Lindenweg 4", "address"),
        ("Chemo", "special_category"),
    }


def test_thresholds_are_per_kind(model):
    model([("person", "Jonas Albrecht", 0.65), ("street address", "Lindenweg 4", 0.71),
           ("health condition", "Chemo", 0.85)])
    assert [v for _s, _e, v, _k, _c in pii_model.find(TEXT)] == ["Lindenweg 4"]


@pytest.mark.parametrize("value", ["Geschäftsführer", "Herrn", "Frau Dr.", "Mandantin"])
def test_a_role_noun_is_not_a_name(value):
    assert pii_model._is_role_noun(value)


@pytest.mark.parametrize("value", ["Herrn Jonas Albrecht", "Frau Dr. Weiß", "Albrecht"])
def test_a_name_with_a_title_is_a_name(value):
    assert not pii_model._is_role_noun(value)


def test_offsets_survive_chunking(model):
    pad = "Lorem ipsum dolor sit amet. " * 120
    text = pad + TEXT + pad
    fake = model(_ENTITIES)
    spans = pii_model.find(text)
    assert fake.calls > 1
    assert all(text[s:e] == v for s, e, v, _k, _c in spans)
    assert {v for _s, _e, v, _k, _c in spans} >= {"Jonas Albrecht", "Lindenweg 4"}


def test_scanner_types_and_confidence(model):
    model(_ENTITIES)
    got = {(f.value, f.pii_type, f.confidence.value) for f in PrivacyScanner().scan(TEXT).findings
           if f.value in {"Jonas Albrecht", "Lindenweg 4", "Chemo"}}
    assert ("Jonas Albrecht", PIIType.NAME, "medium") in got
    assert ("Chemo", PIIType.SPECIAL_CATEGORY, "medium") in got


def test_a_rule_finding_wins_an_overlap(model):
    model([("person", "info@example.org", 0.99)])
    hits = [f for f in PrivacyScanner().scan("Kontakt: info@example.org").findings
            if f.value == "info@example.org"]
    assert [f.pii_type for f in hits] == [PIIType.EMAIL]


def test_model_findings_are_redacted_and_never_block(model):
    model(_ENTITIES)
    doc = scan(TEXT).documents[0]
    assert doc.egress_allowed is True
    for value in ("Jonas Albrecht", "Lindenweg 4", "Chemo"):
        assert value not in doc.overlay
    assert "Geschäftsführer" in doc.overlay


def test_the_gate_verdict_does_not_change(model, monkeypatch):
    monkeypatch.delenv(pii_model.ENV, raising=False)
    before = PrivacyGate()._decide_local({"text": TEXT}, "external_llm")
    model(_ENTITIES)
    after = PrivacyGate()._decide_local({"text": TEXT}, "external_llm")
    assert before.allowed is True
    assert (before.allowed, before.classification) == (after.allowed, after.classification)


# conftest clears PRIVACY_SHIELD_*, so the real model comes in under its own name
_REAL = os.environ.get("PII_MODEL_UNDER_TEST", "")


@pytest.mark.skipif(not _REAL, reason="PII_MODEL_UNDER_TEST not set")
def test_the_real_model_finds_a_bare_name(monkeypatch):
    monkeypatch.setenv(pii_model.ENV, _REAL)
    spans = pii_model.find("Bitte rufen Sie Jonas Albrecht zurück.")
    assert any(k == "name" and "Albrecht" in v for _s, _e, v, k, _c in spans)


def test_the_gate_scan_does_not_run_the_model(model):
    fake = model(_ENTITIES)
    PrivacyScanner(layers=[1]).scan(TEXT)
    assert fake.calls == 0


@pytest.mark.parametrize("text, flagged, leak", [
    ("Die Zufahrt liegt am Bergweg 3-5 hinter dem Lager.", "Bergweg 3-5", "-5"),
    ("Lieferung an Mühlenweg 12–14, Hof.", "Mühlenweg 12–14", "–14"),
    ("Lieferung an Ringstr. 4/6, Hof.", "Ringstr. 4/6", "/6"),
    ("Er leidet an Diabetes mellitus Typ 2 seit Jahren.", "Diabetes mellitus Typ 2", "mellitus"),
])
def test_no_part_of_a_flagged_span_survives_a_partial_rule_match(model, text, flagged, leak):
    model([("street address", flagged, 0.95), ("health condition", flagged, 0.95)])
    overlay = scan(text).documents[0].overlay
    assert leak not in overlay, overlay


@pytest.mark.parametrize("text, single", [
    ("Der Erblasser hat das Grundstück dem Gläubiger übertragen.", "Erblasser"),
    ("Der Notar beurkundet den Vertrag.", "Notar"),
])
def test_a_lone_capitalised_word_is_not_a_name(model, text, single):
    model([("person", single, 0.95)])
    assert pii_model.find(text) == []


def _covered(text, spans, word):
    starts = [m for m in range(len(text)) if text.startswith(word, m)]
    return [any(s <= m and m + len(word) <= e for s, e, _v, _k, _c in spans) for m in starts]


def test_a_lone_surname_is_kept_after_an_honorific_or_a_full_name(model):
    text = "Jonas Albrecht kam später. Albrecht bestätigte. Frau Weiß auch."
    model([("person", "Jonas Albrecht", 0.95), ("person", "Weiß", 0.9)])
    spans = pii_model.find(text)
    assert _covered(text, spans, "Albrecht") == [True, True]
    assert _covered(text, spans, "Weiß") == [True]


def test_a_name_confirmed_by_an_honorific_is_redacted_at_later_mentions(model):
    text = "Herr Wendehals ist Kläger. Im März hat Wendehals die Frist versäumt."
    model([("person", "Wendehals", 0.9)])
    assert scan(text).documents[0].overlay.count("Wendehals") == 0


def test_a_name_the_rules_found_seeds_later_mentions(model):
    model([])
    text = "Dr. Ilse Brandhorst kam. Später sprach Brandhorst."
    spans = pii_model.find(text, [(0, 19)])
    assert _covered(text, spans, "Brandhorst")[1]


@pytest.mark.parametrize("text, flagged", [
    ("Sehr geehrter Herr Präsident, wir danken.", "Herr Präsident"),
    ("Bitte wenden Sie sich an Herrn Notar.", "Herrn Notar"),
    ("Frau Gerichtsvollzieherin hat zugestellt.", "Frau Gerichtsvollzieherin"),
    ("Die Klägerinnen tragen vor.", "Klägerinnen"),
])
def test_an_honorific_before_a_role_is_a_role(model, text, flagged):
    model([("person", flagged, 0.95)])
    assert pii_model.find(text) == []


@pytest.mark.parametrize("value", ["Frau Zeuginnen", "Herren Klägerinnen", "Frau Notarin"])
def test_feminine_and_plural_roles_are_roles(value):
    assert pii_model._is_role_noun(value)


@pytest.mark.parametrize("text, surname", [
    ("Die Zeugin Brandhorst sagte aus. Später bestätigte Brandhorst die Angaben.", "Brandhorst"),
    ("Der Kläger Hollmann beantragt Fristverlängerung.", "Hollmann"),
    ("Dr. Kranichfeld hat das Gutachten erstellt.", "Kranichfeld"),
])
def test_a_surname_after_a_role_or_title_is_kept(model, text, surname):
    model([("person", surname, 0.95)])
    assert surname not in scan(text).documents[0].overlay


@pytest.mark.parametrize("text, kept", [
    ("Herr Wolf kam. Der Wolf im Märchen frisst.", "Der Wolf"),
    ("Frau Koch kocht. Am Abend kam ein Koch.", "ein Koch"),
    ("Ernst Lindemann schreibt: Der Ernst der Lage ist klar.", "Der Ernst"),
    ("Rose Hartwig pflanzt eine Rose.", "eine Rose"),
])
def test_a_surname_after_an_article_is_a_noun(model, text, kept):
    model([("person", text.split(" kam")[0].split(" kocht")[0].split(" schreibt")[0].split(" pflanzt")[0], 0.95)])
    assert kept in scan(text).documents[0].overlay


@pytest.mark.parametrize("text, kept", [
    ("Das Robert Koch-Institut empfiehlt Masken. Laut Koch-Team gilt das.", "Koch-Team"),
    ("Die Hans Böckler Stiftung fördert Studien. Böckler war Gewerkschafter.", "Böckler war"),
    ("Die Karl Marx Allee ist gesperrt. Jede Allee ist voll.", "Jede Allee"),
])
def test_an_institution_named_after_a_person_seeds_nothing(text, kept):
    span = text.index(text.split()[1]), text.index(text.split()[2].split("-")[0]) + len(text.split()[2].split("-")[0])
    assert all(v not in kept for _s, _e, v, _k, _c in pii_model._corefer(text, [], [span]))


def test_an_honorific_confirms_a_role_word_as_a_surname(model):
    text = "Laut Frau Richter ist die Akte vollständig. Richter bestätigte das."
    spans = pii_model._corefer(text, [], [(5, 17)])
    assert _covered(text, spans, "Richter")[1]


def test_a_rank_after_a_role_is_not_a_name(model):
    model([("person", "Polizeiobermeister", 0.95)])
    assert pii_model.find("Der Zeuge Polizeiobermeister wurde vernommen.") == []


def test_a_surname_on_the_role_list_is_redacted_at_later_mentions(model):
    model([])
    text = "Laut Frau Richter ist die Akte vollständig. Richter bestätigte das."
    assert "Richter" not in scan(text).documents[0].overlay
