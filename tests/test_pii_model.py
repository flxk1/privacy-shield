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


@pytest.mark.parametrize("text, flagged", [
    ("Die Zufahrt liegt am Bergweg 3-5 hinter dem Lager.", "Bergweg 3-5"),
    ("Die Zufahrt liegt an der Industriestr. 10-14 hinter dem Lager.", "Industriestr. 10-14"),
    ("Er leidet an Diabetes mellitus Typ 2 seit Jahren.", "Diabetes mellitus Typ 2"),
])
def test_no_part_of_a_flagged_span_survives_a_partial_rule_match(model, text, flagged):
    model([("street address", flagged, 0.95), ("health condition", flagged, 0.95)])
    overlay = scan(text).documents[0].overlay
    tail = flagged.split()[-1]
    assert tail not in overlay, overlay


@pytest.mark.parametrize("text, single", [
    ("Der Erblasser hat das Grundstück dem Gläubiger übertragen.", "Erblasser"),
    ("Der Notar beurkundet den Vertrag.", "Notar"),
])
def test_a_lone_capitalised_word_is_not_a_name(model, text, single):
    model([("person", single, 0.95)])
    assert pii_model.find(text) == []


def test_a_lone_surname_is_kept_after_an_honorific_or_a_full_name(model):
    text = "Jonas Albrecht kam später. Albrecht bestätigte. Frau Weiß auch."
    model([("person", "Jonas Albrecht", 0.95), ("person", "Albrecht", 0.9), ("person", "Weiß", 0.9)])
    assert [v for _s, _e, v, _k, _c in pii_model.find(text)] == ["Jonas Albrecht", "Albrecht", "Weiß"]
