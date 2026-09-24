"""`overlay` is withheld from the serialised report whenever a detected value is
still in it, and `egress_allowed` is left exactly as the gate decided.

Under DETECT_ONLY nothing redacts and under BLOCK the redactor refuses, so
`DocumentScan.overlay` is the untouched original while `egress_allowed` can be
True - the gate rules on source classification, not on the residual (see
docs/limits.md). fff430d closed the span `value`/`context` and left `overlay`
open, so `scan --json` printed verbatim emails and IBANs on the two modes that
were never the default. A test over the default mode alone, or over one field,
stays green through that; these read every string of the whole envelope, for
every RedactionMode x PrivacyMode, over German, English, IBAN and email input.
"""

import json
from typing import Any, Iterator

import pytest

from privacy_shield import PrivacyMode, RedactionMode
from privacy_shield.runner import scan

_EMAIL = "erika.mustermann@example.com"
_IBAN = "DE89370400440532013000"

#: (id, text, literals that must never appear in a default envelope whatever
#: the scanner detected). Names are left out of the literal oracle: whether a
#: name layer finds a given name is a detection question, not a serialiser
#: one, so for them the oracle is the detected values alone.
_INPUTS = [
    ("german", "Sehr geehrte Frau Erika Mustermann, Hauptstraße 5, 10115 Berlin, "
               f"erreichbar unter {_EMAIL}.", (_EMAIL,)),
    ("english", "Please contact John Smith at 221B Baker Street, London; "
                "his card is 4111 1111 1111 1111.", ()),
    ("iban", f"Bitte überweisen Sie den Betrag auf das Konto {_IBAN}.", (_IBAN,)),
    ("email", f"Reply to {_EMAIL} before Friday.", (_EMAIL,)),
    # a name alone: beside a high-confidence identifier, a guard that only counted
    # high-confidence spans still withheld the overlay and passed every cell above.
    ("german-name", "Bitte rufen Sie Frau Erika Mustermann morgen an.", ()),
    ("english-name", "Please call Mr John Smith tomorrow about the invoice.", ()),
]
_SALT = "a" * 64


def _strings(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from _strings(key)
            yield from _strings(value)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from _strings(item)


def _scan(text: str, mode: PrivacyMode, redaction: RedactionMode):
    salt = {"hash_salt": _SALT} if redaction is RedactionMode.HASH else {}
    return scan(text, mode=mode, redaction_mode=redaction, force_text=True, **salt)


_MATRIX = [
    pytest.param(mode, redaction, text, literals, id=f"{mode.value}-{redaction.value}-{name}")
    for mode in PrivacyMode
    for redaction in RedactionMode
    for name, text, literals in _INPUTS
]


@pytest.mark.parametrize("mode,redaction,text,literals", _MATRIX)
def test_no_detected_value_reaches_the_default_envelope(mode, redaction, text, literals):
    report = _scan(text, mode, redaction)
    doc = report.documents[0]
    detected = {s.value for s in doc.spans if s.value}
    if literals:
        assert detected, "nothing was detected, so absence below would prove nothing"

    blob = list(_strings(report.to_dict()))
    leaked = sorted({v for v in detected | set(literals) for s in blob if v in s})
    assert not leaked, f"{mode.value}/{redaction.value} serialised {len(leaked)} original value(s)"


@pytest.mark.parametrize("mode,redaction,text,literals", _MATRIX)
def test_a_withheld_overlay_is_named_and_the_verdict_is_untouched(mode, redaction, text, literals):
    report = _scan(text, mode, redaction)
    doc = report.documents[0]
    out = report.to_dict()["documents"][0]
    asked = report.to_dict(include_original=True)["documents"][0]

    assert out["egress_allowed"] is doc.egress_allowed is asked["egress_allowed"]
    assert report.to_dict()["all_allowed"] is report.all_allowed
    if doc.overlay_residual:
        assert out["overlay"] is None and str(doc.overlay_residual) in out["overlay_withheld"]
        assert "not a cleaned overlay" in out["overlay_withheld"]
    else:
        assert out["overlay"] == doc.overlay and "overlay_withheld" not in out
    # the negative control: asking for the original returns it, overlay included.
    assert asked["overlay"] == doc.overlay and "overlay_withheld" not in asked
    held = list(_strings(asked))
    assert all(any(v in s for s in held) for v in {s.value for s in doc.spans if s.value})


@pytest.mark.parametrize("redaction", [RedactionMode.DETECT_ONLY, RedactionMode.BLOCK])
@pytest.mark.parametrize("mode", list(PrivacyMode))
def test_the_two_modes_that_leaked_now_withhold(mode, redaction):
    """Guards the matrix against passing vacuously: the modes this closes must
    actually take the withholding branch. ANONYMOUS_JSON builds its overlay from
    anonymised JSON whatever the redaction mode, so it has no residual to withhold -
    asserted, so a change there shows up here rather than in the matrix."""
    report = _scan(f"Reply to {_EMAIL}, IBAN {_IBAN}.", mode, redaction)
    doc = report.documents[0]
    if mode is PrivacyMode.ANONYMOUS_JSON:
        assert doc.overlay_residual == 0 and _EMAIL not in doc.overlay
        return
    assert doc.overlay_residual >= 2 and _EMAIL in doc.overlay
    out = report.to_dict()["documents"][0]
    assert out["overlay"] is None and "overlay_withheld" in out
    asked = report.to_dict(include_original=True)["documents"][0]
    assert _EMAIL in asked["overlay"] and _IBAN in asked["overlay"]


@pytest.mark.parametrize("redaction", ["detect_only", "block", "redact"])
def test_the_cli_json_and_out_paths(tmp_path, capsys, redaction):
    """The bytes that reach stdout and the files `--out` writes, not the dict."""
    from privacy_shield.cli import main

    document = tmp_path / "note.txt"
    document.write_text(f"Reply to {_EMAIL}, IBAN {_IBAN}.", encoding="utf-8")
    out_dir = tmp_path / "overlays"

    main(["scan", str(document), "--json", "--redaction-mode", redaction, "--out", str(out_dir)])
    printed = capsys.readouterr().out
    written = list(out_dir.glob("*.overlay.txt"))
    assert _EMAIL not in printed and _IBAN not in printed
    assert all(_EMAIL not in p.read_text(encoding="utf-8") for p in written)
    payload = json.loads(printed)
    if redaction == "redact":
        assert payload["documents"][0]["overlay"] and len(written) == 1
    else:
        assert payload["documents"][0]["overlay"] is None and written == []
        assert "overlay_withheld" in payload["documents"][0]

    main(["scan", str(document), "--redaction-mode", redaction])
    human = capsys.readouterr().out
    assert _EMAIL not in human and _IBAN not in human
    assert ("overlay withheld" in human) is (redaction != "redact")

    main(["scan", str(document), "--json", "--redaction-mode", redaction, "--include-original-values"])
    assert _EMAIL in capsys.readouterr().out


def test_a_bare_name_under_detect_only_is_withheld():
    """Not vacuous: the name layer finds it at medium confidence, alone."""
    report = _scan("Bitte rufen Sie Frau Erika Mustermann morgen an.",
                   PrivacyMode.STANDARD, RedactionMode.DETECT_ONLY)
    doc = report.documents[0]
    assert doc.spans and all(s.confidence != "high" for s in doc.spans)
    out = report.to_dict()["documents"][0]
    assert out["overlay"] is None and "Mustermann" not in json.dumps(report.to_dict())


@pytest.mark.parametrize("hint", ["Alter Wasserturm 7", "", None])
@pytest.mark.parametrize("redaction", [RedactionMode.DETECT_ONLY, RedactionMode.REDACT,
                                       RedactionMode.PSEUDONYMIZE, RedactionMode.BLOCK])
def test_a_span_whose_value_is_not_its_original_is_still_withheld(monkeypatch, redaction, hint):
    """The local-model layer records a `value_hint`, not the matched text, and
    `end = start + 10`: under detect_only a residual read from `value` alone let
    the overlay out verbatim, and under redact the redactor replaced ten
    characters and let the rest of the address out."""
    import privacy_shield.services.local_model_runtime as runtime

    text = "treffpunkt ist wie immer am alten wasserturm 7 hinten."
    hit = {"type": "address", "value_hint": hint, "start_pos": text.index("am alten")}
    monkeypatch.setattr(runtime, "is_local_model_available", lambda *a, **k: True)
    monkeypatch.setattr(runtime, "detect_pii_with_local_model", lambda t, **k: {
        "detected_pii": [hit], "confidence": 0.9, "categories": ["address"],
        "safe_to_send_external": False, "error": None})
    report = scan(text, mode=PrivacyMode.STANDARD, redaction_mode=redaction, force_text=True)
    doc = report.documents[0]
    span = doc.spans[0]
    assert [s.layer for s in doc.spans] == [5] and span.value != text[span.start:span.end]
    out = report.to_dict()["documents"][0]
    assert out["overlay"] is None and "overlay_withheld" in out
    assert "asserturm" not in json.dumps(report.to_dict())
