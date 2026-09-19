"""Serialisation is where a result leaves the process, so it is where
`prohibited: egress_original_unredacted_text` has to hold.

`scan --json` printed each finding's `value` and `context` - the original text -
to stdout. That is local-only telemetry by design, and the design is sound on its
own. What made it a breach is the other half: `skills/privacy-shield/SKILL.md`
grants `allowed-tools: Bash(privacy-shield:*)`, and in a skill context stdout IS
the model's context. Two decisions, each defensible alone, putting the original
one pipe from an external model.

The fix is a default, not a removal: `to_dict()` omits the original unless the
caller asks. These tests are written against the PROMISE - no string reachable
anywhere in the serialised form may contain the original - rather than against
the current field list, because a field list is satisfied by renaming a key.
"""

from typing import Any, Iterator

import pytest

from privacy_shield.runner import scan
from privacy_shield.scanner import scan_text

_EMAIL = "erika.mustermann@example.com"
_IBAN = "DE89370400440532013000"
_DOC = f"Kontakt {_EMAIL} Konto {_IBAN} (intern)"

#: Same prose, same PII shape, different PII values - and deliberately the SAME
#: LENGTHS. A span report cannot be invariant under length: `start`/`end` locate
#: the redaction and are structural, so a shorter email genuinely moves every
#: later offset. Holding length fixed removes that legitimate difference and
#: leaves only the illegitimate one - a field whose value derives from the
#: original text rather than from its position.
_EMAIL_B = "harald.schmidtke@example.com"   # same length as _EMAIL
_IBAN_B = "DE02120300000000202051"          # same length as _IBAN, also valid
_DOC_B = f"Kontakt {_EMAIL_B} Konto {_IBAN_B} (intern)"


def _walk(node: Any, _seen: set[int] | None = None) -> Iterator[Any]:
    """Every key and every value reachable from *node*, at any depth.

    Objects with a ``__dict__`` are walked too, so a future field holding an
    object that carries the original cannot hide behind it. Identity is tracked
    because such a field is exactly what could introduce a cycle, and this test
    has to FAIL on that payload rather than exhaust the stack first.
    """
    seen = set() if _seen is None else _seen
    if id(node) in seen:
        return
    seen.add(id(node))

    yield node
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _walk(key, seen)
            yield from _walk(value, seen)
    elif isinstance(node, (list, tuple, set, frozenset)):
        for item in node:
            yield from _walk(item, seen)
    elif hasattr(node, "__dict__"):
        yield from _walk(vars(node), seen)


def _strings(node: Any) -> list[str]:
    return [n for n in _walk(node) if isinstance(n, str)]


def _report(text: str = _DOC):
    return scan(text, force_text=True)


def _without(node: Any, key: str) -> Any:
    """*node* with every occurrence of *key* removed, at any depth."""
    if isinstance(node, dict):
        return {k: _without(v, key) for k, v in node.items() if k != key}
    if isinstance(node, list):
        return [_without(item, key) for item in node]
    return node


def test_the_audit_id_is_a_nonce_and_not_a_function_of_the_text():
    """Earns the one exemption the invariance test below takes.

    `audit_id` differs between two scans, which would fail invariance. Excusing
    it by name would be the allowlist this file exists to avoid, so the
    exemption is earned instead: scanning the SAME text twice must also produce
    different ids. A digest of the original could not do that; a nonce must.
    """
    first = _report(_DOC).documents[0].audit_id
    second = _report(_DOC).documents[0].audit_id
    assert first and second, "no audit_id at all; the exemption below is unearned"
    assert first != second, (
        "the same text produced the same audit_id, so it is derived from the "
        "text rather than drawn fresh - it may not be exempted from invariance"
    )


def test_the_scan_under_test_actually_holds_the_original():
    """Guards the test, not the product.

    If the scan stopped finding anything, or stopped keeping the original on the
    finding, every assertion below would pass vacuously while proving nothing.
    'The original is absent' and 'there was never an original' must not read as
    the same green.
    """
    report = _report()
    spans = report.documents[0].spans
    assert spans, "the scan found nothing, so this file asserts that nothing leaks out of nothing"
    assert any(_EMAIL in s.value or _IBAN in s.value for s in spans), (
        "no finding carries the original value, so omitting it from the "
        "serialised form proves nothing"
    )


def test_the_serialised_report_carries_no_original_by_default():
    """THE promise, in the form a renamed key cannot satisfy."""
    payload = _report().to_dict()
    leaked = [s for s in _strings(payload) if _EMAIL in s or _IBAN in s]
    assert not leaked, (
        f"the original reached the serialised report through {len(leaked)} "
        f"string(s); the first is {leaked[0]!r}"
    )


def test_the_serialised_report_is_invariant_under_the_original_values():
    """Stronger than substring absence: a hash, a prefix or any other value
    derived from the original would differ between two documents that differ
    only in their PII values. The default payloads must not.

    The two documents are held to the same lengths on purpose - see `_DOC_B`.
    """
    assert len(_EMAIL) == len(_EMAIL_B) and len(_IBAN) == len(_IBAN_B), (
        "the fixtures no longer have equal lengths, so a failure here would be "
        "a moved offset rather than a leaked derivation"
    )
    a = _without(_report(_DOC).to_dict(), "audit_id")
    b = _without(_report(_DOC_B).to_dict(), "audit_id")
    assert a == b, (
        "two documents differing only in their PII values produced different "
        "serialised reports, so some field still derives from the original"
    )


def test_asking_for_the_original_still_returns_it():
    """The capability is defaulted off, not removed - a human at a terminal
    debugging a scan has a real use for it.
    """
    payload = _report().to_dict(include_original=True)
    found = [s for s in _strings(payload) if _EMAIL in s]
    assert found, "--include-original-values no longer returns the original at all"


def test_the_scanner_path_has_the_same_default():
    """Fixing only the CLI would have left the prohibited kind live one call
    away: `ScanResult.to_dict` is a second serialisation surface.
    """
    result = scan_text(_DOC)
    assert result.findings, "the scanner found nothing; this assertion would be vacuous"
    assert any(_EMAIL in f.value or _IBAN in f.value for f in result.findings), (
        "no scanner finding carries the original; omitting it proves nothing"
    )

    leaked = [s for s in _strings(result.to_dict()) if _EMAIL in s or _IBAN in s]
    assert not leaked, f"the scanner's serialised result leaked {leaked[0]!r}"

    asked = [s for s in _strings(result.to_dict(include_original=True)) if _EMAIL in s]
    assert asked, "include_original no longer returns the original on the scanner path"


@pytest.mark.parametrize("flag", [[], ["--include-original-values"]])
def test_the_cli_only_prints_the_original_when_asked(tmp_path, capsys, flag):
    """The bytes that actually reach stdout - the surface the skill's Bash grant
    exposes to a model - not the dict they were built from.
    """
    from privacy_shield.cli import main

    document = tmp_path / "note.txt"
    document.write_text(_DOC, encoding="utf-8")

    main(["scan", str(document), "--json", *flag])
    printed = capsys.readouterr().out

    assert "[EMAIL]" in printed, "the overlay is missing, so this run proved nothing"
    if flag:
        assert _EMAIL in printed
    else:
        assert _EMAIL not in printed and _IBAN not in printed, (
            "the original reached stdout without being asked for"
        )
