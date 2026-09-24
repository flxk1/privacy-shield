"""`RedactionResult.to_dict()` is a public serialiser, so it is where
`prohibited: egress_original_unredacted_text` has to hold for `Redactor` callers.

Under pseudonymize and hash `mappings` is keyed by the original value. The
assertions walk every string of the whole envelope for every RedactionMode,
against the literal fixture values rather than what the scanner detected.
"""

from typing import Any, Iterator

import pytest

from privacy_shield.redactor import RedactionMode, Redactor
from privacy_shield.scanner import scan_text

_SALT = "a" * 64
_EMAIL = "erika.mustermann@example.com"
_IBAN = "DE89370400440532013000"
_DOC = f"Reply to {_EMAIL}, Konto {_IBAN}"

#: Same lengths as the originals, so only a value-derived field can differ.
_EMAIL_B = "harald.schmidtke@example.com"
_IBAN_B = "DE02120300000000202051"
_DOC_B = f"Reply to {_EMAIL_B}, Konto {_IBAN_B}"

_KEYED = {RedactionMode.PSEUDONYMIZE, RedactionMode.HASH}


def _walk(node: Any, seen: set[int] | None = None) -> Iterator[Any]:
    seen = set() if seen is None else seen
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


def _leaks(payload: Any, *originals: str) -> list[str]:
    return [
        s for s in _walk(payload)
        if isinstance(s, str) and any(o in s for o in originals)
    ]


def _redact(mode: RedactionMode, text: str = _DOC, redactor: Redactor | None = None):
    return (redactor or Redactor(mode=mode, hash_salt=_SALT)).redact(scan_text(text))


@pytest.mark.parametrize("mode", list(RedactionMode), ids=lambda m: m.value)
def test_the_redaction_under_test_holds_the_original(mode):
    result = _redact(mode)
    assert any(f.value in (_EMAIL, _IBAN) for f in result.findings), (
        "the scan found neither fixture, so every assertion below is vacuous"
    )
    if mode in _KEYED:
        assert {_EMAIL, _IBAN} <= set(result.mappings), (
            "mappings is no longer keyed by the original, so withholding it proves nothing"
        )


@pytest.mark.parametrize("mode", list(RedactionMode), ids=lambda m: m.value)
def test_the_serialised_result_carries_no_original_by_default(mode):
    payload = _redact(mode).to_dict()
    leaked = _leaks(payload, _EMAIL, _IBAN)
    assert not leaked, f"{mode.value}: the original reached to_dict() via {leaked[0]!r}"


@pytest.mark.parametrize("mode", list(RedactionMode), ids=lambda m: m.value)
def test_the_serialised_result_is_invariant_under_the_original_values(mode):
    assert len(_EMAIL) == len(_EMAIL_B) and len(_IBAN) == len(_IBAN_B)
    assert _redact(mode, _DOC).to_dict() == _redact(mode, _DOC_B).to_dict(), (
        f"{mode.value}: a serialised field still derives from the original"
    )


@pytest.mark.parametrize("mode", list(RedactionMode), ids=lambda m: m.value)
def test_the_omission_is_named(mode):
    payload = _redact(mode).to_dict()
    if mode in _KEYED:
        assert payload["mappings"] is None
        assert payload["mappings_withheld"] is True
    else:
        assert payload["mappings"] == {}
        assert payload["mappings_withheld"] is False


@pytest.mark.parametrize("mode", list(RedactionMode), ids=lambda m: m.value)
def test_asking_for_the_original_still_returns_it(mode):
    result = _redact(mode)
    payload = result.to_dict(include_original=True)
    assert payload["mappings"] == result.mappings
    assert payload["mappings_withheld"] is False
    if mode in _KEYED:
        assert _leaks(payload, _EMAIL) and _leaks(payload, _IBAN), (
            "include_original no longer returns the original map"
        )


@pytest.mark.parametrize("mode", sorted(_KEYED, key=lambda m: m.value), ids=lambda m: m.value)
def test_a_reused_redactor_leaks_no_earlier_document(mode):
    """`Redactor` keeps its map across calls, so a later result carries every
    earlier document's originals too."""
    redactor = Redactor(mode=mode, hash_salt=_SALT)
    _redact(mode, _DOC, redactor)
    second = _redact(mode, _DOC_B, redactor)
    assert _EMAIL in second.mappings, "the map no longer accumulates; the premise moved"
    leaked = _leaks(second.to_dict(), _EMAIL, _IBAN, _EMAIL_B, _IBAN_B)
    assert not leaked, f"{mode.value}: {leaked[0]!r} reached the second result's to_dict()"
