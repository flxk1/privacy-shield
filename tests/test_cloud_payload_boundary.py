"""`to_cloud_payload` is the only code that enforces two declared norms.

    prohibited:  leak_the_value_placeholder_map
    obligation:  value_placeholder_map_stays_local

`AnonymousEnvelope` holds both halves of the re-identification map - the
placeholder->value dict and a hash of the original text - and
``to_cloud_payload`` is the boundary that is supposed to drop them. It is
exported in ``__all__``, so a consumer reaches for it as *the* safe-payload
call, and until this file existed it had no caller inside the package and no
test: ``grep -rn to_cloud_payload src/ tests/`` found one hit, the definition.
Adding ``placeholders`` and ``_original_hash`` back into the returned dict left
the whole suite byte-identically green.

These tests are deliberately NOT a list of allowed keys. An allowlist passes
today and passes again the day an eighth key is added, which is the same shape
of vacuous green this programme keeps finding. They check the PROMISE:

  1. nothing reachable from the payload, at any depth, is derived from the
     original text - proved by holding the PII *shape* fixed and varying only
     the *values*, so any field that carries an original has to differ;
  2. no original value, and no part of the map, is reachable from the payload
     at any depth, for a document whose originals the test chose.

(1) is the one that cannot be satisfied by accident: the hash of the original
text differs between two such documents even though no original appears in it
verbatim, so a payload that carries the hash fails (1) while passing (2).
"""

from __future__ import annotations

from typing import Any, Iterator

import pytest

from privacy_shield import AnonymousEnvelope, create_anonymous_envelope
from privacy_shield.anonymous_json import AnonymousJsonProcessor
from privacy_shield.scanner import PrivacyScanner

# Two documents with identical prose, identical token counts and the same PII
# SHAPE (one email, one IBAN), differing only in the values themselves. The
# published ECBS specimen IBANs, so nothing here is a real account.
_SHARED_PROSE = "Bitte pruefen Sie den Vertrag. Kontakt {email} und Konto {iban} danke."

_DOC_A_EMAIL = "erika.mustermann@example.com"
_DOC_A_IBAN = "DE89370400440532013000"
_DOC_B_EMAIL = "max.headroom@example.org"
_DOC_B_IBAN = "GB82WEST12345698765432"

_DOC_A = _SHARED_PROSE.format(email=_DOC_A_EMAIL, iban=_DOC_A_IBAN)
_DOC_B = _SHARED_PROSE.format(email=_DOC_B_EMAIL, iban=_DOC_B_IBAN)

#: Every original the test put into _DOC_A, plus the fragments a partial leak
#: would show. A leak does not have to be the whole string to be a leak.
_ORIGINALS_A = (
    _DOC_A_EMAIL,
    _DOC_A_IBAN,
    "erika.mustermann",
    "mustermann",
    "370400440532013000",
    "0532013000",
)


def _walk(node: Any, _seen: set[int] | None = None) -> Iterator[Any]:
    """Every key and every value reachable from *node*, at any depth.

    Dataclasses and objects with a ``__dict__`` are walked too: a future field
    holding an object that carries the map must not hide behind it. Identity is
    tracked because that is exactly the kind of field that could introduce a
    cycle, and this test has to FAIL on such a payload rather than exhaust the
    stack before it can assert anything.
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
    elif hasattr(node, "__dict__") and not isinstance(node, type):
        for value in vars(node).values():
            yield from _walk(value, seen)


def _strings(node: Any) -> list[str]:
    return [n for n in _walk(node) if isinstance(n, str)]


def _envelope(text: str) -> AnonymousEnvelope:
    return create_anonymous_envelope(text, skill_id="privacy-shield", jurisdiction="DE")


def test_the_envelope_under_test_actually_holds_the_map():
    """Guards the test, not the product.

    If the envelope stopped carrying the map, every assertion below would pass
    vacuously while proving nothing. The map has to be there for dropping it to
    mean anything.
    """
    envelope = _envelope(_DOC_A)
    assert envelope.placeholders, (
        "the envelope carries no placeholder map, so this file is asserting "
        "that nothing leaks out of nothing"
    )
    assert envelope._original_hash, "the envelope carries no original-text hash"
    assert any(
        original in value
        for value in envelope.placeholders.values()
        for original in (_DOC_A_EMAIL, _DOC_A_IBAN)
    ), f"the map does not hold the originals this test planted: {envelope.placeholders}"


def test_the_payload_is_invariant_under_the_original_values():
    """THE promise, in the form that cannot be satisfied by an allowlist.

    Two documents with the same prose and the same PII shape, differing only in
    the PII values, must produce the SAME cloud payload. Any field whose value
    derives from the original text - the map, the hash, a token of the text, a
    field added next year - makes the two differ, and fails here without this
    test ever naming it.
    """
    payload_a = _envelope(_DOC_A).to_cloud_payload()
    payload_b = _envelope(_DOC_B).to_cloud_payload()

    assert payload_a == payload_b, (
        "the cloud payload changed when only the ORIGINAL PII values changed, "
        "so something in it is derived from the original text:\n"
        f"  A: {payload_a}\n  B: {payload_b}\n"
        f"  differing keys: "
        f"{sorted(k for k in set(payload_a) | set(payload_b) if payload_a.get(k) != payload_b.get(k))}"
    )


def test_no_original_is_reachable_from_the_payload_at_any_depth():
    """The direct reading: walk the payload and look for the values we planted."""
    payload = _envelope(_DOC_A).to_cloud_payload()
    haystack = _strings(payload)

    for original in _ORIGINALS_A:
        hits = [s for s in haystack if original in s]
        assert not hits, (
            f"{original!r} - an original this test planted - is reachable from "
            f"the cloud payload: {hits}"
        )


def test_the_placeholder_map_is_not_reachable_from_the_payload():
    """No mapping inside the payload may resolve a placeholder to its original.

    Checked as a relation rather than as a key name: any dict reachable from
    the payload whose values include an original is the map, whatever it is
    called.
    """
    envelope = _envelope(_DOC_A)
    payload = envelope.to_cloud_payload()

    for node in _walk(payload):
        if not isinstance(node, dict):
            continue
        leaked = {
            k: v
            for k, v in node.items()
            if isinstance(v, str) and any(o in v for o in _ORIGINALS_A)
        }
        assert not leaked, f"a reachable mapping resolves to an original: {leaked}"

    assert envelope._original_hash not in _strings(payload), (
        "the hash of the original text is reachable from the cloud payload; it "
        "is a verifier for the original and does not belong on the wire"
    )


def test_the_local_representation_still_keeps_the_map():
    """`to_dict` is the LOCAL surface and must keep what `to_cloud_payload` drops.

    Without this, deleting the map from the envelope entirely would satisfy
    every test above and quietly break rehydration.
    """
    envelope = _envelope(_DOC_A)
    local = envelope.to_dict()

    assert local["placeholders"] == envelope.placeholders
    assert local["_original_hash"] == envelope._original_hash
    assert local["placeholders"], "the local dict lost the map rehydration needs"


def test_the_boundary_holds_for_an_envelope_built_directly():
    """`create_anonymous_envelope` is not the only way in.

    A consumer may build the processor itself, which is the path that would be
    missed if these tests only ever went through the convenience function.
    """
    processor = AnonymousJsonProcessor()
    scan = PrivacyScanner().scan(_DOC_A)
    envelope = processor.create_envelope(text=_DOC_A, scan_result=scan)

    haystack = _strings(envelope.to_cloud_payload())
    for original in _ORIGINALS_A:
        assert not [s for s in haystack if original in s], (
            f"{original!r} reachable from a directly-built envelope's payload"
        )


@pytest.mark.parametrize("attribute", ["placeholders", "_original_hash"])
def test_the_fields_this_boundary_exists_to_drop_are_still_on_the_envelope(attribute):
    """Renaming a field must not silently retire its test.

    If ``placeholders`` becomes ``mapping``, the invariant test above still
    holds the promise, but this states plainly which fields the boundary was
    written against so the rename is a decision and not a drift.
    """
    assert hasattr(_envelope(_DOC_A), attribute)
