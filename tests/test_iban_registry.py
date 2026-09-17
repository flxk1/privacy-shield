"""The IBAN country/length table, checked against something that maintains it.

`identifiers.IBAN_LENGTHS` is a transcription of ISO 13616, a registry amended
roughly twice a year. Nothing inside this package can notice it going stale:
the detector uses the table to decide what an IBAN is, the gate's oracle uses
the same definition, and a country missing from it is simply not an IBAN to
either of them. It was 87 entries and missing 40 - Honduras and Yemen among
them, both ordinary registrations - and every test passed.

That is the shape of the failure regardless of today's size, so the check has
to come from outside. `schwifty` is a maintained IBAN implementation; if it is
installed this compares every entry against it, and if it is not, this test
says so loudly rather than passing quietly.
"""

from __future__ import annotations

import string
import warnings

import pytest

from privacy_shield.identifiers import IBAN_LENGTHS

schwifty_registry = pytest.importorskip(
    "schwifty.registry",
    reason="schwifty is not installed, so the IBAN registry is UNVERIFIED "
    "against any external source in this run - install the dev extra",
)


def _external_registry() -> dict[str, int]:
    lengths: dict[str, int] = {}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        for first in string.ascii_uppercase:
            for second in string.ascii_uppercase:
                try:
                    spec = schwifty_registry.get_iban_spec(first + second)
                except Exception:
                    continue
                lengths[first + second] = spec.iban_length
    return lengths


def test_the_registry_has_not_gone_stale():
    external = _external_registry()
    assert external, "the external registry produced nothing; check the API"

    missing = sorted(set(external) - set(IBAN_LENGTHS))
    removed = sorted(set(IBAN_LENGTHS) - set(external))
    changed = {
        code: (IBAN_LENGTHS[code], external[code])
        for code in set(external) & set(IBAN_LENGTHS)
        if IBAN_LENGTHS[code] != external[code]
    }

    assert not missing, (
        "ISO 13616 has registrations this package does not know, so an IBAN "
        f"from each is not detected at all: {missing}"
    )
    assert not changed, f"registered lengths changed: {changed}"
    assert not removed, (
        f"codes here that the external registry does not have: {removed}"
    )


def test_the_registrations_that_were_missing_are_present():
    """Named, because they are what the gap was found through."""
    assert IBAN_LENGTHS.get("HN") == 28
    assert IBAN_LENGTHS.get("YE") == 30
