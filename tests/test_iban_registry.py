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

try:
    from schwifty import registry as schwifty_registry
except ImportError:  # pragma: no cover - the loud branch
    schwifty_registry = None


def test_the_external_source_is_actually_present():
    """A quiet skip is not "says so loudly".

    `importorskip` made the whole module vanish when schwifty was absent, so a
    run with no external check reported the same green as a run with one - the
    exact shape this programme keeps finding. schwifty is in the dev extra and
    both CI jobs install it, so its absence is a broken environment and fails.
    """
    assert schwifty_registry is not None, (
        "schwifty is not installed, so the IBAN country/length table is "
        "UNVERIFIED against any external source in this run. It is in the dev "
        "extra; install it. Nothing inside this package can notice that table "
        "going stale."
    )


#: Applied to the checks themselves, NOT to the module: a module-level skip
#: would take the test above with it and restore the silence.
needs_external = pytest.mark.skipif(
    schwifty_registry is None,
    reason="reported as a failure by test_the_external_source_is_actually_present",
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


@needs_external
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
