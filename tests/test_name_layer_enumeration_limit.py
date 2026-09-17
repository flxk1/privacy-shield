"""Where the exclusion lists end - and the ablation that removed two of them.

THE FINDING THIS FILE NOW RECORDS, which is the opposite of the one it was
written to record.

Independent verification rejected German's probe A for two enumeration
failures: a legal-form list that held `Ltd`, `SARL`, `BV` and `NV` and not
`Oy`, `Kft` or `Asa`, so `An: Nordica Oy` was a person; and an uninflected
stoplist that `Automatischer Rechnungslauf` walked past. Both reproduced
against this layer - 7 of 27 and 5 of 12 on `tests/corpora_enumeration.py` -
and both were fixed by making the lists better: the EU rows of ISO 20275 (410
abbreviations, 26 member states) and a six-character stem match. That took the
failures to 3 of 27 and 2 of 12.

Then main withdrew probe A, this layer withdrew its English counterpart, and
the same corpus measures **0 of 27 and 0 of 12** - with the ISO table and the
stem match both deleted. Ablated over 69 clean English and 42 clean German
documents, removing them changed the false-positive count by ZERO in each
direction.

So the enumeration exposure was a property of the POSITION, not of the length
of the list. A value after a label had to be judged, every list that judged it
failed open, and no list was going to stop failing open. Removing the position
removed the need for the lists. That is worth more than either list was.

WHAT THE ABLATION COULD NOT SEE, because none of those 111 documents contained
it: a company whose legal form is a member state's, standing where a person
stands. `Kind regards` / `Nordica Oy` is claimed now and was refused by the
ISO table. `EN_CLEAN_ADVERSARIAL_FOREIGN` is that shape, it costs 6 false
positives, and the table was still not restored - GLEIF publishes the ISO
20275 code list with no licence statement, and licence is a hard gate for data
as well as for code. The alternative is a maintained library, and there is no
ISO 20275 package on PyPI: checked, none exists.

WHAT REMAINS, and still earns its place: the four word-list classes
(`legal_forms`, `organisational`, `non_person_values`, `temporal`), as the
exclusion UNION over registered languages. Ablated the same way, removing them
takes English from 10 false-positive spans to 32.
"""

from __future__ import annotations

import pytest

from corpora_enumeration import (
    COMMON_EU_SURNAMES,
    EU_LEGAL_FORM_VALUES,
    INFLECTED_NON_PERSON_VALUES,
)
from privacy_shield.name_layer import en, registry
from privacy_shield.name_layer.shared import Exclusions
from privacy_shield.names import find_names


def test_the_withdrawn_position_took_the_enumeration_exposure_with_it():
    """0 of 27 and 0 of 12, with both enumeration fixes deleted.

    Every one of these documents is a label, a colon and a value that is not
    a person. Nothing claims them any more, because nothing judges a value
    after a label any more.
    """
    legal = [
        value
        for _code, text in EU_LEGAL_FORM_VALUES
        for _s, _e, value in find_names(text)
    ]
    inflected = [
        value
        for _code, text, _root in INFLECTED_NON_PERSON_VALUES
        for _s, _e, value in find_names(text)
    ]
    assert legal == [], legal
    assert inflected == [], inflected


def test_the_enumeration_fixes_are_gone():
    """Named directly, so re-adding one without re-measuring fails here.

    Both were real fixes to a real hole. They are deleted because the hole is
    deleted, and re-introducing either belongs with re-introducing the label
    probe - see `en.CANDIDATE_PROBES`.
    """
    exclusions = registry.exclusions()
    assert not hasattr(exclusions, "trailing_legal_forms")
    with pytest.raises(ModuleNotFoundError):
        __import__("privacy_shield.name_layer.legal_forms")
    # the stem match is gone: an inflected or derived form of a listed word is
    # no longer refused, and nothing in the shipped positions needs it to be.
    assert exclusions.blocks(["Automatic"])
    assert not exclusions.blocks(["Automatically"])


def test_the_word_lists_that_remain_still_earn_their_place():
    """The ablation the other way: without them, English triples its false
    positives."""
    from corpora_english import (
        EN_CLEAN_ADVERSARIAL,
        EN_CLEAN_ADVERSARIAL_FOREIGN,
        EN_CLEAN_ADVERSARIAL_PROBES,
        EN_CLEAN_DEV,
        EN_CLEAN_HELD_OUT,
    )

    clean = (
        EN_CLEAN_DEV
        + EN_CLEAN_HELD_OUT
        + EN_CLEAN_ADVERSARIAL
        + EN_CLEAN_ADVERSARIAL_PROBES
        + EN_CLEAN_ADVERSARIAL_FOREIGN
    )
    with_lists = sum(len(en.find_names(text)) for text in clean)
    saved = registry._EXCLUSIONS
    try:
        registry._EXCLUSIONS = Exclusions()
        without = sum(len(en.find_names(text)) for text in clean)
    finally:
        registry._EXCLUSIONS = saved
    assert with_lists == 10, with_lists
    assert without == 32, without


def test_no_common_eu_surname_is_refused_by_the_remaining_lists():
    """The cost of the exclusions, counted against names instead of argued.

    Measured over 307 of the most common surnames in the member states, none
    is refused. With the stem match gone this is stronger than it was: exact
    membership cannot refuse a name that merely begins with a listed word.
    """
    exclusions = registry.exclusions()
    refused = [name for name in COMMON_EU_SURNAMES if exclusions.blocks([name])]
    assert not refused, refused
    assert len(COMMON_EU_SURNAMES) == 307, len(COMMON_EU_SURNAMES)


def test_the_exclusion_classes_stay_separable():
    """A false negative has to be traceable to the class that caused it."""
    exclusions = registry.exclusions()
    # German's own legal-form and collective lists went with probe A on main,
    # so the legal-form class is now English's alone - which is exactly why a
    # member state's form in a signature block is claimed.
    assert "Ltd" in exclusions.legal_forms
    assert "GmbH" not in exclusions.legal_forms
    assert "Abteilung" in exclusions.organisational
    assert "Vacant" in exclusions.non_person_values
    assert "Dezember" in exclusions.temporal


@pytest.mark.parametrize(
    "text, claimed",
    [
        ("Kind regards\nNordica Oy\n", ["Nordica Oy"]),
        ("Kind regards\nNordstern Limited\n", []),
        ("Mit freundlichen Gruessen\nNordstern GmbH\n", []),
    ],
)
def test_the_measured_cost_of_not_carrying_the_iso_table(text, claimed):
    """A member state's legal form in a signature block is claimed; England's
    and Germany's are not, because those two lists are ours to keep.

    Pinned so that the cost of the licence decision is visible in the suite
    rather than only in a document.
    """
    assert [value for _s, _e, value in find_names(text)] == claimed
