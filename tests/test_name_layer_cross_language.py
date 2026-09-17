"""What it costs to run every language's rules over every document.

The name layer applies the rules of every language a document evidences, and
of ALL of them when it evidences none. That is a deliberate choice and it is
the one that makes mixed-language documents work, which in EU correspondence
is the normal case: a German letter closed with `Kind regards`, an English
covering note over a French annex, a Dutch invoice with a German address
block.

It is affordable because of the split in `name_layer/shared.py` - evidence per
language, exclusions shared - and that is measured here rather than argued:

    EN rules over 42 clean German documents      0 false-positive spans
    DE rules over 69 clean English documents     0 false-positive spans

Before the exclusion union it was not zero. The German signature rule has
always been able to fire on an English letter, because its closing formulae
have always included `Kind regards` and `Yours sincerely`, and with the German
organisational table alone it claimed `Accounts Payable`. The fix was not to
stop German firing on English text - it FINDS names there - but to hold every
language's rules to every language's reasons not to claim.
"""

from __future__ import annotations

import pytest

from corpora_english import (
    EN_CLEAN_ADVERSARIAL,
    EN_CLEAN_ADVERSARIAL_PROBES,
    EN_CLEAN_DEV,
    EN_CLEAN_HELD_OUT,
)
from corpora_german import CLEAN_ADVERSARIAL, CLEAN_DEV, CLEAN_HELD_OUT
from privacy_shield.name_layer import de, detect, en, find_names, languages, registry

GERMAN_CLEAN = CLEAN_DEV + CLEAN_HELD_OUT + CLEAN_ADVERSARIAL
ENGLISH_CLEAN = (
    EN_CLEAN_DEV
    + EN_CLEAN_HELD_OUT
    + EN_CLEAN_ADVERSARIAL
    + EN_CLEAN_ADVERSARIAL_PROBES
)


def test_english_rules_claim_nothing_in_clean_german_documents():
    claimed = []
    for text in GERMAN_CLEAN:
        claimed.extend(value for _start, _end, value in en.find_names(text))
    assert not claimed, claimed


def test_german_rules_claim_nothing_in_clean_english_documents():
    """The regression that motivated the shared exclusion union.

    `Kind regards` / `Accounts Payable` was claimed by the GERMAN signature
    rule, whose closing formulae include the English ones, because
    `Accounts` and `Payable` were only in the English table.
    """
    claimed = []
    for text in ENGLISH_CLEAN:
        claimed.extend(value for _start, _end, value in de.find_names(text))
    assert not claimed, claimed


def test_the_shared_exclusion_union_is_what_stops_that():
    """Named directly, so deleting the union fails here and not somewhere
    subtle."""
    assert "Payable" in registry.exclusions().organisational
    assert "Abteilung" in registry.exclusions().organisational
    assert "Payable" not in de.ORGANISATIONAL
    assert "Abteilung" not in en.ORGANISATIONAL
    assert de.find_names("Mit freundlichen Gruessen\nAccounts Payable\n") == []
    assert de.find_names("Kind regards\nAbteilung Vertrieb\n") == []


def test_a_mixed_language_document_gets_both_languages():
    """A German salutation and an English sign-off in one letter."""
    text = (
        "Sehr geehrte Frau Schneider,\n\n"
        "please find the signed contract attached.\n\n"
        "Kind regards\nLaura Whitfield\nHead of Procurement\n"
    )
    assert set(detect.resolve(text)) == {"de", "en"}
    assert [value for _s, _e, value in find_names(text)] == [
        "Schneider",
        "Laura Whitfield",
    ]


def test_a_declared_language_wins_over_detection():
    """The caller knows better than the marker count when it knows at all.

    A German table header declares a person column; the English header list
    does not contain it, so declaring English means the column is not read.
    A declaration is a promise and the layer keeps it.
    """
    text = "| Position | Bearbeiter |\n| 10       | Osterloh   |\n"
    assert [v for _s, _e, v in find_names(text, "de")] == ["Osterloh"]
    assert find_names(text, "en") == []


def test_a_declared_language_with_no_ruleset_does_not_look_like_a_clean_document():
    """Declaring Finnish must not silently mean "no names".

    There is no Finnish ruleset. The document falls back to every registered
    ruleset as a best effort, which is why `docs/limits.md` lists Finnish as
    `unmeasured` rather than as supported - but a caller cannot turn the layer
    off by naming a language this package has not measured.
    """
    text = "Dear Mr Ashcroft,\n"
    assert [v for _s, _e, v in find_names(text, "fi")] == ["Ashcroft"]
    assert detect.resolve(text, "fi") == languages()


def test_a_document_with_no_marker_from_any_language_gets_every_ruleset():
    """Detection is allowed to fail. It must fail wide, not silent.

    An address block carries no function word in any language, so nothing
    scores - and the German title rule still finds the name because every
    ruleset was offered the document.
    """
    text = "Dr. Baumann\nMusterweg 4\n"
    assert set(detect.marker_scores(text).values()) == {0}
    assert set(detect.resolve(text)) == set(languages())
    assert [v for _s, _e, v in find_names(text)] == ["Baumann"]


@pytest.mark.parametrize(
    "declared, expected",
    [
        ("de", ["de"]),
        ("DE", ["de"]),
        ("en-GB", ["en"]),
        ("en_US", ["en"]),
        (["en", "de"], ["en", "de"]),
        (["mt"], None),
    ],
)
def test_declared_language_codes_are_normalised(declared, expected):
    text = "Dear Mr Ashcroft,\n"
    resolved = detect.resolve(text, declared)
    assert resolved == (expected if expected is not None else languages())


def test_detection_ranks_the_dominant_language_first():
    """Claim order follows the ranking, so the dominant language wins an
    overlap."""
    german = "Sehr geehrte Damen und Herren, bitte beachten Sie unser Schreiben."
    english = "Dear Sir or Madam, please find our letter attached for your records."
    assert detect.resolve(german)[0] == "de"
    assert detect.resolve(english)[0] == "en"
