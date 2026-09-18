"""National person numbers via `python-stdnum`, and the two things it needs.

The library supplies 27 EU countries of check-digit validators. It does not
supply either of the things that make them usable, and without both an
adoption measurement reads "0 false positives" while testing nothing:

  * a TOKEN-level candidate pass, because `identifiers.identifier_runs` joins
    across every non-alphanumeric character including line terminators, so an
    ordinary four-line letter is one 79-character run and every validator says
    no to it;
  * COUNTRY SCOPING, because `111222333` is a valid Dutch BSN *and* a valid
    Czech birth number *and* a valid Slovak one.

Both are asserted here, and so is the degradation when the extra is absent.
"""

from __future__ import annotations

import pytest

from privacy_shield import national
from privacy_shield.scanner import Confidence, PIIType, PrivacyScanner

from corpora_german import CLEAN_ADVERSARIAL, CLEAN_DEV, CLEAN_HELD_OUT
from test_identifier_runs import CLEAN_BUSINESS_CORPUS

CLEAN = list(CLEAN_DEV) + list(CLEAN_HELD_OUT) + list(CLEAN_ADVERSARIAL) + list(
    CLEAN_BUSINESS_CORPUS
)

#: A Dutch BSN, valid under the eleven-test. Also valid as a Czech and a Slovak
#: birth number, which is the whole reason country scoping exists.
AMBIGUOUS = "111222333"

needs_stdnum = pytest.mark.skipif(
    not national.available(), reason="python-stdnum absent; see the degradation test"
)


# ---------------------------------------------------------------------------
# Degradation - this runs with or without the extra
# ---------------------------------------------------------------------------

def test_the_floor_is_correct_without_the_extra(monkeypatch):
    """The base package keeps `dependencies = []`.

    With `python-stdnum` absent this layer produces nothing and no other layer
    changes behaviour. What is lost is a national number that no pattern
    covers; what is NOT lost is the regex/lexicon floor.
    """
    monkeypatch.setenv("PRIVACY_SHIELD_NATIONAL_COUNTRIES", "nl,de")
    monkeypatch.setattr(national, "available", lambda: False)

    assert national.find_national_ids(f"BSN {AMBIGUOUS}") == []

    scanner = PrivacyScanner(min_confidence=Confidence.MEDIUM)
    findings = scanner.scan("Karte 4111 1111 1111 1111").findings
    assert any(f.pii_type is PIIType.CREDIT_CARD for f in findings), (
        "the floor stopped working when the optional extra was unavailable"
    )


def test_nothing_is_enabled_by_default(monkeypatch):
    """No country configured means the layer is OFF, not "all countries".

    Enabling everything manufactures false positives in proportion to the
    number of countries and reports them as detections.
    """
    monkeypatch.delenv("PRIVACY_SHIELD_NATIONAL_COUNTRIES", raising=False)
    assert national.configured_countries() == ()
    assert national.find_national_ids(f"BSN {AMBIGUOUS}") == []


def test_an_unknown_country_code_is_ignored_not_guessed():
    assert national.configured_countries(["zz", "nl", "NL", " de "]) == ("nl", "de")


# ---------------------------------------------------------------------------
# The token pass
# ---------------------------------------------------------------------------

def test_the_run_pass_is_the_wrong_input_and_the_token_pass_is_not():
    """The reason this module exists at all.

    `identifier_runs` yields ONE run for an ordinary letter, because it joins
    over every non-alphanumeric character including terminators. Handed that,
    every stdnum validator answers no - and a measurement over such candidates
    reads zero false positives because it never offered a real candidate.
    """
    from privacy_shield import identifiers

    document = (
        "Sehr geehrte Damen und Herren,\n"
        f"BSN {AMBIGUOUS}\n"
        "Steuer-ID 44 123 456 789\n"
        "Mit freundlichen Gruessen"
    )
    runs = list(identifiers.identifier_runs(document))
    assert len(runs) == 1 and len(runs[0][0]) > 60, (
        "identifier_runs no longer produces one document-wide run; re-check "
        "whether the token pass is still needed"
    )

    tokens = [value for _s, _e, value in national.candidate_tokens(document)]
    assert AMBIGUOUS in tokens, tokens
    assert all(len(t) <= 40 for t in tokens), tokens


def test_the_token_pass_offers_the_number_without_its_label():
    """"BSN 111222333" is a label and a BSN, and no validator accepts it."""
    tokens = [v for _s, _e, v in national.candidate_tokens(f"BSN {AMBIGUOUS}")]
    assert AMBIGUOUS in tokens
    assert f"BSN {AMBIGUOUS}" in tokens  # the joined form is offered too


def test_the_token_pass_spans_printed_grouping():
    """These numbers are printed with spaces and dots."""
    tokens = [v for _s, _e, v in national.candidate_tokens("Nr 44 123 456 789 Ende")]
    assert "44 123 456 789" in tokens, tokens


def test_prose_is_not_offered_to_twenty_seven_validators():
    """A candidate that is mostly letters is prose, not a national number."""
    tokens = [v for _s, _e, v in national.candidate_tokens("Sehr geehrte Damen und Herren")]
    assert tokens == [], tokens


# ---------------------------------------------------------------------------
# Country scoping
# ---------------------------------------------------------------------------

@needs_stdnum
@pytest.mark.parametrize("country", ["nl", "cz", "sk"])
def test_the_same_number_validates_in_three_countries(country):
    """The reason scoping is not optional."""
    found = national.find_national_ids(AMBIGUOUS, countries=[country])
    assert [c for _s, _e, _v, c, _k in found] == [country], found


@needs_stdnum
def test_scoping_excludes_a_country_that_was_not_configured():
    assert national.find_national_ids(AMBIGUOUS, countries=["de"]) == []
    assert national.find_national_ids(AMBIGUOUS, countries=["fr", "it"]) == []


# ---------------------------------------------------------------------------
# Precision, measured rather than adopted
# ---------------------------------------------------------------------------

#: Zero, with EVERY country enabled - which is the worst case, not the
#: intended configuration.
#:
#: The OSS evaluation reported 0 false positives over 951 tokens from 119 clean
#: documents. That did NOT reproduce here as evaluated: over 136 candidate
#: tokens from these 62 clean documents, `de.stnr` produced 14 (it accepts
#: invoice and order numbers), `si.ddv` 3 and `nl.bsn` 3 (stdnum accepts the
#: eight-digit legacy form, and an eight-digit customer number passes an
#: eleven-test about one time in eleven). The first two are dropped - si.ddv
#: and lv.pvn are VAT schemes and contradicted this layer's own person-only
#: rule - and BSN is held to nine digits. The other 21 validators produced
#: none.
NATIONAL_FP_BUDGET = 0


@needs_stdnum
def test_no_national_id_is_found_in_a_document_that_has_none():
    everything = list(national.PERSON_NUMBER_MODULES)
    false_positives = []
    for document in CLEAN:
        for _s, _e, value, country, scheme in national.find_national_ids(
            document, countries=everything
        ):
            false_positives.append((f"{country}.{scheme}", value))
    assert len(false_positives) == NATIONAL_FP_BUDGET, false_positives


@needs_stdnum
def test_the_dropped_validators_stay_dropped():
    """Named, because each was dropped on a measurement or a rule."""
    flat = {
        path
        for modules in national.PERSON_NUMBER_MODULES.values()
        for path, _minimum in modules
    }
    for dropped in ("stdnum.de.stnr", "stdnum.si.ddv", "stdnum.lv.pvn"):
        assert dropped not in flat, f"{dropped} is back; re-measure before keeping it"


@needs_stdnum
def test_a_scheme_is_held_to_its_current_length():
    """BSN's eight-digit legacy form is what produced its false positives."""
    eight_digit = "10023847"
    assert national.find_national_ids(eight_digit, countries=["nl"]) == []
    assert national.find_national_ids(AMBIGUOUS, countries=["nl"])


# ---------------------------------------------------------------------------
# Through the scanner
# ---------------------------------------------------------------------------

@needs_stdnum
def test_a_validated_national_id_reaches_the_overlay(monkeypatch):
    monkeypatch.setenv("PRIVACY_SHIELD_NATIONAL_COUNTRIES", "nl")
    from privacy_shield import scan

    document = scan(f"BSN {AMBIGUOUS} bitte", force_text=True).documents[0]
    assert document.overlay == "BSN [NATIONAL_ID] bitte", document.overlay


@needs_stdnum
def test_a_checksummed_national_id_outranks_an_overlapping_pattern(monkeypatch):
    """It was redacted as a [PHONE].

    The phone pattern overlapped the number and supplied the placeholder, so a
    checksum-validated national identifier was reported as a phone number. The
    same precedence rule that makes a card a card now covers this type.
    """
    monkeypatch.setenv("PRIVACY_SHIELD_NATIONAL_COUNTRIES", "nl")
    scanner = PrivacyScanner(min_confidence=Confidence.MEDIUM)
    kinds = {
        f.pii_type for f in scanner.scan(f"Sozialnummer {AMBIGUOUS}").findings
    }
    assert PIIType.NATIONAL_ID in kinds, kinds
    assert PIIType.PHONE not in kinds, kinds
