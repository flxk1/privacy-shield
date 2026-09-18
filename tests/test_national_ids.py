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

def _valid_in(country, length, seed=1921):
    """A number of *length* digits this country's validator accepts.

    Searched at runtime. Nothing here is written down: a national person
    number that happens to be issued to somebody does not belong in a file.
    """
    import random

    rng = random.Random(seed)
    for _attempt in range(200000):
        candidate = "".join(str(rng.randrange(10)) for _ in range(length))
        if national.find_national_ids(candidate, countries=[country]):
            return candidate
    raise AssertionError(f"no {length}-digit number accepted by {country}")


@needs_stdnum
@pytest.mark.parametrize("country", ["nl", "cz", "sk"])
def test_the_same_number_validates_in_more_than_one_country(country):
    """The reason scoping is not optional.

    The Czech and Slovak birth number are the SAME scheme, so a valid one is
    valid in both registers and nothing in the number says which. The Dutch
    BSN is nine digits against their ten, so the three no longer share a single
    string - they used to share the nine-digit Czech legacy form, which is now
    excluded because it carries no check digit at all.
    """
    shared = _valid_in("cz", 10)
    if country == "nl":
        found = national.find_national_ids(AMBIGUOUS, countries=[country])
        assert [c for _s, _e, _v, c, _k in found] == ["nl"], found
        assert national.find_national_ids(AMBIGUOUS, countries=["cz", "sk"]) == []
        return
    found = national.find_national_ids(shared, countries=[country])
    assert [c for _s, _e, _v, c, _k in found] == [country], found


@needs_stdnum
def test_scoping_excludes_a_country_that_was_not_configured():
    assert national.find_national_ids(AMBIGUOUS, countries=["de"]) == []
    assert national.find_national_ids(AMBIGUOUS, countries=["fr", "it"]) == []


# ---------------------------------------------------------------------------
# Precision, measured rather than adopted
# ---------------------------------------------------------------------------

#: Zero on the 62 hand-written documents below, and that zero is NOT the
#: layer's precision. It was reported as if it were, and it is the fourth
#: reported zero in this package that an independent corpus refuted: those 62
#: documents carry 2.2 candidate tokens each, and German business text carries
#: far more.
#:
#: WIDE_FP_BUDGET is the number that means something. It is measured on 200
#: generated documents built from ordinary German business field shapes -
#: invoice, order, meter, contract, personnel and file numbers - and it is not
#: small.
NATIONAL_FP_BUDGET = 0

#: Every country enabled, on 200 documents of ordinary German business fields.
#:
#: At 0719c79 this was 75. It is lower here despite FIVE validators having been
#: resurrected (at was importing a module that does not exist; ie.pps, es.nie,
#: fi.hetu and the personal codice fiscale could not fire at any input), which
#: is the honest shape of the trade: dropping the company schemes and the
#: check-digit-free legacy forms took more away than the repairs added back.
#:
#:   0719c79   cz.rc 21, hr.oib 17, nl.bsn 12, dk.cpr 11, pt.nif 8, pl.pesel 2,
#:             lt.asmens 1, it.codicefiscale 1, se.personnummer 1, be.nn 1 = 75
#:   here      hr.oib 17, at.vnr 15, nl.bsn 13, dk.cpr 10, pl.pesel 2,
#:             lt.asmens 1, se.personnummer 1, be.nn 1, cz.rc 1 = 61
#:
#: THE NUMBER IS STILL HIGH, and no minimum length will fix it: what remains is
#: ten- and eleven-digit schemes whose mod-11 check accepts about one arbitrary
#: string in eleven. A check digit that weak cannot carry a claim on its own
#: against thousands of candidate tokens. Country scoping is the control that
#: works - Germany alone measures 0, France alone 0, Italy alone 0 - and the
#: only thing that would fix the full-scope number is corroborating evidence
#: near the token, which is a design decision and not a constant.
WIDE_FP_BUDGET = 61


def _wide_clean_corpus():
    """200 clean German business documents, generated, holding no person number.

    Generated rather than written, because 62 hand-written documents is how the
    withdrawn zero happened: a corpus a person writes carries the field shapes
    that person thought of.
    """
    import random

    rng = random.Random(1918)

    def digits(count):
        return "".join(str(rng.randrange(10)) for _ in range(count))

    templates = [
        "Rechnung Nr. {a} vom 14.03.2026, Kundennummer {b}, Auftragsnummer AB-{c}, Lieferschein {e}",
        "Bestellung {a} / Position 0010 / Menge 1200 / Preis 1.349,00 EUR / Beleg {b} / Charge {c}",
        "Sendungsverfolgung: {e}, Paket 2 von 3, Zollanmeldung {b}, Referenz {a}",
        "Vertragsnummer {a} laufend seit 01.01.2019, Kostenstelle {c}, Buchungskreis {c}, Police {b}",
        "Artikelnummern: {a}, {b}, {e}; Lager {c}; Palette {a}",
        "Zaehlerstand {a} abgelesen am 30.04.2026, Vorjahr {b}, Zaehlernummer {e}, Vertrag {c}",
        "Kundenkonto {a} im System SAP, Referenz {e}, Mandant {c}, Buchung {b}",
        "Steuernummer {a}, Handelsregister HRB {c}, Betriebsnummer {b}, Umsatz {e}",
        "Personalnummer {a}, Kostenstelle {c}, Abrechnung 04/2026, Sozialversicherung {b}",
        "Aktenzeichen 4 O 1123/25, Vorgang {a}, Fristnummer {b}, Registernummer {e}",
    ]
    return [
        templates[index % len(templates)].format(
            a=digits(rng.randint(9, 11)), b=digits(rng.randint(8, 11)),
            c=digits(rng.randint(5, 7)), e=digits(rng.randint(10, 13)),
        )
        for index in range(200)
    ]


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
def test_the_full_scope_false_positive_rate_is_what_it_is():
    """The measurement that replaced the withdrawn zero.

    Asserted as a ceiling AND a floor. A ceiling so a regression shows up; a
    floor so that nobody can make this number smaller by killing validators -
    which is exactly how it was 0 before, with five of them dead.
    """
    from collections import Counter

    everything = list(national.PERSON_NUMBER_MODULES)
    documents = _wide_clean_corpus()
    hits = Counter()
    for document in documents:
        for _s, _e, _v, country, scheme in national.find_national_ids(
            document, countries=everything
        ):
            hits[f"{country}.{scheme}"] += 1
    total = sum(hits.values())
    assert total == WIDE_FP_BUDGET, (
        f"{total} false positives on {len(documents)} clean documents with "
        f"every country enabled, recorded as {WIDE_FP_BUDGET}: {dict(hits)}"
    )

    # Scoping is the control that works, and this is the evidence for saying so.
    for scope in (["de"], ["fr"], ["it"]):
        scoped = sum(
            len(national.find_national_ids(document, countries=scope))
            for document in documents
        )
        assert scoped == 0, f"{scope} measured {scoped}, not 0"


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


# ---------------------------------------------------------------------------
# A validator that cannot fire reports no false positives, and means nothing
# ---------------------------------------------------------------------------

def _documented_examples(path):
    """Valid numbers from the stdnum module's OWN doctests.

    Published documentation, read at runtime, never written into this file.
    They are the only thing that can tell this package that one of its minimum
    lengths has made a validator dead: a table entry that can never fire looks
    exactly like a table entry that is simply very precise.
    """
    import importlib
    import re as _re

    module = importlib.import_module(path)
    text = (module.__doc__ or "") + (getattr(module, "validate", None).__doc__ or "")
    quoted = _re.findall(r">>> (?:validate|is_valid|compact)\('([^']+)'\)", text)
    return [value for value in quoted if module.is_valid(value)]


@needs_stdnum
@pytest.mark.parametrize(
    "country, path, minimum",
    [
        (country, path, minimum)
        for country, entries in national.PERSON_NUMBER_MODULES.items()
        for path, minimum in entries
    ],
    ids=lambda value: value if isinstance(value, str) else str(value),
)
def test_every_configured_validator_can_actually_fire(country, path, minimum):
    """End to end, on the library's own documented numbers.

    Four entries could not fire for any input at all, because the minimum
    column was read as a digit COUNT while the values had been taken from the
    scheme's total LENGTH: ie.pps, es.nie, it.codicefiscale and fi.hetu. A
    fifth country, "at", named `stdnum.at.svnr`, which does not exist - the
    module is `stdnum.at.vnr` - and the ImportError was swallowed at debug
    level, so the country validated as configurable and detected nothing.

    Five dead validators, each of them reporting zero false positives.
    """
    examples = _documented_examples(path)
    assert examples, f"{path} documents no valid example to test with"

    # The BARE form. Several modules document their number with the country
    # code in front of it, and a minimum measured off the prefixed form is a
    # minimum no real field can reach: hr.oib is documented as "HR" and eleven
    # digits, so a minimum of thirteen makes a genuine eleven-digit OIB
    # invisible while the entry still looks configured.
    bare = []
    for example in examples:
        stripped = example
        head = "".join(character for character in example if character.isalnum())[:2]
        if head.upper() == country.upper() and head.isalpha():
            stripped = example[example.index(head[1]) + 1:].lstrip(" ./-")
        bare.append(stripped if len(stripped) >= 8 else example)

    shortest = min(bare, key=lambda value: sum(c.isalnum() for c in value))
    size = sum(character.isalnum() for character in shortest)
    if size < minimum:
        assert path in national.DELIBERATELY_ABOVE_A_DOCUMENTED_FORM, (
            f"{path}'s shortest documented number is {size} characters and the "
            f"minimum here is {minimum}; the validator cannot fire on the real "
            "form, and nothing says that was on purpose"
        )

    fired = False
    for example in bare:
        if sum(character.isalnum() for character in example) < minimum:
            continue
        found = national.find_national_ids(
            f"Angaben zur Person {example} Ende", countries=[country]
        )
        if any(value == example for _s, _e, value, _c, _scheme in found):
            fired = True
            break
    assert fired, (
        f"{path} fires on none of its own {len(examples)} documented examples "
        f"at a minimum length of {minimum}; it is configured and dead"
    )


@needs_stdnum
def test_a_module_that_is_not_there_is_a_loud_failure():
    """It was a debug line, which is how "at" stayed dead."""
    original = national.PERSON_NUMBER_MODULES["cy"]
    national.PERSON_NUMBER_MODULES["cy"] = (("stdnum.cy.no_such_module", 8),)
    try:
        with pytest.raises(national.MissingValidator):
            list(national._validators(["cy"]))
    finally:
        national.PERSON_NUMBER_MODULES["cy"] = original


@needs_stdnum
def test_no_company_identifier_is_configured_as_a_person_number():
    """The inversion si.ddv and lv.pvn were dropped for, applied to the rest.

    `es.nif` accepts the CIF and `pt.nif` shares its format and its check digit
    with the NIPC, both company identifiers, so neither can be scoped to a
    person. The Italian codice fiscale CAN be: its eleven-digit form is a
    partita IVA and its sixteen-character form is the personal one, so the
    length separates them and the personal one is what is configured.
    """
    configured = {
        path for entries in national.PERSON_NUMBER_MODULES.values()
        for path, _minimum in entries
    }
    for company_scheme in ("stdnum.es.nif", "stdnum.pt.nif", "stdnum.si.ddv",
                           "stdnum.lv.pvn", "stdnum.de.stnr"):
        assert company_scheme not in configured, (
            f"{company_scheme} identifies an organisation, or was dropped on a "
            "measurement; re-measure before putting it back"
        )

    company_forms = [
        example for example in _documented_examples("stdnum.it.codicefiscale")
        if sum(character.isalnum() for character in example) == 11
    ]
    assert company_forms, "the case this guards has gone from stdnum's examples"
    for form in company_forms:
        assert not national.find_national_ids(
            f"Partita IVA {form}", countries=["it"]
        ), "a company identifier was claimed as a person number"


@needs_stdnum
def test_candidate_tokens_is_not_superlinear():
    """It enumerated every sub-token pair, building a slice and running a regex
    substitution over each one BEFORE testing the length, and never stopped
    once a candidate was past the maximum.

    Extracted text is the worst case, because `pdftotext` writes long runs of
    space-separated tokens and a space is one of the characters a national
    number may be printed with. Measured on comma-free extracted text at
    0719c79: 0.5 KB 0.013s, 1 KB 0.125s, 2 KB 0.724s, 4 KB 6.954s - about ten
    times per doubling. Here: 0.001s at 4 KB, with the candidate set identical
    at every size.

    Third instance in this package of a gate too slow to run, which is a gate
    that gets bypassed.
    """
    import random
    import time

    rng = random.Random(7)
    words = ["Rechnung", "Nr", "2026-004871", "Kunde", "44 123 456 789",
             "Betrag", "1.349", "EUR", "Mustermann", "GmbH", "Auftrag", "AB-99213"]
    parts = []
    while len(" ".join(parts)) < 4096:
        parts.append(rng.choice(words))
    document = " ".join(parts)

    started = time.perf_counter()
    tokens = national.candidate_tokens(document)
    elapsed = time.perf_counter() - started
    assert tokens, "the pass found nothing at all, so the timing means nothing"
    assert elapsed < 1.0, (
        f"4 KB of extracted text took {elapsed:.2f}s in candidate_tokens; "
        "the pair enumeration is back"
    )
