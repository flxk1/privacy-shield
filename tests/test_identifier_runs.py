"""Precision of the anchor-free identifier pass.

The leak invariant proves the pass finds what it must. This file holds the
other half of the bargain: what it costs. Detecting on maximal runs instead of
`\\b`-delimited tokens means offering the validator candidates a boundary would
never have produced, and some of them check out by coincidence. The numbers
below were measured, not guessed, and they are asserted so that a later change
which widens them fails here rather than quietly shredding overlays.
"""

from __future__ import annotations

import random
import re
import unicodedata

import pytest

from privacy_shield import identifiers
from privacy_shield.scanner import Confidence, PIIType, PrivacyScanner

# Published test vectors: the ECBS specimen IBAN and the reserved test card
# number every payment SDK documents. No other identifier literals in this file.
EXAMPLE_IBAN = "DE89370400440532013000"
EXAMPLE_CARD = "4111111111111111"


# ---------------------------------------------------------------------------
# A corpus of realistic German business text carrying NO payment identifier.
# Every IBAN or card finding on this corpus is therefore a false positive.
# ---------------------------------------------------------------------------

CLEAN_BUSINESS_CORPUS = [
    "Rechnung Nr. 2026-004871 vom 14.03.2026, Kundennummer 10023847, "
    "Auftragsnummer AB-99213, Lieferschein 7741200938455102.",
    "Sehr geehrte Frau Dr. Schneider,\nunsere Steuernummer lautet 12 345 678 901, "
    "die USt-IdNr. DE812526315.\nTelefon: 089 12345678, Fax: 089 12345679.",
    "Bestellung 4400218836 / Position 0010 / Menge 1200 / Preis 1.349,00 EUR",
    "Sendungsverfolgung: 00340434161094015123, Paket 2 von 3.",
    "Vertragsnummer 8811 2299 3344 5566 laufend seit 01.01.2019.",
    "Mitarbeiter-ID 4711, Kostenstelle 65000, Buchungskreis 1000, Beleg 5100004821.",
    "Artikelnummern: 4029764001807, 4006381333931, 4007817327104",
    "Protokoll vom 03.06.2026: Anwesend Herr Weber, Frau Klein, Herr Dr. Baumann.\n"
    "Beschluss 12/2026 einstimmig angenommen.",
    "git commit a3f19c8e4b2d7f60a1c5e93b8d4f2a70c6e1b5d9 ueberprueft",
    "UUID 550e8400-e29b-41d4-a716-446655440000 im Ticket JIRA-4821 vermerkt.",
    "Zaehlerstand 0088123456 abgelesen am 30.04.2026, Vorjahr 0087001299.",
    "IMEI 356938035643809 des Diensthandys, Seriennummer SN7741900238.",
    "Lagerbestand: 100234 Stueck, Charge 20260415, Palette 778812349900217",
    "Betrag 1.234,56 EUR, Skonto 2%, Zahlungsziel 30 Tage netto.",
    "Aktenzeichen 4 O 1123/25 LG Muenchen I, Termin 12.09.2026 um 09:30 Uhr.",
    "Grundbuchblatt 12345, Flurstueck 88/12, Gemarkung Musterhausen.",
    "Handelsregister HRB 123456 B, Amtsgericht Charlottenburg.",
    "Kundenkonto 300124558899 im System SAP, Referenz 9900112233445566778",
    "Telefonliste: 0170 1234567, 0171 7654321, 0160 11223344, 030 90212345",
    "Wareneingang 20260512 Beleg 5000123456 Menge 48 Einzelpreis 12,90",
]

#: Measured over-redaction budget on the corpus above. Cards only. Two shapes:
#: a Luhn-valid window inside a longer digit run (tracking numbers, IMEIs, long
#: internal references), and a window assembled across ONE separator out of two
#: adjacent numbers in a list.
#:
#: This rose from six when gaps of more than one character were admitted, which
#: had to happen - a column gap is the commonest extraction artefact there is
#: and four such shapes leaked whole card numbers. Refusing the assembly case
#: as well would mean requiring both edges of a candidate to sit on a group
#: boundary, and that refuses a glued prefix on a spaced number, which is the
#: leak this detector exists for. Fail-closed wins; the bill is here.
CARD_FALSE_POSITIVE_BUDGET = 8

#: Zero. The ISO 13616 country/length constraint is what buys this: mod-97 over
#: unconstrained lengths fired on ordinary German prose ("Wareneingang 20260512
#: Beleg ...", where "ng20..." starts a 23-character window that checks out) and
#: swallowed the line.
IBAN_FALSE_POSITIVE_BUDGET = 0


#: Text built to provoke a false positive: digit groups punctuated the way
#: tables, CSV exports, version strings, timestamps and serial numbers are.
#: The realistic corpus above says what the rule costs in ordinary documents;
#: this says what it costs when someone is trying to break it.
ADVERSARIAL_FP_CORPUS = [
    "Preise: 1234,5678,9012,3456 in der Tabelle",
    "Version 10.4.2.1 Build 2026.03.14.1157",
    "IP 192.168.100.201 Port 8080 PID 44213",
    "CSV: 1001,2002,3003,4004,5005,6006,7007",
    "Koordinaten 52.520008, 13.404954 Berlin Mitte",
    "Zeitreihe: 12:34:56.789 | 23:45:01.234 | 34:56:12.345",
    "Matrix [[1234][5678][9012][3456]] Ausgabe",
    "Pfad /var/log/2026/03/14/app-1234-5678-9012.log",
    "SHA 3f2a.9b1c.4d7e.8a0f.2c5b.6e9d.1a4f.7b2c",
    "Telefonnummern 030/1234567, 089/7654321, 0170/1112223",
    "Betrag 1.234.567,89 EUR; Rabatt 12.345,67 EUR; Netto 1.222.222,22 EUR",
    "Artikel 4029764001807, 4006381333931, 4007817327104, 4011200296908",
    "Datum 14.03.2026 Zeit 09:30:45 Ticket 1234-5678-9012",
    "Seriennummern: SN-1234-5678-9012-3456-7890",
    "Hex 0x4111.0x1111.0x1111.0x1111 im Dump",
]

#: Measured on documents built specifically to provoke one. Every hit is a
#: comma-, colon- or hyphen-separated digit block that is structurally
#: indistinguishable from a grouped card number satisfying Luhn - which is what
#: they are designed to be. No IBAN false positives, because the ISO 13616
#: country/length registry rules them out.
ADVERSARIAL_CARD_FP_BUDGET = 8
ADVERSARIAL_IBAN_FP_BUDGET = 0


def test_precision_under_deliberately_hostile_punctuation():
    """What widening the joiner rule costs when someone is trying to break it.

    Admitting every non-alphanumeric character as a joiner is what made
    "4111_1111_1111_1111" findable. The bill for it is here, measured rather
    than asserted to be zero.
    """
    cards = sum(len(identifiers.find_cards(d)) for d in ADVERSARIAL_FP_CORPUS)
    ibans = sum(len(identifiers.find_ibans(d)) for d in ADVERSARIAL_FP_CORPUS)
    assert cards == ADVERSARIAL_CARD_FP_BUDGET, (
        f"{cards} card false positives on {len(ADVERSARIAL_FP_CORPUS)} hostile "
        f"documents, budget {ADVERSARIAL_CARD_FP_BUDGET}"
    )
    assert ibans == ADVERSARIAL_IBAN_FP_BUDGET, (
        f"{ibans} IBAN false positives, budget {ADVERSARIAL_IBAN_FP_BUDGET}"
    )


def test_iban_precision_on_clean_business_text():
    total = sum(len(identifiers.find_ibans(doc)) for doc in CLEAN_BUSINESS_CORPUS)
    assert total == IBAN_FALSE_POSITIVE_BUDGET, (
        f"{total} IBAN false positives on {len(CLEAN_BUSINESS_CORPUS)} clean "
        f"documents, budget {IBAN_FALSE_POSITIVE_BUDGET}"
    )


def test_card_precision_on_clean_business_text():
    """The accepted cost, pinned.

    A Luhn-valid 16-digit window inside a longer digit run is redacted. The
    alternative - an issuer-prefix table - would cut this to about one in
    twenty, and would put a stale BIN range between a real card and the gate.
    One extra correctly-typed placeholder on a tracking number is survivable;
    a card number in a cloud payload is not.
    """
    per_document = [len(identifiers.find_cards(doc)) for doc in CLEAN_BUSINESS_CORPUS]
    total = sum(per_document)
    assert total == CARD_FALSE_POSITIVE_BUDGET, (
        f"{total} card false positives on {len(CLEAN_BUSINESS_CORPUS)} clean "
        f"documents, budget {CARD_FALSE_POSITIVE_BUDGET}; per document: {per_document}"
    )


def test_over_redaction_never_eats_a_word():
    """Over-redaction has to stay inside the number it hit.

    The bound that matters is not a percentage of the document - it is that a
    false positive can only ever consume digits and the separators written
    inside a number. A run ends at any other character, so a claim can never
    reach into prose. If that stops being true, over-redaction has turned into
    the overlay damage item 6 was about.
    """
    for document in CLEAN_BUSINESS_CORPUS:
        for start, end, _text in (
            identifiers.find_ibans(document) + identifiers.find_cards(document)
        ):
            claimed = document[start:end]
            assert not any(char.isalpha() for char in claimed), (
                f"a false positive reached into prose: {claimed!r}"
            )


# ---------------------------------------------------------------------------
# What the run-based pass must find, independent of the whole pipeline
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "prefix",
    ["acct_", "Rechnung2026", "id-a3f", "Konto=20", "Gesch=E4ftskonto=20", "x", "7"],
)
def test_iban_found_behind_any_glued_prefix(prefix):
    spans = identifiers.find_ibans(prefix + EXAMPLE_IBAN)
    assert len(spans) == 1, spans
    start, end, _value = spans[0]
    assert start == len(prefix), "the prefix is not part of the identifier"
    assert end == len(prefix) + len(EXAMPLE_IBAN)


@pytest.mark.parametrize(
    "prefix",
    ["acct_", "Rechnung2026", "id-a3f", "Konto=20", "Gesch=E4ftskonto=20", "x", "7"],
)
def test_card_found_behind_any_glued_prefix(prefix):
    """Every digit of the card must be covered, and the alphabetic prefix kept.

    Not "the span equals the card": where the prefix ends in digits there is
    nothing in the text that says where the document number stops and the card
    begins, so the claim absorbs the adjacent digits. What must never happen is
    a claim that covers the card only partially - the first version picked the
    leftmost-longest window and left the last digit standing.
    """
    text = prefix + EXAMPLE_CARD
    spans = identifiers.find_cards(text)
    assert spans, "no candidate was offered to Luhn at all"
    for index in range(len(prefix), len(text)):
        assert any(start <= index < end for start, end, _ in spans), (
            f"character {index} of the card is not covered by any claim"
        )
    trailing_digits = len(prefix) - len(prefix.rstrip("0123456789"))
    earliest = min(start for start, _end, _text in spans)
    assert earliest >= len(prefix) - trailing_digits, (
        "a claim reached back past the prefix's own trailing digits"
    )


def test_spaced_identifier_span_covers_its_separators():
    text = "acct_DE89 3704 0044 0532 0130 00 freigegeben"
    spans = identifiers.find_ibans(text)
    assert len(spans) == 1, spans
    start, end, _value = spans[0]
    assert text[start:end] == "DE89 3704 0044 0532 0130 00"


def test_a_run_crosses_a_newline_and_the_bounds_are_what_hold_it():
    """Reversal. A newline used to end a run and that was a leak class.

    Two unrelated numbers on two lines ARE now one run - what stops them being
    claimed as one identifier is the span bound and the interior-group bound,
    not the line break. Admitting the newline moved no false-positive budget:
    eight cards and no IBANs on the realistic corpus, eight on the hostile one,
    zero across the forty-two German documents.
    """
    runs = list(identifiers.identifier_runs("DE89 3704\n0044 0532"))
    assert len(runs) == 1, runs
    # ...and the bounds still refuse an identifier assembled out of two lines
    # of a table column.
    assert not identifiers.find_cards(
        "4029764001807\n4006381333931\n4007817327104"
    )


def test_unregistered_country_code_is_not_an_iban():
    """mod-97 alone is not the specification.

    "ID 4111..." compacts to eighteen characters that pass mod-97 by
    coincidence. Indonesia has no IBAN, so this is not one - and claiming it as
    one cost the card number underneath it its own type.
    """
    assert not identifiers.find_ibans(f"ID {EXAMPLE_CARD}")
    assert identifiers.find_cards(f"ID {EXAMPLE_CARD}")


def test_email_found_behind_a_non_ascii_word_character():
    spans = identifiers.find_emails("Muelleräerika@example.com")
    assert len(spans) == 1, spans
    assert spans[0][2] == "erika@example.com"


def test_email_prefix_that_is_part_of_the_address_is_kept():
    """"acct_erika@example.com" IS the address, not a prefix plus an address."""
    spans = identifiers.find_emails("acct_erika@example.com")
    assert len(spans) == 1, spans
    assert spans[0][2] == "acct_erika@example.com"


def test_the_scanner_itself_reports_a_glued_identifier():
    """Wiring, not just the module: the pass has to reach PrivacyScanner.scan.

    The module can be perfect and the product still leak if nothing calls it.
    """
    scanner = PrivacyScanner(min_confidence=Confidence.MEDIUM)
    findings = scanner.scan(f"acct_{EXAMPLE_IBAN} und x{EXAMPLE_CARD}").findings
    assert any(
        f.pii_type is PIIType.IBAN and f.value == EXAMPLE_IBAN for f in findings
    ), [f.to_dict()["type"] for f in findings]
    assert any(
        f.pii_type is PIIType.CREDIT_CARD and f.value == EXAMPLE_CARD for f in findings
    ), [f.to_dict()["type"] for f in findings]


# ---------------------------------------------------------------------------
# Separators, generated rather than listed
# ---------------------------------------------------------------------------
#
# This is the test that would have caught the underscore, and it is the same
# lesson as the oracle: a check built from a list I typed can only find the
# cases I already thought of. Twice a list was walked around - first the
# literal " \t-", then the Unicode categories Zs/Pd/Cf, which missed Pc
# (underscore) and Po (colon, dot, slash). So the candidates here are ENUMERATED
# FROM UNICODE ITSELF: every non-alphanumeric character in the BMP, sampled
# across every category that exists, rather than the handful anyone would list.

def _all_joiner_candidates():
    """Every non-alphanumeric, non-line-break character in the BMP, by category.

    Built from `unicodedata`, not from a literal. If Unicode grows a new
    punctuation category tomorrow, this picks it up without anyone editing a
    list.
    """
    by_category: dict[str, list[str]] = {}
    for code in range(0x20, 0x10000):
        char = chr(code)
        if char.isalnum() or char in identifiers._LINE_BREAKS:
            continue
        if not unicodedata.category(char)[0] in ("P", "S", "Z", "C"):
            continue
        if unicodedata.category(char) == "Cf":
            continue  # invisible; covered by its own test
        if not char.isprintable() and char != "\t":
            continue
        by_category.setdefault(unicodedata.category(char), []).append(char)
    return by_category


JOINER_CATEGORIES = _all_joiner_candidates()


def test_the_generated_joiner_set_covers_the_categories_that_were_missed():
    """Guards the generator itself.

    A generator that silently produced nothing would make every test below
    vacuous - which is exactly how the last oracle passed while leaking.
    """
    assert "Pc" in JOINER_CATEGORIES, "underscore's category is not represented"
    assert "Po" in JOINER_CATEGORIES, "colon/dot/slash's category is not represented"
    assert "Zs" in JOINER_CATEGORIES and "Pd" in JOINER_CATEGORIES
    assert "_" in JOINER_CATEGORIES["Pc"]
    assert set(":./") <= set(JOINER_CATEGORIES["Po"])
    assert len(JOINER_CATEGORIES) >= 8, sorted(JOINER_CATEGORIES)


@pytest.mark.parametrize("category", sorted(JOINER_CATEGORIES))
def test_every_joiner_category_groups_an_identifier(category):
    """One sampled character from every category, on both identifier types.

    Sampled deterministically so a failure names a reproducible character.
    """
    rng = random.Random(f"joiner-{category}")
    sample = rng.sample(
        JOINER_CATEGORIES[category], min(12, len(JOINER_CATEGORIES[category]))
    )
    failures = []
    for joiner in sample:
        grouped_card = joiner.join(EXAMPLE_CARD[i:i + 4] for i in range(0, 16, 4))
        grouped_iban = joiner.join(EXAMPLE_IBAN[i:i + 4] for i in range(0, 20, 4))
        grouped_iban += joiner + EXAMPLE_IBAN[20:]
        if not identifiers.find_cards(grouped_card):
            failures.append(("card", hex(ord(joiner)), unicodedata.name(joiner, "?")))
        if not identifiers.find_ibans(grouped_iban):
            failures.append(("iban", hex(ord(joiner)), unicodedata.name(joiner, "?")))
    assert not failures, (
        f"a {category} character between the groups hid the identifier: {failures}"
    )


@pytest.mark.parametrize("category", sorted(JOINER_CATEGORIES))
def test_a_glued_prefix_plus_any_joiner_still_finds_the_identifier(category):
    """The combination that defeated both previous rules at once."""
    rng = random.Random(f"prefix-{category}")
    for joiner in rng.sample(
        JOINER_CATEGORIES[category], min(8, len(JOINER_CATEGORIES[category]))
    ):
        text = "acct_" + joiner.join(
            EXAMPLE_CARD[i:i + 4] for i in range(0, 16, 4)
        )
        assert identifiers.find_cards(text), (
            f"prefix + {hex(ord(joiner))} "
            f"({unicodedata.name(joiner, '?')}) hid the card"
        )


def test_the_layout_bounds_reject_assembled_prose():
    """What keeps "anything non-alphanumeric, however much of it" in check.

    One bound does the work: where a candidate covers three groups or more the
    INTERIOR ones must be small, because an interior group is never clipped by
    the candidate's edges and so is a whole token - four digits in a real
    layout, thirteen in a list of article numbers. The span bound is a
    far-off backstop rather than a discriminator; sweeping it changes no
    false-positive count at all.
    """
    # Single-character groups ARE accepted, and that is a reversal worth
    # naming: text punctuated down to singles ("4.1.1.1...") is redacted along
    # with the letter-spaced form field it is indistinguishable from. The bound
    # that refused both was removed when the form field turned out to leak a
    # whole card number.
    assert identifiers.find_cards(".".join(EXAMPLE_CARD))
    assert identifiers.find_cards(" ".join(EXAMPLE_CARD))
    # An interior group is a whole token, so where a candidate covers three
    # groups or more the middle ones must be small. A list of thirteen-digit
    # article codes must not be claimed as one card spanning all of them.
    for _start, _end, claimed in identifiers.find_cards(
        "Artikel 4029764001807, 4006381333931, 4007817327104, 4011200296908"
    ):
        groups = [len(part) for part in re.split(r"[^0-9]+", claimed) if part]
        assert len(groups) <= 2 or max(groups[1:-1]) <= 6, groups

    # Every real layout, including wide and mixed gaps.
    for gap in (" ", "  ", "   ", "         ", ". ", " | ", "\t\t"):
        assert identifiers.find_cards(
            gap.join(EXAMPLE_CARD[i:i + 4] for i in range(0, 16, 4))
        ), f"gap {gap!r} hid the card"
    assert identifiers.find_cards(
        " ".join(EXAMPLE_CARD[i:i + 2] for i in range(0, 16, 2))
    )
    assert identifiers.find_cards("3782 822463 10005")  # Amex 4-6-5
    assert identifiers.find_cards(EXAMPLE_CARD)         # solid


@pytest.mark.parametrize("local_length", [60, 242, 243, 250, 300])
def test_a_long_local_part_does_not_truncate_the_domain(local_length):
    """The reported shortfall, with the input that produces it.

    `email_ok` caps the whole address at RFC 5321's 254 characters. Using it to
    choose where the address ENDS made the search shorten the domain to get
    under the cap, so a 243-character local part gave a span ending
    "...aaa@example.co" and left the final "m" of the TLD behind. Silent,
    because "example.co" is a valid domain shape. The threshold was exact: 242
    clean, 243 and above short.
    """
    text = "Kontakt " + ("a" * local_length) + "@example.com bitte"
    spans = identifiers.find_emails(text)
    assert spans, "no address found at all"
    claimed = spans[0][2]
    assert claimed.endswith("@example.com"), (
        f"the domain was truncated to {claimed[-16:]!r}"
    )
    assert text[spans[0][1]:] == " bitte", (
        f"the span stopped short, leaving {text[spans[0][1]:][:4]!r} behind"
    )


def test_a_claimed_address_is_never_shorter_than_the_longest_valid_one():
    """The claimed span must reach the end of the TLD, not stop one short.

    Reported as leaving a trailing letter on long local parts. It could not be
    reproduced - not over four thousand generated addresses here, nor
    end-to-end with an adjacent name - so this pins the property rather than a
    repair, and will fail if a shape that does it ever turns up.

    The comparison is against a brute-force search that tries every substring
    around the "@", so it shares nothing with the expansion under test.
    """
    rng = random.Random(3)
    alphabet = "abcdefghijkmnopqrstuvwxyz0123456789._%+-"
    shortfalls = []
    for _ in range(2000):
        local = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 20)))
        domain = "".join(
            rng.choice("abcdefghijkmnopqrstuvwxyz0123456789-")
            for _ in range(rng.randint(1, 12))
        )
        tld = "".join(
            rng.choice("abcdefghijkmnopqrstuvwxyz") for _ in range(rng.randint(2, 6))
        )
        prefix = rng.choice(["", "Kontakt: ", "acct_", "7", "x", "Muellerä", "<"])
        suffix = rng.choice(["", ".", ",", ")", ">", " ende", "-x", ".txt"])
        text = f"{prefix}{local}@{domain}.{tld}{suffix}"

        claimed = max(
            (span[2] for span in identifiers.find_emails(text)), key=len, default=""
        )
        best = max((c for c, _ in _brute_force_addresses(text)), key=len, default="")
        if best and len(claimed) < len(best):
            shortfalls.append((text, best, claimed))
    assert not shortfalls, shortfalls[:3]


def _brute_force_addresses(text):
    """Every RFC-shaped address, by trying every substring around each "@"."""
    from privacy_shield.identifiers import RFC_EMAIL

    found = []
    for at, char in enumerate(text):
        if char != "@":
            continue
        for begin in range(max(0, at - 64), at):
            for finish in range(min(len(text), at + 255), at + 1, -1):
                candidate = text[begin:finish]
                if len(candidate) <= 254 and RFC_EMAIL.match(candidate):
                    found.append((candidate, candidate))
                    break
            if found and found[-1][0].index("@") == at - begin:
                break
    return found


@pytest.mark.parametrize("size", [800, 1600, 3200])
def test_one_long_line_does_not_stall_the_egress_path(size):
    """A gate nobody can afford to run gets bypassed.

    `find_emails` tried every (start, end) pair around each "@", which is cubic
    in the length of one line: 1.6 KB took 8 seconds and 2.4 KB took 27, on the
    egress path. A log line or a wide `pdftotext` row stalled the gate for
    minutes. The local part and the domain are independent given the "@", so
    each is found in one pass.

    The bound is deliberately loose - this asserts the shape of the cost, not a
    machine's speed.
    """
    import time

    from privacy_shield.scanner import scan_text

    text = "a" * size + "@" + "b" * size
    started = time.perf_counter()
    scan_text(text)
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0, (
        f"{2 * size + 1} characters took {elapsed:.1f}s; the superlinear "
        "email search is back"
    )


def test_the_email_search_is_still_correct_after_being_made_linear():
    for text, expected in [
        ("erika@example.com", ["erika@example.com"]),
        ("acct_erika@example.com", ["acct_erika@example.com"]),
        ("Muelleräerika@example.com", ["erika@example.com"]),
        ("erika@example.com.", ["erika@example.com"]),
        ("Mail erika.mustermann@example.com, danke", ["erika.mustermann@example.com"]),
    ]:
        assert [v for _s, _e, v in identifiers.find_emails(text)] == expected, text
    # Two addresses run together are still covered whole, both of them.
    spans = identifiers.find_emails("abcdef1234@example.comabcdef1234@example.com")
    covered = set()
    for start, end, _v in spans:
        covered.update(range(start, end))
    assert covered == set(range(44)), sorted(set(range(44)) - covered)
