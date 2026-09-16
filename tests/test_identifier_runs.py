"""Precision of the anchor-free identifier pass.

The leak invariant proves the pass finds what it must. This file holds the
other half of the bargain: what it costs. Detecting on maximal runs instead of
`\\b`-delimited tokens means offering the validator candidates a boundary would
never have produced, and some of them check out by coincidence. The numbers
below were measured, not guessed, and they are asserted so that a later change
which widens them fails here rather than quietly shredding overlays.
"""

from __future__ import annotations

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

#: Measured over-redaction budget on the corpus above. Cards only, and only
#: where a Luhn-valid window sits inside a longer digit run - tracking numbers,
#: IMEIs, long internal references. Raising this number means the pass started
#: eating business data; lowering it is welcome, and should come with the
#: measurement that earned it.
CARD_FALSE_POSITIVE_BUDGET = 6

#: Zero. The ISO 13616 country/length constraint is what buys this: mod-97 over
#: unconstrained lengths fired on ordinary German prose ("Wareneingang 20260512
#: Beleg ...", where "ng20..." starts a 23-character window that checks out) and
#: swallowed the line.
IBAN_FALSE_POSITIVE_BUDGET = 0


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
            assert all(char.isdigit() or char in " \t-" for char in claimed), (
                f"a false positive claimed non-numeric text: {claimed!r}"
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


def test_a_run_does_not_cross_a_newline():
    """Two unrelated numbers on two lines must not be spliced into one run."""
    runs = list(identifiers.identifier_runs("DE89 3704\n0044 0532"))
    assert len(runs) == 2, runs


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
