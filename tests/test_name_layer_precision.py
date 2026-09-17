"""Precision and recall of the name layer, measured and pinned.

This layer was the release blocker. German capitalises every noun, so the two
capitalisation patterns that used to carry it claimed 75% of every character of
ordinary business documents containing no personal data at all - 121 spans
across twenty documents, 90% on one memo. The overlay is what the cloud model
receives, so that is not over-redaction; it is deletion, and a tool that
deletes the document gets switched off in the first week.

Measured BEFORE the change, with the capitalisation patterns in place:

                        clean docs          documents with names
                        FP spans  char loss  recall  precision
    development            73        75%       86%      24%
    held out               48        76%       89%      25%

Measured AFTER, with names found by evidence (see names.py):

                        FP spans  char loss  recall  precision
    development             0         0%      100%     100%
    held out                0         0%      100%     100%

Recall did not fall. That is not a free lunch, it is a measurement artefact
worth naming: the old spans were so large that they overlapped real names by
accident while destroying everything around them, so "recall" was being paid
for at 4:1 against precision.

THE REAL RECALL COST is a shape the corpora cannot show by counting, so it is
asserted directly below: a bare surname in running prose, with no title, no
signature block, no addressee position and no known given name in front of it,
is NOT found. "Die Pruefung durch Weber ergab" is invisible to this layer.
That is the trade, it is deliberate, and the owner decides whether it is
acceptable - not this file.
"""

from __future__ import annotations

import pytest

from corpora_german import (
    CLEAN_DEV,
    CLEAN_HELD_OUT,
    NAMED_DEV,
    NAMED_HELD_OUT,
)
from privacy_shield.scanner import Confidence, PIIType, PrivacyScanner


def _name_chars(text, scanner):
    chars = set()
    spans = 0
    for finding in scanner.scan(text).findings:
        if finding.pii_type is PIIType.NAME:
            chars.update(range(finding.start, finding.end))
            spans += 1
    return chars, spans


@pytest.fixture
def scanner():
    return PrivacyScanner(min_confidence=Confidence.MEDIUM)


@pytest.mark.parametrize(
    "corpus, label",
    [(CLEAN_DEV, "development"), (CLEAN_HELD_OUT, "held out")],
)
def test_no_name_is_claimed_in_a_document_that_has_none(corpus, label, scanner):
    """Zero, not "fewer". A clean document must come back whole.

    The held-out half was written before the rule and not looked at while it
    was being shaped.
    """
    offenders = []
    for text in corpus:
        chars, spans = _name_chars(text, scanner)
        if spans:
            offenders.append((spans, len(chars), text[:60]))
    assert not offenders, (
        f"{label}: name layer claimed text in documents containing no personal "
        f"data: {offenders}"
    )


@pytest.mark.parametrize(
    "corpus, label",
    [(NAMED_DEV, "development"), (NAMED_HELD_OUT, "held out")],
)
def test_names_are_found_where_names_actually_occur(corpus, label, scanner):
    """Salutation, signature block, address block, after a title, in prose."""
    missed = []
    for text, truth in corpus:
        chars, _spans = _name_chars(text, scanner)
        for start, end, value in truth:
            if not any(index in chars for index in range(start, end)):
                missed.append((value, text[:50]))
    assert not missed, f"{label}: names not found: {missed}"


@pytest.mark.parametrize(
    "corpus, label",
    [(NAMED_DEV, "development"), (NAMED_HELD_OUT, "held out")],
)
def test_nothing_but_the_name_is_claimed(corpus, label, scanner):
    """Precision at character level: the title, the role and the noun stay."""
    extra = []
    for text, truth in corpus:
        chars, _spans = _name_chars(text, scanner)
        truth_chars = set()
        for start, end, _value in truth:
            truth_chars.update(range(start, end))
        surplus = chars - truth_chars
        if surplus:
            extra.append((text[min(surplus):max(surplus) + 1], text[:50]))
    assert not extra, f"{label}: claimed more than the name: {extra}"


def test_the_recall_this_buys_the_precision_with(scanner):
    """The stated cost, asserted so it cannot drift unnoticed in either
    direction.

    A bare surname in running prose has no evidence around it and is not
    found. If a future change starts finding these, the clean-corpus tests
    above are what stop it being paid for with the document again - and this
    test failing is the signal to re-measure and re-state the trade.
    """
    invisible = [
        "Die Pruefung durch Weber ergab keine Beanstandung.",
        "Nach Ruecksprache mit Schneider wurde entschieden.",
        "Der Vorgang liegt bei Hoffmann.",
    ]
    for text in invisible:
        chars, _spans = _name_chars(text, scanner)
        assert not chars, (
            f"a bare surname in prose is now found in {text!r} - re-measure "
            "the clean corpora and re-state the trade before keeping this"
        )


def test_a_title_is_evidence_and_is_not_itself_redacted():
    """"Herr" is not personal data. It is the reason the next word is."""
    scanner = PrivacyScanner(min_confidence=Confidence.MEDIUM)
    document = "Sehr geehrter Herr Dr. Baumann,"
    findings = [
        f for f in scanner.scan(document).findings if f.pii_type is PIIType.NAME
    ]
    assert [f.value for f in findings] == ["Baumann"], [
        (f.value, f.start, f.end) for f in findings
    ]


def test_the_signature_role_and_department_are_not_claimed():
    """Only the first name-shaped line after a closing belongs to a person."""
    scanner = PrivacyScanner(min_confidence=Confidence.MEDIUM)
    document = (
        "Mit freundlichen Gruessen\n"
        "Laura Wagner\n"
        "Leiterin Einkauf\n"
        "Abteilung Beschaffung\n"
    )
    findings = [
        f for f in scanner.scan(document).findings if f.pii_type is PIIType.NAME
    ]
    assert [f.value for f in findings] == ["Laura Wagner"], [
        f.value for f in findings
    ]


# ---------------------------------------------------------------------------
# The rule must do what its docstring says
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        pytest.param("Max. Laufzeit 36 Monate", id="max_as_maximal"),
        pytest.param("Rechnungsdatum: Jan 2026", id="jan_as_januar"),
        pytest.param("Frank furt am Main", id="given_name_then_lowercase"),
        pytest.param("Lieferung bis Mai 2026", id="month"),
        pytest.param("Die Marie-Curie-Strasse ist gesperrt", id="street_named_after"),
    ],
)
def test_a_bare_given_name_without_a_surname_is_not_a_name(text):
    """GIVEN requires the surname its docstring promises.

    The first version claimed the given name whether or not one followed, so
    the shipped rule was "a known given name, OPTIONALLY followed by
    capitalised words". "Max." for maximal and "Jan" for Januar are in every
    German offer, invoice and specification.
    """
    scanner = PrivacyScanner(min_confidence=Confidence.MEDIUM)
    claimed = [
        f.value for f in scanner.scan(text).findings if f.pii_type is PIIType.NAME
    ]
    assert not claimed, claimed


@pytest.mark.parametrize(
    "line",
    [
        "Abteilung Vertrieb",
        "Leitung Einkauf",
        "Zentrale Verwaltung",
        "Sekretariat Geschaeftsfuehrung",
    ],
)
def test_a_department_does_not_sign_a_letter(line):
    """The docstring said roles and departments are evidence, not data."""
    scanner = PrivacyScanner(min_confidence=Confidence.MEDIUM)
    text = f"Mit freundlichen Gruessen\n{line}\n"
    claimed = [
        f.value for f in scanner.scan(text).findings if f.pii_type is PIIType.NAME
    ]
    assert not claimed, claimed


def test_a_person_still_signs_a_letter():
    """The department exclusion must not cost the signature rule."""
    scanner = PrivacyScanner(min_confidence=Confidence.MEDIUM)
    text = "Mit freundlichen Gruessen\nLaura Wagner\nLeiterin Einkauf\n"
    claimed = [
        f.value for f in scanner.scan(text).findings if f.pii_type is PIIType.NAME
    ]
    assert claimed == ["Laura Wagner"], claimed
