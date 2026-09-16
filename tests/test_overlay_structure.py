"""The overlay has to remain a usable document.

Redaction that destroys the text is not the safe side of a trade-off. The
overlay IS the product: it is what the cloud model reads, and an overlay that
has lost its line breaks, its sign-off and the word after the address is
fail-closed on confidentiality and fail-open on the reason the thing exists.
"""

from __future__ import annotations

from privacy_shield import scan
from privacy_shield.scanner import Confidence, PIIType, PrivacyScanner

SIGN_OFF = (
    "Mit freundlichen Gruessen\n"
    "Erika Mustermann\n"
    "Musterstrasse 12\n"
    "Anlage\n"
)


def test_a_four_line_sign_off_survives_redaction():
    """The named regression: four lines collapsed into two placeholders.

    `\\s` matches a newline, so the Layer-2 name pattern ran off the end of its
    line and claimed "\\nErika Mustermann\\nMusterstrasse" as one name. The
    overlay came out as "[NAME][NAME] 12\\nAnlage" - the sign-off gone, the
    street name gone, every line break gone, and the model on the other end
    handed something it cannot use.
    """
    overlay = scan(SIGN_OFF).documents[0].overlay

    assert overlay.count("\n") == SIGN_OFF.count("\n"), (
        f"line breaks destroyed: {overlay!r}"
    )
    assert overlay.splitlines()[0] == "Mit freundlichen Gruessen", (
        f"the sign-off did not survive: {overlay!r}"
    )
    assert overlay.splitlines()[-1] == "Anlage", (
        f"the trailing word did not survive: {overlay!r}"
    )
    assert "Erika" not in overlay and "Mustermann" not in overlay, overlay
    assert "[NAME]" in overlay, overlay


def test_the_name_is_still_found_on_its_own_line():
    """Per-line matching must not cost signature-block detection."""
    scanner = PrivacyScanner(min_confidence=Confidence.MEDIUM)
    findings = scanner.scan(SIGN_OFF).findings
    assert any(
        f.pii_type is PIIType.NAME and f.value == "Erika Mustermann"
        for f in findings
    ), [(f.pii_type.value, f.value) for f in findings]


def test_no_finding_spans_a_line_break():
    """The class, not the instance.

    A name, a street and its number, a postal code and its city, a label and
    its value - each is a pair of SEPARATE fields, and a span that crosses a
    line break has merged two of them that belong to different records.
    """
    scanner = PrivacyScanner(
        layers=[1, 2], min_confidence=Confidence.MEDIUM
    )
    document = (
        "Erika Mustermann\n"
        "Musterstrasse 12\n"
        "12345 Berlin\n"
        "Telefon 0170 1234567\n"
        "geboren 01.02.1970\n"
        "Anlage 1\n"
    )
    for finding in scanner.scan(document).findings:
        assert "\n" not in finding.value, (
            f"{finding.pii_type.value} span crossed a line break: {finding.value!r}"
        )


def test_layer_three_phrases_may_still_wrap():
    """Deliberately NOT constrained.

    "mental health" broken across a line by word wrap is still the phrase
    "mental health". Claiming it is correct - nothing is being merged with a
    neighbour that belongs to someone else - so Layer 3 keeps `\\s`.
    """
    scanner = PrivacyScanner(layers=[3], min_confidence=Confidence.MEDIUM)
    findings = scanner.scan("Diagnose: mental\nhealth Probleme").findings
    assert any(f.pii_type is PIIType.HEALTH_DATA for f in findings), (
        [(f.pii_type.value, f.value) for f in findings]
    )


def test_label_and_value_patterns_still_match_on_one_line():
    """Guards the character class the first attempt at this got wrong.

    Interpolating "[ \\t]" INSIDE another character class produced "[:[ \\t]]+",
    which requires a literal "]" and silently stopped matching date-of-birth
    and age entirely. The suite did not notice; this asserts it directly.
    """
    scanner = PrivacyScanner(layers=[2], min_confidence=Confidence.MEDIUM)
    for text, expected in [
        ("geboren 01.02.1970", PIIType.DATE_OF_BIRTH),
        ("Geburtsdatum: 01.02.1970", PIIType.DATE_OF_BIRTH),
        ("Alter: 42", PIIType.AGE),
        ("age: 30", PIIType.AGE),
    ]:
        findings = scanner.scan(text).findings
        assert any(f.pii_type is expected for f in findings), (
            f"{text!r} no longer matches {expected.value}: "
            f"{[(f.pii_type.value, f.value) for f in findings]}"
        )
