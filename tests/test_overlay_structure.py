"""The overlay has to remain a usable document.

Redaction that destroys the text is not the safe side of a trade-off. The
overlay IS the product: it is what the cloud model reads, and an overlay that
has lost its line breaks, its sign-off and the word after the address is
fail-closed on confidentiality and fail-open on the reason the thing exists.
"""

from __future__ import annotations

import pytest

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


# ---------------------------------------------------------------------------
# Precedence must not cost coverage
# ---------------------------------------------------------------------------

def test_a_pattern_straddling_a_validated_span_keeps_both_remainders():
    """Giving a validated span precedence must not drop the other span's tail.

    A Windows path may legally contain "@", so one FILE_PATH finding can
    straddle an e-mail. Trimming it to a single interval kept the part before
    the address and silently discarded everything after it, so the rest of the
    path egressed: "Datei [PATH][EMAIL]\\geheim-2027.docx". Layer 4 exists to
    keep internal paths out of the overlay.

    A straddled span yields TWO remainders, one either side.
    """
    text = r"Datei C:\Users\mueller@example.com\geheim-2027.docx"
    document = scan(text).documents[0]

    assert document.overlay == "Datei [PATH][EMAIL][PATH]", document.overlay
    assert "geheim" not in document.overlay
    assert "Users" not in document.overlay

    kinds = [span.pii_type for span in document.spans]
    assert kinds.count("file_path") == 2, [
        (s.pii_type, s.start, s.end, s.value) for s in document.spans
    ]


@pytest.mark.parametrize("weaker_first", [True, False])
def test_findings_trimmed_to_one_interval_become_one(weaker_first):
    """Both phone patterns reach from "001" into the card; trimmed, they are
    the same (0, 4). One finding comes out, and the stronger one."""
    from privacy_shield.scanner import Finding

    text = "001 4111 1111 1111 1111 A001"
    card = Finding(PIIType.CREDIT_CARD, text[4:23], 4, 23, Confidence.HIGH, 1,
                   checksum_validated=True)
    weak = Finding(PIIType.PHONE, text[0:18], 0, 18, Confidence.MEDIUM, 1)
    strong = Finding(PIIType.PHONE, text[0:8], 0, 8, Confidence.HIGH, 1)
    phones = [weak, strong] if weaker_first else [strong, weak]

    kept = PrivacyScanner()._yield_to_validated([*phones, card], text)

    trimmed = [(f.start, f.end, f.confidence) for f in kept if f.pii_type is PIIType.PHONE]
    assert trimmed == [(0, 4, Confidence.HIGH)], trimmed


def test_precedence_never_reduces_redacted_coverage(monkeypatch):
    """Whatever the labels, the redacted region may only grow, never shrink.

    Property rather than an example, and measured against precedence turned
    OFF rather than against raw pattern matches - the scan legitimately drops
    allowlisted and superseded findings, and comparing to those would be
    comparing to the wrong thing.
    """
    from privacy_shield.scanner import Confidence, PrivacyScanner

    documents = [
        r"Datei C:\Users\mueller@example.com\geheim-2027.docx",
        "Erika Mustermann erika@example.com/projekt-nordstern-2027 offen",
        "Datei /var/log/app/kunde/mueller@example.com Ende",
        "Karte 4111.1111.1111.1111 Projekt Nordstern",
        "Konto DE89 3704 0044 0532 0130 00 Tel. 0170 1234567",
        "Pfad C:\\Projekt\\erika@example.com\\plan-2027.xlsx Ende",
    ]

    def covered(text, *, precedence):
        scanner = PrivacyScanner(min_confidence=Confidence.MEDIUM)
        if not precedence:
            monkeypatch.setattr(
                PrivacyScanner,
                "_yield_to_validated",
                lambda self, findings, text: findings,
            )
        else:
            monkeypatch.undo()
        chars = set()
        for finding in scanner.scan(text).findings:
            chars.update(range(finding.start, finding.end))
        return chars

    for text in documents:
        without = covered(text, precedence=False)
        with_precedence = covered(text, precedence=True)
        assert without <= with_precedence, (
            f"precedence uncovered {sorted(without - with_precedence)} in {text!r}"
        )


@pytest.mark.parametrize(
    "amount",
    ["1.200,00", "12.500,00", "1.234.567,89", "1.200", "999,00"],
)
def test_a_german_amount_is_not_a_version_string(amount):
    """The cloud path claimed the integer part of every four-figure amount.

    `anonymize_for_cloud` scans at the default LOW floor, where the Layer-4
    version pattern is live, and "1.200,00" is a thousands separator and a
    decimal comma - not a version. "Betrag 1.200,00 EUR" went out as
    "Betrag [ANON_VERS_1],00 EUR", so the claim of zero character loss on clean
    documents could not hold for any invoice.
    """
    from privacy_shield.anonymous_json import anonymize_for_cloud

    text = f"Betrag {amount} EUR"
    overlay, _placeholders = anonymize_for_cloud(text)
    assert overlay == text, overlay


@pytest.mark.parametrize(
    "version", ["v2.0", "v1.4.2-beta2", "2.1.0", "v10.4.2"]
)
def test_a_real_version_is_still_found(version):
    from privacy_shield.anonymous_json import anonymize_for_cloud

    overlay, _placeholders = anonymize_for_cloud(f"Release {version} heute")
    assert "ANON_VERS" in overlay, overlay
