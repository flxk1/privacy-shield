"""Tests for Privacy Shield regex_only mode (Phase A)."""

from __future__ import annotations


def test_privacy_mode_enum_has_regex_only() -> None:
    """REGEX_ONLY is a valid privacy mode."""
    from privacy_shield.shield import PrivacyMode

    assert PrivacyMode.REGEX_ONLY.value == "regex_only"
    # All four modes exist
    assert {m.value for m in PrivacyMode} == {
        "standard",
        "local_only",
        "anonymous_json",
        "regex_only",
    }


def test_regex_only_mode_routing_config() -> None:
    """regex_only mode returns correct routing config."""
    from privacy_shield import PrivacyShield, PrivacyMode

    shield = PrivacyShield(privacy_mode=PrivacyMode.REGEX_ONLY)
    config = shield.get_model_routing_config()
    assert config["privacy_mode"] == "regex_only"
    assert config["pii_scan_mode"] == "regex_only"
    assert config["log_enforcement"] is True
    # regex_only doesn't force local — it allows cloud for the LLM chat,
    # just scans PII with patterns only
    assert config["force_local"] is False


def test_regex_only_requires_method() -> None:
    """requires_regex_only() works correctly."""
    from privacy_shield import PrivacyShield, PrivacyMode

    shield_regex = PrivacyShield(privacy_mode=PrivacyMode.REGEX_ONLY)
    assert shield_regex.requires_regex_only() is True
    assert shield_regex.requires_local_only() is False

    shield_standard = PrivacyShield(privacy_mode=PrivacyMode.STANDARD)
    assert shield_standard.requires_regex_only() is False


def test_regex_only_scanner_detects_pii_without_llm() -> None:
    """Pattern-based scan detects PII without Ollama."""
    from privacy_shield.scanner import scan_text_with_local_llm

    text = "Contact john.doe@example.com or call 0172-1234567 about IBAN DE89370400440532013000"
    result = scan_text_with_local_llm(text, use_llm_enhancement=False)

    # Should detect email, phone, IBAN using regex only
    assert result.findings, "Expected PII findings from regex scan"
    types_found = {f.pii_type.value for f in result.findings}
    assert "email" in types_found
    # Layer 5 should NOT be in layers_used
    assert 5 not in result.layers_used


def test_standard_mode_uses_local_enhancement_when_available(monkeypatch) -> None:
    """Standard Privacy Shield uses the local enhancement layer whenever available."""
    from privacy_shield import PrivacyShield, PrivacyMode
    from privacy_shield.scanner import ScanResult

    calls = {"count": 0}

    def _fake_local_scan(text, layers=None, min_confidence=None, use_llm_enhancement=True):
        calls["count"] += 1
        return ScanResult(text=text, findings=[], scan_time_ms=1.0, layers_used=[1, 5])

    monkeypatch.setattr(PrivacyShield, "check_local_model_available", lambda self: True)
    monkeypatch.setattr("privacy_shield.shield.scan_text_with_local_llm", _fake_local_scan)

    shield = PrivacyShield(privacy_mode=PrivacyMode.STANDARD)
    result = shield.process_text("Project Horse is handled by Max Muller.")

    assert calls["count"] == 1
    assert result.local_model_available is True
    assert result.local_model_used is True
    assert result.local_model_id == shield.local_model_id


def test_regex_only_mode_skips_local_enhancement_even_if_available(monkeypatch) -> None:
    """regex_only must keep deterministic scanning even when a local model exists."""
    from privacy_shield import PrivacyShield, PrivacyMode

    def _fail_local_scan(*args, **kwargs):
        raise AssertionError("regex_only should not call local enhancement")

    monkeypatch.setattr(PrivacyShield, "check_local_model_available", lambda self: True)
    monkeypatch.setattr("privacy_shield.shield.scan_text_with_local_llm", _fail_local_scan)

    shield = PrivacyShield(privacy_mode=PrivacyMode.REGEX_ONLY)
    result = shield.process_text("Contact john.doe@example.com")

    assert result.local_model_available is True
    assert result.local_model_used is False


def test_onnx_shadow_metadata_does_not_change_live_findings(monkeypatch) -> None:
    """ONNX shadow mode is metadata-only and must not alter live regex findings."""
    from privacy_shield import PrivacyShield, PrivacyMode

    monkeypatch.setenv("PRIVACY_SHIELD_ONNX_MODE", "shadow")
    monkeypatch.setenv("PRIVACY_SHIELD_ONNX_AVAILABLE", "1")
    monkeypatch.setenv("PRIVACY_SHIELD_ONNX_MODEL_ID", "privacy-ner-shadow-v1")
    monkeypatch.setattr(PrivacyShield, "check_local_model_available", lambda self: False)

    shield = PrivacyShield(privacy_mode=PrivacyMode.REGEX_ONLY)
    result = shield.process_text("Contact john.doe@example.com")

    assert result.pii_detected is True
    assert result.findings_by_type["email"] == 1
    assert result.onnx_shadow_mode == "shadow"
    assert result.onnx_shadow_available is True
    assert result.onnx_shadow_model_id == "privacy-ner-shadow-v1"
    assert result.onnx_shadow_candidate_count == 0

from privacy_shield.scanner import Confidence, PIIType, PrivacyScanner
import pytest


# ---------------------------------------------------------------------------
# A pattern may not outrank a checksum
# ---------------------------------------------------------------------------

def test_a_vat_number_is_not_an_iban():
    """The Layer-1 IBAN regex claimed a German VAT number at HIGH confidence.

        "USt-IdNr. DE136695976\nGesamtbetrag 1.349,00 EUR"
          -> iban, HIGH, value "DE136695976\nGesamtbetrag 1"

    `find_ibans` correctly returned nothing for it, so the pattern layer and
    the validated run-based layer disagreed about what an IBAN is and the one
    with no checksum won by being HIGH confidence. That is the same structure
    as the suppressor this programme opened with.
    """
    scanner = PrivacyScanner(min_confidence=Confidence.MEDIUM)
    text = "USt-IdNr. DE136695976\nGesamtbetrag 1.349,00 EUR"
    ibans = [f for f in scanner.scan(text).findings if f.pii_type is PIIType.IBAN]
    assert not ibans, [(f.value, f.confidence.value) for f in ibans]


@pytest.mark.parametrize(
    "text, pii_type",
    [
        ("Konto DE89 3704 0044 0532 0130 00", PIIType.IBAN),
        ("Karte 4111 1111 1111 1111", PIIType.CREDIT_CARD),
        ("Mail erika@example.com", PIIType.EMAIL),
    ],
)
def test_a_validated_identifier_is_still_found(text, pii_type):
    """Subordinating the patterns must not cost the real thing."""
    scanner = PrivacyScanner(min_confidence=Confidence.MEDIUM)
    found = [f for f in scanner.scan(text).findings if f.pii_type is pii_type]
    assert found, [(f.pii_type.value, f.value) for f in scanner.scan(text).findings]


def test_no_finding_of_a_validated_type_fails_its_own_validator():
    """The property, rather than three examples.

    Every finding whose type has a validator must satisfy it - UNLESS it is a
    credit-card SHAPE kept deliberately, which is MEDIUM and carries
    checksum_validated=False. That exception is the subject of
    test_a_labelled_card_with_one_transcription_typo_is_still_claimed; here it
    is admitted rather than left to make this test pass by accident on the day
    a mistyped card happens to contain no Luhn-valid sub-window.
    """
    from privacy_shield.scanner import VALIDATORS, is_validated_identifier

    scanner = PrivacyScanner(min_confidence=Confidence.LOW)
    documents = [
        "USt-IdNr. DE136695976\nGesamtbetrag 1.349,00 EUR",
        "Karte 4111 1111 1111 1112",
        "Konto DE00 0000 0000 0000 0000 00",
        "Mail nicht-ganz@@example.com",
        "Steuernummer 12 345 678 901",
        "IBAN DE89 3704 0044 0532 0130 00 und Karte 4111 1111 1111 1111",
        # What a finder reads through a fold, its validator must read too.
        "IBAN \uff24\uff25\uff18\uff19 \uff13\uff17\uff10\uff14 "
        "\uff10\uff10\uff14\uff14 \uff10\uff15\uff13\uff12 "
        "\uff10\uff11\uff13\uff10 \uff10\uff10",
        "Karte \u0664\u0661\u0661\u0661 \u0661\u0661\u0661\u0661 "
        "\u0661\u0661\u0661\u0661 \u0661\u0661\u0661\u0661",
        "Mail \uff45\uff52\uff49\uff4b\uff41\uff20example\uff0ecom",
        "Mail erika@example\u3002com",
    ]
    for text in documents:
        for finding in scanner.scan(text).findings:
            if finding.pii_type not in VALIDATORS:
                continue
            if not finding.checksum_validated:
                assert finding.pii_type is PIIType.CREDIT_CARD, (
                    f"{finding.pii_type.value} survived without a checksum"
                )
                assert finding.confidence is Confidence.MEDIUM, (
                    "an unvalidated shape must not be HIGH"
                )
                continue
            # The SPAN may be wider than one identifier: card windows are
            # merged so that no validating window is left partly uncovered, so
            # the union itself need not satisfy Luhn. What must hold is that
            # the span contains something that does - otherwise the finding is
            # a pattern's word against a checksum, which is the structure this
            # test exists to forbid.
            value = finding.value
            if is_validated_identifier(finding.pii_type, value):
                continue
            compact = "".join(c for c in value if c.isalnum())
            assert any(
                is_validated_identifier(finding.pii_type, compact[i:i + size])
                for size in range(len(compact), 2, -1)
                for i in range(0, len(compact) - size + 1)
            ), (
                f"{finding.pii_type.value} {value!r} contains nothing that "
                "satisfies its own validator"
            )


def test_no_finding_of_a_validated_type_crosses_a_line_terminator():
    """The VAT span crossed a newline while limits.md described the
    terminator rule. A validated identifier may contain at most one
    terminator, and an unvalidated pattern may not produce one at all."""
    from privacy_shield.identifiers import count_terminators
    from privacy_shield.scanner import VALIDATORS

    scanner = PrivacyScanner(min_confidence=Confidence.LOW)
    for text in [
        "USt-IdNr. DE136695976\nGesamtbetrag 1.349,00 EUR",
        "Konto DE89 3704\nGesamtbetrag 1.349,00 EUR",
        "Karte 4111 1111\n1111 1111 Ende",
    ]:
        for finding in scanner.scan(text).findings:
            if finding.pii_type in VALIDATORS:
                assert count_terminators(finding.value) <= 1, (
                    f"{finding.pii_type.value} span crossed "
                    f"{count_terminators(finding.value)} terminators: "
                    f"{finding.value!r}"
                )


# ---------------------------------------------------------------------------
# ... but a SHAPE is still evidence, and the demotion was scoped wrong
# ---------------------------------------------------------------------------

def _card_with_a_typo_and_no_valid_window(seed):
    """A labelled card carrying one wrong digit and no Luhn-valid substring.

    Most single-digit typos leave some shorter window that still satisfies
    Luhn, and the run-based layer claims those regardless. The ones that do
    not are the cases the demotion lost outright, and they are what this
    builds - by search, at runtime, never written down.
    """
    import random

    from privacy_shield.identifiers import luhn_ok
    import synth

    rng = random.Random(seed)
    for _attempt in range(2000):
        card = synth.make_card(rng, 16)
        position = rng.randrange(16)
        wrong = str((int(card[position]) + rng.randint(1, 9)) % 10)
        mistyped = card[:position] + wrong + card[position + 1:]
        if any(
            luhn_ok(mistyped[i:i + size])
            for size in range(13, 17)
            for i in range(0, 17 - size)
        ):
            continue
        return mistyped
    raise AssertionError("could not construct the shape")


def test_a_labelled_card_with_one_transcription_typo_is_still_claimed():
    """The trade, measured both ways over 200 documents each.

                                              521fec2   0719c79
        card false positives, 200 clean         119       119
        IBAN false positives, 200 clean           0         0
        labelled card, one typo, not claimed    3/200     73/200

    The entire precision gain of demoting the Layer-1 patterns is on the IBAN
    pattern, whose shape is two letters, two digits and anything at all. The
    CARD pattern's false positives did not move by a single span, so the
    seventy extra missed cards bought nothing.

    A single wrong digit always defeats Luhn - that is what Luhn is for - and
    it is the most ordinary defect in an OCR'd or hand-typed document. The
    literal word "Kreditkarte" beside a correctly grouped, issuer-prefixed
    sixteen-digit number is evidence no checksum can overrule.
    """
    from privacy_shield.scanner import Confidence, PIIType, PrivacyScanner

    mistyped = _card_with_a_typo_and_no_valid_window(seed=1911)
    grouped = " ".join(mistyped[i:i + 4] for i in range(0, 16, 4))
    for written in (mistyped, grouped):
        text = f"Kreditkarte: {written}\nBetrag 1.349,00 EUR"
        findings = [
            f for f in PrivacyScanner(min_confidence=Confidence.LOW).scan(text).findings
            if f.pii_type is PIIType.CREDIT_CARD
        ]
        assert findings, f"a labelled card with one typo went unclaimed: {text!r}"
        for finding in findings:
            assert finding.confidence is Confidence.MEDIUM, (
                "a shape with no checksum behind it must not be HIGH - that is "
                "the structure the round-18 demotion existed to remove"
            )
            assert not finding.checksum_validated


def test_a_card_shape_cannot_outrank_a_checksum():
    """The half of the demotion that stays.

    Keeping the shape must not put it back in front of a validated claim. The
    rank rule asks the FINDING whether a checksum stands behind it, not its
    type, so a demoted card is ranked with the patterns where it belongs.
    """
    from privacy_shield.scanner import Confidence, PIIType, PrivacyScanner

    mistyped = _card_with_a_typo_and_no_valid_window(seed=1912)
    text = f"Kreditkarte {mistyped} und Konto DE89 3704 0044 0532 0130 00"
    findings = PrivacyScanner(min_confidence=Confidence.LOW).scan(text).findings
    shapes = [f for f in findings if not f.checksum_validated]
    assert all(
        f.pii_type is not PIIType.IBAN for f in shapes
    ), "the IBAN pattern is still demoted and must stay dropped"
    for shape in shapes:
        assert shape.confidence is not Confidence.HIGH or shape.pii_type not in {
            PIIType.IBAN, PIIType.CREDIT_CARD, PIIType.EMAIL
        }


@pytest.mark.parametrize(
    "minimum, expected",
    [(Confidence.LOW, True), (Confidence.MEDIUM, True), (Confidence.HIGH, False)],
    ids=["low", "medium", "high"],
)
def test_min_confidence_reads_the_confidence_a_finding_ends_up_with(minimum, expected):
    """It read the PATTERN's declared confidence, before anything changed it.

    Round 19's release note said a demoted card shape is absent at
    `min_confidence=HIGH`. It was not: `_match_patterns` filters on the
    pattern's own confidence, the demotion to MEDIUM happens later in the
    validation pass, and nothing re-filtered afterwards - so a scan at HIGH
    returned the finding at `medium`. The claim reached public main and was
    corrected there rather than quietly dropped.

    Both tests cited beside that claim ran at LOW, which is why neither caught
    it. This one runs at all three, and it is the behaviour that changed to
    match the sentence rather than the sentence trimmed to match the behaviour:
    a caller who asks for checksum-backed findings only has a way to get them.
    """
    from privacy_shield.scanner import PIIType, PrivacyScanner

    mistyped = _card_with_a_typo_and_no_valid_window(seed=2011)
    grouped = " ".join(mistyped[i:i + 4] for i in range(0, 16, 4))
    text = f"Kreditkarte: {grouped}\nBetrag 1.349,00 EUR"

    findings = [
        finding for finding in PrivacyScanner(min_confidence=minimum).scan(text).findings
        if finding.pii_type is PIIType.CREDIT_CARD
    ]
    assert bool(findings) is expected, [
        (f.pii_type.value, f.confidence.value) for f in findings
    ]
    for finding in findings:
        assert finding.confidence is Confidence.MEDIUM
        assert not finding.checksum_validated
