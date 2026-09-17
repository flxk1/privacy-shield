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

    Every finding whose type has a validator must satisfy it. The run-based
    layer owns these three types now; the patterns are candidate generators and
    nothing they match survives unvalidated.
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
    ]
    for text in documents:
        for finding in scanner.scan(text).findings:
            if finding.pii_type not in VALIDATORS:
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
