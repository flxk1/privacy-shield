"""Tests for Privacy Shield regex_only mode (Phase A)."""

from __future__ import annotations


def test_privacy_mode_enum_has_regex_only() -> None:
    """REGEX_ONLY is a valid privacy mode."""
    from brain.privacy_shield.shield import PrivacyMode

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
    from brain.privacy_shield import PrivacyShield, PrivacyMode

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
    from brain.privacy_shield import PrivacyShield, PrivacyMode

    shield_regex = PrivacyShield(privacy_mode=PrivacyMode.REGEX_ONLY)
    assert shield_regex.requires_regex_only() is True
    assert shield_regex.requires_local_only() is False

    shield_standard = PrivacyShield(privacy_mode=PrivacyMode.STANDARD)
    assert shield_standard.requires_regex_only() is False


def test_regex_only_scanner_detects_pii_without_llm() -> None:
    """Pattern-based scan detects PII without Ollama."""
    from brain.privacy_shield.scanner import scan_text_with_local_llm

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
    from brain.privacy_shield import PrivacyShield, PrivacyMode
    from brain.privacy_shield.scanner import ScanResult

    calls = {"count": 0}

    def _fake_local_scan(text, layers=None, min_confidence=None, use_llm_enhancement=True):
        calls["count"] += 1
        return ScanResult(text=text, findings=[], scan_time_ms=1.0, layers_used=[1, 5])

    monkeypatch.setattr(PrivacyShield, "check_local_model_available", lambda self: True)
    monkeypatch.setattr("brain.privacy_shield.shield.scan_text_with_local_llm", _fake_local_scan)

    shield = PrivacyShield(privacy_mode=PrivacyMode.STANDARD)
    result = shield.process_text("Project Horse is handled by Max Muller.")

    assert calls["count"] == 1
    assert result.local_model_available is True
    assert result.local_model_used is True
    assert result.local_model_id == shield.local_model_id


def test_regex_only_mode_skips_local_enhancement_even_if_available(monkeypatch) -> None:
    """regex_only must keep deterministic scanning even when a local model exists."""
    from brain.privacy_shield import PrivacyShield, PrivacyMode

    def _fail_local_scan(*args, **kwargs):
        raise AssertionError("regex_only should not call local enhancement")

    monkeypatch.setattr(PrivacyShield, "check_local_model_available", lambda self: True)
    monkeypatch.setattr("brain.privacy_shield.shield.scan_text_with_local_llm", _fail_local_scan)

    shield = PrivacyShield(privacy_mode=PrivacyMode.REGEX_ONLY)
    result = shield.process_text("Contact john.doe@example.com")

    assert result.local_model_available is True
    assert result.local_model_used is False


def test_onnx_shadow_metadata_does_not_change_live_findings(monkeypatch) -> None:
    """ONNX shadow mode is metadata-only and must not alter live regex findings."""
    from brain.privacy_shield import PrivacyShield, PrivacyMode

    monkeypatch.setenv("BRAIN_PRIVACY_SHIELD_ONNX_MODE", "shadow")
    monkeypatch.setenv("BRAIN_PRIVACY_SHIELD_ONNX_AVAILABLE", "1")
    monkeypatch.setenv("BRAIN_PRIVACY_SHIELD_ONNX_MODEL_ID", "privacy-ner-shadow-v1")
    monkeypatch.setattr(PrivacyShield, "check_local_model_available", lambda self: False)

    shield = PrivacyShield(privacy_mode=PrivacyMode.REGEX_ONLY)
    result = shield.process_text("Contact john.doe@example.com")

    assert result.pii_detected is True
    assert result.findings_by_type["email"] == 1
    assert result.onnx_shadow_mode == "shadow"
    assert result.onnx_shadow_available is True
    assert result.onnx_shadow_model_id == "privacy-ner-shadow-v1"
    assert result.onnx_shadow_candidate_count == 0
