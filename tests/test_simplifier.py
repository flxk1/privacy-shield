"""Tests for the Plain Language Mode simplifier module."""

import asyncio
import pytest
from unittest.mock import patch, MagicMock


class TestShouldSimplify:
    """Tests for should_simplify function."""

    def test_direct_override_true(self):
        """Direct override should take precedence."""
        from privacy_shield.simplifier import should_simplify

        result = should_simplify(plain_language_mode=True)
        assert result is True

    def test_direct_override_false(self):
        """Direct override of False should return False."""
        from privacy_shield.simplifier import should_simplify

        result = should_simplify(plain_language_mode=False)
        assert result is False

    def test_user_settings_enabled(self):
        """User settings with plain_language_mode enabled."""
        from privacy_shield.simplifier import should_simplify

        settings = {"plain_language_mode": True}
        result = should_simplify(user_settings=settings)
        assert result is True

    def test_user_settings_disabled(self):
        """User settings with plain_language_mode disabled."""
        from privacy_shield.simplifier import should_simplify

        settings = {"plain_language_mode": False}
        result = should_simplify(user_settings=settings)
        assert result is False

    def test_user_settings_missing_key(self):
        """User settings without the key should return False."""
        from privacy_shield.simplifier import should_simplify

        settings = {"other_setting": True}
        result = should_simplify(user_settings=settings)
        assert result is False

    def test_no_arguments(self):
        """No arguments should return False."""
        from privacy_shield.simplifier import should_simplify

        result = should_simplify()
        assert result is False

    def test_direct_override_beats_settings(self):
        """Direct override should beat user settings."""
        from privacy_shield.simplifier import should_simplify

        settings = {"plain_language_mode": True}
        result = should_simplify(user_settings=settings, plain_language_mode=False)
        assert result is False

    def test_none_settings(self):
        """None settings should return False."""
        from privacy_shield.simplifier import should_simplify

        result = should_simplify(user_settings=None)
        assert result is False


class TestQuickSimplify:
    """Tests for quick_simplify function (fast word substitution)."""

    def test_empty_string(self):
        """Empty string should return empty."""
        from privacy_shield.simplifier import quick_simplify

        assert quick_simplify("") == ""

    def test_none_input(self):
        """None input should return None."""
        from privacy_shield.simplifier import quick_simplify

        assert quick_simplify(None) is None

    def test_pursuant_to(self):
        """Replace 'pursuant to' with 'according to'."""
        from privacy_shield.simplifier import quick_simplify

        text = "Pursuant to Article 6, the data controller must..."
        result = quick_simplify(text)
        assert "according to" in result.lower()
        assert "pursuant to" not in result.lower()

    def test_notwithstanding(self):
        """Replace 'notwithstanding' with 'despite'."""
        from privacy_shield.simplifier import quick_simplify

        text = "Notwithstanding the above provisions..."
        result = quick_simplify(text)
        assert "despite" in result.lower()
        assert "notwithstanding" not in result.lower()

    def test_inter_alia(self):
        """Replace 'inter alia' with 'among other things'."""
        from privacy_shield.simplifier import quick_simplify

        text = "The regulation covers, inter alia, personal data."
        result = quick_simplify(text)
        assert "among other things" in result.lower()

    def test_force_majeure(self):
        """Replace 'force majeure' with explanation."""
        from privacy_shield.simplifier import quick_simplify

        text = "In case of force majeure, the contract..."
        result = quick_simplify(text)
        assert "events beyond control" in result.lower()

    def test_data_controller_explanation(self):
        """Replace 'data controller' with explanation."""
        from privacy_shield.simplifier import quick_simplify

        text = "The data controller is responsible for..."
        result = quick_simplify(text)
        assert "organization that decides how data is used" in result.lower()

    def test_case_insensitive(self):
        """Substitutions should be case insensitive."""
        from privacy_shield.simplifier import quick_simplify

        text = "PURSUANT TO the regulations..."
        result = quick_simplify(text)
        assert "pursuant to" not in result.lower()

    def test_german_term_aufgrund(self):
        """Replace German 'aufgrund' with 'wegen'."""
        from privacy_shield.simplifier import quick_simplify

        text = "Aufgrund der Verordnung muss..."
        result = quick_simplify(text)
        assert "wegen" in result.lower()

    def test_no_changes_needed(self):
        """Text without jargon should remain unchanged."""
        from privacy_shield.simplifier import quick_simplify

        text = "This is a simple sentence about everyday things."
        result = quick_simplify(text)
        assert result == text


class TestEstimateComplexity:
    """Tests for estimate_complexity function."""

    def test_empty_string(self):
        """Empty string should have 0 complexity."""
        from privacy_shield.simplifier import estimate_complexity

        assert estimate_complexity("") == 0.0

    def test_none_input(self):
        """None input should have 0 complexity."""
        from privacy_shield.simplifier import estimate_complexity

        assert estimate_complexity(None) == 0.0

    def test_simple_text(self):
        """Simple everyday text should have low complexity."""
        from privacy_shield.simplifier import estimate_complexity

        text = "I bought a car. It is blue. I like it."
        score = estimate_complexity(text)
        assert score < 0.3

    def test_long_sentences(self):
        """Long sentences increase complexity."""
        from privacy_shield.simplifier import estimate_complexity

        text = (
            "The comprehensive regulatory framework established by the European Union "
            "encompasses a wide range of provisions and requirements that must be "
            "carefully considered and implemented by all affected organizations operating "
            "within the jurisdiction of member states."
        )
        score = estimate_complexity(text)
        assert score > 0.1

    def test_legal_terms_increase_complexity(self):
        """Text with legal terms should have higher complexity."""
        from privacy_shield.simplifier import estimate_complexity

        text = "Pursuant to the aforementioned provisions, notwithstanding any inter alia considerations."
        score = estimate_complexity(text)
        assert score >= 0.2

    def test_latin_phrases(self):
        """Latin phrases should increase complexity."""
        from privacy_shield.simplifier import estimate_complexity

        text = "The court ruled per se that the defendant acted in a prima facie manner."
        score = estimate_complexity(text)
        assert score > 0.1

    def test_passive_voice(self):
        """Passive voice should increase complexity."""
        from privacy_shield.simplifier import estimate_complexity

        text = (
            "The document was reviewed. The data was processed. "
            "The request was submitted. The form was completed. "
            "The application was approved. The system was configured."
        )
        score = estimate_complexity(text)
        assert score > 0.1

    def test_max_complexity_capped(self):
        """Complexity should be capped at 1.0."""
        from privacy_shield.simplifier import estimate_complexity

        text = (
            "Pursuant to the aforementioned provisions, notwithstanding any "
            "inter alia considerations, prima facie evidence suggests that the "
            "data controller, acting vis-a-vis the data processor, failed to "
            "implement de facto measures mutatis mutandis as required by GDPR "
            "and the comprehensive regulatory framework was not adhered to."
        )
        score = estimate_complexity(text)
        assert score <= 1.0


class TestNeedsSimplification:
    """Tests for needs_simplification function."""

    def test_simple_text_below_threshold(self):
        """Simple text should not need simplification."""
        from privacy_shield.simplifier import needs_simplification

        text = "Hello. How are you? I am fine."
        assert needs_simplification(text) is False

    def test_complex_text_above_threshold(self):
        """Complex legal text should need simplification."""
        from privacy_shield.simplifier import needs_simplification

        text = (
            "Pursuant to the aforementioned provisions established under the "
            "comprehensive regulatory framework, notwithstanding any exceptions "
            "inter alia as specified in the applicable legal instruments."
        )
        assert needs_simplification(text) is True

    def test_custom_threshold(self):
        """Custom threshold should be respected."""
        from privacy_shield.simplifier import needs_simplification

        text = "This is moderately complex text with some legal terminology."
        # With high threshold, should not need simplification
        assert needs_simplification(text, threshold=0.9) is False
        # With very low threshold, should need simplification
        assert needs_simplification(text, threshold=0.0) is True


class TestSimplifyResponseSync:
    """Tests for simplify_response_sync function with mocked LLM."""

    def test_empty_response(self):
        """Empty response should return unchanged."""
        from privacy_shield.simplifier import simplify_response_sync

        assert simplify_response_sync("") == ""
        assert simplify_response_sync("   ") == "   "

    def test_short_response_skipped(self):
        """Short responses (< 100 chars) should be returned unchanged."""
        from privacy_shield.simplifier import simplify_response_sync

        text = "This is a short response."
        assert simplify_response_sync(text) == text

    @patch("privacy_shield.runtime.llm_gateway.call_smart")
    def test_llm_simplification_success(self, mock_call_smart):
        """Successful LLM simplification."""
        from privacy_shield.simplifier import simplify_response_sync

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.text = "This is a simpler version of the text that explains things clearly and is much easier to understand."
        mock_call_smart.return_value = mock_result

        original = "Pursuant to the provisions of the GDPR, the data controller must implement appropriate technical and organizational measures."
        result = simplify_response_sync(original)

        assert result == mock_result.text.strip()
        mock_call_smart.assert_called_once()

    @patch("privacy_shield.runtime.llm_gateway.call_smart")
    def test_llm_failure_returns_original(self, mock_call_smart):
        """LLM failure should return original text."""
        from privacy_shield.simplifier import simplify_response_sync

        mock_result = MagicMock()
        mock_result.success = False
        mock_result.error = "LLM unavailable"
        mock_call_smart.return_value = mock_result

        original = "This is a longer text that would normally be simplified but the LLM is not available right now."
        result = simplify_response_sync(original)

        assert result == original

    @patch("privacy_shield.runtime.llm_gateway.call_smart")
    def test_llm_empty_result_returns_original(self, mock_call_smart):
        """Empty LLM result should return original text."""
        from privacy_shield.simplifier import simplify_response_sync

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.text = "   "
        mock_call_smart.return_value = mock_result

        original = "This is the original text that is longer than 100 characters and would be sent for simplification."
        result = simplify_response_sync(original)

        assert result == original

    @patch("privacy_shield.runtime.llm_gateway.call_smart")
    def test_llm_short_result_returns_original(self, mock_call_smart):
        """Very short LLM result (< 50 chars) should return original."""
        from privacy_shield.simplifier import simplify_response_sync

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.text = "Too short"
        mock_call_smart.return_value = mock_result

        original = "This is the original text that is longer than 100 characters and would be sent for simplification."
        result = simplify_response_sync(original)

        assert result == original

    @patch("privacy_shield.runtime.llm_gateway.call_smart")
    def test_llm_exception_returns_original(self, mock_call_smart):
        """LLM exception should return original text."""
        from privacy_shield.simplifier import simplify_response_sync

        mock_call_smart.side_effect = Exception("Network error")

        original = "This is the original text that is longer than 100 characters and would be sent for simplification."
        result = simplify_response_sync(original)

        assert result == original

    @patch("privacy_shield.runtime.llm_gateway.call_smart")
    def test_german_language(self, mock_call_smart):
        """German language should use German prompt."""
        from privacy_shield.simplifier import simplify_response_sync

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.text = "Dies ist eine vereinfachte Version des Textes, die viel einfacher zu verstehen ist."
        mock_call_smart.return_value = mock_result

        original = "Gemäß den Bestimmungen der DSGVO muss der Verantwortliche geeignete technische und organisatorische Maßnahmen implementieren."
        result = simplify_response_sync(original, language="de")

        assert result == mock_result.text.strip()
        # Verify the prompt used German
        call_args = mock_call_smart.call_args
        assert "Vereinfachte Antwort" in call_args[1]["prompt"]


class TestSimplifyResponseAsync:
    """Tests for simplify_response async path."""

    @patch("privacy_shield.services.llm_runtime.call_smart_async")
    def test_async_simplification_success(self, mock_call_smart_async):
        """Async simplification should return rewritten text when successful."""
        from privacy_shield.simplifier import simplify_response

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.text = (
            "This async simplified response keeps meaning while being easier to understand "
            "for non-expert users."
        )
        mock_call_smart_async.return_value = mock_result

        original = (
            "Pursuant to the provisions of the GDPR, the data controller must implement "
            "appropriate technical and organizational measures to protect personal data."
        )
        result = asyncio.run(simplify_response(original))

        assert result == mock_result.text.strip()
        mock_call_smart_async.assert_called_once()

    @patch("privacy_shield.services.llm_runtime.call_smart_async")
    def test_async_failure_returns_original(self, mock_call_smart_async):
        """Async simplification failure should preserve original text."""
        from privacy_shield.simplifier import simplify_response

        mock_call_smart_async.side_effect = RuntimeError("timeout")
        original = (
            "This is the original text that is longer than 100 characters and would "
            "normally be simplified by the async pipeline."
        )

        result = asyncio.run(simplify_response(original))
        assert result == original


class TestGetSimplifyPrompt:
    """Tests for _get_simplify_prompt function."""

    def test_english_default(self):
        """Default should return English prompt."""
        from privacy_shield.simplifier import _get_simplify_prompt

        prompt = _get_simplify_prompt()
        assert "Simplified response:" in prompt

    def test_english_explicit(self):
        """Explicit 'en' should return English prompt."""
        from privacy_shield.simplifier import _get_simplify_prompt

        prompt = _get_simplify_prompt("en")
        assert "Simplified response:" in prompt

    def test_german(self):
        """'de' should return German prompt."""
        from privacy_shield.simplifier import _get_simplify_prompt

        prompt = _get_simplify_prompt("de")
        assert "Vereinfachte Antwort:" in prompt

    def test_unknown_defaults_to_english(self):
        """Unknown language should default to English."""
        from privacy_shield.simplifier import _get_simplify_prompt

        prompt = _get_simplify_prompt("fr")
        assert "Simplified response:" in prompt

    def test_none_defaults_to_english(self):
        """None should default to English."""
        from privacy_shield.simplifier import _get_simplify_prompt

        prompt = _get_simplify_prompt(None)
        assert "Simplified response:" in prompt


class TestQuickSimplificationsDict:
    """Tests for the QUICK_SIMPLIFICATIONS dictionary."""

    def test_contains_legal_terms(self):
        """Should contain common legal terms."""
        from privacy_shield.simplifier import QUICK_SIMPLIFICATIONS

        assert "pursuant to" in QUICK_SIMPLIFICATIONS
        assert "notwithstanding" in QUICK_SIMPLIFICATIONS
        assert "aforementioned" in QUICK_SIMPLIFICATIONS

    def test_contains_latin_phrases(self):
        """Should contain Latin legal phrases."""
        from privacy_shield.simplifier import QUICK_SIMPLIFICATIONS

        assert "inter alia" in QUICK_SIMPLIFICATIONS
        assert "prima facie" in QUICK_SIMPLIFICATIONS
        assert "de facto" in QUICK_SIMPLIFICATIONS

    def test_contains_german_terms(self):
        """Should contain German legal terms."""
        from privacy_shield.simplifier import QUICK_SIMPLIFICATIONS

        assert "gemäß" in QUICK_SIMPLIFICATIONS
        assert "aufgrund" in QUICK_SIMPLIFICATIONS

    def test_contains_technical_terms(self):
        """Should contain technical/compliance terms."""
        from privacy_shield.simplifier import QUICK_SIMPLIFICATIONS

        assert "data subject" in QUICK_SIMPLIFICATIONS
        assert "data controller" in QUICK_SIMPLIFICATIONS
        assert "GDPR" in QUICK_SIMPLIFICATIONS


class TestIntegration:
    """Integration tests for the simplifier pipeline."""

    def test_full_pipeline_with_quick_simplify(self):
        """Quick simplify followed by complexity check."""
        from privacy_shield.simplifier import quick_simplify, needs_simplification

        text = "Pursuant to the GDPR, the data controller must implement measures."
        quick_result = quick_simplify(text)

        # After quick simplify, the text should be somewhat simpler
        assert "pursuant to" not in quick_result.lower()
        assert "according to" in quick_result.lower()

    def test_complexity_after_quick_simplify(self):
        """Complexity should decrease after quick simplify."""
        from privacy_shield.simplifier import quick_simplify, estimate_complexity

        text = (
            "Pursuant to the aforementioned provisions, notwithstanding any "
            "inter alia considerations, the data controller must act."
        )
        original_complexity = estimate_complexity(text)
        simplified = quick_simplify(text)
        new_complexity = estimate_complexity(simplified)

        # Complexity should decrease after simplification
        assert new_complexity <= original_complexity
