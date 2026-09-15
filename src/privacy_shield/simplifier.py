"""Plain Language Mode - Simplifies legal/technical jargon for non-expert users.

Transforms complex professional language into everyday terms while preserving
accuracy and important information.

Usage:
    from privacy_shield.simplifier import simplify_response, should_simplify

    if should_simplify(user_settings):
        simplified = await simplify_response(response, language="en")
"""

from __future__ import annotations

import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

SIMPLIFY_PROMPT_EN = """Rewrite this response for someone without legal or technical background.

Rules:
- Use everyday words (no jargon)
- If a technical term must stay, explain it in parentheses
- Use concrete examples where helpful
- Keep bullet points and structure
- Preserve all important information
- Keep the same meaning and accuracy
- Do not add opinions or commentary
- Keep approximately the same length

Original response:
{response}

Simplified response:"""

SIMPLIFY_PROMPT_DE = """Schreibe diese Antwort um für jemanden ohne juristischen oder technischen Hintergrund.

Regeln:
- Verwende Alltagssprache (kein Fachjargon)
- Wenn ein Fachbegriff bleiben muss, erkläre ihn in Klammern
- Verwende konkrete Beispiele wo hilfreich
- Behalte Aufzählungen und Struktur bei
- Bewahre alle wichtigen Informationen
- Behalte dieselbe Bedeutung und Genauigkeit
- Füge keine Meinungen oder Kommentare hinzu
- Behalte ungefähr dieselbe Länge

Ursprüngliche Antwort:
{response}

Vereinfachte Antwort:"""


def _get_simplify_prompt(language: str = "en") -> str:
    """Get the simplification prompt for the given language."""
    lang = str(language or "en").strip().lower()
    if lang == "de":
        return SIMPLIFY_PROMPT_DE
    return SIMPLIFY_PROMPT_EN


def should_simplify(
    user_settings: Optional[Dict[str, Any]] = None,
    plain_language_mode: Optional[bool] = None,
) -> bool:
    """Check if plain language mode is enabled.

    Args:
        user_settings: User settings dict (checks 'plain_language_mode' key)
        plain_language_mode: Direct override

    Returns:
        True if plain language mode should be applied
    """
    if plain_language_mode is not None:
        return bool(plain_language_mode)

    if user_settings and isinstance(user_settings, dict):
        return bool(user_settings.get("plain_language_mode", False))

    return False


def simplify_response_sync(
    response: str,
    language: str = "en",
    timeout: float = 15.0,
) -> str:
    """Synchronously simplify a response through LLM.

    Args:
        response: The original response text
        language: Language code ("en" or "de")
        timeout: Request timeout in seconds

    Returns:
        Simplified response, or original if simplification fails
    """
    if not response or not response.strip():
        return response

    # Skip if response is very short (likely already simple)
    if len(response.strip()) < 100:
        return response

    try:
        from privacy_shield.services.llm_runtime import call_smart, LLMGatewayResult
    except ImportError as exc:
        logger.debug("LLM gateway not available for simplification: %s", exc)
        return response

    prompt_template = _get_simplify_prompt(language)
    prompt = prompt_template.format(response=response)

    try:
        result: LLMGatewayResult = call_smart(
            prompt=prompt,
            module="simplifier",
            intent="rewrite",
            data_classification="internal",
            has_playbook=False,
            timeout=timeout,
        )

        if result.success and result.text:
            simplified = result.text.strip()
            # Sanity check: simplified should be substantial
            if len(simplified) > 50:
                return simplified

        logger.debug("Simplification returned empty or failed: %s", result.error)
        return response

    except Exception as exc:
        logger.warning("Simplification failed: %s", exc)
        return response


async def simplify_response(
    response: str,
    language: str = "en",
    timeout: float = 15.0,
) -> str:
    """Asynchronously simplify a response through LLM.

    Args:
        response: The original response text
        language: Language code ("en" or "de")
        timeout: Request timeout in seconds

    Returns:
        Simplified response, or original if simplification fails
    """
    if not response or not response.strip():
        return response

    if len(response.strip()) < 100:
        return response

    try:
        from privacy_shield.services.llm_runtime import call_smart_async, LLMGatewayResult
    except ImportError as exc:
        logger.debug("LLM gateway async runtime not available for simplification: %s", exc)
        return simplify_response_sync(response, language, timeout)

    prompt_template = _get_simplify_prompt(language)
    prompt = prompt_template.format(response=response)

    try:
        result: LLMGatewayResult = await call_smart_async(
            prompt=prompt,
            module="simplifier",
            intent="rewrite",
            data_classification="internal",
            has_playbook=False,
            timeout=timeout,
        )

        if result.success and result.text:
            simplified = result.text.strip()
            if len(simplified) > 50:
                return simplified

        logger.debug("Async simplification returned empty or failed: %s", getattr(result, "error", ""))
        return response

    except Exception as exc:
        logger.warning("Async simplification failed: %s", exc)
        return response


# Common legal/technical terms and their plain language equivalents
# Used for quick substitution without full LLM call
QUICK_SIMPLIFICATIONS = {
    # Legal terms (English)
    "pursuant to": "according to",
    "hereinafter": "from now on called",
    "notwithstanding": "despite",
    "aforementioned": "mentioned earlier",
    "inter alia": "among other things",
    "prima facie": "at first look",
    "bona fide": "genuine",
    "force majeure": "events beyond control (like natural disasters)",
    "de facto": "in practice",
    "de jure": "by law",
    "ipso facto": "by that very fact",
    "mutatis mutandis": "with necessary changes",
    "pro rata": "proportionally",
    "vis-a-vis": "compared to",
    "inter se": "among themselves",

    # Legal terms (German)
    "gemäß": "nach",
    "aufgrund": "wegen",
    "hinsichtlich": "bezüglich",
    "diesbezüglich": "dazu",
    "unbeschadet": "ohne zu beeinträchtigen",

    # Technical/compliance terms
    "data subject": "the person whose data is being processed",
    "data controller": "the organization that decides how data is used",
    "data processor": "a company that handles data on behalf of another",
    "legitimate interest": "a valid business reason",
    "DPIA": "Data Protection Impact Assessment (a privacy risk check)",
    "GDPR": "GDPR (the EU's main data protection law)",
    "AI Act": "AI Act (the EU's law regulating artificial intelligence)",
}


def quick_simplify(text: str) -> str:
    """Apply quick word substitutions without LLM call.

    This is a fast, lightweight simplification for common terms.
    Use simplify_response() for full simplification.

    Args:
        text: Text to simplify

    Returns:
        Text with common jargon replaced
    """
    if not text:
        return text

    result = text
    for term, replacement in QUICK_SIMPLIFICATIONS.items():
        # Case-insensitive replacement
        import re
        pattern = re.compile(re.escape(term), re.IGNORECASE)
        result = pattern.sub(replacement, result)

    return result


def estimate_complexity(text: str) -> float:
    """Estimate the complexity of text (0.0 = simple, 1.0 = complex).

    Uses heuristics like:
    - Average sentence length
    - Presence of legal/technical terms
    - Latin phrases
    - Nested clauses

    Args:
        text: Text to analyze

    Returns:
        Complexity score between 0.0 and 1.0
    """
    if not text or not text.strip():
        return 0.0

    import re

    text_lower = text.lower()
    words = text.split()
    sentences = re.split(r'[.!?]+', text)
    sentences = [s.strip() for s in sentences if s.strip()]

    score = 0.0

    # Average sentence length (longer = more complex)
    if sentences:
        avg_sentence_len = len(words) / len(sentences)
        if avg_sentence_len > 30:
            score += 0.3
        elif avg_sentence_len > 20:
            score += 0.2
        elif avg_sentence_len > 15:
            score += 0.1

    # Count legal/technical terms
    term_count = sum(
        1 for term in QUICK_SIMPLIFICATIONS.keys()
        if term.lower() in text_lower
    )
    if term_count > 5:
        score += 0.3
    elif term_count > 2:
        score += 0.2
    elif term_count > 0:
        score += 0.1

    # Latin phrases (common in legal text)
    latin_patterns = [
        r'\b(et al|etc|e\.g\.|i\.e\.|viz|cf|ibid|supra|infra)\b',
        r'\b(per se|ex parte|ad hoc|pro bono|quid pro quo)\b',
    ]
    for pattern in latin_patterns:
        if re.search(pattern, text_lower):
            score += 0.1

    # Passive voice indicators (common in formal/legal writing)
    passive_indicators = [
        r'\bis\s+\w+ed\b',
        r'\bare\s+\w+ed\b',
        r'\bwas\s+\w+ed\b',
        r'\bwere\s+\w+ed\b',
        r'\bbeen\s+\w+ed\b',
    ]
    passive_count = sum(
        len(re.findall(pattern, text_lower))
        for pattern in passive_indicators
    )
    if passive_count > 5:
        score += 0.2
    elif passive_count > 2:
        score += 0.1

    return min(1.0, score)


def needs_simplification(text: str, threshold: float = 0.4) -> bool:
    """Check if text likely needs simplification based on complexity.

    Args:
        text: Text to check
        threshold: Complexity threshold (0.0-1.0)

    Returns:
        True if text complexity exceeds threshold
    """
    return estimate_complexity(text) >= threshold
