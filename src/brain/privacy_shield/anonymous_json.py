"""
Privacy Shield - Anonymous JSON Mode

Converts user input to anonymous JSON envelopes for cloud LLMs.
Only controlled, anonymized metadata is sent to cloud; raw text stays local.

Data Flow:
    User Input
      |
    Privacy Shield Scan (detect all PII)
      |
    Extract intent + entities as JSON schema
      |
    Anonymize: Replace PII with placeholders
      |
    Send JSON envelope to Cloud LLM
      |
    Cloud LLM returns structured response
      |
    Local model rehydrates with original values
      |
    Full response to user
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .scanner import Finding, PIIType, ScanResult

logger = logging.getLogger(__name__)


@dataclass
class AnonymousEnvelope:
    """Controlled JSON envelope for cloud LLM.

    Contains only anonymized, structured data that is safe
    to send to external cloud LLMs.
    """
    # Request metadata
    intent: str  # Detected intent (e.g., "contract_review", "risk_assessment")
    query_type: str  # Type of query (e.g., "legal_question", "document_analysis")

    # Anonymized entities (PII replaced with placeholders)
    entities: Dict[str, str] = field(default_factory=dict)

    # Context metadata (no PII)
    skill_id: Optional[str] = None
    jurisdiction: Optional[str] = None
    language: str = "en"
    context_tokens: int = 0

    # Placeholder mappings (kept local for rehydration)
    placeholders: Dict[str, str] = field(default_factory=dict)

    # Original text hash (for integrity, not for transmission)
    _original_hash: str = ""

    def to_cloud_payload(self) -> Dict[str, Any]:
        """Convert to payload safe for cloud transmission.

        Note: placeholders and _original_hash are NOT included
        as they contain mapping to original values.
        """
        return {
            "intent": self.intent,
            "query_type": self.query_type,
            "entities": self.entities,
            "skill_id": self.skill_id,
            "jurisdiction": self.jurisdiction,
            "language": self.language,
            "context_tokens": self.context_tokens,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Full dict representation (for local storage/logging)."""
        return {
            "intent": self.intent,
            "query_type": self.query_type,
            "entities": self.entities,
            "skill_id": self.skill_id,
            "jurisdiction": self.jurisdiction,
            "language": self.language,
            "context_tokens": self.context_tokens,
            "placeholders": self.placeholders,
            "_original_hash": self._original_hash,
        }


# Intent detection patterns
INTENT_PATTERNS = [
    # Contract-related
    (r"\b(?:review|analyze|check)\b.*\b(?:contract|agreement|nda|license)\b", "contract_review"),
    (r"\b(?:nda|non-disclosure)\b", "nda_review"),
    (r"\b(?:license|licensing)\b.*\b(?:agreement|review)\b", "license_review"),

    # Risk/Compliance
    (r"\b(?:risk|compliance|audit)\b.*\b(?:assess|review|check)\b", "risk_assessment"),
    (r"\b(?:gdpr|dsgvo|privacy)\b.*\b(?:compliance|check|review)\b", "privacy_compliance"),
    (r"\b(?:ai\s?act|eu\s?ai)\b", "ai_act_review"),

    # Legal questions
    (r"\b(?:is|are|does|can|may)\b.*\b(?:legal|lawful|enforceable|compliant)\b", "legal_question"),
    (r"\b(?:explain|what\s+is|define)\b.*\b(?:law|regulation|article|section)\b", "legal_explanation"),

    # Document operations
    (r"\b(?:draft|write|create)\b.*\b(?:document|contract|policy)\b", "document_drafting"),
    (r"\b(?:summarize|summary|abstract)\b", "document_summary"),

    # Research
    (r"\b(?:search|find|research)\b.*\b(?:case|precedent|ruling)\b", "case_research"),
]

# Query type detection
QUERY_TYPE_PATTERNS = [
    (r"\?$", "question"),
    (r"\b(?:please|could you|can you)\b", "request"),
    (r"\b(?:review|analyze|assess|check)\b", "analysis"),
    (r"\b(?:draft|write|create|generate)\b", "generation"),
    (r"\b(?:explain|define|what\s+is)\b", "explanation"),
]


class AnonymousJsonProcessor:
    """Converts user input to anonymous JSON for cloud LLMs.

    This processor ensures that:
    1. All PII is replaced with consistent placeholders
    2. Intent and query type are extracted
    3. Only structured, anonymized data goes to cloud
    4. Original values can be rehydrated locally
    """

    def __init__(
        self,
        placeholder_prefix: str = "ANON_",
        include_context_stats: bool = True,
    ):
        """
        Initialize the processor.

        Args:
            placeholder_prefix: Prefix for generated placeholders.
            include_context_stats: Whether to include token count stats.
        """
        self.placeholder_prefix = placeholder_prefix
        self.include_context_stats = include_context_stats

        # Session-scoped placeholder mappings (for consistency)
        self._placeholder_counter: Dict[PIIType, int] = {}
        self._value_to_placeholder: Dict[str, str] = {}
        self._placeholder_to_value: Dict[str, str] = {}

    def create_envelope(
        self,
        text: str,
        scan_result: ScanResult,
        skill_id: Optional[str] = None,
        jurisdiction: Optional[str] = None,
        language: str = "en",
    ) -> AnonymousEnvelope:
        """Create anonymized JSON envelope from user input.

        Args:
            text: Original user input text.
            scan_result: PII scan results from PrivacyScanner.
            skill_id: Optional skill ID being invoked.
            jurisdiction: Optional jurisdiction context.
            language: Language code (default: en).

        Returns:
            AnonymousEnvelope ready for cloud transmission.
        """
        # Detect intent
        intent = self._detect_intent(text)
        query_type = self._detect_query_type(text)

        # Create placeholders for all PII
        entities = self._anonymize_entities(text, scan_result)

        # Calculate context stats
        context_tokens = len(text.split()) if self.include_context_stats else 0

        # Create original hash (for integrity verification)
        original_hash = hashlib.sha256(text.encode()).hexdigest()[:16]

        return AnonymousEnvelope(
            intent=intent,
            query_type=query_type,
            entities=entities,
            skill_id=skill_id,
            jurisdiction=jurisdiction,
            language=language,
            context_tokens=context_tokens,
            placeholders=dict(self._placeholder_to_value),
            _original_hash=original_hash,
        )

    def _detect_intent(self, text: str) -> str:
        """Detect intent from text using pattern matching."""
        text_lower = text.lower()

        for pattern, intent in INTENT_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return intent

        return "general_query"

    def _detect_query_type(self, text: str) -> str:
        """Detect query type from text."""
        text_lower = text.lower().strip()

        for pattern, query_type in QUERY_TYPE_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return query_type

        return "statement"

    def _anonymize_entities(
        self,
        text: str,
        scan_result: ScanResult,
    ) -> Dict[str, str]:
        """Extract and anonymize entities from text.

        Args:
            text: Original text.
            scan_result: PII scan results.

        Returns:
            Dict mapping entity keys to anonymized placeholder values.
        """
        entities: Dict[str, str] = {}

        # Group findings by type
        by_type: Dict[PIIType, List[Finding]] = {}
        for finding in scan_result.findings:
            if finding.pii_type not in by_type:
                by_type[finding.pii_type] = []
            by_type[finding.pii_type].append(finding)

        # Create placeholder for each unique value
        for pii_type, findings in by_type.items():
            seen_values: set = set()
            for finding in findings:
                if finding.value in seen_values:
                    continue
                seen_values.add(finding.value)

                placeholder = self._get_or_create_placeholder(pii_type, finding.value)
                entity_key = f"{pii_type.value}_{len([k for k in entities if k.startswith(pii_type.value)])}"
                entities[entity_key] = placeholder

        return entities

    def _get_or_create_placeholder(self, pii_type: PIIType, value: str) -> str:
        """Get existing placeholder or create new one for a value.

        Ensures consistent placeholder assignment within a session.
        """
        if value in self._value_to_placeholder:
            return self._value_to_placeholder[value]

        # Generate new placeholder
        counter = self._placeholder_counter.get(pii_type, 0)
        self._placeholder_counter[pii_type] = counter + 1

        # Create readable placeholder
        type_abbrev = {
            PIIType.NAME: "NAME",
            PIIType.EMAIL: "EMAIL",
            PIIType.PHONE: "PHONE",
            PIIType.ADDRESS: "ADDR",
            PIIType.IBAN: "IBAN",
            PIIType.CREDIT_CARD: "CC",
            PIIType.PLZ_CITY: "LOC",
            PIIType.DATE_OF_BIRTH: "DOB",
        }.get(pii_type, pii_type.value.upper()[:4])

        placeholder = f"[{self.placeholder_prefix}{type_abbrev}_{counter + 1}]"

        # Store bidirectional mapping
        self._value_to_placeholder[value] = placeholder
        self._placeholder_to_value[placeholder] = value

        return placeholder

    def rehydrate(
        self,
        response: str,
        envelope: AnonymousEnvelope,
    ) -> str:
        """Replace placeholders with original values in response.

        Args:
            response: Response from cloud LLM (may contain placeholders).
            envelope: Original envelope with placeholder mappings.

        Returns:
            Response with placeholders replaced by original values.
        """
        result = response

        # Replace all placeholders with original values
        for placeholder, original_value in envelope.placeholders.items():
            result = result.replace(placeholder, original_value)

        return result

    def anonymize_text(
        self,
        text: str,
        scan_result: ScanResult,
    ) -> Tuple[str, Dict[str, str]]:
        """Anonymize text by replacing PII with placeholders.

        This is useful when you need the anonymized text itself
        rather than just an envelope.

        Args:
            text: Original text.
            scan_result: PII scan results.

        Returns:
            Tuple of (anonymized_text, placeholder_mappings).
        """
        result = text

        # Sort findings by position (reverse order to maintain positions)
        sorted_findings = sorted(
            scan_result.findings,
            key=lambda f: f.start,
            reverse=True,
        )

        for finding in sorted_findings:
            placeholder = self._get_or_create_placeholder(
                finding.pii_type,
                finding.value,
            )
            result = result[:finding.start] + placeholder + result[finding.end:]

        return result, dict(self._placeholder_to_value)

    def reset_session(self) -> None:
        """Reset placeholder mappings for a new session."""
        self._placeholder_counter.clear()
        self._value_to_placeholder.clear()
        self._placeholder_to_value.clear()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_anonymous_envelope(
    text: str,
    skill_id: Optional[str] = None,
    jurisdiction: Optional[str] = None,
    language: str = "en",
) -> AnonymousEnvelope:
    """Convenience function to create anonymous envelope.

    Scans text for PII and creates envelope in one call.

    Args:
        text: User input text.
        skill_id: Optional skill ID.
        jurisdiction: Optional jurisdiction.
        language: Language code.

    Returns:
        AnonymousEnvelope ready for cloud transmission.
    """
    from .scanner import PrivacyScanner

    scanner = PrivacyScanner()
    scan_result = scanner.scan(text)

    processor = AnonymousJsonProcessor()
    return processor.create_envelope(
        text=text,
        scan_result=scan_result,
        skill_id=skill_id,
        jurisdiction=jurisdiction,
        language=language,
    )


def anonymize_for_cloud(
    text: str,
    scan_result: Optional[ScanResult] = None,
) -> Tuple[str, Dict[str, str]]:
    """Anonymize text for cloud transmission.

    Args:
        text: Original text.
        scan_result: Optional pre-computed scan result.

    Returns:
        Tuple of (anonymized_text, placeholder_mappings).
    """
    if scan_result is None:
        from .scanner import PrivacyScanner
        scanner = PrivacyScanner()
        scan_result = scanner.scan(text)

    processor = AnonymousJsonProcessor()
    return processor.anonymize_text(text, scan_result)


def rehydrate_response(
    response: str,
    placeholders: Dict[str, str],
) -> str:
    """Rehydrate cloud response with original values.

    Args:
        response: Response from cloud LLM.
        placeholders: Placeholder to original value mappings.

    Returns:
        Response with placeholders replaced.
    """
    result = response
    for placeholder, original_value in placeholders.items():
        result = result.replace(placeholder, original_value)
    return result
