"""
Privacy Shield - Privacy-proof PII detection and redaction.

100% local execution, zero external API calls.
Supports documents, images, audio, and video.
"""

from .scanner import (
    PrivacyScanner,
    ScanResult,
    Finding,
    scan_text,
    scan_text_with_local_llm,
    is_safe_for_external_llm,
)
from .extractor import (
    DocumentExtractor,
    extract_document,
    detect_document_type,
)
from .redactor import (
    Redactor,
    RedactionMode,
    redact_text,
)
from .shield import (
    PrivacyShield,
    AuditError,
    ResourceLimitError,
    PrivacyMode,
    get_global_privacy_mode,
    set_global_privacy_mode,
    get_global_local_model_id,
    set_global_local_model_id,
    create_shield_with_global_mode,
)
from .anonymous_json import (
    AnonymousEnvelope,
    AnonymousJsonProcessor,
    create_anonymous_envelope,
    anonymize_for_cloud,
    rehydrate_response,
)
from .security_scanner import (
    SecurityScanner,
    SecurityScanResult,
    SecurityScanCache,
    ThreatFinding,
    ThreatType,
    ThreatSeverity,
    scan_document_security,
    scan_with_local_llm,
    get_security_cache,
    reset_security_cache,
)

from .anonymisation_skill import (
    AnonymisationSkill,
    AnonymisationResult,
    AnonymisationMode,
    PseudonymisationSession,
    anonymise_text,
    pseudonymise_text,
    assess_anonymisation,
)
from .privacy_skill_kg import (
    record_privacy_kg_fact,
    list_privacy_kg_facts,
    summarize_privacy_kg_facts,
)
from .gate import (
    PrivacyGate,
    PrivacyGateResult,
    privacy_gate,
    require_privacy_check,
)
from .enforcement import (
    EnforcementSink,
    EnforcementDecision,
    EnforcementVerdict,
    NoOpEnforcementSink,
    RvndEnforcementAdapter,
    NOOP_SINK,
)
from .runner import (
    scan,
    ScanReport,
    DocumentScan,
    SpanFinding,
)

__all__ = [
    # Main API
    "PrivacyShield",
    "PrivacyMode",
    "AuditError",
    "ResourceLimitError",
    # Global privacy mode state
    "get_global_privacy_mode",
    "set_global_privacy_mode",
    "get_global_local_model_id",
    "set_global_local_model_id",
    "create_shield_with_global_mode",
    # Anonymous JSON Mode
    "AnonymousEnvelope",
    "AnonymousJsonProcessor",
    "create_anonymous_envelope",
    "anonymize_for_cloud",
    "rehydrate_response",
    # Scanner
    "PrivacyScanner",
    "ScanResult",
    "Finding",
    "scan_text",
    "scan_text_with_local_llm",
    "is_safe_for_external_llm",
    # Extractor
    "DocumentExtractor",
    "extract_document",
    "detect_document_type",
    # Redactor
    "Redactor",
    "RedactionMode",
    "redact_text",
    # Security Scanner
    "SecurityScanner",
    "SecurityScanResult",
    "SecurityScanCache",
    "ThreatFinding",
    "ThreatType",
    "ThreatSeverity",
    "scan_document_security",
    "scan_with_local_llm",
    "get_security_cache",
    "reset_security_cache",
    # Anonymisation Skill
    "AnonymisationSkill",
    "AnonymisationResult",
    "AnonymisationMode",
    "PseudonymisationSession",
    "anonymise_text",
    "pseudonymise_text",
    "assess_anonymisation",
    # Privacy Skill KG
    "record_privacy_kg_fact",
    "list_privacy_kg_facts",
    "summarize_privacy_kg_facts",
    # Egress guard
    "PrivacyGate",
    "PrivacyGateResult",
    "privacy_gate",
    "require_privacy_check",
    # Optional RVND enforcement/audit seam (RVND-optional)
    "EnforcementSink",
    "EnforcementDecision",
    "EnforcementVerdict",
    "NoOpEnforcementSink",
    "RvndEnforcementAdapter",
    "NOOP_SINK",
    # Governed-folder runner (agent-invokable capability + CLI)
    "scan",
    "ScanReport",
    "DocumentScan",
    "SpanFinding",
]

__version__ = "1.0.0"
