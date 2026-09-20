"""
Privacy Shield - Unified API

Main entry point for all privacy protection operations.
Designed to be an invisible middleware in the LLM pipeline.

Architecture:
    User Input → [PRIVACY SHIELD PRE-FLIGHT] → Clean Data → LLM
    LLM Response → [PRIVACY SHIELD POST-FLIGHT] → Clean Response → User

All processing is 100% local - no external API calls.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

logger = logging.getLogger(__name__)

from .scanner import (
    Confidence,
    Finding,
    PIIType,
    PrivacyScanner,
    ScanResult,
    scan_text_with_local_llm,
)
from .extractor import (
    DocumentExtractor,
    DocumentType,
    ExtractionResult,
    detect_document_type,
)
from .utils.file_io import path_exists
from .redactor import (
    Clause,
    Redactor,
    RedactionMode,
    RedactionResult,
    SelectionMode,
    TextRegion,
    detect_clauses,
)

_SEMANTIC_CONTEXT_MATCHER: Any = None
_SEMANTIC_CATEGORY_TO_PII_TYPE: Dict[str, PIIType] = {
    "name": PIIType.NAME,
    "email": PIIType.EMAIL,
    "phone": PIIType.PHONE,
    "address": PIIType.ADDRESS,
    "financial": PIIType.IBAN,
    "health": PIIType.HEALTH_DATA,
    "id_document": PIIType.ID_CARD,
    "date_of_birth": PIIType.DATE_OF_BIRTH,
    "location": PIIType.ADDRESS,
}


def _truthy_env(raw: str) -> bool:
    return str(raw or "").strip().lower() in {"1", "true", "yes", "on"}


def _get_semantic_context_matcher() -> Optional[Any]:
    """Lazily initialize semantic matcher from privacy_shield_embeddings.py."""
    global _SEMANTIC_CONTEXT_MATCHER

    if _SEMANTIC_CONTEXT_MATCHER is False:
        return None
    if _SEMANTIC_CONTEXT_MATCHER is not None:
        return _SEMANTIC_CONTEXT_MATCHER

    try:
        from privacy_shield.privacy_shield_embeddings import PIIContextMatcher

        _SEMANTIC_CONTEXT_MATCHER = PIIContextMatcher()
        return _SEMANTIC_CONTEXT_MATCHER
    except Exception as exc:
        logger.debug("Semantic context matcher unavailable: %s", exc)
        _SEMANTIC_CONTEXT_MATCHER = False
        return None


def _chunk_spans(text: str, *, chunk_size: int, overlap: int) -> List[tuple[int, int, str]]:
    """Build chunk spans aligned with privacy_shield_embeddings._chunk_text behavior."""
    if not text.strip():
        return []

    spans: List[tuple[int, int, str]] = []
    if len(text) <= chunk_size:
        chunk = text.strip()
        start = text.find(chunk)
        if start >= 0:
            spans.append((start, start + len(chunk), chunk))
        return spans

    start = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        segment = text[start:end]
        chunk = segment.strip()
        if chunk:
            rel_start = segment.find(chunk)
            abs_start = start + (rel_start if rel_start >= 0 else 0)
            spans.append((abs_start, abs_start + len(chunk), chunk))

        if end >= len(text):
            break
        next_start = end - overlap
        if next_start <= start:
            next_start = start + 1
        start = next_start
    return spans


class AuditError(Exception):
    """Raised when audit logging fails and audit_required=True.

    DSK K-02 Compliance: Processing must not continue without audit trail
    when audit logging is mandatory.
    """
    pass


class ResourceLimitError(Exception):
    """Raised when input exceeds configured resource limits.

    DSK TEC-05 Compliance: Resource limits protect against DoS attacks
    and memory exhaustion from oversized inputs.
    """
    pass


class PrivacyMode(str, Enum):
    """Privacy mode controlling how data flows to LLMs.

    STANDARD: Default behavior - uses optimal model for task quality.
    LOCAL_ONLY: All model processing stays on supported local runtimes.
                Guarantees no data leaves the machine.
    ANONYMOUS_JSON: Only controlled, anonymized JSON sent to cloud LLMs.
                    Raw text stays local; only structured metadata goes to cloud.
    REGEX_ONLY: Pattern-based PII detection using Layers 1-4 only.
                No LLM required — works on mobile/PWA without Ollama.
                Provides strong coverage for direct identifiers, quasi-identifiers,
                GDPR Art. 9 special categories, and internal references.
    """
    STANDARD = "standard"
    LOCAL_ONLY = "local_only"
    ANONYMOUS_JSON = "anonymous_json"
    REGEX_ONLY = "regex_only"


class MediaType(str, Enum):
    """Supported media types."""
    TEXT = "text"
    DOCUMENT = "document"
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"
    UNKNOWN = "unknown"


class ProcessingStage(str, Enum):
    """Pipeline stage where Privacy Shield runs."""
    PRE_FLIGHT = "pre_flight"  # Before LLM sees data
    POST_FLIGHT = "post_flight"  # Before user sees response
    INTAKE = "intake"  # Document upload/intake
    EXPORT = "export"  # Before download/export


@dataclass
class ShieldResult:
    """
    Unified result from Privacy Shield processing.

    This is the single return type for all Privacy Shield operations,
    regardless of input type (text, document, image, audio, video).
    """
    # Input info
    input_type: MediaType
    input_source: str  # file path or "text_input"
    processing_stage: ProcessingStage

    # Extraction results
    extracted_text: str = ""
    extraction_method: Optional[str] = None

    # Scan results
    findings: List[Finding] = field(default_factory=list)
    findings_by_type: Dict[str, int] = field(default_factory=dict)
    pii_detected: bool = False
    high_confidence_count: int = 0

    # Redaction results
    redacted_text: str = ""
    redaction_mode: Optional[RedactionMode] = None
    redactions_applied: int = 0

    # Clause-based selection (for opt-in mode)
    clauses: List[Clause] = field(default_factory=list)
    selected_clause_count: int = 0

    # Media-specific results
    faces_detected: int = 0
    metadata_pii_fields: List[str] = field(default_factory=list)
    transcript_available: bool = False

    # Processing info
    processing_time_ms: float = 0.0
    blocked: bool = False
    block_reason: Optional[str] = None
    local_model_available: bool = False
    local_model_used: bool = False
    local_model_id: Optional[str] = None
    onnx_shadow_mode: str = "off"
    onnx_shadow_available: bool = False
    onnx_shadow_executed: bool = False
    onnx_shadow_model_id: Optional[str] = None
    onnx_shadow_model_path: Optional[str] = None
    onnx_shadow_execution_provider: Optional[str] = None
    onnx_shadow_device_class: str = "desktop"
    onnx_shadow_candidate_count: int = 0
    onnx_shadow_score: Optional[float] = None
    onnx_shadow_label: Optional[str] = None
    onnx_shadow_processing_time_ms: float = 0.0
    onnx_shadow_error: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    # Audit
    audit_id: Optional[str] = None
    timestamp: Optional[str] = None

    @property
    def is_safe(self) -> bool:
        """Check if content is safe to pass through."""
        return not self.blocked and not self.pii_detected

    @property
    def clean_output(self) -> str:
        """Get the clean output text (redacted if needed)."""
        return self.redacted_text if self.redacted_text else self.extracted_text

    def to_dict(self) -> dict:
        return {
            "input_type": self.input_type.value,
            "input_source": self.input_source,
            "processing_stage": self.processing_stage.value,
            "pii_detected": self.pii_detected,
            "finding_count": len(self.findings),
            "findings_by_type": self.findings_by_type,
            "high_confidence_count": self.high_confidence_count,
            "redaction_mode": self.redaction_mode.value if self.redaction_mode else None,
            "redactions_applied": self.redactions_applied,
            "faces_detected": self.faces_detected,
            "metadata_pii_fields": self.metadata_pii_fields,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "local_model_available": self.local_model_available,
            "local_model_used": self.local_model_used,
            "local_model_id": self.local_model_id,
            "onnx_shadow": {
                "mode": self.onnx_shadow_mode,
                "available": self.onnx_shadow_available,
                "executed": self.onnx_shadow_executed,
                "model_id": self.onnx_shadow_model_id,
                "model_path": self.onnx_shadow_model_path,
                "execution_provider": self.onnx_shadow_execution_provider,
                "device_class": self.onnx_shadow_device_class,
                "candidate_count": self.onnx_shadow_candidate_count,
                "score": self.onnx_shadow_score,
                "label": self.onnx_shadow_label,
                "processing_time_ms": self.onnx_shadow_processing_time_ms,
                "error": self.onnx_shadow_error,
            },
            "is_safe": self.is_safe,
            "processing_time_ms": self.processing_time_ms,
            "audit_id": self.audit_id,
            "errors": self.errors,
        }

    def to_audit_log(self) -> dict:
        """Generate audit log entry."""
        return {
            "audit_id": self.audit_id,
            "timestamp": self.timestamp,
            "input_type": self.input_type.value,
            "processing_stage": self.processing_stage.value,
            "pii_detected": self.pii_detected,
            "finding_count": len(self.findings),
            "findings_summary": self.findings_by_type,
            "redactions_applied": self.redactions_applied,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "processing_time_ms": self.processing_time_ms,
            "onnx_shadow_mode": self.onnx_shadow_mode,
            "onnx_shadow_available": self.onnx_shadow_available,
            "onnx_shadow_executed": self.onnx_shadow_executed,
            "onnx_shadow_model_id": self.onnx_shadow_model_id,
            "onnx_shadow_model_path": self.onnx_shadow_model_path,
            "onnx_shadow_execution_provider": self.onnx_shadow_execution_provider,
            "onnx_shadow_device_class": self.onnx_shadow_device_class,
            "onnx_shadow_candidate_count": self.onnx_shadow_candidate_count,
            "onnx_shadow_score": self.onnx_shadow_score,
            "onnx_shadow_label": self.onnx_shadow_label,
            "onnx_shadow_processing_time_ms": self.onnx_shadow_processing_time_ms,
            "onnx_shadow_error": self.onnx_shadow_error,
        }


class PrivacyShield:
    """
    Unified Privacy Shield API.

    Provides a single interface for all privacy protection operations:
    - Text scanning and redaction
    - Document extraction and scanning
    - Image OCR, face detection, and EXIF extraction
    - Audio transcription and scanning
    - Video processing (audio + frames)
    - Metadata extraction and stripping

    Designed to be an invisible middleware:
    - PRE_FLIGHT: Intercept user input before LLM
    - POST_FLIGHT: Intercept LLM response before user
    - INTAKE: Process document uploads
    - EXPORT: Process downloads/exports

    All processing is 100% local - no external API calls.
    """

    def __init__(
        self,
        # Redaction settings
        mode: RedactionMode = RedactionMode.REDACT,
        selection_mode: SelectionMode = SelectionMode.ALL,
        min_confidence: Confidence = Confidence.MEDIUM,
        # REQUIRED for HASH mode (DSK K-03): the Redactor refuses to invent one, so
        # without a way to pass it here HASH was unreachable through this class.
        hash_salt: Optional[str] = None,

        # Privacy mode settings (data flow control)
        privacy_mode: PrivacyMode = PrivacyMode.STANDARD,
        local_model_id: str = "qwen2.5:7b",

        # Scanner settings
        layers: Optional[List[int]] = None,

        # Media settings
        enable_ocr: bool = True,
        enable_face_detection: bool = True,
        enable_stt: bool = True,
        enable_metadata_extraction: bool = True,

        # Engine preferences
        ocr_engine: str = "auto",
        stt_engine: str = "auto",
        stt_model_size: str = "base",

        # Blocking settings
        block_on_types: Optional[Set[PIIType]] = None,

        # Audit settings (DSK K-02 compliance)
        audit_log_path: Optional[str] = None,
        audit_required: bool = False,
        user_context: Optional[str] = None,

        # Resource limits (DSK TEC-05 compliance - DoS protection)
        max_text_length: int = 10_000_000,  # 10MB of text
        max_file_size: int = 100_000_000,   # 100MB file size
    ):
        """
        Initialize Privacy Shield.

        Args:
            mode: Redaction mode (detect_only, redact, pseudonymize, hash, block).
            selection_mode: Content selection (all, opt_in, opt_out).
            min_confidence: Minimum confidence to flag/redact.
            privacy_mode: Data flow control mode (standard, local_only, anonymous_json).
            local_model_id: Model ID for local processing (default: qwen2.5:7b).
            layers: Scanner layers to use (1-4).
            enable_ocr: Whether to OCR images/documents.
            enable_face_detection: Whether to detect faces.
            enable_stt: Whether to transcribe audio.
            enable_metadata_extraction: Whether to extract file metadata.
            ocr_engine: OCR engine preference.
            stt_engine: Speech-to-text engine preference.
            stt_model_size: STT model size.
            block_on_types: PII types that trigger blocking.
            audit_log_path: Path for audit log file.
            audit_required: If True, processing fails if audit logging fails (DSK K-02).
            user_context: User/role identifier for audit trail (DSK compliance).
            max_text_length: Maximum text length to process (DSK TEC-05, default 10MB).
            max_file_size: Maximum file size to process (DSK TEC-05, default 100MB).

        Raises:
            ResourceLimitError: If input exceeds configured limits.
            AuditError: If audit_required=True and audit logging fails.
        """
        self.mode = mode
        self.selection_mode = selection_mode
        self.min_confidence = min_confidence
        self.privacy_mode = privacy_mode
        self.local_model_id = local_model_id
        self.layers = layers or [1, 2, 3, 4]

        self.enable_ocr = enable_ocr
        self.enable_face_detection = enable_face_detection
        self.enable_stt = enable_stt
        self.enable_metadata_extraction = enable_metadata_extraction

        self.ocr_engine = ocr_engine
        self.stt_engine = stt_engine
        self.stt_model_size = stt_model_size

        self.block_on_types = block_on_types or {
            PIIType.IBAN,
            PIIType.CREDIT_CARD,
            PIIType.HEALTH_DATA,
            PIIType.BIOMETRIC,
            PIIType.CRIMINAL,
        }

        self.audit_log_path = audit_log_path
        self.audit_required = audit_required
        self.user_context = user_context

        # Resource limits (DSK TEC-05)
        self.max_text_length = max_text_length
        self.max_file_size = max_file_size

        # DSK K-02: Warn if audit_required but no path configured
        if audit_required and not audit_log_path:
            logger.warning(
                "audit_required=True but no audit_log_path configured. "
                "Processing will fail without a valid audit log path."
            )

        # Initialize core components
        self.scanner = PrivacyScanner(
            layers=self.layers,
            min_confidence=min_confidence,
        )
        self.redactor = Redactor(
            mode=mode,
            selection_mode=selection_mode,
            hash_salt=hash_salt,
            min_confidence=min_confidence,
            block_on_types=self.block_on_types,
        )
        self.doc_extractor = DocumentExtractor(
            detect_zones=True,
            extract_metadata=enable_metadata_extraction,
        )

        # Lazy-loaded media processors
        self._image_processor = None
        self._audio_processor = None
        self._video_processor = None
        self._metadata_extractor = None

    def _get_image_processor(self):
        """Lazy-load image processor."""
        if self._image_processor is None:
            from .media.image import ImageProcessor
            self._image_processor = ImageProcessor(
                ocr_engine=self.ocr_engine,
                detect_faces=self.enable_face_detection,
                extract_metadata=self.enable_metadata_extraction,
            )
        return self._image_processor

    def _get_audio_processor(self):
        """Lazy-load audio processor."""
        if self._audio_processor is None:
            from .media.audio import AudioProcessor
            self._audio_processor = AudioProcessor(
                stt_engine=self.stt_engine,
                model_size=self.stt_model_size,
            )
        return self._audio_processor

    def _get_video_processor(self):
        """Lazy-load video processor."""
        if self._video_processor is None:
            from .media.video import VideoProcessor
            self._video_processor = VideoProcessor(
                process_audio=self.enable_stt,
                process_frames=self.enable_ocr,
                detect_faces=self.enable_face_detection,
                stt_engine=self.stt_engine,
                stt_model_size=self.stt_model_size,
                ocr_engine=self.ocr_engine,
            )
        return self._video_processor

    def _get_metadata_extractor(self):
        """Lazy-load metadata extractor."""
        if self._metadata_extractor is None:
            from .media.metadata import MetadataExtractor
            self._metadata_extractor = MetadataExtractor()
        return self._metadata_extractor

    def _generate_audit_id(self) -> str:
        """Generate a unique audit ID."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        random_part = hashlib.sha256(os.urandom(16)).hexdigest()[:8]
        return f"ps-{timestamp}-{random_part}"

    def _detect_media_type(self, file_path: Path) -> MediaType:
        """Detect media type from file."""
        suffix = file_path.suffix.lower()

        image_exts = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp", ".heic", ".heif"}
        audio_exts = {".mp3", ".wav", ".m4a", ".flac", ".ogg", ".aac", ".wma"}
        video_exts = {".mp4", ".mov", ".avi", ".mkv", ".wmv", ".flv", ".webm"}
        doc_exts = {".pdf", ".docx", ".doc", ".txt", ".rtf", ".html", ".htm", ".xlsx", ".pptx"}

        if suffix in image_exts:
            return MediaType.IMAGE
        elif suffix in audio_exts:
            return MediaType.AUDIO
        elif suffix in video_exts:
            return MediaType.VIDEO
        elif suffix in doc_exts:
            return MediaType.DOCUMENT
        else:
            return MediaType.UNKNOWN

    def _log_audit(self, result: ShieldResult) -> None:
        """Write audit log entry with integrity protection.

        DSK K-02 Compliance: Audit logging is critical for accountability.
        If audit_required=True and logging fails, raises AuditError.
        """
        if not self.audit_log_path:
            if self.audit_required:
                raise AuditError(
                    "Audit logging required but no audit_log_path configured. "
                    "Processing cannot continue without audit trail."
                )
            return

        try:
            log_entry = result.to_audit_log()

            # Add user context for traceability (DSK requirement)
            if self.user_context:
                log_entry["user_context"] = self.user_context

            # Add integrity hash for tamper detection
            entry_content = json.dumps(log_entry, sort_keys=True)
            integrity_hash = hashlib.sha256(entry_content.encode()).hexdigest()[:16]
            log_entry["integrity_hash"] = integrity_hash

            log_entry_json = json.dumps(log_entry)

            with open(self.audit_log_path, "a") as f:
                f.write(log_entry_json + "\n")

        except Exception as e:
            error_msg = f"Audit logging failed: {e}"
            logger.error(error_msg)

            if self.audit_required:
                raise AuditError(error_msg) from e
            else:
                logger.warning(
                    "Audit logging failed but audit_required=False. "
                    "Processing continues without audit record."
                )

    def _apply_onnx_shadow(self, text: str, scan_result: ScanResult, result: ShieldResult) -> None:
        """Run ONNX in shadow mode only; never affect live decisions here."""
        try:
            from .onnx_shadow import run_onnx_shadow_scan

            shadow = run_onnx_shadow_scan(text, scan_result)
            result.onnx_shadow_mode = shadow.mode
            result.onnx_shadow_available = shadow.available
            result.onnx_shadow_executed = shadow.executed
            result.onnx_shadow_model_id = shadow.model_id
            result.onnx_shadow_model_path = shadow.model_path
            result.onnx_shadow_execution_provider = shadow.execution_provider
            result.onnx_shadow_device_class = shadow.device_class
            result.onnx_shadow_candidate_count = shadow.candidate_count
            result.onnx_shadow_score = shadow.score
            result.onnx_shadow_label = shadow.label
            result.onnx_shadow_processing_time_ms = shadow.processing_time_ms
            result.onnx_shadow_error = shadow.error
        except Exception as exc:
            result.onnx_shadow_mode = "off"
            result.onnx_shadow_available = False
            result.onnx_shadow_executed = False
            result.onnx_shadow_model_id = None
            result.onnx_shadow_model_path = None
            result.onnx_shadow_execution_provider = None
            result.onnx_shadow_device_class = "desktop"
            result.onnx_shadow_candidate_count = 0
            result.onnx_shadow_score = None
            result.onnx_shadow_label = None
            result.onnx_shadow_processing_time_ms = 0.0
            result.onnx_shadow_error = f"onnx_shadow_failed:{exc}"

    def _semantic_context_enabled(self) -> bool:
        """Semantic context scan is enabled for standard and anonymous-json flows only."""
        if self.requires_local_only() or self.requires_regex_only():
            return False
        return _truthy_env(os.getenv("PRIVACY_SHIELD_SEMANTIC_ENABLED", "1"))

    def _apply_semantic_context_matches(self, text: str, scan_result: ScanResult) -> int:
        """Augment scan_result with embedding-based context findings."""
        if not self._semantic_context_enabled():
            return 0

        matcher = _get_semantic_context_matcher()
        if matcher is None or not getattr(matcher, "is_ready", False):
            return 0

        try:
            threshold = float(os.getenv("PRIVACY_SHIELD_SEMANTIC_THRESHOLD", "0.75"))
        except Exception:
            threshold = 0.75
        threshold = max(0.0, min(1.0, threshold))

        try:
            chunk_size = int(os.getenv("PRIVACY_SHIELD_SEMANTIC_CHUNK_SIZE", "200"))
        except Exception:
            chunk_size = 200
        chunk_size = max(80, min(2000, chunk_size))

        try:
            matches = matcher.scan_for_pii_contexts(text, threshold=threshold, chunk_size=chunk_size)
        except Exception as exc:
            logger.debug("Semantic context scan skipped: %s", exc)
            return 0
        if not matches:
            return 0

        spans = _chunk_spans(text, chunk_size=chunk_size, overlap=50)
        existing_spans: List[tuple[int, int]] = [(f.start, f.end) for f in scan_result.findings]
        added = 0

        for match in matches:
            category = str(getattr(match, "pii_category", "")).strip().lower()
            pii_type = _SEMANTIC_CATEGORY_TO_PII_TYPE.get(category)
            if pii_type is None:
                continue

            start = -1
            end = -1
            chunk_idx = int(getattr(match, "chunk_index", -1) or -1)
            chunk_text = str(getattr(match, "chunk_text", "") or "").strip()

            if 0 <= chunk_idx < len(spans):
                start, end, chunk_text = spans[chunk_idx]
            elif chunk_text:
                start = text.find(chunk_text)
                if start >= 0:
                    end = start + len(chunk_text)
            if start < 0 or end <= start:
                continue

            overlaps_existing = any(not (end <= seen_start or start >= seen_end) for seen_start, seen_end in existing_spans)
            if overlaps_existing:
                continue

            try:
                score = float(getattr(match, "similarity_score", 0.0) or 0.0)
            except Exception:
                score = 0.0
            if score >= 0.9:
                confidence = Confidence.HIGH
            elif score >= 0.8:
                confidence = Confidence.MEDIUM
            else:
                confidence = Confidence.LOW

            finding = Finding(
                pii_type=pii_type,
                value=chunk_text[:80] if chunk_text else "[semantic-context]",
                start=start,
                end=end,
                confidence=confidence,
                layer=6,
                context=self.scanner._get_context(text, start, end),
            )
            scan_result.findings.append(finding)
            existing_spans.append((start, end))
            added += 1

        if added > 0:
            scan_result.findings.sort(key=lambda finding: finding.start)
            if 6 not in scan_result.layers_used:
                scan_result.layers_used.append(6)
        return added

    # =========================================================================
    # MAIN PROCESSING METHODS
    # =========================================================================

    def process_text(
        self,
        text: str,
        stage: ProcessingStage = ProcessingStage.PRE_FLIGHT,
    ) -> ShieldResult:
        """
        Process text for PII.

        This is the core method for text-only processing.
        Used for both user input (PRE_FLIGHT) and LLM output (POST_FLIGHT).

        Args:
            text: Text to process.
            stage: Pipeline stage.

        Returns:
            ShieldResult with scan and redaction results.

        Raises:
            ResourceLimitError: If text exceeds max_text_length.
        """
        # DSK TEC-05: Check resource limits
        if len(text) > self.max_text_length:
            raise ResourceLimitError(
                f"Text length ({len(text):,} chars) exceeds limit "
                f"({self.max_text_length:,} chars). "
                "Reduce input size or increase max_text_length."
            )

        start_time = time.perf_counter()

        result = ShieldResult(
            input_type=MediaType.TEXT,
            input_source="text_input",
            processing_stage=stage,
            extracted_text=text,
            audit_id=self._generate_audit_id(),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        local_model_available = self.check_local_model_available()
        use_local_enhancement = local_model_available and not self.requires_regex_only()
        result.local_model_available = local_model_available
        result.local_model_used = use_local_enhancement
        result.local_model_id = self.local_model_id if use_local_enhancement else None

        # Scan text
        if use_local_enhancement:
            scan_result = scan_text_with_local_llm(
                text,
                layers=self.layers,
                min_confidence=self.min_confidence,
                use_llm_enhancement=True,
            )
        else:
            scan_result = self.scanner.scan(text)
        self._apply_semantic_context_matches(text, scan_result)
        result.findings = scan_result.findings
        result.pii_detected = scan_result.has_pii
        result.high_confidence_count = scan_result.high_confidence_count
        self._apply_onnx_shadow(text, scan_result, result)

        # Count findings by type
        for finding in scan_result.findings:
            key = finding.pii_type.value
            result.findings_by_type[key] = result.findings_by_type.get(key, 0) + 1

        # Redact if needed
        if self.mode != RedactionMode.DETECT_ONLY and scan_result.has_pii:
            redaction_result = self.redactor.redact(scan_result)
            result.redacted_text = redaction_result.redacted_text
            result.redaction_mode = self.mode
            result.redactions_applied = redaction_result.redactions_applied
            result.blocked = redaction_result.blocked
            result.block_reason = redaction_result.block_reason
        else:
            result.redacted_text = text

        result.processing_time_ms = (time.perf_counter() - start_time) * 1000
        self._log_audit(result)

        return result

    def process_file(
        self,
        file_path: Union[str, Path],
        stage: ProcessingStage = ProcessingStage.INTAKE,
    ) -> ShieldResult:
        """
        Process any file type for PII.

        Automatically detects file type and routes to appropriate processor.

        Args:
            file_path: Path to the file.
            stage: Pipeline stage.

        Returns:
            ShieldResult with extraction, scan, and redaction results.

        Raises:
            ResourceLimitError: If file exceeds max_file_size.
        """
        start_time = time.perf_counter()

        path = Path(file_path)
        media_type = self._detect_media_type(path)

        result = ShieldResult(
            input_type=media_type,
            input_source=str(path),
            processing_stage=stage,
            audit_id=self._generate_audit_id(),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        if not path.exists():
            result.errors.append(f"File not found: {path}")
            return result

        # DSK TEC-05: Check file size limits
        try:
            file_size = path.stat().st_size
            if file_size > self.max_file_size:
                raise ResourceLimitError(
                    f"File size ({file_size:,} bytes) exceeds limit "
                    f"({self.max_file_size:,} bytes). "
                    "Reduce file size or increase max_file_size."
                )
        except OSError as e:
            result.errors.append(f"Cannot read file stats: {e}")
            return result

        # Route to appropriate processor
        try:
            if media_type == MediaType.DOCUMENT:
                self._process_document(path, result)
            elif media_type == MediaType.IMAGE:
                self._process_image(path, result)
            elif media_type == MediaType.AUDIO:
                self._process_audio(path, result)
            elif media_type == MediaType.VIDEO:
                self._process_video(path, result)
            else:
                # Try as text file
                try:
                    text = path.read_text()
                    result.extracted_text = text
                    result.extraction_method = "direct_read"
                except Exception:
                    result.errors.append(f"Unknown file type: {path.suffix}")

        except Exception as e:
            result.errors.append(f"Processing error: {str(e)}")

        # Scan extracted text
        if result.extracted_text:
            local_model_available = self.check_local_model_available()
            use_local_enhancement = local_model_available and not self.requires_regex_only()
            result.local_model_available = local_model_available
            result.local_model_used = use_local_enhancement
            result.local_model_id = self.local_model_id if use_local_enhancement else None

            if use_local_enhancement:
                scan_result = scan_text_with_local_llm(
                    result.extracted_text,
                    layers=self.layers,
                    min_confidence=self.min_confidence,
                    use_llm_enhancement=True,
                )
            else:
                scan_result = self.scanner.scan(result.extracted_text)
            self._apply_semantic_context_matches(result.extracted_text, scan_result)
            result.findings = scan_result.findings
            result.pii_detected = scan_result.has_pii
            result.high_confidence_count = scan_result.high_confidence_count
            self._apply_onnx_shadow(result.extracted_text, scan_result, result)

            for finding in scan_result.findings:
                key = finding.pii_type.value
                result.findings_by_type[key] = result.findings_by_type.get(key, 0) + 1

            # Detect clauses for opt-in selection
            if self.selection_mode == SelectionMode.OPT_IN:
                result.clauses = detect_clauses(result.extracted_text, scan_result)
                result.selected_clause_count = sum(1 for c in result.clauses if c.selected)

            # Redact if needed
            if self.mode != RedactionMode.DETECT_ONLY and scan_result.has_pii:
                redaction_result = self.redactor.redact(scan_result)
                result.redacted_text = redaction_result.redacted_text
                result.redaction_mode = self.mode
                result.redactions_applied = redaction_result.redactions_applied
                result.blocked = redaction_result.blocked
                result.block_reason = redaction_result.block_reason
            else:
                result.redacted_text = result.extracted_text

        # Also check for faces (biometric PII)
        if result.faces_detected > 0:
            result.pii_detected = True
            result.findings_by_type["face"] = result.faces_detected

        # Also check metadata PII
        if result.metadata_pii_fields:
            result.pii_detected = True
            result.findings_by_type["metadata"] = len(result.metadata_pii_fields)

        result.processing_time_ms = (time.perf_counter() - start_time) * 1000
        self._log_audit(result)

        return result

    def _process_document(self, path: Path, result: ShieldResult) -> None:
        """Process document file."""
        extraction = self.doc_extractor.extract(path)
        result.extracted_text = extraction.full_text
        result.extraction_method = extraction.extraction_method.value

        if extraction.errors:
            result.errors.extend(extraction.errors)

        # Extract metadata PII
        if self.enable_metadata_extraction and extraction.metadata:
            for key, value in extraction.metadata.items():
                if key.lower() in ("author", "creator", "last_modified_by"):
                    result.metadata_pii_fields.append(key)

    def _process_image(self, path: Path, result: ShieldResult) -> None:
        """Process image file."""
        if not self.enable_ocr:
            return

        processor = self._get_image_processor()
        img_result = processor.process(path)

        result.extracted_text = img_result.full_text
        result.extraction_method = f"ocr_{img_result.ocr_engine}"
        result.faces_detected = len(img_result.faces)
        result.metadata_pii_fields = img_result.metadata.pii_fields

        if img_result.errors:
            result.errors.extend(img_result.errors)

    def _process_audio(self, path: Path, result: ShieldResult) -> None:
        """Process audio file."""
        if not self.enable_stt:
            return

        processor = self._get_audio_processor()
        audio_result = processor.process(path)

        result.extracted_text = audio_result.full_transcript
        result.extraction_method = f"stt_{audio_result.stt_engine}"
        result.transcript_available = audio_result.has_transcript
        result.metadata_pii_fields = audio_result.metadata.pii_fields

        if audio_result.errors:
            result.errors.extend(audio_result.errors)

    def _process_video(self, path: Path, result: ShieldResult) -> None:
        """Process video file."""
        processor = self._get_video_processor()
        video_result = processor.process(path)

        # Combine transcript and visual text
        texts = []
        if video_result.full_transcript:
            texts.append(video_result.full_transcript)
        if video_result.all_visual_text:
            texts.append(video_result.all_visual_text)

        result.extracted_text = "\n\n".join(texts)
        result.extraction_method = "video_multimodal"
        result.faces_detected = video_result.total_faces_detected
        result.transcript_available = bool(video_result.full_transcript)
        result.metadata_pii_fields = video_result.metadata.pii_fields

        if video_result.errors:
            result.errors.extend(video_result.errors)

    # =========================================================================
    # PIPELINE INTEGRATION METHODS
    # =========================================================================

    def pre_flight(
        self,
        content: Union[str, Path],
    ) -> ShieldResult:
        """
        Pre-flight check before sending to LLM.

        This is the main entry point for the pipeline.
        Automatically handles text or file input.

        Args:
            content: Text string or file path.

        Returns:
            ShieldResult with clean_output ready for LLM.
        """
        if isinstance(content, str) and not path_exists(content):
            return self.process_text(content, ProcessingStage.PRE_FLIGHT)
        else:
            return self.process_file(content, ProcessingStage.PRE_FLIGHT)

    def post_flight(self, text: str) -> ShieldResult:
        """
        Post-flight check on LLM response.

        Scans LLM output before delivering to user.

        Args:
            text: LLM response text.

        Returns:
            ShieldResult with clean_output ready for user.
        """
        return self.process_text(text, ProcessingStage.POST_FLIGHT)

    def intake(self, file_path: Union[str, Path]) -> ShieldResult:
        """
        Process document on intake/upload.

        Args:
            file_path: Uploaded file path.

        Returns:
            ShieldResult with extraction and scan results.
        """
        return self.process_file(file_path, ProcessingStage.INTAKE)

    def export(
        self,
        text: str,
        output_path: Optional[Union[str, Path]] = None,
    ) -> ShieldResult:
        """
        Process content before export/download.

        Args:
            text: Content to export.
            output_path: Optional path for redacted output file.

        Returns:
            ShieldResult with redacted content.
        """
        result = self.process_text(text, ProcessingStage.EXPORT)

        # Optionally write to file
        if output_path and result.redacted_text:
            try:
                Path(output_path).write_text(result.redacted_text)
            except Exception as e:
                result.errors.append(f"Export write error: {str(e)}")

        return result

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    def get_clauses(self, text: str) -> List[Clause]:
        """
        Get detected clauses for opt-in selection UI.

        Args:
            text: Document text.

        Returns:
            List of Clause objects with PII indicators.
        """
        scan_result = self.scanner.scan(text)
        return detect_clauses(text, scan_result)

    def process_with_selection(
        self,
        text: str,
        selected_clause_indices: List[int],
    ) -> ShieldResult:
        """
        Process with user-selected clauses (opt-in mode).

        Args:
            text: Full document text.
            selected_clause_indices: Indices of clauses to include.

        Returns:
            ShieldResult with only selected clauses processed.
        """
        # Get clauses
        scan_result = self.scanner.scan(text)
        clauses = detect_clauses(text, scan_result)

        # Mark selection
        for i, clause in enumerate(clauses):
            clause.selected = i in selected_clause_indices

        # Convert to regions
        from .redactor import clauses_to_regions
        regions = clauses_to_regions(clauses)

        # Create temporary redactor with opt-in mode
        redactor = Redactor(
            mode=self.mode,
            selection_mode=SelectionMode.OPT_IN,
            min_confidence=self.min_confidence,
        )

        # Redact
        redaction_result = redactor.redact(
            scan_result,
            included_regions=[r for r in regions if r.included],
        )

        # Build result
        result = ShieldResult(
            input_type=MediaType.TEXT,
            input_source="text_input",
            processing_stage=ProcessingStage.PRE_FLIGHT,
            extracted_text=text,
            findings=scan_result.findings,
            pii_detected=scan_result.has_pii,
            redacted_text=redaction_result.redacted_text,
            redaction_mode=self.mode,
            redactions_applied=redaction_result.redactions_applied,
            clauses=clauses,
            selected_clause_count=len(selected_clause_indices),
            audit_id=self._generate_audit_id(),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        self._log_audit(result)
        return result

    def strip_metadata(
        self,
        input_path: Union[str, Path],
        output_path: Union[str, Path],
    ) -> bool:
        """
        Strip metadata from a file.

        Args:
            input_path: Input file.
            output_path: Output file (cleaned).

        Returns:
            True if successful.
        """
        extractor = self._get_metadata_extractor()
        return extractor.strip_metadata(input_path, output_path)

    def reset_session(self) -> None:
        """Reset pseudonymization state for a new session."""
        self.redactor.reset_session()

    # =========================================================================
    # PRIVACY MODE METHODS
    # =========================================================================

    def get_privacy_mode(self) -> PrivacyMode:
        """Get current privacy mode."""
        return self.privacy_mode

    def set_privacy_mode(self, mode: PrivacyMode) -> None:
        """Set privacy mode for data flow control."""
        self.privacy_mode = mode
        logger.info("Privacy mode changed to: %s", mode.value)

    def requires_local_only(self) -> bool:
        """Check if current mode requires local-only processing."""
        return self.privacy_mode == PrivacyMode.LOCAL_ONLY

    def requires_anonymous_json(self) -> bool:
        """Check if current mode requires anonymous JSON envelope."""
        return self.privacy_mode == PrivacyMode.ANONYMOUS_JSON

    def requires_regex_only(self) -> bool:
        """Check if current mode uses pattern-based PII detection only (no LLM)."""
        return self.privacy_mode == PrivacyMode.REGEX_ONLY

    def get_model_routing_config(self) -> Dict[str, Any]:
        """Get model routing configuration based on privacy mode.

        Returns:
            Dict with routing configuration:
            - force_local: bool - If True, only use local models
            - allowed_providers: List[str] - Allowed model providers
            - fallback_model: str - Model to use when others unavailable
            - log_enforcement: bool - Whether to log privacy decisions
        """
        if self.privacy_mode == PrivacyMode.REGEX_ONLY:
            return {
                "force_local": False,
                "allowed_providers": ["embedded", "lm_studio", "jan", "gpt4all", "ollama", "openai", "anthropic"],
                "fallback_model": self.local_model_id,
                "log_enforcement": True,
                "privacy_mode": "regex_only",
                "pii_scan_mode": "regex_only",
            }
        elif self.privacy_mode == PrivacyMode.LOCAL_ONLY:
            return {
                "force_local": True,
                "allowed_providers": ["embedded", "lm_studio", "jan", "gpt4all", "ollama"],
                "fallback_model": self.local_model_id,
                "log_enforcement": True,
                "privacy_mode": "local_only",
            }
        elif self.privacy_mode == PrivacyMode.ANONYMOUS_JSON:
            return {
                "force_local": False,
                "allowed_providers": ["embedded", "lm_studio", "jan", "gpt4all", "ollama", "openai", "anthropic"],
                "fallback_model": self.local_model_id,
                "log_enforcement": True,
                "privacy_mode": "anonymous_json",
                "require_envelope": True,
            }
        else:
            return {
                "force_local": False,
                "allowed_providers": ["embedded", "lm_studio", "jan", "gpt4all", "ollama", "openai", "anthropic"],
                "fallback_model": self.local_model_id,
                "log_enforcement": False,
                "privacy_mode": "standard",
            }

    def check_local_model_available(self) -> bool:
        """Check if local model is available for LOCAL_ONLY mode."""
        try:
            from privacy_shield.services.local_model_runtime import is_local_model_available
            return is_local_model_available()
        except ImportError:
            return False


# =============================================================================
# PRIVACY MODE GLOBAL STATE
# =============================================================================

_global_privacy_mode: PrivacyMode = PrivacyMode.STANDARD
_global_local_model_id: str = "qwen2.5:7b"


def get_global_privacy_mode() -> PrivacyMode:
    """Get the global privacy mode setting."""
    return _global_privacy_mode


def set_global_privacy_mode(mode: PrivacyMode) -> None:
    """Set the global privacy mode setting."""
    global _global_privacy_mode
    _global_privacy_mode = mode
    logger.info("Global privacy mode set to: %s", mode.value)


def get_global_local_model_id() -> str:
    """Get the global local model ID."""
    return _global_local_model_id


def set_global_local_model_id(model_id: str) -> None:
    """Set the global local model ID."""
    global _global_local_model_id
    _global_local_model_id = model_id
    logger.info("Global local model ID set to: %s", model_id)


def create_shield_with_global_mode(**kwargs) -> "PrivacyShield":
    """Create a PrivacyShield instance using global privacy mode settings.

    This is a convenience factory that applies the global privacy mode
    to a new PrivacyShield instance.
    """
    kwargs.setdefault("privacy_mode", _global_privacy_mode)
    kwargs.setdefault("local_model_id", _global_local_model_id)
    return PrivacyShield(**kwargs)
