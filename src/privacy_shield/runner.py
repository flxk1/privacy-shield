"""Governed-folder runner — the agent-invokable ``scan()`` capability.

This is the thin entry point that turns the existing Privacy Shield pipeline into
a single callable. It orchestrates and presents; it does **not** reimplement the
engine. Per document it drives the real pipeline —

    extract  (shield.process_file / process_text via extractor.py)
      -> regex/lexicon scan        (scanner.PrivacyScanner)
      -> semantic 2nd pass         (privacy_shield_embeddings, when installed)
      -> local-LLM check           (services.local_model_runtime, when available)
      -> redact / walk spans       (redactor.Redactor)
      -> build clean overlay       (redactor overlay, or anonymous_json in
                                     ANONYMOUS_JSON mode)
      -> egress-guard decision     (gate.PrivacyGate on source classification)
      -> audit                     (gate records AI_PRIVACY_SHIELD_DECISION)

and returns a structured :class:`ScanReport`: the clean overlay (the only thing
meant to leave the machine), the per-span findings, and the egress verdict.

No external enforcement sink is attached. The gate
decides locally and records to the standalone :mod:`privacy_shield.audit_log`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ._legacy_env import reject_legacy_env
from .utils.file_io import path_exists
from .anonymous_json import anonymize_for_cloud
from .gate import PrivacyGate
from .redactor import RedactionMode, SelectionMode
from .scanner import Confidence, ScanResult
from .shield import (
    MediaType,
    PrivacyMode,
    PrivacyShield,
    ShieldResult,
    get_global_privacy_mode,
    set_global_privacy_mode,
)

# Text / document extensions considered when walking a folder. A single file
# passed directly is always processed regardless of extension.
DEFAULT_EXTENSIONS = frozenset({
    ".txt", ".md", ".markdown", ".rst", ".csv", ".tsv", ".json",
    ".log", ".html", ".htm", ".xml", ".yaml", ".yml",
    ".pdf", ".docx", ".doc", ".rtf",
})


@dataclass
class SpanFinding:
    """One PII span found in a document (the span-by-span unit)."""

    pii_type: str
    start: int
    end: int
    confidence: str
    layer: int
    # Original matched value + context are LOCAL-only telemetry. They are part of
    # the on-machine result and are NEVER placed in the overlay that egresses.
    value: str = ""
    context: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pii_type": self.pii_type,
            "start": self.start,
            "end": self.end,
            "confidence": self.confidence,
            "layer": self.layer,
            "value": self.value,
            "context": self.context,
        }


@dataclass
class DocumentScan:
    """Per-document result of the pipeline."""

    source: str
    input_type: str
    overlay: str  # the clean overlay — the ONLY thing meant to leave the machine
    spans: List[SpanFinding] = field(default_factory=list)
    pii_detected: bool = False
    findings_by_type: Dict[str, int] = field(default_factory=dict)
    # Egress verdict from the gate over the overlay.
    egress_allowed: bool = True
    classification: str = "public"
    blocked_reason: str = ""
    # Redactor BLOCK-mode block (distinct from an egress block).
    redaction_blocked: bool = False
    redaction_block_reason: Optional[str] = None
    placeholder_count: int = 0
    audit_id: Optional[str] = None
    errors: List[str] = field(default_factory=list)

    @property
    def span_count(self) -> int:
        return len(self.spans)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "input_type": self.input_type,
            "overlay": self.overlay,
            "span_count": self.span_count,
            "spans": [s.to_dict() for s in self.spans],
            "pii_detected": self.pii_detected,
            "findings_by_type": self.findings_by_type,
            "egress_allowed": self.egress_allowed,
            "classification": self.classification,
            "blocked_reason": self.blocked_reason,
            "redaction_blocked": self.redaction_blocked,
            "redaction_block_reason": self.redaction_block_reason,
            "placeholder_count": self.placeholder_count,
            "audit_id": self.audit_id,
            "errors": self.errors,
        }


@dataclass
class ScanReport:
    """Aggregate result over one target (text, file, or folder)."""

    mode: str
    destination: str
    root: str
    documents: List[DocumentScan] = field(default_factory=list)

    @property
    def document_count(self) -> int:
        return len(self.documents)

    @property
    def total_spans(self) -> int:
        return sum(d.span_count for d in self.documents)

    @property
    def all_allowed(self) -> bool:
        """True iff every document's overlay is cleared for egress."""
        return all(d.egress_allowed for d in self.documents)

    @property
    def blocked_documents(self) -> List[DocumentScan]:
        return [d for d in self.documents if not d.egress_allowed]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "destination": self.destination,
            "root": self.root,
            "document_count": self.document_count,
            "total_spans": self.total_spans,
            "all_allowed": self.all_allowed,
            "documents": [d.to_dict() for d in self.documents],
        }


def _iter_files(
    root: Path,
    *,
    recursive: bool,
    extensions: Optional[frozenset],
) -> List[Path]:
    """Collect candidate document files under *root* (deterministic order)."""
    files: List[Path] = []
    walker = root.rglob("*") if recursive else root.glob("*")
    for path in walker:
        if not path.is_file():
            continue
        # Skip hidden files/dirs and python caches.
        parts = path.relative_to(root).parts
        if any(p.startswith(".") for p in parts) or "__pycache__" in parts:
            continue
        if extensions is not None and path.suffix.lower() not in extensions:
            continue
        files.append(path)
    return sorted(files)


def _build_overlay(
    mode: PrivacyMode,
    result: ShieldResult,
) -> tuple[str, int]:
    """Build the clean overlay for *result* according to *mode*.

    Returns ``(overlay_text, placeholder_count)``. In ANONYMOUS_JSON mode the
    overlay is produced by the anonymous-JSON path (PII -> placeholders, the
    value<->placeholder map stays LOCAL). Otherwise it is the redactor overlay
    already computed by the shield.
    """
    if mode == PrivacyMode.ANONYMOUS_JSON and result.extracted_text:
        scan_result = ScanResult(text=result.extracted_text, findings=result.findings)
        overlay, placeholders = anonymize_for_cloud(result.extracted_text, scan_result)
        return overlay, len(placeholders)
    return result.clean_output, result.redactions_applied


def _spans_from(result: ShieldResult) -> List[SpanFinding]:
    return [
        SpanFinding(
            pii_type=f.pii_type.value,
            start=f.start,
            end=f.end,
            confidence=f.confidence.value,
            layer=f.layer,
            value=f.value,
            context=f.context,
        )
        for f in result.findings
    ]


def _process_one(
    shield: PrivacyShield,
    gate: PrivacyGate,
    mode: PrivacyMode,
    *,
    source: str,
    result: ShieldResult,
    destination: str,
    tenant_id: str,
    user_id: str,
) -> DocumentScan:
    """Turn a raw ShieldResult into a DocumentScan + egress verdict."""
    overlay, placeholder_count = _build_overlay(mode, result)

    # Egress guard decides on the SOURCE classification (privacy mode +
    # confidential/berufsgeheimnis tiers + Art. 9), which is source-sensitivity —
    # not residual PII, which redaction has already removed into the overlay.
    # When egress is allowed, the OVERLAY is the only thing that leaves.
    source_text = result.extracted_text or overlay
    verdict = gate.check(
        {"text": source_text},
        destination=destination,
        tenant_id=tenant_id,
        user_id=user_id,
    )

    return DocumentScan(
        source=source,
        input_type=result.input_type.value,
        overlay=overlay,
        spans=_spans_from(result),
        pii_detected=result.pii_detected,
        findings_by_type=dict(result.findings_by_type),
        egress_allowed=verdict.allowed,
        classification=verdict.classification,
        blocked_reason=verdict.blocked_reason,
        redaction_blocked=result.blocked,
        redaction_block_reason=result.block_reason,
        placeholder_count=placeholder_count,
        audit_id=result.audit_id,
        errors=list(result.errors),
    )


def scan(
    target: Union[str, Path],
    *,
    mode: PrivacyMode = PrivacyMode.STANDARD,
    destination: str = "external_llm",
    redaction_mode: RedactionMode = RedactionMode.REDACT,
    min_confidence: Confidence = Confidence.MEDIUM,
    recursive: bool = True,
    extensions: Optional[frozenset] = DEFAULT_EXTENSIONS,
    audit_log_path: Optional[str] = None,
    tenant_id: str = "",
    user_id: str = "",
    force_text: bool = False,
) -> ScanReport:
    """Scan *target* span by span and return a governed :class:`ScanReport`.

    *target* may be:

    - **raw text** — a string that is not an existing filesystem path;
    - **a single file** — a path to one document; or
    - **a folder** — every candidate document beneath it is walked.

    For each document the real pipeline runs (extract -> regex -> semantic ->
    local-LLM -> redact -> overlay), the clean overlay is built, and the egress
    guard decides — on the source classification — whether the (overlaid) payload
    may leave for *destination*. Only when it may does the clean overlay leave.
    Every decision is recorded to the standalone audit trail by the gate.

    The result carries, per document, the clean overlay, the per-span findings,
    and the egress verdict; and, in aggregate, ``all_allowed``.

    No host implementation is imported and no enforcement sink is attached; the gate decides
    locally. Honours the four privacy modes (STANDARD, LOCAL_ONLY,
    ANONYMOUS_JSON, REGEX_ONLY): LOCAL_ONLY blocks every external egress, and the
    global privacy mode is set for the duration so the gate honours it, then
    restored.
    """
    reject_legacy_env()
    shield = PrivacyShield(
        mode=redaction_mode,
        selection_mode=SelectionMode.ALL,
        min_confidence=min_confidence,
        privacy_mode=mode,
        audit_log_path=audit_log_path,
    )
    gate = PrivacyGate()  # standalone local decision and audit

    # The gate reads the *global* privacy mode; align it with this call so
    # LOCAL_ONLY (and friends) are honoured, then restore.
    previous_mode = get_global_privacy_mode()
    set_global_privacy_mode(mode)
    try:
        # --- Resolve the target into a list of (source, ShieldResult) ---------
        is_path = not force_text and (
            isinstance(target, Path) or path_exists(target)
        )

        documents: List[DocumentScan] = []

        if not is_path:
            # Raw text.
            result = shield.process_text(str(target))
            documents.append(
                _process_one(
                    shield, gate, mode,
                    source="text_input", result=result,
                    destination=destination, tenant_id=tenant_id, user_id=user_id,
                )
            )
            root_label = "text_input"
        else:
            path = Path(target)
            if path.is_dir():
                root_label = str(path)
                for file_path in _iter_files(
                    path, recursive=recursive, extensions=extensions
                ):
                    result = shield.process_file(file_path)
                    documents.append(
                        _process_one(
                            shield, gate, mode,
                            source=str(file_path), result=result,
                            destination=destination,
                            tenant_id=tenant_id, user_id=user_id,
                        )
                    )
            else:
                # A single file passed directly — no extension filter.
                root_label = str(path)
                result = shield.process_file(path)
                documents.append(
                    _process_one(
                        shield, gate, mode,
                        source=str(path), result=result,
                        destination=destination,
                        tenant_id=tenant_id, user_id=user_id,
                    )
                )

        return ScanReport(
            mode=mode.value,
            destination=destination,
            root=root_label,
            documents=documents,
        )
    finally:
        set_global_privacy_mode(previous_mode)


__all__ = [
    "scan",
    "ScanReport",
    "DocumentScan",
    "SpanFinding",
    "DEFAULT_EXTENSIONS",
]
