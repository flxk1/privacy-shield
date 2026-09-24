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

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ._legacy_env import reject_legacy_env
from .utils.file_io import path_exists
from .anonymous_json import anonymize_for_cloud
from .gate import PrivacyGate
from .redactor import RedactionMode, SelectionMode
from .scanner import Confidence, ScanResult
from .media._tools import CHANNEL_UNAVAILABLE
logger = logging.getLogger(__name__)

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

# Sentinel for "the caller did not pass `extensions` at all", distinct from
# every value a caller COULD pass - including `None` (no filter) and
# `DEFAULT_EXTENSIONS` itself, passed explicitly. `extensions: ... =
# DEFAULT_EXTENSIONS` could not tell those apart: a caller who names
# `DEFAULT_EXTENSIONS` on purpose has chosen a scope and knows what it
# excludes; a caller who passes nothing gets that scope IMPOSED and does not
# know a `.xlsx` fell out of it. `scan()` resolves this sentinel to
# `DEFAULT_EXTENSIONS` internally; the distinction it carries lives on in
# `ScanReport.imposed_filtered_files` vs. `chosen_filtered_files`.
_UNSET_EXTENSIONS = object()

# Tag prefix used in the *display text* of a filtered-file entry, kept for
# callers who grep the printed report, same mechanism as
# `media._tools.CHANNEL_UNAVAILABLE`. It is NOT what classifies an entry as
# imposed / chosen / unreadable any more - see `WalkErrorKind` below for why.
EXTENSION_FILTERED = "extension_filtered"
EXTENSION_FILTERED_DEFAULT = f"{EXTENSION_FILTERED}_default"
EXTENSION_FILTERED_CHOSEN = f"{EXTENSION_FILTERED}_chosen"


class WalkErrorKind(str, Enum):
    """Why a document went unread. The classifier a caller must be able to
    tell apart - see `ScanReport.all_allowed`: only UNREADABLE and
    FILTERED_DEFAULT count against it, FILTERED_CHOSEN does not.
    """

    UNREADABLE = "unreadable"
    FILTERED_DEFAULT = "filtered_default"
    FILTERED_CHOSEN = "filtered_chosen"


@dataclass(frozen=True)
class WalkError:
    """One document the walk did not read, and WHY.

    `kind` is a field of its own, set once by whichever branch of the walk
    produced the entry - never inferred from `message`. `message` is free
    text for a human or a JSON consumer and may contain an OS-reported
    filename, which is attacker- or filesystem-controlled and MUST NOT be
    parsed to recover `kind`: a directory literally named
    `extension_filtered_chosen_docs` produced a `message` that began with the
    chosen-filter tag while its `kind` was UNREADABLE, and the old
    `str.startswith` classifier read the message and got it backwards - a
    permission error the caller never chose was reported as a scope the
    caller chose, and `all_allowed` came back True over an unread document.
    """

    kind: WalkErrorKind
    message: str

    def __str__(self) -> str:  # display only; never re-parsed for `kind`
        return self.message


def _filtered_entry(path: Path, *, chosen: bool) -> WalkError:
    """The `walk_errors` entry for a file skipped by the extension filter."""
    kind = WalkErrorKind.FILTERED_CHOSEN if chosen else WalkErrorKind.FILTERED_DEFAULT
    tag = EXTENSION_FILTERED_CHOSEN if chosen else EXTENSION_FILTERED_DEFAULT
    suffix = path.suffix.lower() or "<none>"
    return WalkError(kind, f"{tag}: {path}: suffix {suffix} not in extensions")


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

    def to_dict(self, *, include_original: bool = False) -> Dict[str, Any]:
        """Serialised span. `value` and `context` are the ORIGINAL text and are
        omitted unless the caller asks for them.

        Serialisation is where the result leaves the process, so it is where the
        skill's `prohibited: egress_original_unredacted_text` has to hold. The
        skill grants `Bash(privacy-shield:*)`, and in a skill context stdout IS
        the model's context - `--json` carrying the original put it one pipe away
        from an external model. Local-only telemetry stays reachable on the
        object; asking for it in the serialised form is now a deliberate act.
        """
        span = {
            "pii_type": self.pii_type,
            "start": self.start,
            "end": self.end,
            "confidence": self.confidence,
            "layer": self.layer,
        }
        if include_original:
            span["value"] = self.value
            span["context"] = self.context
        return span


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

    @property
    def incomplete_channels(self) -> List[str]:
        """PII channels that could not run on this document.

        A media file is read through several independent channels - EXIF, OCR,
        face detection, container tags, speech-to-text, sampled frames - each
        needing a backend this package does not ship. A channel that could not
        run finds nothing, which is indistinguishable from a channel that ran
        and found nothing unless the document says so.
        """
        return [e for e in self.errors if str(e).startswith(CHANNEL_UNAVAILABLE)]

    @property
    def scan_complete(self) -> bool:
        """False when some PII channel never looked at this document."""
        return not self.incomplete_channels

    @property
    def overlay_residual(self) -> int:
        """How many distinct detected values are still verbatim in `overlay`.

        Under DETECT_ONLY nothing redacts and under BLOCK the redactor refuses,
        so `overlay` is the untouched original while `egress_allowed` can be
        True: the gate rules on source classification, not on the residual.
        Read span by span against the detected values, not from
        `placeholder_count`, which counts what was replaced, not what was left.
        """
        return len({s.value for s in self.spans if s.value and s.value in self.overlay})

    def to_dict(self, *, include_original: bool = False) -> Dict[str, Any]:
        # `overlay` is withheld, and the omission named, whenever a detected
        # value is still in it: the same boundary as the span `value`/`context`,
        # since there it IS the original. `egress_allowed` is left as it is.
        residual = 0 if include_original else self.overlay_residual
        withheld = (
            {"overlay_withheld": f"{residual} detected value(s) still present; not a cleaned overlay"}
            if residual else {}
        )
        return {
            "source": self.source,
            "input_type": self.input_type,
            "overlay": None if residual else self.overlay,
            **withheld,
            "span_count": self.span_count,
            "spans": [s.to_dict(include_original=include_original) for s in self.spans],
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
            "scan_complete": self.scan_complete,
            "incomplete_channels": self.incomplete_channels,
        }


@dataclass
class ScanReport:
    """Aggregate result over one target (text, file, or folder)."""

    mode: str
    destination: str
    root: str
    documents: List[DocumentScan] = field(default_factory=list)
    #: Directories/files the walk could not read, AND files the walk read but
    #: chose not to open because `extensions` did not name their suffix. All
    #: three leave a document unaccounted for, so all three live in the same
    #: list and all three make the document list INCOMPLETE. Classification
    #: is `WalkError.kind` - a field set once by the branch of the walk that
    #: produced the entry, never inferred from the human-readable `message`
    #: (which may embed an OS-reported filename the caller does not control;
    #: see `WalkError`'s docstring for the defect that shape produced).
    walk_errors: List[WalkError] = field(default_factory=list)

    @property
    def document_count(self) -> int:
        return len(self.documents)

    @property
    def filtered_files(self) -> List[str]:
        """`walk_errors` entries for files skipped by the extension filter.

        The union of `imposed_filtered_files` and `chosen_filtered_files` -
        every extension-skip regardless of why. Distinct from the rest of
        `walk_errors` (`unreadable_errors`): those are a file/directory the
        walk could not read; these were readable and the walk chose not to
        read them because of `extensions`.
        """
        return [str(e) for e in self.walk_errors if e.kind is not WalkErrorKind.UNREADABLE]

    @property
    def imposed_filtered_files(self) -> List[str]:
        """Files skipped by `DEFAULT_EXTENSIONS` because the caller passed
        no `extensions` at all.

        The caller did not choose this scope and does not know what fell out
        of it - the case that hits an ordinary user. This is what makes
        `all_allowed` False alongside `unreadable_errors`; see its docstring.
        """
        return [str(e) for e in self.walk_errors if e.kind is WalkErrorKind.FILTERED_DEFAULT]

    @property
    def chosen_filtered_files(self) -> List[str]:
        """Files skipped by an `extensions` the caller passed explicitly.

        Includes a caller who names `DEFAULT_EXTENSIONS` by hand - that is
        still a choice, not an imposition. Recorded, and makes
        `scan_complete` False like everything else in `walk_errors`, but
        does NOT affect `all_allowed` on its own.
        """
        return [str(e) for e in self.walk_errors if e.kind is WalkErrorKind.FILTERED_CHOSEN]

    @property
    def unreadable_errors(self) -> List[str]:
        """`walk_errors` entries the walk could not read at all.

        The complement of `filtered_files` within `walk_errors`: a
        directory/file `os.walk` raised on, not one `extensions` (imposed or
        chosen) skipped. Classified by `WalkError.kind`, set by `_record` at
        the moment the `OSError` is caught - never by inspecting the message,
        which carries the OS-reported filename and is not a safe classifier
        (see `WalkError`'s docstring).
        """
        return [str(e) for e in self.walk_errors if e.kind is WalkErrorKind.UNREADABLE]

    @property
    def total_spans(self) -> int:
        return sum(d.span_count for d in self.documents)

    @property
    def incomplete_documents(self) -> List[DocumentScan]:
        """Documents some PII channel never looked at."""
        return [d for d in self.documents if not d.scan_complete]

    @property
    def scan_complete(self) -> bool:
        """False when part of the tree, or part of a document, was not read."""
        return not self.walk_errors and not self.incomplete_documents

    @property
    def all_allowed(self) -> bool:
        """True iff every document the walk actually read is cleared for egress.

        False when the walk hit something it could not read at all -
        `unreadable_errors` non-empty. "Every document is cleared" cannot be
        asserted about documents that were never read, and a folder scan that
        skipped an unreadable directory used to report exactly that.

        False, equally, when a document was only PARTLY read. The folder walk
        settled this question once: completeness is part of the verdict. A
        media file has several independent PII channels and each needs a
        backend this package does not ship, so "cleared" over a video whose
        container nobody parsed and whose frames nobody sampled is the same
        assertion about the same nothing - and a consumer reading this
        aggregate shipped the geotagged file.

        The per-document ``egress_allowed`` is deliberately NOT changed: it is
        the gate's verdict on source classification and is documented as
        exactly that. Completeness lives here, next to ``walk_errors``, and in
        ``DocumentScan.scan_complete``.

        False, equally, when `extensions` skipped a file and the caller did
        not choose that scope - `imposed_filtered_files` non-empty. The line
        is not "was a filter applied" but "did the caller know". A default
        the caller never named (`DEFAULT_EXTENSIONS`, applied because
        `extensions` was not passed) hides a `.xlsx` from someone who has no
        way to know it fell out - the ordinary, no-flags scan. That is not
        different in kind from an unreadable directory: the caller asked for
        "the folder" in both cases and got less than that back, silently.

        NOT False, on its own, when the caller passed `extensions` explicitly
        - `chosen_filtered_files` non-empty, `imposed_filtered_files` empty.
        That still clears `scan_complete`, unconditionally (see its
        docstring): a scope decision is still a decision about what got
        looked at, not a claim that the rest was read. But it does not clear
        `all_allowed`, because a caller who names a scope - `--extensions
        .txt`, or `DEFAULT_EXTENSIONS` by hand - knows what it excludes, the
        same way a caller reading `blocked_documents` already knows a
        specific document was excluded from the aggregate without that
        exclusion being folded into `scan_complete`. A caller that wants
        "cleared AND every file in the scope I chose was read" checks
        `chosen_filtered_files` and `all_allowed` together, not one bool.
        """
        if self.unreadable_errors or self.imposed_filtered_files:
            return False
        return all(d.egress_allowed and d.scan_complete for d in self.documents)

    @property
    def blocked_documents(self) -> List[DocumentScan]:
        return [d for d in self.documents if not d.egress_allowed]

    def to_dict(self, *, include_original: bool = False) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "destination": self.destination,
            "root": self.root,
            "document_count": self.document_count,
            "total_spans": self.total_spans,
            "all_allowed": self.all_allowed,
            "scan_complete": self.scan_complete,
            # Structured, not flattened to a bare string: `kind` is the field
            # that decides imposed/chosen/unreadable, and `WalkError`'s own
            # docstring says `message` must never be re-parsed to recover it
            # (an OS-reported filename can start with any tag by coincidence
            # - see commit 5b6c4b5). A consumer of this JSON is exactly the
            # boundary that guarantee is for; flattening here would recreate
            # the defect one layer up, in whoever reads this dict next.
            "walk_errors": [
                {"kind": e.kind.value, "message": e.message} for e in self.walk_errors
            ],
            "filtered_files": self.filtered_files,
            "imposed_filtered_files": self.imposed_filtered_files,
            "chosen_filtered_files": self.chosen_filtered_files,
            "unreadable_errors": self.unreadable_errors,
            "incomplete_documents": [d.source for d in self.incomplete_documents],
            "documents": [
                d.to_dict(include_original=include_original) for d in self.documents
            ],
        }


def _iter_files(
    root: Path,
    *,
    recursive: bool,
    extensions: Optional[frozenset],
    extensions_chosen: bool,
) -> tuple[List[Path], List[WalkError]]:
    """Collect candidate document files under *root*, and what went unread.

    Returns ``(files, unread)``. The second value is not decoration: a folder
    scan that silently skipped part of the tree must not be reported as a
    clean result, so ``ScanReport.scan_complete`` is False whenever it is
    non-empty. It carries three different facts, tagged apart (see
    ``ScanReport.unreadable_errors`` / ``imposed_filtered_files`` /
    ``chosen_filtered_files``): a file the walk could not read at all; a file
    skipped by ``DEFAULT_EXTENSIONS`` because the caller passed no
    ``extensions`` (*imposed* - the caller does not know what fell out); and
    a file skipped by an ``extensions`` the caller passed explicitly
    (*chosen*). All three clear ``scan_complete``; only the first two also
    clear ``ScanReport.all_allowed`` (see its docstring for why).

    This used to call ``rglob`` and catch OSError around ``next()``. A
    generator that raises is finished - the following ``next()`` raises
    StopIteration and the loop exits - so the handler could not do what it
    said. On 3.14 ``rglob`` swallows the error internally and the handler never
    fired at all; on 3.10, where PermissionError propagates, it turned a loud
    crash into a SILENT PARTIAL SCAN certified ``all_allowed=True``. For an
    egress gate that is worse than the crash it replaced.

    ``os.walk`` reports per-directory errors through ``onerror`` and keeps
    going, which is the behaviour the old comment claimed.
    """
    import os

    files: List[Path] = []
    unread: List[WalkError] = []

    def _record(error: OSError) -> None:
        # `kind` is UNREADABLE unconditionally - set here, by the branch that
        # caught the OSError, never derived from `message`. `error.filename`
        # is filesystem-controlled text and may itself read as
        # `extension_filtered_chosen_docs/locked` for an ordinary relative
        # path; that must not make this entry look like a chosen filter skip.
        unread.append(
            WalkError(
                WalkErrorKind.UNREADABLE,
                f"{getattr(error, 'filename', root)}: {error.strerror}",
            )
        )

    for directory, subdirectories, names in os.walk(root, onerror=_record):
        here = Path(directory)
        # Prune hidden directories and caches in place, so os.walk does not
        # descend into them at all.
        subdirectories[:] = [
            name for name in subdirectories
            if not name.startswith(".") and name != "__pycache__"
        ]
        if not recursive and here != root:
            subdirectories[:] = []
            continue
        for name in names:
            if name.startswith("."):
                continue
            path = here / name
            try:
                if not path.is_file():
                    continue
            except OSError as error:
                _record(error)
                continue
            if extensions is not None and path.suffix.lower() not in extensions:
                unread.append(_filtered_entry(path, chosen=extensions_chosen))
                continue
            files.append(path)

    return sorted(files), unread


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
    hash_salt: Optional[str] = None,
    recursive: bool = True,
    extensions: Optional[frozenset] = _UNSET_EXTENSIONS,  # type: ignore[assignment]
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

    ``extensions`` defaults to nothing being passed at all, which is not the
    same as passing ``DEFAULT_EXTENSIONS``: not passing it means that default
    scope is IMPOSED on the caller (who does not know what it excludes) and
    counts against ``ScanReport.all_allowed`` when it skips a file; naming
    ``extensions`` explicitly - including ``DEFAULT_EXTENSIONS`` by hand, or
    ``None`` for every file - means the caller CHOSE that scope, and a skip
    is recorded (``ScanReport.chosen_filtered_files``, ``scan_complete``
    still goes False) without moving ``all_allowed``. See
    ``ScanReport.all_allowed`` for the full reasoning.

    No host implementation is imported and no enforcement sink is attached; the gate decides
    locally. Honours the four privacy modes (STANDARD, LOCAL_ONLY,
    ANONYMOUS_JSON, REGEX_ONLY): LOCAL_ONLY blocks every external egress, and the
    global privacy mode is set for the duration so the gate honours it, then
    restored.
    """
    extensions_chosen = extensions is not _UNSET_EXTENSIONS
    if not extensions_chosen:
        extensions = DEFAULT_EXTENSIONS
    reject_legacy_env()
    shield = PrivacyShield(
        mode=redaction_mode,
        selection_mode=SelectionMode.ALL,
        min_confidence=min_confidence,
        hash_salt=hash_salt,
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
        walk_errors: List[WalkError] = []

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
                walked, unread = _iter_files(
                    path, recursive=recursive, extensions=extensions,
                    extensions_chosen=extensions_chosen,
                )
                walk_errors.extend(unread)
                for file_path in walked:
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
            walk_errors=walk_errors,
        )
    finally:
        set_global_privacy_mode(previous_mode)


__all__ = [
    "scan",
    "ScanReport",
    "DocumentScan",
    "SpanFinding",
    "WalkError",
    "WalkErrorKind",
    "DEFAULT_EXTENSIONS",
    "EXTENSION_FILTERED",
    "EXTENSION_FILTERED_DEFAULT",
    "EXTENSION_FILTERED_CHOSEN",
]
