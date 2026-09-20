"""
Privacy Shield - Redactor

Redact, pseudonymize, or hash detected PII.
Supports multiple output modes and opt-in/opt-out selection.
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Set, Tuple

from .scanner import Confidence, Finding, PIIType, ScanResult

logger = logging.getLogger(__name__)


class RedactionMode(str, Enum):
    """How to handle detected PII."""
    DETECT_ONLY = "detect_only"  # Report findings, don't modify
    REDACT = "redact"  # Replace with [TYPE] placeholders
    PSEUDONYMIZE = "pseudonymize"  # Replace with consistent fake values
    HASH = "hash"  # Replace with SHA256 tokens
    BLOCK = "block"  # Block entire content if PII found


class SelectionMode(str, Enum):
    """Content selection mode."""
    ALL = "all"  # Process all content
    OPT_OUT = "opt_out"  # Process all except explicitly excluded
    OPT_IN = "opt_in"  # Process only explicitly included


@dataclass
class TextRegion:
    """A region of text that's included or excluded."""
    start: int
    end: int
    included: bool
    label: Optional[str] = None  # User-provided label


@dataclass
class RedactionResult:
    """Result of redaction operation."""
    original_text: str
    redacted_text: str
    mode: RedactionMode
    selection_mode: SelectionMode
    findings: List[Finding] = field(default_factory=list)
    redactions_applied: int = 0
    mappings: Dict[str, str] = field(default_factory=dict)  # For pseudonymize/hash
    regions_processed: int = 0
    regions_excluded: int = 0
    blocked: bool = False
    block_reason: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "mode": self.mode.value,
            "selection_mode": self.selection_mode.value,
            "redactions_applied": self.redactions_applied,
            "regions_processed": self.regions_processed,
            "regions_excluded": self.regions_excluded,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "mappings": self.mappings,
            "finding_count": len(self.findings),
        }


# =============================================================================
# PSEUDONYMIZATION DATA
# =============================================================================

# Fake names for pseudonymization (German/European)
FAKE_NAMES = [
    "Max Mustermann", "Erika Musterfrau", "John Doe", "Jane Doe",
    "Hans Schmidt", "Anna Müller", "Thomas Meyer", "Maria Weber",
    "Peter Fischer", "Laura Wagner", "Michael Becker", "Sophie Hoffmann",
]

# Fake email domains
FAKE_EMAIL_DOMAINS = ["example.com", "test.de", "sample.org"]

# Fake addresses
FAKE_ADDRESSES = [
    "Musterstraße 1", "Beispielweg 42", "Testplatz 7",
    "Sample Street 123", "Demo Avenue 456",
]

# Fake cities
FAKE_CITIES = [
    "12345 Musterstadt", "10115 Berlin", "80331 München",
    "20095 Hamburg", "50667 Köln",
]


def merge_replacements(
    replacements: List[Tuple[int, int, str]],
) -> List[Tuple[int, int, str]]:
    """Collapse overlapping (start, end, text) spans into disjoint ones.

    A merged span covers the union of the spans it absorbs, so nothing that any
    contributing finding matched can survive into the output. The first span of
    an overlapping run - earliest start, longest at equal start - supplies the
    replacement text.
    """
    merged: List[Tuple[int, int, str]] = []
    for start, end, text in sorted(
        replacements, key=lambda r: (r[0], -(r[1] - r[0]))
    ):
        if merged and start < merged[-1][1]:
            prev_start, prev_end, prev_text = merged[-1]
            merged[-1] = (prev_start, max(prev_end, end), prev_text)
            continue
        merged.append((start, end, text))
    return merged


class Redactor:
    """
    Redact PII from text with multiple modes and selection options.
    """

    def __init__(
        self,
        mode: RedactionMode = RedactionMode.REDACT,
        selection_mode: SelectionMode = SelectionMode.ALL,
        min_confidence: Confidence = Confidence.MEDIUM,
        hash_salt: Optional[str] = None,
        custom_placeholders: Optional[Dict[PIIType, str]] = None,
        block_on_types: Optional[Set[PIIType]] = None,
    ):
        """
        Initialize the redactor.

        Args:
            mode: Redaction mode.
            selection_mode: Content selection mode.
            min_confidence: Minimum confidence to redact.
            hash_salt: Salt for hashing. REQUIRED for HASH mode per DSK compliance.
                       For other modes, a secure random salt is generated if not provided.
            custom_placeholders: Custom placeholder text per PII type.
            block_on_types: PII types that trigger blocking (in BLOCK mode).

        Raises:
            ValueError: If HASH mode is used without an explicit hash_salt.
        """
        self.mode = mode
        self.selection_mode = selection_mode
        self.min_confidence = min_confidence

        # DSK K-03 Compliance: Require explicit salt for HASH mode
        if mode == RedactionMode.HASH and not hash_salt:
            raise ValueError(
                "HASH mode requires an explicit hash_salt parameter. "
                "Using a default salt is not GDPR-compliant per DSK guidelines. "
                "Generate a secure salt with: secrets.token_hex(32)"
            )

        # For non-HASH modes, generate a secure random salt if not provided
        if hash_salt:
            self.hash_salt = hash_salt
            # Warn if salt appears weak
            if len(hash_salt) < 32:
                logger.warning(
                    "hash_salt is shorter than 32 characters. "
                    "Consider using a stronger salt: secrets.token_hex(32)"
                )
        else:
            # Generate ephemeral salt for session (not for HASH mode - blocked above)
            self.hash_salt = secrets.token_hex(32)

        self.custom_placeholders = custom_placeholders or {}
        self.block_on_types = block_on_types or {
            PIIType.IBAN,
            PIIType.CREDIT_CARD,
            PIIType.SVNR,
            PIIType.HEALTH_DATA,
            PIIType.CRIMINAL,
            PIIType.BIOMETRIC,
        }

        # Pseudonymization state (for consistency within a session)
        self._pseudo_counter: Dict[PIIType, int] = {}
        self._pseudo_mappings: Dict[str, str] = {}

    def _confidence_value(self, conf: Confidence) -> int:
        return {"high": 3, "medium": 2, "low": 1}.get(conf.value, 0)

    def _get_placeholder(self, pii_type: PIIType) -> str:
        """Get placeholder text for a PII type."""
        if pii_type in self.custom_placeholders:
            return self.custom_placeholders[pii_type]

        # Default placeholders
        placeholders = {
            PIIType.EMAIL: "[EMAIL]",
            PIIType.PHONE: "[PHONE]",
            PIIType.IBAN: "[IBAN]",
            PIIType.CREDIT_CARD: "[CREDIT_CARD]",
            PIIType.IP_ADDRESS: "[IP]",
            PIIType.STEUER_ID: "[TAX_ID]",
            PIIType.SVNR: "[SSN]",
            PIIType.PASSPORT: "[PASSPORT]",
            PIIType.ID_CARD: "[ID]",
            PIIType.NATIONAL_ID: "[NATIONAL_ID]",
            PIIType.NAME: "[NAME]",
            PIIType.ADDRESS: "[ADDRESS]",
            PIIType.PLZ_CITY: "[LOCATION]",
            PIIType.DATE_OF_BIRTH: "[DOB]",
            PIIType.AGE: "[AGE]",
            PIIType.HEALTH_DATA: "[HEALTH]",
            PIIType.ICD_CODE: "[ICD]",
            PIIType.BIOMETRIC: "[BIOMETRIC]",
            PIIType.POLITICAL: "[POLITICAL]",
            PIIType.RELIGIOUS: "[RELIGIOUS]",
            PIIType.UNION: "[UNION]",
            PIIType.SEXUAL: "[SEXUAL]",
            PIIType.CRIMINAL: "[CRIMINAL]",
            PIIType.GENETIC: "[GENETIC]",
            PIIType.FILE_PATH: "[PATH]",
            PIIType.INTERNAL_URL: "[URL]",
            PIIType.TICKET_ID: "[TICKET]",
            PIIType.PROJECT_CODENAME: "[PROJECT]",
            PIIType.DRAFT_MARKER: "[MARKER]",
            PIIType.VERSION_STRING: "[VERSION]",
        }
        return placeholders.get(pii_type, "[REDACTED]")

    def _get_pseudonym(self, pii_type: PIIType, original: str) -> str:
        """Get a consistent pseudonym for a value."""
        # Return cached pseudonym if exists
        if original in self._pseudo_mappings:
            return self._pseudo_mappings[original]

        # Generate new pseudonym
        counter = self._pseudo_counter.get(pii_type, 0)
        self._pseudo_counter[pii_type] = counter + 1

        if pii_type == PIIType.NAME:
            pseudo = FAKE_NAMES[counter % len(FAKE_NAMES)]
        elif pii_type == PIIType.EMAIL:
            name_part = f"user{counter}"
            domain = FAKE_EMAIL_DOMAINS[counter % len(FAKE_EMAIL_DOMAINS)]
            pseudo = f"{name_part}@{domain}"
        elif pii_type == PIIType.PHONE:
            pseudo = f"+49 000 000{counter:04d}"
        elif pii_type == PIIType.ADDRESS:
            pseudo = FAKE_ADDRESSES[counter % len(FAKE_ADDRESSES)]
        elif pii_type == PIIType.PLZ_CITY:
            pseudo = FAKE_CITIES[counter % len(FAKE_CITIES)]
        elif pii_type == PIIType.IBAN:
            pseudo = f"DE00 0000 0000 0000 0000 {counter:02d}"
        elif pii_type == PIIType.DATE_OF_BIRTH:
            pseudo = "01.01.1990"
        else:
            pseudo = f"[{pii_type.value.upper()}_{counter}]"

        self._pseudo_mappings[original] = pseudo
        return pseudo

    def _get_hash(self, original: str) -> str:
        """Get a deterministic hash for a value.

        Uses SHA256 with configurable salt. Hash is truncated to 16 hex chars
        (64 bits) for readability while maintaining sufficient collision resistance.
        """
        if original in self._pseudo_mappings:
            return self._pseudo_mappings[original]

        # Use HMAC-like construction for better security
        salted = f"{self.hash_salt}:{original}:{len(original)}"
        hash_val = hashlib.sha256(salted.encode()).hexdigest()[:16]  # 64 bits
        result = f"[SHA:{hash_val}]"
        self._pseudo_mappings[original] = result
        return result

    def redact(
        self,
        scan_result: ScanResult,
        included_regions: Optional[List[TextRegion]] = None,
        excluded_regions: Optional[List[TextRegion]] = None,
    ) -> RedactionResult:
        """
        Redact PII from scanned text.

        Args:
            scan_result: Result from PrivacyScanner.
            included_regions: For OPT_IN mode, regions to include.
            excluded_regions: For OPT_OUT mode, regions to exclude.

        Returns:
            RedactionResult with redacted text.
        """
        text = scan_result.text
        findings = scan_result.findings
        min_conf_value = self._confidence_value(self.min_confidence)

        result = RedactionResult(
            original_text=text,
            redacted_text=text,
            mode=self.mode,
            selection_mode=self.selection_mode,
        )

        # Filter findings by confidence
        filtered_findings = [
            f for f in findings
            if self._confidence_value(f.confidence) >= min_conf_value
        ]
        result.findings = filtered_findings

        # Handle DETECT_ONLY mode
        if self.mode == RedactionMode.DETECT_ONLY:
            return result

        # Handle BLOCK mode
        if self.mode == RedactionMode.BLOCK:
            blocking_findings = [
                f for f in filtered_findings
                if f.pii_type in self.block_on_types
            ]
            if blocking_findings:
                result.blocked = True
                types_found = set(f.pii_type.value for f in blocking_findings)
                result.block_reason = f"Blocked due to: {', '.join(types_found)}"
                result.redacted_text = ""
                return result

        # Determine which regions to process
        if self.selection_mode == SelectionMode.OPT_IN:
            if not included_regions:
                # Nothing included = nothing to process
                result.redacted_text = ""
                result.regions_excluded = 1
                return result
            processable_chars = self._get_included_chars(text, included_regions)
            result.regions_processed = len(included_regions)
        elif self.selection_mode == SelectionMode.OPT_OUT:
            if excluded_regions:
                processable_chars = self._get_excluded_chars(text, excluded_regions)
                result.regions_excluded = len(excluded_regions)
            else:
                processable_chars = set(range(len(text)))
            result.regions_processed = 1
        else:  # ALL
            processable_chars = set(range(len(text)))
            result.regions_processed = 1

        # Build replacement map. Findings routinely overlap - a validated IBAN
        # and a Steuer-ID pattern claim the same digits, a name and an address
        # share a token. Replacements are computed on ORIGINAL offsets, so
        # applying an overlapping pair to an already-mutated string spliced
        # placeholder fragments into the output ("[NAME]L]ME] +[PHONE]"):
        # corrupt text, and PII that survived because its offsets had moved.
        # Overlaps are resolved into disjoint spans below, before anything is
        # applied.
        candidate_replacements: List[Tuple[int, int, str]] = []

        for finding in sorted(
            filtered_findings, key=lambda f: (f.start, -(f.end - f.start))
        ):
            # Check if finding is in processable region
            finding_chars = set(range(finding.start, finding.end))
            if not finding_chars.issubset(processable_chars):
                continue

            # Determine replacement
            if self.mode == RedactionMode.REDACT:
                replacement = self._get_placeholder(finding.pii_type)
            elif self.mode == RedactionMode.PSEUDONYMIZE:
                replacement = self._get_pseudonym(finding.pii_type, finding.value)
            elif self.mode == RedactionMode.HASH:
                replacement = self._get_hash(finding.value)
            else:
                replacement = self._get_placeholder(finding.pii_type)

            candidate_replacements.append((finding.start, finding.end, replacement))

        # Merge overlapping spans into disjoint ones. The merged span covers the
        # union, so no part of an overlapped finding can survive; the earliest
        # (and, at equal start, the longest) finding supplies the placeholder.
        replacements = merge_replacements(candidate_replacements)
        result.redactions_applied = len(replacements)

        # Apply right-to-left, so the offsets of spans not yet applied - all of
        # which lie to the left - stay valid in the mutated string.
        redacted = text
        for start, end, replacement in sorted(replacements, reverse=True):
            redacted = redacted[:start] + replacement + redacted[end:]

        # For OPT_IN mode, extract only included regions
        if self.selection_mode == SelectionMode.OPT_IN and included_regions:
            included_parts = []
            for region in sorted(included_regions, key=lambda r: r.start):
                # Adjust positions after redactions
                part = self._extract_region_after_redaction(
                    text, redacted, region.start, region.end, replacements
                )
                if region.label:
                    included_parts.append(f"[{region.label}]\n{part}")
                else:
                    included_parts.append(part)
            redacted = "\n\n---\n\n".join(included_parts)

        result.redacted_text = redacted
        result.mappings = dict(self._pseudo_mappings)

        return result

    def _get_included_chars(
        self,
        text: str,
        regions: List[TextRegion],
    ) -> Set[int]:
        """Get set of character indices that are included."""
        chars: Set[int] = set()
        for region in regions:
            if region.included:
                chars.update(range(region.start, min(region.end, len(text))))
        return chars

    def _get_excluded_chars(
        self,
        text: str,
        regions: List[TextRegion],
    ) -> Set[int]:
        """Get set of character indices that are NOT excluded."""
        excluded: Set[int] = set()
        for region in regions:
            if not region.included:
                excluded.update(range(region.start, min(region.end, len(text))))
        return set(range(len(text))) - excluded

    def _extract_region_after_redaction(
        self,
        original: str,
        redacted: str,
        orig_start: int,
        orig_end: int,
        replacements: List[Tuple[int, int, str]],
    ) -> str:
        """
        Extract a region from redacted text, adjusting for position changes.
        """
        # Calculate offset caused by replacements before this region
        offset = 0
        for rep_start, rep_end, rep_text in sorted(replacements, key=lambda x: x[0]):
            if rep_end <= orig_start:
                # Replacement is entirely before our region
                offset += len(rep_text) - (rep_end - rep_start)
            elif rep_start < orig_start < rep_end:
                # Replacement overlaps start of our region - complex case
                break

        adjusted_start = orig_start + offset

        # Similarly for end
        end_offset = 0
        for rep_start, rep_end, rep_text in sorted(replacements, key=lambda x: x[0]):
            if rep_end <= orig_end:
                end_offset += len(rep_text) - (rep_end - rep_start)

        adjusted_end = orig_end + end_offset

        return redacted[adjusted_start:adjusted_end]

    def reset_session(self) -> None:
        """Reset pseudonymization state for a new session."""
        self._pseudo_counter.clear()
        self._pseudo_mappings.clear()


# =============================================================================
# CLAUSE-BASED SELECTION
# =============================================================================

@dataclass
class Clause:
    """A detected clause or section in a document."""
    index: int
    title: Optional[str]
    text: str
    start: int
    end: int
    pii_types: Set[PIIType] = field(default_factory=set)
    pii_count: int = 0
    selected: bool = True  # Default: include


def detect_clauses(text: str, scan_result: ScanResult) -> List[Clause]:
    """
    Detect clause/section boundaries in text.

    Uses common patterns:
    - Numbered sections (1., 2., etc.)
    - Lettered sections (a), b), etc.)
    - Headers (ALL CAPS lines)
    - Paragraph breaks
    """
    clauses: List[Clause] = []

    # Pattern for clause starts
    clause_patterns = [
        # Numbered: "1." or "1)" or "(1)"
        re.compile(r"^[\s]*(\d+)[.)]\s+", re.MULTILINE),
        # Lettered: "a)" or "(a)" or "a."
        re.compile(r"^[\s]*\(?([a-z])\)?[.)]\s+", re.MULTILINE),
        # Roman: "I." or "II." or "(i)"
        re.compile(r"^[\s]*\(?([IVXivx]+)\)?[.)]\s+", re.MULTILINE),
        # Section headers (§ or Article)
        re.compile(r"^[\s]*(§\s*\d+|Article\s+\d+|Artikel\s+\d+)", re.MULTILINE | re.IGNORECASE),
        # ALL CAPS headers
        re.compile(r"^[\s]*([A-Z][A-Z\s]{5,}[A-Z])[\s]*$", re.MULTILINE),
    ]

    # Find all clause boundaries
    boundaries: List[Tuple[int, str]] = [(0, "")]

    for pattern in clause_patterns:
        for match in pattern.finditer(text):
            boundaries.append((match.start(), match.group(1) if match.groups() else ""))

    # Sort and dedupe
    boundaries = sorted(set(boundaries), key=lambda x: x[0])

    # Create clauses
    for i, (start, title) in enumerate(boundaries):
        end = boundaries[i + 1][0] if i + 1 < len(boundaries) else len(text)
        clause_text = text[start:end].strip()

        if not clause_text:
            continue

        # Find PII in this clause
        clause_pii_types: Set[PIIType] = set()
        clause_pii_count = 0

        for finding in scan_result.findings:
            if start <= finding.start < end:
                clause_pii_types.add(finding.pii_type)
                clause_pii_count += 1

        clauses.append(Clause(
            index=len(clauses),
            title=title if title else None,
            text=clause_text,
            start=start,
            end=end,
            pii_types=clause_pii_types,
            pii_count=clause_pii_count,
            selected=clause_pii_count == 0,  # Auto-select if no PII
        ))

    # If no clauses detected, treat whole text as one clause
    if not clauses:
        pii_types = set(f.pii_type for f in scan_result.findings)
        clauses.append(Clause(
            index=0,
            title=None,
            text=text,
            start=0,
            end=len(text),
            pii_types=pii_types,
            pii_count=len(scan_result.findings),
            selected=len(scan_result.findings) == 0,
        ))

    return clauses


def clauses_to_regions(clauses: List[Clause]) -> List[TextRegion]:
    """Convert selected clauses to TextRegions for redaction."""
    return [
        TextRegion(
            start=clause.start,
            end=clause.end,
            included=clause.selected,
            label=clause.title,
        )
        for clause in clauses
    ]


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def redact_text(
    text: str,
    mode: RedactionMode = RedactionMode.REDACT,
    min_confidence: Confidence = Confidence.MEDIUM,
    layers: Optional[List[int]] = None,
    hash_salt: Optional[str] = None,
) -> RedactionResult:
    """
    Convenience function to scan and redact text in one call.

    Args:
        text: Text to process.
        mode: Redaction mode.
        min_confidence: Minimum confidence to redact.
        layers: Scanner layers to use.
        hash_salt: Salt for hashing. REQUIRED for HASH mode per DSK compliance.

    Returns:
        RedactionResult with redacted text.
    """
    from .scanner import PrivacyScanner

    scanner = PrivacyScanner(layers=layers, min_confidence=min_confidence)
    scan_result = scanner.scan(text)

    redactor = Redactor(mode=mode, min_confidence=min_confidence, hash_salt=hash_salt)
    return redactor.redact(scan_result)
