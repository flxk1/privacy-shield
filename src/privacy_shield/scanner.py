"""
Privacy Shield - Core Scanner

Pattern-based PII detection with zero LLM calls.
Four detection layers with configurable confidence thresholds.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Pattern, Tuple

from ._legacy_env import reject_legacy_env

logger = logging.getLogger(__name__)


class PIIType(str, Enum):
    """PII categories aligned with GDPR Art. 4 and Art. 9."""

    # Layer 1: Direct identifiers
    EMAIL = "email"
    PHONE = "phone"
    IBAN = "iban"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    STEUER_ID = "steuer_id"  # German tax ID
    SVNR = "svnr"  # German social security
    PASSPORT = "passport"
    ID_CARD = "id_card"

    # Layer 2: Quasi-identifiers
    NAME = "name"
    ADDRESS = "address"
    PLZ_CITY = "plz_city"
    DATE_OF_BIRTH = "date_of_birth"
    AGE = "age"

    # Layer 3: GDPR Article 9 special categories
    HEALTH_DATA = "health_data"
    ICD_CODE = "icd_code"
    BIOMETRIC = "biometric"
    POLITICAL = "political"
    RELIGIOUS = "religious"
    UNION = "union"
    SEXUAL = "sexual"
    CRIMINAL = "criminal"
    GENETIC = "genetic"

    # Layer 4: Internal references
    FILE_PATH = "file_path"
    INTERNAL_URL = "internal_url"
    TICKET_ID = "ticket_id"
    PROJECT_CODENAME = "project_codename"
    DRAFT_MARKER = "draft_marker"
    VERSION_STRING = "version_string"


class Confidence(str, Enum):
    """Detection confidence levels."""
    HIGH = "high"      # 0.9+ - Definite PII
    MEDIUM = "medium"  # 0.7-0.9 - Likely PII
    LOW = "low"        # 0.5-0.7 - Possible PII


@dataclass
class Finding:
    """A single PII detection finding."""
    pii_type: PIIType
    value: str
    start: int
    end: int
    confidence: Confidence
    layer: int
    context: str = ""  # Surrounding text for review
    zone: Optional[str] = None  # Document zone (header, body, signature)
    page: Optional[int] = None  # Page number for documents

    def to_dict(self) -> dict:
        return {
            "type": self.pii_type.value,
            "value": self.value,
            "start": self.start,
            "end": self.end,
            "confidence": self.confidence.value,
            "layer": self.layer,
            "context": self.context,
            "zone": self.zone,
            "page": self.page,
        }


@dataclass
class ScanResult:
    """Result of a privacy scan."""
    text: str
    findings: List[Finding] = field(default_factory=list)
    scan_time_ms: float = 0.0
    layers_used: List[int] = field(default_factory=list)

    @property
    def has_pii(self) -> bool:
        return len(self.findings) > 0

    @property
    def high_confidence_count(self) -> int:
        return sum(1 for f in self.findings if f.confidence == Confidence.HIGH)

    @property
    def findings_by_type(self) -> Dict[str, List[Finding]]:
        result: Dict[str, List[Finding]] = {}
        for f in self.findings:
            key = f.pii_type.value
            if key not in result:
                result[key] = []
            result[key].append(f)
        return result

    def to_dict(self) -> dict:
        return {
            "has_pii": self.has_pii,
            "finding_count": len(self.findings),
            "high_confidence_count": self.high_confidence_count,
            "scan_time_ms": self.scan_time_ms,
            "layers_used": self.layers_used,
            "findings": [f.to_dict() for f in self.findings],
            "findings_by_type": {
                k: [f.to_dict() for f in v]
                for k, v in self.findings_by_type.items()
            },
        }


# =============================================================================
# PATTERN DEFINITIONS
# =============================================================================

@dataclass
class PatternDef:
    """Pattern definition with metadata."""
    pattern: Pattern
    pii_type: PIIType
    confidence: Confidence
    description: str


def _compile(pattern: str, flags: int = re.IGNORECASE) -> Pattern:
    """Compile a regex pattern with standard flags."""
    return re.compile(pattern, flags)


# -----------------------------------------------------------------------------
# Layer 1: Direct PII Patterns (High Confidence)
# -----------------------------------------------------------------------------

LAYER_1_PATTERNS: List[PatternDef] = [
    # Email - RFC 5322 simplified
    PatternDef(
        pattern=_compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
        pii_type=PIIType.EMAIL,
        confidence=Confidence.HIGH,
        description="Email address",
    ),

    # Phone - International formats
    PatternDef(
        pattern=_compile(
            r"\b(?:\+?\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b"
        ),
        pii_type=PIIType.PHONE,
        confidence=Confidence.HIGH,
        description="Phone number",
    ),

    # German phone specific
    PatternDef(
        pattern=_compile(r"\b0\d{2,4}[\s/-]?\d{4,8}\b"),
        pii_type=PIIType.PHONE,
        confidence=Confidence.HIGH,
        description="German phone number",
    ),

    # IBAN - EU format
    PatternDef(
        pattern=_compile(r"\b[A-Z]{2}\d{2}[\sA-Z0-9]{10,30}\b"),
        pii_type=PIIType.IBAN,
        confidence=Confidence.HIGH,
        description="IBAN bank account",
    ),

    # Credit Card - Major formats with Luhn-compatible patterns
    PatternDef(
        pattern=_compile(
            r"\b(?:4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|"  # Visa
            r"5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|"  # Mastercard
            r"3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}|"  # Amex
            r"6(?:011|5\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})\b"  # Discover
        ),
        pii_type=PIIType.CREDIT_CARD,
        confidence=Confidence.HIGH,
        description="Credit card number",
    ),

    # IP Address - IPv4
    PatternDef(
        pattern=_compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
        pii_type=PIIType.IP_ADDRESS,
        confidence=Confidence.HIGH,
        description="IPv4 address",
    ),

    # German Tax ID (Steuer-ID) - 11 digits
    PatternDef(
        pattern=_compile(r"\b\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b"),
        pii_type=PIIType.STEUER_ID,
        confidence=Confidence.MEDIUM,  # Could be other 11-digit numbers
        description="German tax ID (Steuer-ID)",
    ),

    # German Social Security Number (SVNR)
    PatternDef(
        pattern=_compile(r"\b\d{2}[A-Z]\d{6}[A-Z]\d{3}\b"),
        pii_type=PIIType.SVNR,
        confidence=Confidence.HIGH,
        description="German social security number",
    ),

    # Passport numbers (EU format)
    PatternDef(
        pattern=_compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
        pii_type=PIIType.PASSPORT,
        confidence=Confidence.LOW,  # Many false positives
        description="Passport number",
    ),

    # German ID card (Personalausweis) - new format
    PatternDef(
        pattern=_compile(r"\b[CFGHJKLMNPRTVWXYZ0-9]{9}\d\b"),
        pii_type=PIIType.ID_CARD,
        confidence=Confidence.MEDIUM,
        description="German ID card number",
    ),
]


# -----------------------------------------------------------------------------
# Layer 2: Quasi-Identifiers (Medium Confidence)
# -----------------------------------------------------------------------------

LAYER_2_PATTERNS: List[PatternDef] = [
    # Names - German/European format (Vorname Nachname)
    PatternDef(
        pattern=_compile(
            r"\b(?:Herr|Frau|Dr\.|Prof\.)?\s*"
            r"[A-ZÄÖÜ][a-zäöüß]+(?:\s+[a-zäöüß]+)?\s+"
            r"[A-ZÄÖÜ][a-zäöüß]+(?:-[A-ZÄÖÜ][a-zäöüß]+)?\b"
        ),
        pii_type=PIIType.NAME,
        confidence=Confidence.MEDIUM,
        description="Person name (German format)",
    ),

    # Names - Simple two-word capitalized
    PatternDef(
        pattern=_compile(r"\b[A-ZÄÖÜ][a-zäöüß]{2,}\s+[A-ZÄÖÜ][a-zäöüß]{2,}\b"),
        pii_type=PIIType.NAME,
        confidence=Confidence.LOW,
        description="Potential person name",
    ),

    # German street address
    PatternDef(
        pattern=_compile(
            r"\b[A-ZÄÖÜ][a-zäöüß]+(?:straße|str\.|weg|platz|allee|gasse|ring|damm|ufer)\s+\d+[a-z]?\b"
        ),
        pii_type=PIIType.ADDRESS,
        confidence=Confidence.HIGH,
        description="German street address",
    ),

    # Generic street address
    PatternDef(
        pattern=_compile(r"\b\d+\s+[A-Z][a-z]+\s+(?:Street|St\.|Avenue|Ave\.|Road|Rd\.|Lane|Ln\.)\b"),
        pii_type=PIIType.ADDRESS,
        confidence=Confidence.HIGH,
        description="Street address",
    ),

    # German postal code + city
    PatternDef(
        pattern=_compile(r"\b\d{5}\s+[A-ZÄÖÜ][a-zäöüß]+(?:\s+[a-zäöüß]+)?\b"),
        pii_type=PIIType.PLZ_CITY,
        confidence=Confidence.HIGH,
        description="German postal code and city",
    ),

    # Date of birth patterns
    PatternDef(
        pattern=_compile(
            r"\b(?:geboren|geb\.|DOB|birth|Geburtsdatum)[:\s]+\d{1,2}[./]\d{1,2}[./]\d{2,4}\b"
        ),
        pii_type=PIIType.DATE_OF_BIRTH,
        confidence=Confidence.HIGH,
        description="Date of birth",
    ),

    # Standalone date (potential DOB)
    PatternDef(
        pattern=_compile(r"\b(?:0?[1-9]|[12]\d|3[01])[./](?:0?[1-9]|1[0-2])[./](?:19|20)\d{2}\b"),
        pii_type=PIIType.DATE_OF_BIRTH,
        confidence=Confidence.LOW,
        description="Date (potential DOB)",
    ),

    # Age with context
    PatternDef(
        pattern=_compile(r"\b(?:age|Alter|Jahre?\s+alt)[:\s]+\d{1,3}\b"),
        pii_type=PIIType.AGE,
        confidence=Confidence.MEDIUM,
        description="Age",
    ),
]


# -----------------------------------------------------------------------------
# Layer 3: GDPR Article 9 Special Categories
# -----------------------------------------------------------------------------

LAYER_3_PATTERNS: List[PatternDef] = [
    # ICD-10 codes
    PatternDef(
        pattern=_compile(r"\b[A-Z]\d{2}(?:\.\d{1,2})?\b"),
        pii_type=PIIType.ICD_CODE,
        confidence=Confidence.MEDIUM,
        description="ICD code",
    ),

    # Health keywords (German/English)
    PatternDef(
        pattern=_compile(
            r"\b(?:diagnos\w*|medication|prescription|symptom|treatment|therapy|"
            r"Diagnose|Medikament|Rezept|Behandlung|Therapie|Symptom|"
            r"HIV|AIDS|cancer|Krebs|tumor|Tumor|diabetes|Diabetes|"
            r"psychiatric|Psychiatrie|mental\s+health|depression|Depression|"
            r"surgery|Operation|chronic|chronisch|disability|Behinderung)\b"
        ),
        pii_type=PIIType.HEALTH_DATA,
        confidence=Confidence.MEDIUM,
        description="Health-related term",
    ),

    # Biometric data
    PatternDef(
        pattern=_compile(
            r"\b(?:fingerprint|Fingerabdruck|retina|iris\s+scan|"
            r"facial\s+recognition|Gesichtserkennung|biometric|biometrisch|"
            r"DNA|voice\s+print|Stimmerkennung|palm\s+print)\b"
        ),
        pii_type=PIIType.BIOMETRIC,
        confidence=Confidence.HIGH,
        description="Biometric data reference",
    ),

    # Political opinions
    PatternDef(
        pattern=_compile(
            r"\b(?:party\s+member|Parteimitglied|political\s+(?:opinion|affiliation)|"
            r"politische\s+(?:Meinung|Zugehörigkeit)|vote[sd]?\s+for|gewählt|"
            r"conservative|liberal|socialist|kommunist|rechts|links)\b"
        ),
        pii_type=PIIType.POLITICAL,
        confidence=Confidence.MEDIUM,
        description="Political opinion",
    ),

    # Religious beliefs
    PatternDef(
        pattern=_compile(
            r"\b(?:religious?\s+(?:belief|affiliation)|Religionszugehörigkeit|"
            r"church\s+member|Kirchenmitglied|muslim|christian|jewish|hindu|buddhist|"
            r"atheist|Konfession|denomination)\b"
        ),
        pii_type=PIIType.RELIGIOUS,
        confidence=Confidence.MEDIUM,
        description="Religious belief",
    ),

    # Trade union membership
    PatternDef(
        pattern=_compile(
            r"\b(?:union\s+member|Gewerkschaftsmitglied|trade\s+union|Gewerkschaft|"
            r"Betriebsrat|works\s+council|labor\s+union)\b"
        ),
        pii_type=PIIType.UNION,
        confidence=Confidence.HIGH,
        description="Trade union membership",
    ),

    # Sexual orientation
    PatternDef(
        pattern=_compile(
            r"\b(?:sexual\s+orientation|sexuelle\s+Orientierung|"
            r"homosexual|heterosexual|bisexual|gay|lesbian|LGBT|LGBTQ)\b"
        ),
        pii_type=PIIType.SEXUAL,
        confidence=Confidence.HIGH,
        description="Sexual orientation",
    ),

    # Criminal data
    PatternDef(
        pattern=_compile(
            r"\b(?:criminal\s+record|Vorstrafe|conviction|Verurteilung|"
            r"offense|Straftat|arrest|Verhaftung|prison|Gefängnis|"
            r"Strafregister|police\s+record|Führungszeugnis)\b"
        ),
        pii_type=PIIType.CRIMINAL,
        confidence=Confidence.HIGH,
        description="Criminal record reference",
    ),

    # Genetic data
    PatternDef(
        pattern=_compile(
            r"\b(?:genetic|genetisch|genome|Genom|DNA\s+test|"
            r"hereditary|erblich|gene\s+therapy|Gentherapie)\b"
        ),
        pii_type=PIIType.GENETIC,
        confidence=Confidence.HIGH,
        description="Genetic data reference",
    ),
]


# -----------------------------------------------------------------------------
# Layer 4: Internal References
# -----------------------------------------------------------------------------

LAYER_4_PATTERNS: List[PatternDef] = [
    # File paths (Unix)
    PatternDef(
        pattern=_compile(r"(?:/[a-zA-Z0-9_.-]+){3,}"),
        pii_type=PIIType.FILE_PATH,
        confidence=Confidence.MEDIUM,
        description="Unix file path",
    ),

    # File paths (Windows)
    PatternDef(
        pattern=_compile(r"[A-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]+"),
        pii_type=PIIType.FILE_PATH,
        confidence=Confidence.MEDIUM,
        description="Windows file path",
    ),

    # Internal URLs
    PatternDef(
        pattern=_compile(
            r"https?://(?:internal|intranet|localhost|192\.168|10\.|172\.(?:1[6-9]|2\d|3[01]))\S+"
        ),
        pii_type=PIIType.INTERNAL_URL,
        confidence=Confidence.HIGH,
        description="Internal URL",
    ),

    # Ticket/Issue IDs
    PatternDef(
        pattern=_compile(r"\b(?:JIRA|TICKET|ISSUE|BUG|TASK|STORY|EPIC)[-#]?\d{3,}\b"),
        pii_type=PIIType.TICKET_ID,
        confidence=Confidence.HIGH,
        description="Ticket/Issue ID",
    ),

    # Generic ticket pattern
    PatternDef(
        pattern=_compile(r"\b[A-Z]{2,5}-\d{3,6}\b"),
        pii_type=PIIType.TICKET_ID,
        confidence=Confidence.MEDIUM,
        description="Generic ticket ID",
    ),

    # Project codenames
    PatternDef(
        pattern=_compile(r"\b(?:Project|Projekt|Codename)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b"),
        pii_type=PIIType.PROJECT_CODENAME,
        confidence=Confidence.MEDIUM,
        description="Project codename",
    ),

    # Draft markers
    PatternDef(
        pattern=_compile(r"\b(?:DRAFT|ENTWURF|CONFIDENTIAL|INTERNAL|VERTRAULICH|INTERN)\b"),
        pii_type=PIIType.DRAFT_MARKER,
        confidence=Confidence.HIGH,
        description="Draft/confidential marker",
    ),

    # Version strings
    PatternDef(
        pattern=_compile(r"\bv?\d+\.\d+(?:\.\d+)?(?:-(?:alpha|beta|rc|draft)\d*)?\b"),
        pii_type=PIIType.VERSION_STRING,
        confidence=Confidence.LOW,
        description="Version string",
    ),
]


# -----------------------------------------------------------------------------
# Allowlist Patterns (Do NOT flag these)
# -----------------------------------------------------------------------------

ALLOWLIST_PATTERNS: List[Pattern] = [
    # Legal citations
    _compile(r"\bArt(?:\.|\s)\s*\d+"),
    _compile(r"\b§+\s*\d+"),
    _compile(r"\bCase\s+C-\d+/\d+"),

    # Regulation names
    _compile(r"\b(?:GDPR|DSGVO|BDSG|AI\s?Act|NIS2|ePrivacy|UrhG|BGB|StGB|HGB)\b"),

    # Public figure titles (in official capacity)
    _compile(r"\b(?:Commissioner|Minister|President|Chancellor|CEO|CFO|CTO)\s+[A-Z][a-z]+"),

    # Common placeholder emails
    _compile(r"\b(?:example|test|noreply|info|contact)@(?:example\.com|test\.com)\b"),

    # Generic IDs that are clearly not PII.
    # Case-SENSITIVE hex body (flags=0): under the module default IGNORECASE the
    # class [0-9a-f] also matches A-F, which put every German IBAN body inside
    # it, so four characters of "Ref " in front of a validated IBAN suppressed
    # it. This is depth only - the load-bearing guard is that suppression runs
    # after the validating detectors and cannot touch what they claimed.
    _compile(
        r"\b(?:UUID|Uuid|uuid|ID|Id|id|REF|Ref|ref)[-:]?\s*[0-9a-f][0-9a-f-]{7,}\b",
        flags=0,
    ),
]


# -----------------------------------------------------------------------------
# Validating detectors
# -----------------------------------------------------------------------------
#
# A pattern says "this is shaped like an IBAN". A validating detector says "this
# IS an IBAN" - mod-97, Luhn, RFC-shaped address. A finding a validating
# detector claims is not a candidate any more, and no false-positive suppressor
# may discard it.


def _luhn_ok(value: str) -> bool:
    digits = re.sub(r"[\s-]", "", value)
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _iban_ok(value: str) -> bool:
    compact = re.sub(r"\s", "", value).upper()
    if not 15 <= len(compact) <= 34:
        return False
    if not (compact[:2].isalpha() and compact[2:4].isdigit() and compact[4:].isalnum()):
        return False
    rotated = compact[4:] + compact[:4]
    try:
        expanded = "".join(str(int(ch, 36)) if ch.isalpha() else ch for ch in rotated)
        return int(expanded) % 97 == 1
    except ValueError:
        return False


_RFC_EMAIL = re.compile(
    r"\A[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\Z"
)


def _email_ok(value: str) -> bool:
    return bool(_RFC_EMAIL.match(value.strip())) and len(value) <= 254


VALIDATORS = {
    PIIType.IBAN: _iban_ok,
    PIIType.CREDIT_CARD: _luhn_ok,
    PIIType.EMAIL: _email_ok,
}


def is_validated_identifier(pii_type: PIIType, value: str) -> bool:
    """True when a validating detector - not merely a pattern - claims *value*."""
    validator = VALIDATORS.get(pii_type)
    return bool(validator) and validator(value)


# =============================================================================
# SCANNER CLASS
# =============================================================================

class PrivacyScanner:
    """
    Multi-layer PII scanner with configurable detection levels.

    All detection is done locally via regex patterns - no LLM calls.
    """

    def __init__(
        self,
        layers: Optional[List[int]] = None,
        min_confidence: Confidence = Confidence.LOW,
        context_chars: int = 30,
        use_allowlist: bool = True,
    ):
        """
        Initialize the scanner.

        Args:
            layers: Which layers to use (1-4). Default: all layers.
            min_confidence: Minimum confidence level to report.
            context_chars: Characters of context to include around findings.
            use_allowlist: Whether to apply allowlist patterns.
        """
        self.layers = layers or [1, 2, 3, 4]
        self.min_confidence = min_confidence
        self.context_chars = context_chars
        self.use_allowlist = use_allowlist

        # Build pattern list based on selected layers
        self.patterns: List[Tuple[int, PatternDef]] = []
        if 1 in self.layers:
            self.patterns.extend((1, p) for p in LAYER_1_PATTERNS)
        if 2 in self.layers:
            self.patterns.extend((2, p) for p in LAYER_2_PATTERNS)
        if 3 in self.layers:
            self.patterns.extend((3, p) for p in LAYER_3_PATTERNS)
        if 4 in self.layers:
            self.patterns.extend((4, p) for p in LAYER_4_PATTERNS)

    def _allowlist_spans(self, text: str) -> List[Tuple[int, int]]:
        """Spans of *text* an allowlist pattern actually covers."""
        if not self.use_allowlist:
            return []
        spans: List[Tuple[int, int]] = []
        for pattern in ALLOWLIST_PATTERNS:
            for match in pattern.finditer(text):
                spans.append((match.start(), match.end()))
        return spans

    def _is_allowlisted(
        self,
        start: int,
        end: int,
        allowlist_spans: List[Tuple[int, int]],
    ) -> bool:
        """True when an allowlist match CONTAINS the span [start, end).

        Containment, not proximity. This used to search a +/-20 character
        context window for any allowlist pattern, so an "Art. 6 DSGVO" or a
        "CEO Meyer" standing next to an email address or a phone number
        switched detection off for it.
        """
        for a_start, a_end in allowlist_spans:
            if a_start <= start and end <= a_end:
                return True
        return False

    @staticmethod
    def _overlaps_validated(
        finding: Finding,
        validated_spans: List[Tuple[int, int]],
    ) -> bool:
        """True when *finding* touches a span a validating detector claimed."""
        return any(
            finding.start < v_end and v_start < finding.end
            for v_start, v_end in validated_spans
        )

    def _confidence_value(self, conf: Confidence) -> int:
        """Convert confidence to numeric value for comparison."""
        return {"high": 3, "medium": 2, "low": 1}.get(conf.value, 0)

    def _get_context(self, text: str, start: int, end: int) -> str:
        """Extract context around a finding."""
        ctx_start = max(0, start - self.context_chars)
        ctx_end = min(len(text), end + self.context_chars)
        prefix = "..." if ctx_start > 0 else ""
        suffix = "..." if ctx_end < len(text) else ""
        return prefix + text[ctx_start:ctx_end] + suffix

    def scan(
        self,
        text: str,
        page: Optional[int] = None,
        zone: Optional[str] = None,
    ) -> ScanResult:
        """
        Scan text for PII.

        Args:
            text: Text to scan.
            page: Optional page number for document context.
            zone: Optional zone (header, body, signature) for context.

        Returns:
            ScanResult with all findings.
        """
        import time
        start_time = time.perf_counter()

        # Pass 1 - detect. Every pattern runs; nothing is suppressed yet. The
        # 2.0.0 release gate rejected the previous single pass, in which a
        # candidate false-positive suppressor ran INSTEAD of the validated
        # Layer-1 detectors and could discard them.
        candidates: List[Finding] = []
        seen_spans: set = set()  # Avoid duplicate findings at same position

        min_conf_value = self._confidence_value(self.min_confidence)

        for layer, pattern_def in self.patterns:
            # Skip if confidence too low
            if self._confidence_value(pattern_def.confidence) < min_conf_value:
                continue

            for match in pattern_def.pattern.finditer(text):
                start, end = match.start(), match.end()
                value = match.group()

                # Skip if already found at this position
                span_key = (start, end)
                if span_key in seen_spans:
                    continue

                seen_spans.add(span_key)

                candidates.append(Finding(
                    pii_type=pattern_def.pii_type,
                    value=value,
                    start=start,
                    end=end,
                    confidence=pattern_def.confidence,
                    layer=layer,
                    context=self._get_context(text, start, end),
                    zone=zone,
                    page=page,
                ))

        # Pass 2 - validate. A validating detector (IBAN mod-97, Luhn,
        # RFC-shaped email) either claims a candidate or it does not.
        validated_spans = [
            (f.start, f.end)
            for f in candidates
            if is_validated_identifier(f.pii_type, f.value)
        ]

        # Pass 3 - suppress, and only now. A suppressor may drop a candidate no
        # validating detector claimed, and may not touch anything overlapping
        # what one did.
        allowlist_spans = self._allowlist_spans(text)
        findings: List[Finding] = []
        for finding in candidates:
            if self._is_allowlisted(finding.start, finding.end, allowlist_spans):
                if not self._overlaps_validated(finding, validated_spans):
                    continue
                logger.debug(
                    "allowlist match ignored: %s at [%d,%d) is claimed by a "
                    "validating detector",
                    finding.pii_type.value, finding.start, finding.end,
                )
            findings.append(finding)

        # Sort by position
        findings.sort(key=lambda f: f.start)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return ScanResult(
            text=text,
            findings=findings,
            scan_time_ms=elapsed_ms,
            layers_used=self.layers,
        )


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def scan_text(
    text: str,
    layers: Optional[List[int]] = None,
    min_confidence: Confidence = Confidence.LOW,
) -> ScanResult:
    """
    Convenience function to scan text for PII.

    Args:
        text: Text to scan.
        layers: Which layers to use (1-4). Default: all.
        min_confidence: Minimum confidence level to report.

    Returns:
        ScanResult with all findings.
    """
    scanner = PrivacyScanner(layers=layers, min_confidence=min_confidence)
    return scanner.scan(text)


# =============================================================================
# LLM-ENHANCED SCANNING (LOCAL ONLY)
# =============================================================================

def scan_text_with_local_llm(
    text: str,
    layers: Optional[List[int]] = None,
    min_confidence: Confidence = Confidence.LOW,
    use_llm_enhancement: bool = True,
) -> ScanResult:
    """
    Enhanced PII scanning using local LLM for context-aware detection.

    This combines pattern-based scanning with local LLM analysis:
    - Pattern matching catches obvious PII (emails, phones, IBANs)
    - Local LLM catches context-dependent PII (names in context, implied locations)

    100% privacy-safe: All processing stays on-device.

    Args:
        text: Text to scan.
        layers: Which layers to use (1-4). Default: all.
        min_confidence: Minimum confidence level to report.
        use_llm_enhancement: Whether to use local LLM for enhanced detection.

    Returns:
        ScanResult with combined findings.
    """
    import time

    start = time.perf_counter()

    # First, do pattern-based scan
    scanner = PrivacyScanner(layers=layers, min_confidence=min_confidence)
    result = scanner.scan(text)

    if not use_llm_enhancement:
        return result

    # Try LLM enhancement (only if local model available)
    try:
        from privacy_shield.services.local_model_runtime import (
            detect_pii_with_local_model,
            is_local_model_available,
        )

        if not is_local_model_available():
            return result

        # Get LLM-based detections
        llm_result = detect_pii_with_local_model(text, timeout=20.0)

        if llm_result.get("error"):
            return result

        # Merge LLM findings with pattern findings
        existing_positions = {(f.start, f.end) for f in result.findings}

        for pii_item in llm_result.get("detected_pii", []):
            pii_type_str = pii_item.get("type", "").lower()
            start_pos = pii_item.get("start_pos", -1)

            # Map LLM types to PIIType
            type_mapping = {
                "name": PIIType.NAME,
                "email": PIIType.EMAIL,
                "phone": PIIType.PHONE,
                "address": PIIType.ADDRESS,
                "financial": PIIType.IBAN,
                "health": PIIType.HEALTH_DATA,
                "legal": PIIType.CRIMINAL,
                "date_of_birth": PIIType.DATE_OF_BIRTH,
            }

            pii_type = type_mapping.get(pii_type_str)
            if not pii_type:
                continue

            # Avoid duplicates
            if start_pos >= 0 and any(
                abs(start_pos - pos[0]) < 10 for pos in existing_positions
            ):
                continue

            # Add LLM-detected finding
            confidence_score = llm_result.get("confidence", 0.5)
            if confidence_score >= 0.8:
                conf = Confidence.HIGH
            elif confidence_score >= 0.6:
                conf = Confidence.MEDIUM
            else:
                conf = Confidence.LOW

            finding = Finding(
                pii_type=pii_type,
                value=pii_item.get("value_hint", "[LLM detected]"),
                start=start_pos if start_pos >= 0 else 0,
                end=start_pos + 10 if start_pos >= 0 else 10,
                confidence=conf,
                layer=5,  # Layer 5 = LLM enhancement
                context="LLM-detected",
            )
            result.findings.append(finding)

        # Update categories
        if llm_result.get("categories"):
            result.layers_used.append(5)

    except ImportError:
        logger.debug("LLM gateway unavailable for privacy scanner enhancement")
    except Exception as exc:
        logger.debug("Privacy scanner LLM enhancement skipped: %s", exc)

    result.scan_time_ms = (time.perf_counter() - start) * 1000
    return result


def is_safe_for_external_llm(
    text: str,
    use_local_llm_check: bool = True,
) -> Tuple[bool, str, List[str]]:
    """
    Check if text is safe to send to external LLM.

    Uses both pattern matching and optional local LLM analysis.

    Args:
        text: Text to check.
        use_local_llm_check: Whether to use local LLM for deeper analysis.

    Returns:
        Tuple of (is_safe, reason, pii_categories_found)
    """
    reject_legacy_env()
    # First do pattern scan
    result = scan_text(text, min_confidence=Confidence.MEDIUM)

    if result.has_pii:
        categories = list({f.pii_type.value for f in result.findings})
        return False, "PII detected by pattern matching", categories

    # Optional LLM check
    if use_local_llm_check:
        try:
            from privacy_shield.services.local_model_runtime import (
                detect_pii_with_local_model,
                is_local_model_available,
            )

            if is_local_model_available():
                llm_result = detect_pii_with_local_model(text, timeout=15.0)

                if not llm_result.get("safe_to_send_external", True):
                    return (
                        False,
                        "PII detected by local LLM analysis",
                        llm_result.get("categories", []),
                    )
        except ImportError:
            logger.debug("LLM gateway unavailable for external-LLM safety check")

    return True, "No PII detected", []
