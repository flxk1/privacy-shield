"""
Privacy Shield - Core Scanner

Pattern-based PII detection with zero LLM calls.
Four detection layers with configurable confidence thresholds.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Dict, List, Optional, Pattern, Tuple

from . import identifiers, names as names_module, national
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
    #: A national person number validated by python-stdnum (see national.py).
    #: Only produced when that optional extra is installed AND a country is
    #: configured; otherwise this type never appears.
    NATIONAL_ID = "national_id"

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

    #: Does a CHECKSUM stand behind this finding, or only a shape?
    #:
    #: The distinction used to be carried by the pii_type alone, and that is
    #: what let an unvalidated regex outrank a validated claim. It is a fact
    #: about the individual finding, not about its type, so it lives on the
    #: finding.
    checksum_validated: bool = False

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
            "checksum_validated": self.checksum_validated,
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


# Filler for allowlisted text during the masked detection pass. Offsets must be
# preserved, so it is one character wide, and no detector pattern may match it.
_MASK_CHAR = "\x00"


# Horizontal whitespace - a space or a tab, never a line break.
#
# `\s` matches "\n", and a multi-token pattern built on it does not stop at the
# end of a line: it runs on into the next one and claims both. On a German
# sign-off
#
#     Mit freundlichen Gruessen
#     Erika Mustermann
#     Musterstrasse 12
#     Anlage
#
# the name pattern matched "\nErika Mustermann\nMusterstrasse" as ONE name, and
# the overlay the cloud model receives was "[NAME][NAME] 12\nAnlage" - the
# sign-off, the street, and every line break gone. That is not a cosmetic
# defect. The overlay is the product: fail-closed on confidentiality and
# fail-open on the reason the thing exists.
#
# So every pattern whose tokens are SEPARATE FIELDS - a name, a street and its
# number, a postal code and its city, a label and its value - is matched per
# line. Layer 3 and Layer 4 keep `\s` deliberately: "mental health" wrapped
# across a line break is still the phrase "mental health", and claiming it is
# right, because nothing is being merged with a neighbour that belongs to
# someone else.
_H = r"[ \t]"


# A digit-run identifier is bounded by DIGITS, not by word characters.
#
# `\b` sits between a word character and a non-word character, so a number
# immediately followed by a LETTER has no boundary after it and a
# `\b`-terminated pattern does not match at all. "+49 170 1234567Ref " - an
# ordinary `pdftotext` letterhead footer, where the field label runs into the
# value - was not detected as a phone number, and the whole number egressed.
#
# Every layout fix before this one was about what may sit BETWEEN or BEFORE an
# identifier. This is the trailing side, and it is the same mistake: the thing
# that must not be adjacent to a digit run is another DIGIT, because that would
# mean the match had clipped a longer number. A letter is not a continuation of
# a number, it is the next word.
#
# The validated types do not need this - the run-based pass in identifiers.py
# already finds them regardless of what is glued on - so it is the types with
# no validator that were exposed.
_NOT_DIGIT_BEFORE = r"(?<!\d)"
_NOT_DIGIT_AFTER = r"(?!\d)"


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
            _NOT_DIGIT_BEFORE
            + r"(?:\+?\d{1,3}[ \t.-]?)?\(?\d{2,4}\)?[ \t.-]?\d{3,4}[ \t.-]?\d{3,4}"
            + _NOT_DIGIT_AFTER
        ),
        pii_type=PIIType.PHONE,
        confidence=Confidence.HIGH,
        description="Phone number",
    ),

    # German phone specific
    PatternDef(
        pattern=_compile(_NOT_DIGIT_BEFORE + r"0\d{2,4}[ \t/-]?\d{4,8}" + _NOT_DIGIT_AFTER),
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
        pattern=_compile(
            _NOT_DIGIT_BEFORE
            + r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
            + _NOT_DIGIT_AFTER
        ),
        pii_type=PIIType.IP_ADDRESS,
        confidence=Confidence.HIGH,
        description="IPv4 address",
    ),

    # German Tax ID (Steuer-ID) - 11 digits
    PatternDef(
        pattern=_compile(_NOT_DIGIT_BEFORE + r"\d{2}\s?\d{3}\s?\d{3}\s?\d{3}" + _NOT_DIGIT_AFTER),
        pii_type=PIIType.STEUER_ID,
        confidence=Confidence.MEDIUM,  # Could be other 11-digit numbers
        description="German tax ID (Steuer-ID)",
    ),

    # German Social Security Number (SVNR)
    PatternDef(
        pattern=_compile(_NOT_DIGIT_BEFORE + r"\d{2}[A-Z]\d{6}[A-Z]\d{3}" + _NOT_DIGIT_AFTER),
        pii_type=PIIType.SVNR,
        confidence=Confidence.HIGH,
        description="German social security number",
    ),

    # Passport numbers (EU format)
    PatternDef(
        pattern=_compile(r"\b[A-Z]{1,2}\d{6,9}" + _NOT_DIGIT_AFTER),
        pii_type=PIIType.PASSPORT,
        confidence=Confidence.LOW,  # Many false positives
        description="Passport number",
    ),

    # German ID card (Personalausweis) - new format
    PatternDef(
        pattern=_compile(r"\b[CFGHJKLMNPRTVWXYZ0-9]{9}\d" + _NOT_DIGIT_AFTER),
        pii_type=PIIType.ID_CARD,
        confidence=Confidence.MEDIUM,
        description="German ID card number",
    ),
]


# -----------------------------------------------------------------------------
# Layer 2: Quasi-Identifiers (Medium Confidence)
# -----------------------------------------------------------------------------

LAYER_2_PATTERNS: List[PatternDef] = [
    # Person names are NOT a pattern here. German capitalises every noun, so
    # "capitalised word followed by capitalised word" claimed 75% of the
    # characters of ordinary business documents containing no personal data at
    # all. They are found in names.py, by the evidence around them - a title, a
    # signature block, an addressee position, a known given name - and folded
    # in by _merge_names below. See tests/test_name_layer_precision.py for what
    # that costs in recall.

    # German street address
    PatternDef(
        pattern=_compile(
            rf"\b[A-ZÄÖÜ][a-zäöüß]+(?:straße|str\.|weg|platz|allee|gasse|ring|damm|ufer){_H}+\d+[a-z]?\b"
        ),
        pii_type=PIIType.ADDRESS,
        confidence=Confidence.HIGH,
        description="German street address",
    ),

    # Generic street address
    PatternDef(
        pattern=_compile(rf"\b\d+{_H}+[A-Z][a-z]+{_H}+(?:Street|St\.|Avenue|Ave\.|Road|Rd\.|Lane|Ln\.)\b"),
        pii_type=PIIType.ADDRESS,
        confidence=Confidence.HIGH,
        description="Street address",
    ),

    # German postal code + city
    PatternDef(
        pattern=_compile(rf"\b\d{{5}}{_H}+[A-ZÄÖÜ][a-zäöüß]+(?:{_H}+[a-zäöüß]+)?\b"),
        pii_type=PIIType.PLZ_CITY,
        confidence=Confidence.HIGH,
        description="German postal code and city",
    ),

    # Date of birth patterns
    PatternDef(
        pattern=_compile(
            r"\b(?:geboren|geb\.|DOB|birth|Geburtsdatum)[: \t]+\d{1,2}[./]\d{1,2}[./]\d{2,4}\b"
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
        pattern=_compile(r"\b(?:age|Alter|Jahre?[ \t]+alt)[: \t]+\d{1,3}\b"),
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

    # Version strings.
    #
    # NOT a German-notation amount. "1.200,00" and "12.500,00" are a thousands
    # separator and a decimal comma, and this pattern claimed the integer part
    # of every four-figure amount on an invoice - in the cloud path, where the
    # scanner runs at its default LOW floor, "Betrag 1.200,00 EUR" went out as
    # "Betrag [ANON_VERS_1],00 EUR".
    #
    # So a version may not be preceded by a digit or a separator, may not be
    # followed by a decimal comma or a further dotted group, and has to LOOK
    # like a version: a leading "v", or three components. That costs the
    # two-component form written without a "v" - "Version 2.1" is no longer
    # claimed - which is a Layer-4 internal reference at the lowest confidence,
    # weighed against every four-figure amount on every invoice.
    PatternDef(
        pattern=_compile(
            r"(?<![\d.,])(?:v\d+\.\d+(?:\.\d+)?|\d+\.\d+\.\d+)"
            r"(?:-(?:alpha|beta|rc|draft)\d*)?(?![\d,]|\.\d)"
        ),
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

    # Letter salutations and closings. Fixed formulas, not names: "Mit
    # freundlichen Gruessen" is two capitalised words to the Layer-2 name
    # pattern, so the sign-off of every German business letter came back as
    # [NAME] and the overlay lost the shape of the document.
    #
    # Only formulas that contain NO name are listed. "Sehr geehrte Frau" is
    # deliberately absent: the name follows it, and masking the formula must
    # never be a way of losing the name's own detection.
    _compile(
        r"\b(?:Mit\s+(?:freundlichen|besten|herzlichen)\s+Gr(?:ü|ue)(?:ß|ss)en"
        r"|(?:Viele|Beste|Freundliche|Herzliche)\s+Gr(?:ü|ue)(?:ß|ss)e"
        r"|Sehr\s+geehrte\s+Damen\s+und\s+Herren"
        r"|(?:Best|Kind|Warm)\s+regards"
        r"|Yours\s+(?:sincerely|faithfully|truly)"
        r"|Dear\s+Sir\s+or\s+Madam)"
    ),

    # There was an entry here for placeholder addresses -
    # (example|test|noreply|info|contact)@(example|test).com - and it had
    # stopped doing anything. A validating detector claims every RFC-shaped
    # address before any suppressor is consulted, so the entry matched, was
    # overridden, and the address was flagged regardless.
    #
    # It was deleted rather than made live again. Making it live means giving
    # one suppressor the last word over a validated identifier, which is the
    # exact structure the 2.0.0 rejection was about: it would turn "does this
    # look like a documentation address" into a way of getting a real address
    # past the detector. The cost of deleting it is that test@example.com is
    # reported as an email. It is an email. Reporting it is the safe error, and
    # a reserved RFC 2606 domain is cheap to over-redact.
    #
    # test_allowlist_cannot_suppress_a_validated_identifier pins the rule.

    # Generic IDs that are clearly not PII.
    # Two narrowings, both depth only - the load-bearing guard is that
    # suppression runs after the validating detectors and cannot touch what
    # they claimed (see tests/test_leak_invariant.py, which proves the
    # structural guard holds with THIS pattern restored to its broken form):
    #  - case-SENSITIVE (flags=0). Under the module default IGNORECASE the class
    #    [a-f0-9-] also matches A-F, so every German IBAN body was inside it and
    #    four characters of "Ref " in front of a validated IBAN suppressed it.
    #  - the body must contain at least one hex LETTER. A run of digits behind
    #    an "ID " prefix is a card or a phone number far more often than it is
    #    an opaque identifier.
    _compile(
        r"\b(?:UUID|Uuid|uuid|ID|Id|id|REF|Ref|ref)[-:]?\s*"
        r"(?=[0-9a-f-]*[a-f])[0-9a-f][0-9a-f-]{7,}\b",
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


_luhn_ok = identifiers.luhn_ok
_iban_ok = identifiers.iban_ok
_email_ok = identifiers.email_ok
_RFC_EMAIL = identifiers.RFC_EMAIL


#: Types whose findings carry a CHECKSUM, and so outrank any pattern that
#: merely overlaps them. NATIONAL_ID belongs here even though its validator
#: lives in python-stdnum rather than in VALIDATORS below: a validated Dutch
#: BSN was being redacted as a [PHONE], because the phone pattern overlapped it
#: and supplied the placeholder.
CHECKSUM_VALIDATED_TYPES = frozenset()

VALIDATORS = {
    PIIType.IBAN: _iban_ok,
    PIIType.CREDIT_CARD: _luhn_ok,
    PIIType.EMAIL: _email_ok,
}


CHECKSUM_VALIDATED_TYPES = frozenset(VALIDATORS) | {PIIType.NATIONAL_ID}


def is_validated_identifier(pii_type: PIIType, value: str) -> bool:
    """True when a validating detector - not merely a pattern - claims *value*."""
    validator = VALIDATORS.get(pii_type)
    return bool(validator) and validator(value)


_MIN_REFINED_LENGTH = 12


def refine_to_validated(pii_type: PIIType, value: str) -> Optional[str]:
    """The longest prefix of *value* a validating detector claims, if any.

    Several Layer-1 patterns are greedy and case-insensitive, so an IBAN or a
    card number routinely matches with a trailing word glued on
    ("DE71...550\\nNr"). That breaks the checksum, which used to mean the
    validating detector could not claim it and a suppressor could therefore
    discard the whole span - real IBAN included. Trimming back to the
    validating prefix keeps the identifier claimed.
    """
    validator = VALIDATORS.get(pii_type)
    if validator is None:
        return None
    if validator(value):
        return value
    if pii_type is PIIType.EMAIL:
        return None
    for end in range(len(value) - 1, _MIN_REFINED_LENGTH, -1):
        if not value[end - 1].isalnum():
            continue
        if validator(value[:end]):
            return value[:end]
    return None


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
        """True when an allowlist match OVERLAPS the span [start, end).

        Overlap, not proximity. This used to search a +/-20 character context
        window for any allowlist pattern and suppress on a hit anywhere in it,
        so an "Art. 6 DSGVO" or a "CEO Meyer" standing *next to* an email
        address or a phone number switched detection off for it. A suppressor
        may now only speak about text it actually covers.
        """
        for a_start, a_end in allowlist_spans:
            if start < a_end and a_start < end:
                return True
        return False

    @staticmethod
    def _mask(text: str, spans: List[Tuple[int, int]]) -> str:
        """Blank *spans* out of *text*, preserving every offset."""
        if not spans:
            return text
        chars = list(text)
        for start, end in spans:
            for index in range(max(0, start), min(len(chars), end)):
                chars[index] = _MASK_CHAR
        return "".join(chars)

    def _match_patterns(
        self,
        haystack: str,
        original: str,
        *,
        zone: Optional[str],
        page: Optional[int],
    ) -> List[Finding]:
        """Run every enabled pattern over *haystack*; report against *original*.

        *haystack* and *original* are the same length, so offsets carry over.
        """
        findings: List[Finding] = []
        seen_spans: set = set()  # Avoid duplicate findings at same position
        min_conf_value = self._confidence_value(self.min_confidence)

        for layer, pattern_def in self.patterns:
            # Skip if confidence too low
            if self._confidence_value(pattern_def.confidence) < min_conf_value:
                continue

            for match in pattern_def.pattern.finditer(haystack):
                start, end = match.start(), match.end()

                # Skip if already found at this position
                span_key = (start, end)
                if span_key in seen_spans:
                    continue
                seen_spans.add(span_key)

                findings.append(Finding(
                    pii_type=pattern_def.pii_type,
                    value=original[start:end],
                    start=start,
                    end=end,
                    confidence=pattern_def.confidence,
                    layer=layer,
                    context=self._get_context(original, start, end),
                    zone=zone,
                    page=page,
                ))
        return findings

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

    def _merge_run_based(
        self,
        text: str,
        findings: List[Finding],
        *,
        zone: Optional[str],
        page: Optional[int],
    ) -> List[Finding]:
        """Fold the anchor-free identifier pass into *findings*.

        A run-based span is the identifier itself. Where a boundary-anchored
        finding of the same type overlaps one, it is the same identifier with a
        neighbour swallowed or a fragment of it, and it is dropped - otherwise
        the redactor merges the two into their union and blanks the neighbour
        out as well, which is safe and destroys the document the caller asked
        for back.
        """
        if 1 not in self.layers:
            return findings
        if self._confidence_value(Confidence.HIGH) < self._confidence_value(self.min_confidence):
            return findings

        iban_spans = identifiers.find_ibans(text)
        card_spans = identifiers.find_cards(
            text, avoid=[(start, end) for start, end, _ in iban_spans]
        )
        merged = list(findings)

        for pii_type, spans in (
            (PIIType.IBAN, iban_spans),
            (PIIType.CREDIT_CARD, card_spans),
            (PIIType.EMAIL, identifiers.find_emails(text)),
        ):
            if not spans:
                continue
            # Evict overlapping PATTERN findings once, against the whole set of
            # run-based spans - not once per span. Two run-based spans of the
            # same type can overlap each other now that card intervals are no
            # longer merged across a line terminator, and evicting per span
            # meant the second one deleted the first: a card claimed at
            # [57,122) vanished because another was claimed at [119,149), and
            # sixty-five characters of the document went out unredacted.
            merged = [
                f for f in merged
                if not (
                    f.pii_type is pii_type
                    and any(f.start < end and start < f.end for start, end, _v in spans)
                )
            ]
            for start, end, _value in spans:
                if any(
                    f.pii_type is pii_type and f.start == start and f.end == end
                    for f in merged
                ):
                    continue
                merged.append(Finding(
                    pii_type=pii_type,
                    value=text[start:end],
                    start=start,
                    end=end,
                    confidence=Confidence.HIGH,
                    layer=1,
                    context=self._get_context(text, start, end),
                    zone=zone,
                    page=page,
                    checksum_validated=True,
                ))
                logger.debug(
                    "run-based %s claimed at [%d,%d) with no boundary consulted",
                    pii_type.value, start, end,
                )

        return self._yield_to_validated(merged, text)

    def _yield_to_validated(
        self, findings: List[Finding], text: str
    ) -> List[Finding]:
        """A checksum-validated span outranks a pattern that merely overlaps it.

        A card number written with dots matched the PHONE pattern, and one
        written with slashes matched the Unix FILE_PATH pattern, so the overlay
        read "[PHONE].1111" and "4111[PATH]" - the identifier redacted by
        accident, by a detector that thought it was looking at something else,
        with fragments of it left behind. The redactor's union kept those cases
        safe, but only incidentally: which type supplied the placeholder came
        down to which span happened to start first. If the phone or path
        pattern were ever narrowed, they would become leaks with nothing to
        flag them.

        So it is settled here instead. A pattern finding contained in a
        validated span is dropped, and one that merely reaches into it is
        trimmed back to where the validated span begins - which keeps whatever
        it found outside and guarantees a validated claim is never swallowed
        into another type's placeholder. A card is redacted as a card.
        """
        # THE FINDING is asked, not its type. A CREDIT_CARD finding that no
        # checksum accepted - the labelled card with one transcription typo,
        # kept below at MEDIUM - is a shape and must not outrank anything. Ask
        # the type and it would, which is the structure this rule exists to
        # forbid.
        claimed = [
            (f.start, f.end) for f in findings if f.checksum_validated
        ]
        if not claimed:
            return findings

        merged: List[List[int]] = []
        for claim_start, claim_end in sorted(claimed):
            if merged and claim_start <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], claim_end)
            else:
                merged.append([claim_start, claim_end])

        kept: List[Finding] = []
        for finding in findings:
            if finding.checksum_validated:
                kept.append(finding)
                continue

            # Everything of this finding that the validated claims do NOT
            # cover - which can be TWO pieces, one either side. The first
            # version trimmed to a single interval and dropped whatever lay
            # beyond the claim's right edge, so a path or a project codename
            # with an address in the middle of it lost its tail into the
            # overlay: "Datei [PATH][EMAIL]\geheim-2027.docx". Layer 4 exists
            # to keep exactly that out.
            remainders: List[Tuple[int, int]] = [(finding.start, finding.end)]
            for claim_start, claim_end in merged:
                nxt: List[Tuple[int, int]] = []
                for start, end in remainders:
                    if end <= claim_start or start >= claim_end:
                        nxt.append((start, end))
                        continue
                    if start < claim_start:
                        nxt.append((start, claim_start))
                    if end > claim_end:
                        nxt.append((claim_end, end))
                remainders = nxt

            if remainders == [(finding.start, finding.end)]:
                kept.append(finding)
                continue
            for start, end in remainders:
                if end <= start:
                    continue
                kept.append(replace(
                    finding,
                    start=start,
                    end=end,
                    value=text[start:end],
                    context=self._get_context(text, start, end),
                ))
        return kept

    def _merge_names(
        self,
        text: str,
        findings: List[Finding],
        *,
        zone: Optional[str],
        page: Optional[int],
    ) -> List[Finding]:
        """Fold in the evidence-based name pass (see names.py)."""
        if 2 not in self.layers:
            return findings
        if self._confidence_value(Confidence.MEDIUM) < self._confidence_value(
            self.min_confidence
        ):
            return findings

        merged = list(findings)
        for start, end, value in names_module.find_names(text):
            if any(
                f.pii_type is PIIType.NAME and f.start < end and start < f.end
                for f in merged
            ):
                continue
            merged.append(Finding(
                pii_type=PIIType.NAME,
                value=value,
                start=start,
                end=end,
                confidence=Confidence.MEDIUM,
                layer=2,
                context=self._get_context(text, start, end),
                zone=zone,
                page=page,
            ))
        merged.sort(key=lambda f: f.start)
        return merged

    def _merge_national(
        self,
        text: str,
        findings: List[Finding],
        *,
        zone: Optional[str],
        page: Optional[int],
    ) -> List[Finding]:
        """Fold in validated national person numbers (see national.py).

        Off unless `python-stdnum` is installed AND a country is configured.
        The floor is correct without it; what is lost is in docs/limits.md.
        """
        if 1 not in self.layers:
            return findings
        if self._confidence_value(Confidence.HIGH) < self._confidence_value(
            self.min_confidence
        ):
            return findings

        merged = list(findings)
        for start, end, value, country, scheme in national.find_national_ids(text):
            if any(
                f.pii_type is PIIType.NATIONAL_ID and f.start < end and start < f.end
                for f in merged
            ):
                continue
            merged.append(Finding(
                pii_type=PIIType.NATIONAL_ID,
                value=value,
                start=start,
                end=end,
                confidence=Confidence.HIGH,
                layer=1,
                context=self._get_context(text, start, end),
                zone=zone,
                page=page,
                checksum_validated=True,
            ))
            logger.debug("national id %s/%s claimed at [%d,%d)", country, scheme, start, end)
        merged.sort(key=lambda f: f.start)
        return merged

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

        # The 2.0.0 release gate rejected the previous single pass, in which a
        # candidate false-positive suppressor ran INSTEAD of the validated
        # Layer-1 detectors and could discard them. Detection and suppression
        # are now separate, and suppression is strictly the weaker of the two.

        # Pass 1 - suppress, by masking. Allowlisted text is blanked out before
        # any detector sees it, so a suppressor can only speak about the text it
        # actually covers. It can no longer drop a finding for standing next to
        # something it recognises, nor drop a whole greedy span because the span
        # happened to absorb one allowlisted token.
        allowlist_spans = self._allowlist_spans(text)
        masked = self._mask(text, allowlist_spans)

        findings = self._match_patterns(masked, text, zone=zone, page=page)
        findings = [
            f for f in findings
            if not self._is_allowlisted(f.start, f.end, allowlist_spans)
        ]

        # A PATTERN MAY NOT OUTRANK A CHECKSUM.
        #
        # For the three types that have a validator, the Layer-1 regex is a
        # candidate generator and nothing more: if the validator does not
        # accept what it matched, the finding goes. It used to be emitted at
        # HIGH confidence unvalidated, so the pattern layer and the validated
        # run-based layer disagreed about what an IBAN is and the one with no
        # checksum won:
        #
        #     "USt-IdNr. DE136695976\nGesamtbetrag 1.349,00 EUR"
        #       -> iban, HIGH, value "DE136695976\nGesamtbetrag 1"
        #
        # A German VAT number is not an IBAN, `find_ibans` correctly returned
        # nothing for it, and the span crossed a line terminator besides. An
        # unvalidated HIGH-confidence finding overruling a checksum is the same
        # structure as the suppressor that opened this programme.
        #
        # Ownership, stated: the run-based layer in identifiers.py OWNS IBAN,
        # card and e-mail detection. It is anchor-free, it validates, and it
        # finds these regardless of what is glued to them. The patterns are
        # kept because they match layouts the run pass reaches differently, but
        # only as candidates.
        validated: List[Finding] = []
        for finding in findings:
            if finding.pii_type not in VALIDATORS:
                validated.append(finding)
                continue
            refined = refine_to_validated(finding.pii_type, finding.value)
            if refined is None:
                if finding.pii_type is PIIType.CREDIT_CARD:
                    # A SHAPE, kept - at MEDIUM, and carrying no checksum.
                    #
                    # Dropping these was the wrong half of the right fix. The
                    # demotion was measured over 200 documents each way: the
                    # IBAN pattern's false positives fell from 62 to 10 and
                    # the CARD pattern's did not move at all - 119 either side
                    # on the corpus here, 34 either side on the verifier's -
                    # while labelled cards carrying one transcription typo went
                    # from 3 in 200 unclaimed to 73. Seventy extra misses for
                    # no precision.
                    #
                    # A single mistyped digit always defeats Luhn; that is what
                    # Luhn is FOR. It is the most ordinary defect there is in
                    # an OCR'd or hand-typed document, and the word
                    # "Kreditkarte" beside a correctly grouped issuer-prefixed
                    # sixteen-digit number is evidence no checksum can
                    # overrule. Unlike the IBAN pattern, which matches any two
                    # letters and two digits followed by anything, this pattern
                    # is a shape in its own right.
                    #
                    # MEDIUM, and checksum_validated stays False: it is still
                    # redacted by default, a caller running at
                    # min_confidence=HIGH gets only checksum-backed findings,
                    # and it cannot outrank a validated claim anywhere.
                    finding.confidence = Confidence.MEDIUM
                    validated.append(finding)
                    continue
                logger.debug(
                    "dropped unvalidated %s candidate at [%d,%d)",
                    finding.pii_type.value, finding.start, finding.end,
                )
                continue
            finding.checksum_validated = True
            if refined != finding.value:
                finding.value = refined
                finding.end = finding.start + len(refined)
                finding.context = self._get_context(text, finding.start, finding.end)
            validated.append(finding)
        findings = validated

        # Pass 2 - rescue, by validation. Masking is still a suppressor, and a
        # suppressor must never be the last word on a high-confidence finding.
        # So the unmasked text is scanned too, and anything a validating
        # detector claims (IBAN mod-97, Luhn, RFC-shaped email) is reinstated
        # whatever the allowlist thought of it. This is the load-bearing guard:
        # it holds even with the pre-fix suppressor pattern restored.
        known = {(f.start, f.end) for f in findings}
        for finding in self._match_patterns(text, text, zone=zone, page=page):
            if finding.pii_type not in VALIDATORS:
                continue
            refined = refine_to_validated(finding.pii_type, finding.value)
            if refined is None:
                continue
            finding.checksum_validated = True
            if refined != finding.value:
                finding.value = refined
                finding.end = finding.start + len(refined)
                finding.context = self._get_context(text, finding.start, finding.end)
                # The greedy candidate this was trimmed out of is the same
                # identifier plus a swallowed neighbour. Keeping both would make
                # the redactor merge them and blank the neighbour out too, so
                # the trimmed one replaces it.
                findings = [
                    f for f in findings
                    if not (
                        f.pii_type is finding.pii_type
                        and f.start == finding.start
                        and f.end > finding.end
                    )
                ]
                known = {(f.start, f.end) for f in findings}
            if (finding.start, finding.end) in known:
                continue
            known.add((finding.start, finding.end))
            findings.append(finding)
            logger.debug(
                "validated %s at [%d,%d) reinstated over the allowlist",
                finding.pii_type.value, finding.start, finding.end,
            )

        # Pass 3 - find, without a word boundary. Passes 1 and 2 both discover
        # candidates with `\b`-anchored patterns, which do not find an
        # identifier so much as a place one is allowed to start. One word
        # character glued in front of an IBAN or a card number means no
        # boundary exists at its first character, and since the rest of the
        # identifier is word characters too, none exists inside it either: the
        # pattern matches nothing, the validator is never offered the
        # candidate, and the caller is told pii_detected=False while a
        # mod-97-valid account number goes out in the payload. Worse than the
        # defect this replaced, which at least flagged.
        #
        # So for the three types that have a validator, the authoritative pass
        # walks maximal runs of identifier characters and offers the validator
        # every candidate substring. See identifiers.py for the precision cost.
        findings = self._merge_run_based(text, findings, zone=zone, page=page)
        findings = self._merge_national(text, findings, zone=zone, page=page)
        findings = self._merge_names(text, findings, zone=zone, page=page)
        findings = self._yield_to_validated(findings, text)

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
