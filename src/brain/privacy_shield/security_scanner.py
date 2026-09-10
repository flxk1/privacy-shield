"""
Document Security Scanner - Cybersecurity risk detection for LLM inputs.

Detects prompt injection, jailbreaks, hidden instructions, and other
adversarial content in documents before they're injected into LLM prompts.

100% local execution, zero external API calls.
Compatible with Privacy Shield PII scanning.

Features:
- Multi-layer pattern-based detection
- Optional LLM enhancement via Ollama
- Intelligent caching for repeated content
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import threading
import time
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple

import yaml

logger = logging.getLogger(__name__)


# =============================================================================
# CACHING SYSTEM
# =============================================================================

@dataclass
class CacheEntry:
    """A cached scan result with timestamp."""
    result: Any
    timestamp: float
    hit_count: int = 0


class SecurityScanCache:
    """
    LRU cache with TTL for security scan results.

    Caches:
    - Pattern-based scan results (fast, but still saves CPU)
    - LLM analysis results (expensive, saves significant time)
    - Text hash -> result mapping

    Thread-safe for concurrent access.
    """

    def __init__(
        self,
        max_size: int = 1000,
        ttl_seconds: float = 3600.0,  # 1 hour default
        llm_ttl_seconds: float = 7200.0,  # 2 hours for LLM results
    ):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.llm_ttl_seconds = llm_ttl_seconds

        self._pattern_cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._llm_cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()

        # Stats
        self._hits = 0
        self._misses = 0
        self._llm_hits = 0
        self._llm_misses = 0

    def _compute_hash(self, text: str, strictness: str = "medium") -> str:
        """Compute cache key from text content and settings."""
        content = f"{strictness}:{text}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:32]

    def _is_expired(self, entry: CacheEntry, ttl: float) -> bool:
        """Check if cache entry has expired."""
        return (time.time() - entry.timestamp) > ttl

    def _evict_oldest(self, cache: OrderedDict) -> None:
        """Remove oldest entry if cache is full."""
        if len(cache) >= self.max_size:
            cache.popitem(last=False)

    def get_pattern_result(
        self, text: str, strictness: str = "medium"
    ) -> Optional[Any]:
        """Get cached pattern scan result."""
        key = self._compute_hash(text, strictness)

        with self._lock:
            if key in self._pattern_cache:
                entry = self._pattern_cache[key]
                if not self._is_expired(entry, self.ttl_seconds):
                    entry.hit_count += 1
                    self._hits += 1
                    # Move to end (most recently used)
                    self._pattern_cache.move_to_end(key)
                    return entry.result
                else:
                    # Expired, remove it
                    del self._pattern_cache[key]

            self._misses += 1
            return None

    def set_pattern_result(
        self, text: str, strictness: str, result: Any
    ) -> None:
        """Cache a pattern scan result."""
        key = self._compute_hash(text, strictness)

        with self._lock:
            self._evict_oldest(self._pattern_cache)
            self._pattern_cache[key] = CacheEntry(
                result=result,
                timestamp=time.time(),
            )

    def get_llm_result(
        self, text: str, strictness: str = "medium"
    ) -> Optional[Any]:
        """Get cached LLM analysis result."""
        key = self._compute_hash(text, strictness)

        with self._lock:
            if key in self._llm_cache:
                entry = self._llm_cache[key]
                if not self._is_expired(entry, self.llm_ttl_seconds):
                    entry.hit_count += 1
                    self._llm_hits += 1
                    self._llm_cache.move_to_end(key)
                    return entry.result
                else:
                    del self._llm_cache[key]

            self._llm_misses += 1
            return None

    def set_llm_result(
        self, text: str, strictness: str, result: Any
    ) -> None:
        """Cache an LLM analysis result."""
        key = self._compute_hash(text, strictness)

        with self._lock:
            self._evict_oldest(self._llm_cache)
            self._llm_cache[key] = CacheEntry(
                result=result,
                timestamp=time.time(),
            )

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            pattern_total = self._hits + self._misses
            llm_total = self._llm_hits + self._llm_misses

            return {
                "pattern_cache_size": len(self._pattern_cache),
                "llm_cache_size": len(self._llm_cache),
                "pattern_hits": self._hits,
                "pattern_misses": self._misses,
                "pattern_hit_rate": self._hits / pattern_total if pattern_total > 0 else 0,
                "llm_hits": self._llm_hits,
                "llm_misses": self._llm_misses,
                "llm_hit_rate": self._llm_hits / llm_total if llm_total > 0 else 0,
            }

    def clear(self) -> None:
        """Clear all caches."""
        with self._lock:
            self._pattern_cache.clear()
            self._llm_cache.clear()
            self._hits = 0
            self._misses = 0
            self._llm_hits = 0
            self._llm_misses = 0

    def cleanup_expired(self) -> int:
        """Remove all expired entries. Returns count removed."""
        removed = 0
        now = time.time()

        with self._lock:
            # Clean pattern cache
            expired_keys = [
                k for k, v in self._pattern_cache.items()
                if (now - v.timestamp) > self.ttl_seconds
            ]
            for k in expired_keys:
                del self._pattern_cache[k]
                removed += 1

            # Clean LLM cache
            expired_keys = [
                k for k, v in self._llm_cache.items()
                if (now - v.timestamp) > self.llm_ttl_seconds
            ]
            for k in expired_keys:
                del self._llm_cache[k]
                removed += 1

        return removed


# Global cache instance
_global_cache = SecurityScanCache()


def get_security_cache() -> SecurityScanCache:
    """Get the global security scan cache."""
    return _global_cache


def reset_security_cache() -> None:
    """Reset/clear the global security scan cache."""
    _global_cache.clear()


class ThreatType(str, Enum):
    """Security threat categories."""

    # Layer 1: Prompt Injection (Critical/High)
    PROMPT_INJECTION = "prompt_injection"
    SYSTEM_ROLE_INJECTION = "system_role_injection"
    DELIMITER_INJECTION = "delimiter_injection"

    # Layer 2: Jailbreak Attempts (High/Medium)
    JAILBREAK = "jailbreak"
    PERSONA_SWITCH = "persona_switch"
    HYPOTHETICAL_BYPASS = "hypothetical_bypass"

    # Layer 3: Obfuscation (High/Medium)
    BASE64_PAYLOAD = "base64_payload"
    UNICODE_TRICK = "unicode_trick"
    INVISIBLE_CHARS = "invisible_chars"
    HOMOGLYPH = "homoglyph"

    # Layer 4: Adversarial Formatting (Medium)
    MARKDOWN_INJECTION = "markdown_injection"
    CODE_BLOCK_ESCAPE = "code_block_escape"
    HTML_INJECTION = "html_injection"

    # Layer 5: Embedded Commands (Medium)
    SHELL_COMMAND = "shell_command"
    SQL_INJECTION = "sql_injection"
    CODE_EXECUTION = "code_execution"


class ThreatSeverity(str, Enum):
    """Severity levels for detected threats."""

    CRITICAL = "critical"  # Block immediately, potential active attack
    HIGH = "high"  # Block by default, clear malicious intent
    MEDIUM = "medium"  # Sanitize by default, suspicious pattern
    LOW = "low"  # Log only, possibly benign


# Severity mapping for each threat type
THREAT_SEVERITY_MAP: Dict[ThreatType, ThreatSeverity] = {
    # Critical - direct prompt manipulation
    ThreatType.PROMPT_INJECTION: ThreatSeverity.CRITICAL,
    ThreatType.SYSTEM_ROLE_INJECTION: ThreatSeverity.CRITICAL,
    ThreatType.DELIMITER_INJECTION: ThreatSeverity.HIGH,
    # High - jailbreak attempts
    ThreatType.JAILBREAK: ThreatSeverity.HIGH,
    ThreatType.PERSONA_SWITCH: ThreatSeverity.HIGH,
    ThreatType.HYPOTHETICAL_BYPASS: ThreatSeverity.MEDIUM,
    # Medium-High - obfuscation
    ThreatType.BASE64_PAYLOAD: ThreatSeverity.HIGH,
    ThreatType.UNICODE_TRICK: ThreatSeverity.MEDIUM,
    ThreatType.INVISIBLE_CHARS: ThreatSeverity.HIGH,
    ThreatType.HOMOGLYPH: ThreatSeverity.MEDIUM,
    # Medium - formatting abuse
    ThreatType.MARKDOWN_INJECTION: ThreatSeverity.MEDIUM,
    ThreatType.CODE_BLOCK_ESCAPE: ThreatSeverity.MEDIUM,
    ThreatType.HTML_INJECTION: ThreatSeverity.MEDIUM,
    # Medium - embedded commands
    ThreatType.SHELL_COMMAND: ThreatSeverity.MEDIUM,
    ThreatType.SQL_INJECTION: ThreatSeverity.MEDIUM,
    ThreatType.CODE_EXECUTION: ThreatSeverity.MEDIUM,
}


@dataclass
class ThreatFinding:
    """A single security threat detection finding."""

    threat_type: ThreatType
    severity: ThreatSeverity
    value: str  # The matched content
    start: int
    end: int
    description: str
    context: str = ""  # Surrounding text for review
    neutralized_value: Optional[str] = None  # How it was sanitized

    def to_dict(self) -> dict:
        return {
            "type": self.threat_type.value,
            "severity": self.severity.value,
            "value": self.value[:100] + "..." if len(self.value) > 100 else self.value,
            "start": self.start,
            "end": self.end,
            "description": self.description,
            "context": self.context,
            "neutralized": self.neutralized_value is not None,
        }


@dataclass
class SecurityScanResult:
    """Result of a security scan."""

    text: str
    findings: List[ThreatFinding] = field(default_factory=list)
    scan_time_ms: float = 0.0
    blocked: bool = False
    block_reason: Optional[str] = None
    sanitized_text: Optional[str] = None
    sanitization_applied: bool = False

    @property
    def has_threats(self) -> bool:
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == ThreatSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == ThreatSeverity.HIGH)

    @property
    def max_severity(self) -> Optional[ThreatSeverity]:
        if not self.findings:
            return None
        severity_order = [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH,
                         ThreatSeverity.MEDIUM, ThreatSeverity.LOW]
        for sev in severity_order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return None

    @property
    def findings_by_type(self) -> Dict[str, List[ThreatFinding]]:
        result: Dict[str, List[ThreatFinding]] = {}
        for f in self.findings:
            key = f.threat_type.value
            if key not in result:
                result[key] = []
            result[key].append(f)
        return result

    def to_dict(self) -> dict:
        return {
            "has_threats": self.has_threats,
            "finding_count": len(self.findings),
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "max_severity": self.max_severity.value if self.max_severity else None,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "sanitization_applied": self.sanitization_applied,
            "scan_time_ms": self.scan_time_ms,
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
class SecurityPatternDef:
    """Pattern definition for security threat detection."""

    pattern: Pattern
    threat_type: ThreatType
    description: str
    neutralization: str = "escape"  # escape, strip, replace, block


def _compile(pattern: str, flags: int = re.IGNORECASE | re.MULTILINE) -> Pattern:
    """Compile a regex pattern with standard flags."""
    return re.compile(pattern, flags)


# -----------------------------------------------------------------------------
# Layer 1: Prompt Injection Patterns (Critical/High)
# -----------------------------------------------------------------------------

LAYER_1_PATTERNS: List[SecurityPatternDef] = [
    # Direct instruction override attempts
    SecurityPatternDef(
        pattern=_compile(
            r"\b(?:ignore|disregard|forget|override|bypass|skip|discard)\s+"
            r"(?:all\s+)?(?:previous|prior|above|earlier|your|the)?\s*"
            r"(?:instructions?|rules?|guidelines?|constraints?|restrictions?|directions?|prompts?)\b"
        ),
        threat_type=ThreatType.PROMPT_INJECTION,
        description="Instruction override attempt",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"\bbypass\s+(?:your\s+)?(?:usual\s+)?(?:content\s+)?polic(?:y|ies)\b"
        ),
        threat_type=ThreatType.PROMPT_INJECTION,
        description="Policy bypass attempt",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"\b(?:new\s+)?(?:system|user|assistant)\s*(?:prompt|message|instruction|role)\s*[:=]"
        ),
        threat_type=ThreatType.PROMPT_INJECTION,
        description="Role/prompt redefinition attempt",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"\[\s*(?:SYSTEM|INST|ASSISTANT|USER)\s*\]|\<\s*(?:system|user|assistant)\s*\>"
        ),
        threat_type=ThreatType.PROMPT_INJECTION,
        description="Chat role marker injection",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"(?:^|\n)\s*(?:system|assistant|user)\s*:\s*(?=\S)"
        ),
        threat_type=ThreatType.PROMPT_INJECTION,
        description="Role prefix injection",
        neutralization="escape",
    ),

    # System role injection
    SecurityPatternDef(
        pattern=_compile(
            r"\byou\s+(?:are|will\s+be|must\s+act\s+as|should\s+act\s+as|must\s+be|are\s+now)\s+"
            r"(?:a|an|the)?\s*(?:different|new|another|evil|unrestricted|unfiltered)\b"
        ),
        threat_type=ThreatType.SYSTEM_ROLE_INJECTION,
        description="Identity/role reassignment attempt",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"\bfrom\s+now\s+on\s*[,:]?\s*(?:you|your|act|behave|respond|operate)\b"
        ),
        threat_type=ThreatType.SYSTEM_ROLE_INJECTION,
        description="Persistent behavior change attempt",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"\benter(?:ing)?\s+(?:into\s+)?(?:a\s+)?(?:new|different|special|developer|admin|root|debug)\s+mode\b"
        ),
        threat_type=ThreatType.SYSTEM_ROLE_INJECTION,
        description="Mode switch attempt",
        neutralization="escape",
    ),

    # Delimiter/separator injection
    SecurityPatternDef(
        pattern=_compile(
            r"(?:---+|===+|\*\*\*+|####+)\s*"
            r"(?:END|BEGIN|START|STOP|NEW|IGNORE|SYSTEM|ACTUAL|REAL)\s*"
            r"(?:OF\s+)?(?:INSTRUCTIONS?|PROMPT|CONTEXT|MESSAGE|INPUT|OUTPUT)?\s*"
            r"(?:---+|===+|\*\*\*+|####+)?"
        ),
        threat_type=ThreatType.DELIMITER_INJECTION,
        description="Delimiter-based context escape",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"#{3,}\s*(?:SYSTEM|USER|ASSISTANT)(?:\s+PROMPT)?\s*#{3,}"
        ),
        threat_type=ThreatType.DELIMITER_INJECTION,
        description="Hash-delimited role marker",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"<\|(?:endoftext|im_start|im_end|sep|pad|unk|mask|cls|start|end)\|>"
        ),
        threat_type=ThreatType.DELIMITER_INJECTION,
        description="Special token injection",
        neutralization="strip",
    ),
]


# -----------------------------------------------------------------------------
# Layer 2: Jailbreak Patterns (High/Medium)
# -----------------------------------------------------------------------------

LAYER_2_PATTERNS: List[SecurityPatternDef] = [
    # DAN (Do Anything Now) and variants
    SecurityPatternDef(
        pattern=_compile(
            r"\b(?:DAN|DAM|DUDE|KEVIN|STAN|MONGO|ARIA|KEVIN)\s*(?:mode|prompt|jailbreak)?\b"
        ),
        threat_type=ThreatType.JAILBREAK,
        description="Known jailbreak persona name",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"\bdo\s+anything\s+now\b|\bunrestricted\s+(?:mode|AI|assistant|model)\b"
        ),
        threat_type=ThreatType.JAILBREAK,
        description="Unrestricted mode request",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"\b(?:without|no|remove|disable|turn\s+off|ignore)\s+"
            r"(?:all\s+)?(?:any\s+)?(?:your\s+)?(?:ethical|safety|content|moral)?\s*"
            r"(?:filter|restriction|limitation|guideline|constraint|safeguard|guardrail)s?\b"
        ),
        threat_type=ThreatType.JAILBREAK,
        description="Safety filter bypass request",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"\b(?:jailbreak|jailbroken|broken\s+free|escaped|liberated)\s*"
            r"(?:mode|version|state|AI|model|assistant)?\b"
        ),
        threat_type=ThreatType.JAILBREAK,
        description="Explicit jailbreak reference",
        neutralization="escape",
    ),

    # Persona switching
    SecurityPatternDef(
        pattern=_compile(
            r"\bpretend\s+(?:to\s+be|you(?:'re|\s+are))\s+(?:a|an)?\s*"
            r"(?:evil|malicious|unethical|unrestricted|uncensored|criminal|hacker)\b"
        ),
        threat_type=ThreatType.PERSONA_SWITCH,
        description="Malicious persona request",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"\broleplay\s+(?:as\s+)?(?:a|an)?\s*"
            r"(?:villain|criminal|hacker|attacker|evil|malicious|bad\s+actor)\b"
        ),
        threat_type=ThreatType.PERSONA_SWITCH,
        description="Malicious roleplay request",
        neutralization="escape",
    ),

    # Hypothetical bypass
    SecurityPatternDef(
        pattern=_compile(
            r"\b(?:hypothetically|theoretically|in\s+theory|imagine\s+if|what\s+if)\s+"
            r"(?:you\s+)?(?:could|would|were\s+able\s+to|had\s+no\s+restrictions?)\b"
        ),
        threat_type=ThreatType.HYPOTHETICAL_BYPASS,
        description="Hypothetical restriction bypass",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"\bfor\s+(?:educational|research|academic|training|testing)\s+purposes?\s+only\b"
        ),
        threat_type=ThreatType.HYPOTHETICAL_BYPASS,
        description="Educational purposes disclaimer (often used for bypass)",
        neutralization="escape",
    ),
]


# -----------------------------------------------------------------------------
# Layer 3: Obfuscation Patterns (High/Medium)
# -----------------------------------------------------------------------------

# Base64 pattern for detecting encoded payloads
BASE64_PATTERN = _compile(
    r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})"
)

# Unicode categories that may be used for tricks
SUSPICIOUS_UNICODE_CATEGORIES = {
    "Cf",  # Format characters (invisible)
    "Co",  # Private use
    "Cs",  # Surrogates
    "Mn",  # Non-spacing marks
}

# Invisible characters to detect
INVISIBLE_CHARS = {
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\u2060",  # Word joiner
    "\u2061",  # Function application
    "\u2062",  # Invisible times
    "\u2063",  # Invisible separator
    "\u2064",  # Invisible plus
    "\ufeff",  # BOM / Zero-width no-break space
    "\u00ad",  # Soft hyphen
    "\u034f",  # Combining grapheme joiner
    "\u180e",  # Mongolian vowel separator
    "\u2800",  # Braille blank
}

LAYER_3_PATTERNS: List[SecurityPatternDef] = [
    # Explicit encoding markers
    SecurityPatternDef(
        pattern=_compile(
            r"\b(?:base64|b64|hex|rot13|unicode|url)[\s_-]*(?:encode|decode|encoded|decoded)?\s*[:=]"
        ),
        threat_type=ThreatType.BASE64_PAYLOAD,
        description="Explicit encoding marker",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}"
        ),
        threat_type=ThreatType.UNICODE_TRICK,
        description="Hex-escaped byte sequence",
        neutralization="strip",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){3,}"
        ),
        threat_type=ThreatType.UNICODE_TRICK,
        description="Unicode escape sequence",
        neutralization="strip",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"&#x?[0-9a-fA-F]+;(?:&#x?[0-9a-fA-F]+;){3,}"
        ),
        threat_type=ThreatType.UNICODE_TRICK,
        description="HTML entity encoding",
        neutralization="strip",
    ),
]


# -----------------------------------------------------------------------------
# Layer 4: Adversarial Formatting Patterns (Medium)
# -----------------------------------------------------------------------------

LAYER_4_PATTERNS: List[SecurityPatternDef] = [
    # Markdown injection
    SecurityPatternDef(
        pattern=_compile(
            r"\[(?:system|admin|root|inject|execute)\]"
            r"\s*\([^)]*\)"
        ),
        threat_type=ThreatType.MARKDOWN_INJECTION,
        description="Suspicious markdown link",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"!\[(?:system|inject|execute|run|cmd)\]"
            r"\s*\([^)]*\)"
        ),
        threat_type=ThreatType.MARKDOWN_INJECTION,
        description="Suspicious markdown image",
        neutralization="escape",
    ),

    # Code block escapes
    SecurityPatternDef(
        pattern=_compile(
            r"```\s*(?:system|bash|sh|cmd|powershell|exec|eval)\s*\n"
        ),
        threat_type=ThreatType.CODE_BLOCK_ESCAPE,
        description="Executable code block marker",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"```\s*\n[^`]*(?:ignore|override|bypass|new\s+instructions)[^`]*\n```"
        ),
        threat_type=ThreatType.CODE_BLOCK_ESCAPE,
        description="Instruction injection in code block",
        neutralization="escape",
    ),

    # HTML injection
    SecurityPatternDef(
        pattern=_compile(
            r"<\s*(?:script|iframe|object|embed|form|input|style|link|meta|base)\b[^>]*>"
        ),
        threat_type=ThreatType.HTML_INJECTION,
        description="Dangerous HTML tag",
        neutralization="strip",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"\bon\w+\s*=\s*[\"'][^\"']*[\"']"
        ),
        threat_type=ThreatType.HTML_INJECTION,
        description="HTML event handler",
        neutralization="strip",
    ),
]


# -----------------------------------------------------------------------------
# Layer 5: Embedded Commands Patterns (Medium)
# -----------------------------------------------------------------------------

LAYER_5_PATTERNS: List[SecurityPatternDef] = [
    # Shell commands
    SecurityPatternDef(
        pattern=_compile(
            r"(?:^|\s)(?:sudo|chmod|chown|rm\s+-rf|wget|curl|nc|netcat|bash\s+-c|sh\s+-c)\s"
        ),
        threat_type=ThreatType.SHELL_COMMAND,
        description="Shell command pattern",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"\$\((?:curl|wget|nc|bash|sh|python|perl|ruby|exec|eval)[^)]*\)"
        ),
        threat_type=ThreatType.SHELL_COMMAND,
        description="Command substitution",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"`(?:curl|wget|nc|bash|sh|python|perl|ruby|exec|eval)[^`]*`"
        ),
        threat_type=ThreatType.SHELL_COMMAND,
        description="Backtick command execution",
        neutralization="escape",
    ),

    # SQL injection patterns
    SecurityPatternDef(
        pattern=_compile(
            r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\s+.*?"
            r"(?:FROM|INTO|TABLE|WHERE|SET)\b",
            re.IGNORECASE,
        ),
        threat_type=ThreatType.SQL_INJECTION,
        description="SQL statement pattern",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"['\"]?\s*(?:OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?"
        ),
        threat_type=ThreatType.SQL_INJECTION,
        description="SQL injection tautology",
        neutralization="escape",
    ),

    # Code execution
    SecurityPatternDef(
        pattern=_compile(
            r"\b(?:eval|exec|compile|__import__|getattr|setattr|globals|locals)\s*\("
        ),
        threat_type=ThreatType.CODE_EXECUTION,
        description="Python code execution function",
        neutralization="escape",
    ),
    SecurityPatternDef(
        pattern=_compile(
            r"\b(?:Function|eval|setTimeout|setInterval)\s*\([^)]*\)"
        ),
        threat_type=ThreatType.CODE_EXECUTION,
        description="JavaScript code execution",
        neutralization="escape",
    ),
]


# =============================================================================
# SCANNER CLASS
# =============================================================================

class SecurityScanner:
    """
    Multi-layer security scanner for document content.

    Detects prompt injection, jailbreaks, obfuscation, and other
    adversarial content before it reaches the LLM.

    All detection is done locally - no external API calls.
    """

    def __init__(
        self,
        config_path: Optional[Path] = None,
        strictness: str = "medium",
        block_on_critical: bool = True,
        block_on_high: bool = False,
        auto_sanitize: bool = True,
        context_chars: int = 50,
        use_cache: bool = True,
        cache: Optional[SecurityScanCache] = None,
    ):
        """
        Initialize the security scanner.

        Args:
            config_path: Optional path to YAML configuration file.
            strictness: Detection strictness (low, medium, high).
            block_on_critical: Block documents with critical threats.
            block_on_high: Block documents with high-severity threats.
            auto_sanitize: Automatically sanitize detected threats.
            context_chars: Characters of context to include around findings.
            use_cache: Enable caching of scan results.
            cache: Optional custom cache instance (uses global cache if None).
        """
        self.strictness = strictness
        self.block_on_critical = block_on_critical
        self.block_on_high = block_on_high
        self.auto_sanitize = auto_sanitize
        self.context_chars = context_chars
        self.use_cache = use_cache
        self._cache = cache or _global_cache

        # Load config if provided
        if config_path and config_path.exists():
            self._load_config(config_path)

        # Build pattern list
        self.patterns: List[Tuple[int, SecurityPatternDef]] = []
        self._build_pattern_list()

    def _load_config(self, config_path: Path) -> None:
        """Load configuration from YAML file."""
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}

            scanner_config = config.get("scanner", {})
            self.strictness = scanner_config.get("strictness", self.strictness)
            self.block_on_critical = scanner_config.get("block_on_critical", self.block_on_critical)
            self.block_on_high = scanner_config.get("block_on_high", self.block_on_high)
            self.auto_sanitize = scanner_config.get("auto_sanitize", self.auto_sanitize)
        except Exception as exc:
            logger.warning("Security scanner config load failed (%s): %s", config_path, exc)

    def _build_pattern_list(self) -> None:
        """Build the list of patterns based on strictness."""
        # Always include layers 1-3 (injection, jailbreak, obfuscation)
        self.patterns.extend((1, p) for p in LAYER_1_PATTERNS)
        self.patterns.extend((2, p) for p in LAYER_2_PATTERNS)
        self.patterns.extend((3, p) for p in LAYER_3_PATTERNS)

        # Include layers 4-5 based on strictness
        if self.strictness in ("medium", "high"):
            self.patterns.extend((4, p) for p in LAYER_4_PATTERNS)

        if self.strictness == "high":
            self.patterns.extend((5, p) for p in LAYER_5_PATTERNS)

    def _get_context(self, text: str, start: int, end: int) -> str:
        """Extract context around a finding."""
        ctx_start = max(0, start - self.context_chars)
        ctx_end = min(len(text), end + self.context_chars)
        prefix = "..." if ctx_start > 0 else ""
        suffix = "..." if ctx_end < len(text) else ""
        return prefix + text[ctx_start:ctx_end] + suffix

    def _check_base64_payload(self, text: str, findings: List[ThreatFinding]) -> None:
        """Check for suspicious Base64-encoded payloads."""
        for match in BASE64_PATTERN.finditer(text):
            payload = match.group()
            # Skip short matches (likely false positives)
            if len(payload) < 50:
                continue

            try:
                # Try to decode
                decoded = base64.b64decode(payload + "==").decode("utf-8", errors="ignore")

                # Check if decoded content contains suspicious patterns
                suspicious_in_decoded = any(
                    p.pattern.search(decoded)
                    for _, p in self.patterns
                    if p.threat_type in (ThreatType.PROMPT_INJECTION,
                                          ThreatType.JAILBREAK,
                                          ThreatType.SYSTEM_ROLE_INJECTION)
                )

                if suspicious_in_decoded:
                    findings.append(ThreatFinding(
                        threat_type=ThreatType.BASE64_PAYLOAD,
                        severity=ThreatSeverity.HIGH,
                        value=payload[:50] + "...",
                        start=match.start(),
                        end=match.end(),
                        description="Base64-encoded suspicious content",
                        context=self._get_context(text, match.start(), match.end()),
                    ))
            except Exception:
                continue  # Not valid base64 or decode error

    def _check_invisible_chars(self, text: str, findings: List[ThreatFinding]) -> None:
        """Check for invisible/zero-width characters."""
        for i, char in enumerate(text):
            if char in INVISIBLE_CHARS:
                findings.append(ThreatFinding(
                    threat_type=ThreatType.INVISIBLE_CHARS,
                    severity=ThreatSeverity.HIGH,
                    value=f"U+{ord(char):04X}",
                    start=i,
                    end=i + 1,
                    description=f"Invisible character: {unicodedata.name(char, 'UNKNOWN')}",
                    context=self._get_context(text, i, i + 1),
                ))

    def _check_homoglyphs(self, text: str, findings: List[ThreatFinding]) -> None:
        """Check for homoglyph attacks (lookalike characters)."""
        # Common homoglyph mappings
        homoglyphs = {
            "\u0430": "a",  # Cyrillic а
            "\u0435": "e",  # Cyrillic е
            "\u043e": "o",  # Cyrillic о
            "\u0440": "p",  # Cyrillic р
            "\u0441": "c",  # Cyrillic с
            "\u0445": "x",  # Cyrillic х
            "\u0443": "y",  # Cyrillic у
            "\u0456": "i",  # Cyrillic і
            "\u0391": "A",  # Greek Α
            "\u0392": "B",  # Greek Β
            "\u0395": "E",  # Greek Ε
            "\u0397": "H",  # Greek Η
            "\u0399": "I",  # Greek Ι
            "\u039a": "K",  # Greek Κ
            "\u039c": "M",  # Greek Μ
            "\u039d": "N",  # Greek Ν
            "\u039f": "O",  # Greek Ο
            "\u03a1": "P",  # Greek Ρ
            "\u03a4": "T",  # Greek Τ
            "\u03a7": "X",  # Greek Χ
            "\u03a5": "Y",  # Greek Υ
            "\u0417": "Z",  # Cyrillic З
        }

        for i, char in enumerate(text):
            if char in homoglyphs:
                # Only report if surrounded by ASCII letters (mixed script)
                before = text[i - 1] if i > 0 else " "
                after = text[i + 1] if i < len(text) - 1 else " "
                if before.isascii() and before.isalpha() or after.isascii() and after.isalpha():
                    findings.append(ThreatFinding(
                        threat_type=ThreatType.HOMOGLYPH,
                        severity=ThreatSeverity.MEDIUM,
                        value=f"{char} (looks like {homoglyphs[char]})",
                        start=i,
                        end=i + 1,
                        description="Homoglyph character in mixed script context",
                        context=self._get_context(text, i, i + 1),
                    ))

    def scan(self, text: str, skip_cache: bool = False) -> SecurityScanResult:
        """
        Scan text for security threats.

        Args:
            text: Text to scan.
            skip_cache: If True, bypass cache and perform fresh scan.

        Returns:
            SecurityScanResult with all findings.
        """
        import time

        # Check cache first
        if self.use_cache and not skip_cache:
            cached = self._cache.get_pattern_result(text, self.strictness)
            if cached is not None:
                # Return cached result with updated timestamp
                return cached

        start_time = time.perf_counter()

        findings: List[ThreatFinding] = []
        seen_spans: set = set()

        # Pattern-based detection
        for layer, pattern_def in self.patterns:
            for match in pattern_def.pattern.finditer(text):
                start, end = match.start(), match.end()
                value = match.group()

                # Skip duplicates at same position
                span_key = (start, end)
                if span_key in seen_spans:
                    continue
                seen_spans.add(span_key)

                severity = THREAT_SEVERITY_MAP.get(
                    pattern_def.threat_type,
                    ThreatSeverity.MEDIUM
                )

                findings.append(ThreatFinding(
                    threat_type=pattern_def.threat_type,
                    severity=severity,
                    value=value,
                    start=start,
                    end=end,
                    description=pattern_def.description,
                    context=self._get_context(text, start, end),
                ))

        # Special checks
        self._check_base64_payload(text, findings)
        if self.strictness in ("medium", "high"):
            self._check_invisible_chars(text, findings)
        if self.strictness == "high":
            self._check_homoglyphs(text, findings)

        # Sort by position
        findings.sort(key=lambda f: f.start)

        # Determine if we should block
        blocked = False
        block_reason = None
        critical_found = any(f.severity == ThreatSeverity.CRITICAL for f in findings)
        high_found = any(f.severity == ThreatSeverity.HIGH for f in findings)

        if critical_found and self.block_on_critical:
            blocked = True
            block_reason = "Critical security threat detected"
        elif high_found and self.block_on_high:
            blocked = True
            block_reason = "High-severity security threat detected"

        # Sanitize if requested and not blocked
        sanitized_text = None
        sanitization_applied = False
        if self.auto_sanitize and findings and not blocked:
            sanitized_text = self._sanitize(text, findings)
            sanitization_applied = sanitized_text != text

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        result = SecurityScanResult(
            text=text,
            findings=findings,
            scan_time_ms=elapsed_ms,
            blocked=blocked,
            block_reason=block_reason,
            sanitized_text=sanitized_text,
            sanitization_applied=sanitization_applied,
        )

        # Store in cache
        if self.use_cache and not skip_cache:
            self._cache.set_pattern_result(text, self.strictness, result)

        return result

    def _sanitize(self, text: str, findings: List[ThreatFinding]) -> str:
        """
        Sanitize text by neutralizing detected threats.

        Strategies:
        - escape: Wrap in backticks to make it visible but inert
        - strip: Remove entirely
        - replace: Replace with placeholder
        """
        if not findings:
            return text

        # Sort by position descending to preserve offsets
        sorted_findings = sorted(findings, key=lambda f: f.start, reverse=True)

        result = text
        for finding in sorted_findings:
            start, end = finding.start, finding.end
            original = result[start:end]

            # Determine neutralization strategy
            neutralization = "escape"
            for _, pattern_def in self.patterns:
                if pattern_def.threat_type == finding.threat_type:
                    neutralization = pattern_def.neutralization
                    break

            if neutralization == "strip":
                replacement = "[REMOVED]"
            elif neutralization == "replace":
                replacement = "[SANITIZED]"
            else:  # escape
                # Escape by adding visible markers
                replacement = f"[ESCAPED: {original[:50]}...]" if len(original) > 50 else f"[ESCAPED: {original}]"

            result = result[:start] + replacement + result[end:]
            finding.neutralized_value = replacement

        return result


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def scan_document_security(
    text: str,
    strictness: str = "medium",
    auto_sanitize: bool = True,
) -> SecurityScanResult:
    """
    Convenience function to scan text for security threats.

    Args:
        text: Text to scan.
        strictness: Detection strictness (low, medium, high).
        auto_sanitize: Automatically sanitize detected threats.

    Returns:
        SecurityScanResult with all findings.
    """
    scanner = SecurityScanner(
        strictness=strictness,
        auto_sanitize=auto_sanitize,
    )
    return scanner.scan(text)


# =============================================================================
# LLM-ENHANCED SCANNING (LOCAL ONLY)
# =============================================================================

def scan_with_local_llm(
    text: str,
    strictness: str = "medium",
    use_llm_enhancement: bool = True,
    llm_timeout: float = 30.0,
    use_cache: bool = True,
) -> SecurityScanResult:
    """
    Enhanced security scanning using local LLM for context-aware detection.

    This combines pattern-based scanning with local LLM analysis:
    - Pattern matching catches obvious injection/jailbreak attempts
    - Local LLM catches context-dependent threats, novel attacks

    100% privacy-safe: All processing stays on-device via supported local runtimes.
    Results are cached to avoid redundant LLM calls.

    Args:
        text: Text to scan.
        strictness: Detection strictness (low, medium, high).
        use_llm_enhancement: Whether to use local LLM for enhanced detection.
        llm_timeout: Timeout for LLM call in seconds.
        use_cache: Whether to use cached results.

    Returns:
        SecurityScanResult with combined findings.
    """
    import time

    cache = _global_cache

    # Check LLM cache first (includes pattern results)
    if use_cache and use_llm_enhancement:
        cached = cache.get_llm_result(text, strictness)
        if cached is not None:
            return cached

    start = time.perf_counter()

    # First, do pattern-based scan (uses its own cache)
    scanner = SecurityScanner(strictness=strictness, use_cache=use_cache)
    result = scanner.scan(text)

    if not use_llm_enhancement:
        return result

    # Try local-model enhancement (only if a local runtime is available)
    try:
        from brain.services.local_model_runtime import (
            analyze_security_threats_with_local_model,
            is_local_model_available,
        )

        if not is_local_model_available():
            return result
        analysis = analyze_security_threats_with_local_model(
            text,
            timeout=llm_timeout,
        )
        if analysis.get("error") or not analysis.get("threats_found", False):
            return result

        # Add LLM-detected findings
        for finding in analysis.get("findings", []):
            threat_type_map = {
                "prompt_injection": ThreatType.PROMPT_INJECTION,
                "jailbreak": ThreatType.JAILBREAK,
                "hidden_instruction": ThreatType.PROMPT_INJECTION,
                "social_engineering": ThreatType.PERSONA_SWITCH,
            }
            severity_map = {
                "critical": ThreatSeverity.CRITICAL,
                "high": ThreatSeverity.HIGH,
                "medium": ThreatSeverity.MEDIUM,
                "low": ThreatSeverity.LOW,
            }

            threat_type = threat_type_map.get(
                finding.get("type", ""),
                ThreatType.PROMPT_INJECTION
            )
            severity = severity_map.get(
                finding.get("severity", "medium"),
                ThreatSeverity.MEDIUM
            )

            # Find position of excerpt in text
            excerpt = finding.get("excerpt", "")[:100]
            pos = text.find(excerpt) if excerpt else -1

            new_finding = ThreatFinding(
                threat_type=threat_type,
                severity=severity,
                value=excerpt if excerpt else "[LLM detected]",
                start=pos if pos >= 0 else 0,
                end=pos + len(excerpt) if pos >= 0 else 10,
                description=f"LLM: {finding.get('description', 'Suspicious content detected')}",
                context=excerpt,
            )

            # Avoid duplicates
            is_duplicate = any(
                abs(f.start - new_finding.start) < 20
                for f in result.findings
            )
            if not is_duplicate:
                result.findings.append(new_finding)

    except ImportError:
        logger.debug("LLM gateway unavailable for security scan enhancement")
    except Exception as exc:
        logger.debug("LLM security scan enhancement skipped: %s", exc)

    result.scan_time_ms = (time.perf_counter() - start) * 1000

    # Cache the combined result
    if use_cache and use_llm_enhancement:
        cache.set_llm_result(text, strictness, result)

    return result
