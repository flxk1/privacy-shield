"""Credential detection with the gitleaks rule set.

The rules, their keywords, entropy floors and allowlists are gitleaks' own
(see _gitleaks_rules.py for the pinned commit); this module applies them the
way gitleaks does, to free text instead of a git history.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import List, Tuple

from ._gitleaks_rules import GLOBAL_ALLOW, RULES

# Local additions, held to gitleaks' generic-rule semantics (entropy floor 3.5,
# a digit required, global allowlist): German credential labels, credentials
# inside a URL, and bearer tokens, none of which the upstream generic rule keys on.
_LOCAL_RULES = [
    {"id": "generic-german-credential", "group": 1, "entropy": 3.5,
     "keywords": ["passwort", "zugangsdaten", "geheimschlüssel", "schlüssel"],
     "regex": r"(?i)\b(?:passwort|zugangsdaten|geheimschlüssel|api-schlüssel)\b[ \t]*[:=][ \t]*[\"']?([^\s\"']{8,})",
     "allow": []},
    {"id": "generic-url-credential", "group": 1, "entropy": 3.0,
     "keywords": ["://"],
     "regex": r"\b[a-z][a-z0-9+.\-]*://[^\s/:@]*:([^\s/@]{6,})@[^\s/]+",
     "allow": []},
    {"id": "generic-bearer-token", "group": 1, "entropy": 3.5,
     "keywords": ["bearer"],
     "regex": r"(?i)\bbearer[ \t]+([A-Za-z0-9._~+/\-]{20,}=*)",
     "allow": []},
    {"id": "generic-password-printable", "group": 1, "entropy": 3.5,
     "keywords": ["password", "passwd", "secret"],
     "regex": r"(?i)\b\w*(?:password|passwd|secret_key|client_secret)\b[\"']?[ \t]*[:=][ \t]*[\"']?([^\s\"';,]{8,})",
     "allow": []},
    {"id": "basic-auth-header", "group": 1, "entropy": 3.0,
     "keywords": ["basic"],
     "regex": r"(?i)\bbasic[ \t]+([A-Za-z0-9+/]{12,}={0,2})",
     "allow": []},
]

_HYPHEN_WORDS = re.compile(r"[A-Za-zÄÖÜäöüß]{3,}")


def _is_word_chain(secret: str) -> bool:
    """A value of hyphen-joined words ("KA-Vertrieb-Sued-2026") is a label, not a token."""
    parts = [p for p in re.split(r"[-_.]", secret) if p]
    words = [p for p in parts if _HYPHEN_WORDS.fullmatch(p) and any(c.islower() for c in p)]
    return len(parts) >= 3 and len(words) >= 2


def _is_basic_credential(secret: str) -> bool:
    import base64
    import binascii
    try:
        decoded = base64.b64decode(secret + "=" * (-len(secret) % 4), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False
    return ":" in decoded and decoded.isprintable()

_GLOBAL_REGEXES = [re.compile(x) for x in GLOBAL_ALLOW["regexes"]]
_GLOBAL_STOPWORDS = GLOBAL_ALLOW["stopwords"]
_COMPILED = [
    (
        rule,
        re.compile(rule["regex"]),
        [
            {**a, "compiled": [re.compile(x) for x in a["regexes"]]}
            for a in rule["allow"]
        ],
    )
    for rule in RULES + _LOCAL_RULES
]


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _secret_span(match: re.Match, group: int) -> Tuple[int, int]:
    if group and match.re.groups >= group and match.group(group):
        return match.span(group)
    for i in range(1, match.re.groups + 1):
        if match.group(i):
            return match.span(i)
    return match.span()


def _line(text: str, start: int, end: int) -> str:
    return text[text.rfind("\n", 0, start) + 1: (text.find("\n", end) + 1 or len(text) + 1) - 1]


def _allowed(allow: dict, secret: str, match: str, line: str) -> bool:
    target = {"match": match, "line": line}.get(allow["target"], secret)
    checks = []
    if allow["compiled"]:
        checks.append(any(r.search(target) for r in allow["compiled"]))
    if allow["stopwords"]:
        low = secret.lower()
        checks.append(any(w in low for w in allow["stopwords"]))
    if not checks:
        return False
    return all(checks) if allow["condition"] == "AND" else any(checks)


def find_credentials(text: str) -> List[Tuple[int, int, str, str]]:
    """Every credential in *text* as (start, end, value, rule_id)."""
    low = text.lower()
    out: List[Tuple[int, int, str, str]] = []
    for rule, regex, allows in _COMPILED:
        if rule["keywords"] and not any(k in low for k in rule["keywords"]):
            continue
        for match in regex.finditer(text):
            start, end = _secret_span(match, rule["group"])
            secret = text[start:end]
            if not secret.strip():
                continue
            if rule["entropy"] and shannon_entropy(secret) < rule["entropy"]:
                continue
            if rule["id"].startswith("generic") and not any(ch.isdigit() for ch in secret):
                continue
            if rule["id"].startswith("generic") and _is_word_chain(secret):
                continue
            if rule["id"] == "basic-auth-header" and not _is_basic_credential(secret):
                continue
            if any(r.search(secret) for r in _GLOBAL_REGEXES):
                continue
            if any(w in secret.lower() for w in _GLOBAL_STOPWORDS):
                continue
            line = _line(text, start, end)
            if any(_allowed(a, secret, match.group(0), line) for a in allows):
                continue
            if any(start < e and s < end for s, e, _v, _r in out):
                continue
            out.append((start, end, secret, rule["id"]))
    return out
