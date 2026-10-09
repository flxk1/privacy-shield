"""Names, street addresses and special-category mentions from a local GLiNER2 model.

Optional, off unless ``PRIVACY_SHIELD_PII_MODEL`` names a model (a local
directory or a Hugging Face id already in the local cache) and the ``model``
extra is installed. The model is never downloaded here: an id resolves from the
cache only, so a scan makes no network connection.

What it finds is redacted and never blocks. Nothing in gate.py reads these
findings, and SPECIAL_CATEGORY sits in no block set: the model names the wrong
category for about one span in fifteen, so its Art. 9 hits are one advisory
type rather than a verdict.
"""

from __future__ import annotations

import os
import re
import threading
from typing import List, Optional, Tuple

ENV = "PRIVACY_SHIELD_PII_MODEL"

NAME, ADDRESS, SPECIAL = "name", "address", "special_category"

_LABELS = {
    "person": NAME,
    "street address": ADDRESS,
    "health condition": SPECIAL,
    "religion": SPECIAL,
    "political opinion": SPECIAL,
    "trade union membership": SPECIAL,
    "sexual orientation": SPECIAL,
    "criminal record": SPECIAL,
    "ethnic origin": SPECIAL,
}
_THRESHOLD = {NAME: 0.7, ADDRESS: 0.7, SPECIAL: 0.9}
_CHUNK = 1500

# the measured clean-text false positives were all role nouns taken for a person
_ROLE_NOUNS = frozenset("""
herr herrn frau dr prof geschäftsführer geschäftsführerin geschäftsführung
mandant mandantin mandanten kunde kundin kunden arzt ärztin patient patientin
mitarbeiter mitarbeiterin mitarbeitende ansprechpartner ansprechpartnerin
vorstand vorsitzende vorsitzender rechtsanwalt rechtsanwältin anwalt anwältin
steuerberater steuerberaterin sachbearbeiter sachbearbeiterin leiter leiterin
inhaber inhaberin vermieter vermieterin mieter mieterin käufer käuferin
verkäufer verkäuferin auftraggeber auftraggeberin auftragnehmer
auftragnehmerin gesellschafter gesellschafterin prokurist prokuristin
empfänger empfängerin absender absenderin team kollege kollegin kollegen
""".split())
_WORD = re.compile(r"[^\W\d_]+", re.UNICODE)
_HONORIFIC = re.compile(r"(?:\b(?:Herrn?|Frau|Dr|Prof|Mr|Mrs|Ms)\.?\s+)$")

_lock = threading.Lock()
_model = None
_loaded_for: Optional[str] = None

Span = Tuple[int, int, str, str, float]


def configured() -> Optional[str]:
    return os.environ.get(ENV, "").strip() or None


def _resolve(spec: str) -> str:
    if os.path.isdir(spec):
        return spec
    from huggingface_hub import snapshot_download
    return snapshot_download(spec, local_files_only=True)


def _load(spec: str):
    # the snapshot resolves locally, but the encoder's tokenizer is fetched by id;
    # huggingface_hub reads these at import, so a host that imported it first decides
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    try:
        from gliner2 import GLiNER2
    except ImportError as exc:
        raise RuntimeError(
            f"{ENV} is set but gliner2 is not installed: pip install 'privacy-shield[model]'"
        ) from exc
    try:
        return GLiNER2.from_pretrained(_resolve(spec))
    except Exception as exc:
        raise RuntimeError(
            f"{ENV}={spec!r} did not load from local files; download it once yourself"
        ) from exc


def _get(spec: str):
    global _model, _loaded_for
    with _lock:
        if _model is None or _loaded_for != spec:
            _model = _load(spec)
            _loaded_for = spec
        return _model


def _is_role_noun(value: str) -> bool:
    words = _WORD.findall(value)
    return not words or all(w.lower() in _ROLE_NOUNS for w in words)


def _chunks(text: str):
    start = 0
    while start < len(text):
        end = min(len(text), start + _CHUNK)
        if end < len(text):
            cut = max(text.rfind("\n", start, end), text.rfind(". ", start, end))
            if cut > start + _CHUNK // 2:
                end = cut + 1
        yield start, text[start:end]
        start = end


def find(text: str) -> List[Span]:
    """Every model span in *text* as (start, end, value, kind, score); [] when off."""
    spec = configured()
    if not spec or not text.strip():
        return []
    model = _get(spec)
    out: List[Span] = []
    for offset, chunk in _chunks(text):
        result = model.extract_entities(
            chunk, list(_LABELS), threshold=min(_THRESHOLD.values()),
            include_confidence=True, include_spans=True,
        )
        for label, hits in (result.get("entities") or {}).items():
            kind = _LABELS.get(label)
            if kind is None:
                continue
            for hit in hits:
                score = float(hit.get("confidence", 0.0))
                if score < _THRESHOLD[kind]:
                    continue
                start, end = offset + int(hit["start"]), offset + int(hit["end"])
                value = text[start:end]
                if not value.strip() or (kind == NAME and _is_role_noun(value)):
                    continue
                out.append((start, end, value, kind, score))
    out.sort(key=lambda s: (s[0], -s[4]))
    return _confirm_single_words(text, out)


def _confirm_single_words(text: str, spans: List[Span]) -> List[Span]:
    # one capitalised word is as often a legal role (Erblasser, Gläubiger, Notar)
    # as a surname: keep it after an honorific or when a longer name in the same
    # text carries it ("Jonas Albrecht" ... "Albrecht")
    known = {
        w.lower()
        for _s, _e, v, k, _c in spans if k == NAME
        for w in _WORD.findall(v) if len(_WORD.findall(v)) > 1 and w.lower() not in _ROLE_NOUNS
    }
    kept = []
    for span in spans:
        start, _end, value, kind, _score = span
        words = _WORD.findall(value)
        if kind == NAME and len(words) == 1:
            if words[0].lower() not in known and not _HONORIFIC.search(text[max(0, start - 12):start]):
                continue
        kept.append(span)
    return kept
