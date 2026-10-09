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
from typing import Iterable, List, Optional, Tuple

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
herr herrn herren frau damen dr prof geschäftsführer geschäftsführerin geschäftsführung
mandant mandantin mandanten kunde kundin kunden arzt ärztin patient patientin
mitarbeiter mitarbeiterin mitarbeitende ansprechpartner ansprechpartnerin
vorstand vorsitzende vorsitzender rechtsanwalt rechtsanwältin anwalt anwältin
steuerberater steuerberaterin sachbearbeiter sachbearbeiterin leiter leiterin
inhaber inhaberin vermieter vermieterin mieter mieterin käufer käuferin
verkäufer verkäuferin auftraggeber auftraggeberin auftragnehmer
auftragnehmerin gesellschafter gesellschafterin prokurist prokuristin
empfänger empfängerin absender absenderin team kollege kollegin kollegen
notar präsident richter kläger klägerin beklagte beklagter zeuge
zeugin gläubiger schuldner erblasser erbe erbin bürge insolvenzverwalter
gerichtsvollzieher staatsanwalt verteidiger sachverständige sachverständiger
betreuer vormund bevollmächtigte bevollmächtigter antragsteller
antragsgegner berufungskläger revisionskläger nebenkläger angeklagte
angeklagter betroffene betroffener beteiligte beteiligter verwalter
treuhänder schiedsrichter gutachter dolmetscher pfleger direktor professor
doktor minister bürgermeister
""".split())
_WORD = re.compile(r"[^\W\d_]+", re.UNICODE)
_HONORIFIC = re.compile(r"(?:\b(?:Herrn?|Frau|Dr|Prof|Mr|Mrs|Ms)\.?\s+)$")
_LAST_WORD = re.compile(r"([^\W\d_]+)\.?\s+$")

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


def _is_role(word: str) -> bool:
    w = word.lower()
    if w in _ROLE_NOUNS:
        return True
    # feminine and plural forms of a listed role: Klägerin(nen), Zeugin (Zeuge)
    for suffix in ("innen", "in"):
        if w.endswith(suffix):
            stem = w[: -len(suffix)]
            return stem in _ROLE_NOUNS or stem + "e" in _ROLE_NOUNS
    return False


_RANK_SUFFIXES = ("meister", "kommissar", "inspektor", "sekretär", "direktor", "präsident",
                  "rat", "rätin", "leiter", "leiterin", "beamter", "beamtin", "offizier", "hauptmann")


def _is_rank(word: str) -> bool:
    w = word.lower()
    return _is_role(word) or any(w.endswith(x) and len(w) > len(x) + 2 for x in _RANK_SUFFIXES)


def _is_role_noun(value: str) -> bool:
    words = _WORD.findall(value)
    return not words or all(_is_role(w) for w in words)


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


def find(text: str, known_names: Iterable[Tuple[int, int]] = ()) -> List[Span]:
    """Every model span in *text* as (start, end, value, kind, score); [] when off.

    *known_names* are (start, end) of names other layers found; their surnames
    seed the same-text coreference below.
    """
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
    return _corefer(text, _confirm_single_words(text, out), known_names)


def _name_words(value: str) -> List[str]:
    return [w for w in _WORD.findall(value) if not _is_role(w) and len(w) >= 3 and w[0].isupper()]


def _confirm_single_words(text: str, spans: List[Span]) -> List[Span]:
    # one capitalised word is as often a legal role (Erblasser, Gläubiger, Notar)
    # as a surname: keep it after an honorific or a role ("Zeugin Brandhorst"),
    # or when a longer name in the same text carries it ("Jonas Albrecht" ... "Albrecht")
    known = {
        w.lower()
        for _s, _e, v, k, _c in spans if k == NAME and len(_WORD.findall(v)) > 1
        for w in _name_words(v)
    }
    kept = []
    for span in spans:
        start, _end, value, kind, _score = span
        words = _WORD.findall(value)
        if kind == NAME and len(words) == 1:
            before = text[max(0, start - 40):start]
            last = _LAST_WORD.search(before)
            confirmed = (words[0].lower() in known or _HONORIFIC.search(before)
                         or (last and _is_role(last.group(1)) and not _is_rank(words[0])))
            if not confirmed:
                continue
        kept.append(span)
    return kept


_HEAD_NOUNS = frozenset("""
institut stiftung universität hochschule allee straße strasse platz weg ring
gasse gesellschaft gmbh ag kg schule gymnasium klinik klinikum krankenhaus
haus preis zentrum verlag museum halle werk werke team bank kasse verein
verband kirche brücke park bahnhof
""".split())
_HEAD_AFTER = re.compile(r"[\s-]*([^\W\d_]+)")
_DETERMINER = re.compile(
    r"(?i)\b(?:der|die|das|den|dem|des|ein|eine|einen|einem|einer|eines|im|am|beim|zum|zur|vom|ins|ans)\s+$")
_HONORIFIC_WORDS = frozenset({"herr", "herrn", "frau", "dr", "prof", "mr", "mrs", "ms"})


def _seed(text: str, start: int, end: int) -> Optional[str]:
    # only the surname position seeds, and never a name that is the front of an
    # institution ("Robert Koch-Institut", "Hans Böckler Stiftung")
    words = _WORD.findall(text[start:end])
    if not words:
        return None
    last = words[-1]
    if len(last) < 3 or not last[0].isupper() or last.lower() in _HEAD_NOUNS:
        return None
    head = _HEAD_AFTER.match(text, end)
    if head and head.group(1).lower() in _HEAD_NOUNS:
        return None
    if _is_role(last):
        # "Frau Richter": a role-list word an honorific confirms is a surname
        before = [w.lower() for w in words[:-1]] or [
            w.lower() for w in _WORD.findall(text[max(0, start - 12):start])[-1:]]
        if not before or before[-1] not in _HONORIFIC_WORDS:
            return None
    return last


def _corefer(text: str, spans: List[Span], known_names: Iterable[Tuple[int, int]]) -> List[Span]:
    # a name confirmed once ("Herr Wendehals") is redacted at every later bare
    # mention ("hat Wendehals die Frist versäumt"), found by the model or not;
    # never after an article, where the word is a noun ("der Wolf", "eine Rose")
    seeds = [_seed(text, s, e) for s, e, _v, k, _c in spans if k == NAME]
    seeds += [_seed(text, s, e) for s, e in known_names]
    words = {w for w in seeds if w}
    if not words:
        return spans
    taken = [(s, e) for s, e, _v, _k, _c in spans]
    extra: List[Span] = []
    for word in sorted(words):
        for m in re.finditer(r"(?<![^\W\d_-])" + re.escape(word) + r"(?![^\W\d_-])", text):
            if any(m.start() < e and s < m.end() for s, e in taken):
                continue
            if _DETERMINER.search(text[max(0, m.start() - 8):m.start()]):
                continue
            taken.append((m.start(), m.end()))
            extra.append((m.start(), m.end(), word, NAME, _THRESHOLD[NAME]))
    return sorted(spans + extra, key=lambda s: (s[0], -s[4]))
