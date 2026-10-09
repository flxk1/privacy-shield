"""Diagnosis terms from the BfArM ICD-10-GM alphabetical index, read from the user's own copy.

The index is an official work published by BfArM under its download
conditions: use is free with the source cited (§ 63 UrhG) and the work may not
be changed (§ 62 UrhG). So nothing from it ships in this package. The user
downloads it once from bfarm.de (Kodiersysteme > Downloads > ICD-10-GM >
"Alphabet EDV-Fassung TXT (CSV)"), and this module finds that file and reads it
unchanged, the ZIP included.

Found, in this order: the file or folder in ``PRIVACY_SHIELD_ICD10GM``; the
user-state folder ``<state>/privacy-shield/icd10gm/``; a BfArM ZIP in
``~/Downloads``. Absent, nothing here runs and no other layer changes.
"""

from __future__ import annotations

import os
import re
import threading
import zipfile
from pathlib import Path
from typing import Dict, FrozenSet, Iterator, List, Optional, Tuple

from .audit_log import _STATE_APP_DIR, _user_state_home

ENV = "PRIVACY_SHIELD_ICD10GM"
SOURCE = (
    "ICD-10-GM, Alphabetisches Verzeichnis, herausgegeben vom Bundesinstitut für "
    "Arzneimittel und Medizinprodukte (BfArM) im Auftrag des Bundesministeriums für Gesundheit"
)
DOWNLOAD_PAGE = "https://www.bfarm.de/DE/Kodiersysteme/Services/Downloads/_node.html"

_NAME = re.compile(r"icd10gm(\d{4})alpha_edvtxt_(\d{8})\.txt$", re.IGNORECASE)
_ZIP = re.compile(r"icd10gm(\d{4})alpha-txt\.zip$", re.IGNORECASE)

# chapters U (special purposes) and Z (contact with health services) name
# circumstances rather than conditions: "Opfer", "Verarmung", "Simulieren"
_CHAPTERS = frozenset("ABCDEFGHIJKLMNOPQRST")

# index entries that are also everyday German or a surname; a medical sense
# they carry is not worth the business text they would block
_EVERYDAY = frozenset("""
Abort Abriss Alter Altern Anfall Angst Anomalie Artefakt Blackout Blase
Blendung Brand Bride Buckel Conus Erregung Ergrauen Ermüdung Eruption Fatigue
Fever Figueira Fluor Flush Fraktur Furcht Gewächs Globus Gähnen Hunger Hungern
Koro Kollaps Konus Krebs Kuru Latah Lequesne Malaise Moria Panik Partus Pest
Poltern Raserei Rauchen Rose Rotz Schock Schwäche Seufzen Siti Sorge Spotting
Tattoo Taumel Tic Tick Tod Trance Unruhe Virago Wahn Wut Zorn Ganglion Trauma
Störung Reaktion Abhängigkeit Mangel Depression Infektion Blockade Krise
Erschöpfung Verletzung Lähmung Schaden Stress Sucht Wunde Narbe Tumor
Verstopfung Verbrennung Schwindel Ausschlag Krampf Lethargie Fieber Blindheit
Erfrierung Stenose Insuffizienz Embolie Fistel Infektion Kollaps Blutung
""".split())

_TOKEN = re.compile(r"[^\W\d_][\w-]*", re.UNICODE)

# diagnoses the index lists only inside longer entries ("Diabetes mellitus"),
# chosen by hand from its most frequent first words; general ones (Defekt,
# Schaden, Störung, Folgen, Befall) are left out
_HEADS = frozenset("""
Diabetes Typ-2-Diabetes Schwangerschaft Gravidität Fehlbildung Prolaps
Hyperplasie Hypertrophie Hypoplasie Fibrose Striktur Atresie Agenesie Zyste Morbus Melanoma Epidermolysis Ablatio
Mikrodeletionssyndrom Mikroduplikationssyndrom Fetusschädigung Hypersekretion
""".split())
# a single index word blocks only with a medical ending: the index holds
# Überlastung, Übergewicht, Hysterie, Atemnot and Grippe too, and each of
# them has a business sense an exclusion list will never finish naming
_MEDICAL_ENDINGS = (
    "itis", "ose", "osis", "om", "oma", "ämie", "pathie", "algie", "plegie",
    "karzinom", "sarkom", "infarkt", "sklerose", "syndrom", "krankheit",
)

# acronyms common in German correspondence that name nothing but a condition;
# the index has some 400, most of which are also business terms (IHK, SPS, CAD)
_ACRONYMS = frozenset("AIDS HIV ADHS COPD KHK PAVK FSME TBC PCOS".split())

_lock = threading.Lock()
_Lexicon = Tuple[FrozenSet[str], Dict[str, Tuple[Tuple[str, ...], ...]]]
_cache: Dict[str, _Lexicon] = {}


def _version(name: str) -> Tuple[int, int]:
    m = _NAME.search(name) or _ZIP.search(name)
    if not m:
        return (0, 0)
    return (int(m.group(1)), int(m.group(2)) if m.lastindex and m.lastindex > 1 else 0)


def _candidates() -> Iterator[Path]:
    override = os.environ.get(ENV, "").strip()
    if override:
        yield Path(override).expanduser()
        return
    yield _user_state_home() / _STATE_APP_DIR / "icd10gm"
    yield Path.home() / "Downloads"


def locate() -> Optional[Path]:
    """The newest alphabetical-index file or BfArM ZIP the search order finds, or None."""
    for place in _candidates():
        if place.is_file() and (_NAME.search(place.name) or _ZIP.search(place.name)):
            return place
        if not place.is_dir():
            continue
        found = [p for p in place.iterdir() if _NAME.search(p.name) or _ZIP.search(p.name)]
        if found:
            # an unpacked file beats its ZIP of the same year
            return max(found, key=lambda p: (_version(p.name)[0], p.suffix.lower() == ".txt", _version(p.name)[1]))
    return None


def _lines(path: Path) -> Iterator[str]:
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            member = max((n for n in archive.namelist() if _NAME.search(n)), key=_version, default=None)
            if member is None:
                raise RuntimeError(f"{path} holds no ICD-10-GM alphabet file")
            with archive.open(member) as handle:
                for raw in handle:
                    yield raw.decode("utf-8")
        return
    with path.open(encoding="utf-8") as handle:
        yield from handle


def _norm(token: str) -> str:
    # one German ending off, so "Multipler Sklerose" meets "Multiple Sklerose"
    low = token.lower()
    if len(low) > 5:
        for ending in ("en", "em", "er", "es", "e", "n", "s"):
            if low.endswith(ending):
                return low[: -len(ending)]
    return low


def _clean(text: str) -> str:
    text = re.sub(r"\[.*?\]|\(.*?\)", "", text)
    text = re.sub(r"\s+(?:a\.n\.k\.|o\.n\.A\.)", "", text)
    text = re.sub(r"\s+-\s+s\..*$", "", text)
    return " ".join(text.split()).strip(" ,;-")


def _load(path: Path) -> _Lexicon:
    words, phrases = set(), set()
    for line in _lines(path):
        fields = line.rstrip("\r\n").split("|")
        if len(fields) < 8 or fields[0] == "0" or not fields[3] or fields[3][0] not in _CHAPTERS:
            continue
        term = _clean(fields[7])
        parts = _TOKEN.findall(term)
        if not parts or term.isupper() or not term[0].isupper():
            continue
        if len(parts) == 1:
            if len(parts[0]) >= 4 and parts[0].lower().endswith(_MEDICAL_ENDINGS):
                words.add(parts[0])
        elif len(parts) <= 4:
            phrases.add(tuple(_norm(p) for p in parts))
    words = (words | _HEADS | _ACRONYMS) - _EVERYDAY
    by_first: Dict[str, List[Tuple[str, ...]]] = {}
    for phrase in phrases:
        by_first.setdefault(phrase[0], []).append(phrase)
    return frozenset(words), {k: tuple(sorted(v, key=len, reverse=True)) for k, v in by_first.items()}


def lexicon() -> Optional[_Lexicon]:
    """(single-word terms, multi-word terms lowercased by first word) from the located index; None when absent."""
    path = locate()
    if path is None:
        return None
    key = f"{path}:{path.stat().st_mtime_ns}"
    with _lock:
        if key not in _cache:
            _cache.clear()
            _cache[key] = _load(path)
        return _cache[key]


def status() -> Dict[str, object]:
    path = locate()
    if path is None:
        return {"found": False, "searched": [str(p) for p in _candidates()], "download": DOWNLOAD_PAGE}
    words, by_first = lexicon() or (frozenset(), {})
    return {"found": True, "path": str(path), "version": _version(path.name)[0],
            "single_terms": len(words), "phrases": sum(map(len, by_first.values())), "source": SOURCE}


def find_terms(text: str) -> List[Tuple[int, int, str]]:
    """Every index term in *text* as (start, end, term); [] when the index is absent."""
    lex = lexicon()
    if lex is None:
        return []
    words, by_first = lex
    tokens = [(m.start(), m.end(), m.group(0)) for m in _TOKEN.finditer(text)]
    out: List[Tuple[int, int, str]] = []
    i = 0
    while i < len(tokens):
        start, end, word = tokens[i]
        matched = False
        for phrase in by_first.get(_norm(word), ()):
            span = tokens[i:i + len(phrase)]
            if len(span) == len(phrase) and tuple(_norm(t[2]) for t in span) == phrase:
                out.append((start, span[-1][1], text[start:span[-1][1]]))
                i += len(phrase)
                matched = True
                break
        if matched:
            continue
        head = word.split("-")[0] if word.split("-")[0] in _ACRONYMS else word
        if word in words or head in _ACRONYMS:
            out.append((start, end, word))
        i += 1
    return out
