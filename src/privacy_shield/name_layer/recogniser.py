"""The seam a statistical recogniser plugs into, with no model in it.

WHY THERE IS NO MODEL HERE. A multilingual NER model was the obvious way to
carry the twenty-four official languages, and the licence and size evaluation
in `docs/limits.md` is what stopped it: the multilingual NER weights that
exist are either non-commercial (`Babelscape/wikineural-multilingual-ner` is
CC-BY-NC-SA-4.0, `urchade/gliner_multi` is CC-BY-NC-4.0 and its own card says
"research purpose", `flair/ner-english-large` carries a licence literally
named `flukes-nc-1.0`), or carry no licence statement at all
(`flair/ner-multi`, the `onnx-community` GLiNER exports), or are 180 MB to
1.9 GB - an order of magnitude past what a wheel can carry. The one family
that clears the declared-licence gate (GLiNER v2.1, Apache-2.0 code, weights
and training set) still needs 1.16 GB of weights and its own span-decoding
logic.

So the package ships the SEAM and not the model. A deployment that has cleared
a model licence for itself registers it here; nothing is downloaded, nothing
is imported from a path in an environment variable, and no model is a
dependency of this package. Absent a registration this module does nothing at
all and the rule floor is the whole layer, which is the documented degradation
and not a surprise.

A registered recogniser is held to the SAME exclusion union as the rules. A
model that returns PERSON for `Accounts Payable` is wrong in exactly the way
the rules are stopped from being wrong, and a statistical claim is not
privileged over a measured one.
"""

from __future__ import annotations

from typing import Callable, Dict, Iterable, List, Tuple

from . import registry
from .shared import Span

#: (text, language) -> spans. Offsets are into the text it was given.
Recogniser = Callable[[str, str], Iterable[Tuple[int, int, str]]]

_RECOGNISERS: Dict[str, List[Recogniser]] = {}


def register_recogniser(language: str, recogniser: Recogniser) -> None:
    """Add a recogniser for one language. In-process registration only."""
    _RECOGNISERS.setdefault(language.strip().lower(), []).append(recogniser)


def clear_recognisers(language: str = None) -> None:
    if language is None:
        _RECOGNISERS.clear()
    else:
        _RECOGNISERS.pop(language.strip().lower(), None)


def recognisers(language: str) -> List[Recogniser]:
    return list(_RECOGNISERS.get(language.strip().lower(), ()))


def registered_languages() -> List[str]:
    return sorted(code for code, entries in _RECOGNISERS.items() if entries)


def recognise(text: str, language: str) -> List[Span]:
    """What the registered recognisers claim, after the exclusion union.

    A recogniser that raises is dropped for this document rather than taking
    the scan down with it: the rule floor is still a correct answer, an
    exception is not.
    """
    spans: List[Span] = []
    exclusions = registry.exclusions()
    for recogniser in recognisers(language):
        try:
            claims = list(recogniser(text, language))
        except Exception:
            continue
        for start, end, value in claims:
            if not 0 <= start < end <= len(text):
                continue
            if exclusions.blocks(str(value).split()):
                continue
            spans.append((start, end, text[start:end]))
    return spans
