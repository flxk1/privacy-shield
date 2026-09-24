"""Which language's rules a document is offered to.

THE DECISION, STATED: language is DECLARED BY THE CALLER when the caller knows
it, DETECTED when it does not, and when detection is not sure the document is
offered to EVERY registered ruleset at once. Detection is therefore a routing
hint and a reporting device, never a correctness condition - which is the
point. A layer whose precision depends on getting the language right fails
silently on the case EU correspondence produces constantly: a German letter
with an English closing formula, an English covering note over a French
contract, a Dutch invoice with a German address block.

Applying every ruleset in parallel is only safe because of the split in
shared.py: evidence is per-language and additive, exclusions are the union.
The cost of running English rules over German documents and German rules over
English documents is not argued here, it is measured -
tests/test_name_layer_cross_language.py runs each corpus through the other
language's rules and the numbers are in `docs/limits.md`.

There is no language-identification model here and no vocabulary: the score is
how many of a ruleset's OWN closed-class markers appear in the text. That is
weak, and it is allowed to be weak, because being wrong costs a wider union
rather than a missed name.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Union

from . import registry

_TOKEN = re.compile(r"[^\W\d_]+", re.UNICODE)


def marker_scores(text: str) -> Dict[str, int]:
    """Marker-token hits per registered language."""
    tokens = [token.group().lower() for token in _TOKEN.finditer(text)]
    scores: Dict[str, int] = {}
    for code, ruleset in registry.rulesets().items():
        scores[code] = sum(1 for token in tokens if token in ruleset.markers)
    return scores


def detect(text: str) -> List[str]:
    """Registered languages whose markers appear, most first.

    Empty means "no marker from any language" - the caller decides, and
    `resolve` turns that into the full union rather than into nothing.
    """
    scores = marker_scores(text)
    ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    return [code for code, hits in ranked if hits > 0]


def resolve(
    text: str,
    declared: Optional[Union[str, Iterable[str]]] = None,
) -> List[str]:
    """The rulesets to apply, in claim order.

    * A declared language wins, and only registered ones are kept. A
      declaration is a promise the caller makes and the layer keeps it
      exactly - including a language that is NOT German, which is why this
      branch does not also add German: `find_names(text, "en")` isolates
      English on purpose, for the cross-language measurement in
      tests/test_name_layer_cross_language.py.
    * A declared language with no ruleset in this package falls back to the
      full union as a best effort. It is NOT silently treated as "no names":
      an unsupported language must not look like a clean document. Its status
      is `unmeasured` in `docs/limits.md` and it stays unmeasured until
      somebody builds a corpus for it.
    * Otherwise detection decides, and an undecided document gets everything.
      German is always in that result when it is registered: it is the only
      language with independent measurements, and detection is a routing hint
      that may only ADD a language, never remove the one the docs promise is
      always on. Before this, a document scoring even one English marker and
      zero German ones dropped German's GIVEN rule entirely - "Kind
      regards\\nJan Mueller" is closed with an English marker and carries a
      German name, and detection may not cost it.
    """
    registered = registry.languages()
    if declared:
        wanted = [declared] if isinstance(declared, str) else list(declared)
        normalised = [str(code).strip().lower().replace("_", "-").split("-")[0] for code in wanted]
        known = [code for code in normalised if code in registered]
        if known:
            return known
        return registered
    detected = detect(text)
    if not detected:
        return registered
    if "de" in registered and "de" not in detected:
        detected = detected + ["de"]
    return detected
