"""Precision budget: what every detector together claims on the name-free corpora.

Each corpus is pinned at its measured span count and character loss. A change
that claims more fails here and has to re-measure and re-state the trade
(docs/limits.md) before the pin moves; a change that claims less should lower
the pin. Some of these spans are not false (a company phone number in a
business letter), so the numbers are a ceiling, not a defect count.
"""

from __future__ import annotations

import pytest

from corpora_english import EN_CLEAN_ADVERSARIAL, EN_CLEAN_DEV, EN_CLEAN_HELD_OUT
from corpora_german import CLEAN_ADVERSARIAL, CLEAN_DEV, CLEAN_HELD_OUT
from privacy_shield.scanner import PIIType, PrivacyScanner

# corpus: (max spans, max character loss in percent)
BUDGET = {
    "de_dev": (CLEAN_DEV, 2, 1.06),
    "de_held_out": (CLEAN_HELD_OUT, 0, 0.0),
    "de_adversarial": (CLEAN_ADVERSARIAL, 5, 2.63),
    "en_dev": (EN_CLEAN_DEV, 4, 1.90),
    "en_held_out": (EN_CLEAN_HELD_OUT, 2, 1.44),
    "en_adversarial": (EN_CLEAN_ADVERSARIAL, 7, 2.56),
}


def _measure(docs):
    texts = [d if isinstance(d, str) else d[-1] for d in docs]
    findings = [f for t in texts for f in PrivacyScanner().scan(t).findings]
    loss = 100 * sum(f.end - f.start for f in findings) / sum(len(t) for t in texts)
    return findings, loss


@pytest.mark.parametrize("corpus", sorted(BUDGET))
def test_the_name_free_corpora_stay_within_the_precision_budget(corpus):
    docs, max_spans, max_loss = BUDGET[corpus]
    findings, loss = _measure(docs)
    claimed = sorted((f.pii_type.value, f.value) for f in findings)
    assert len(findings) <= max_spans, f"{corpus}: {len(findings)} spans, budget {max_spans}: {claimed}"
    assert loss <= max_loss + 0.005, f"{corpus}: {loss:.2f}% lost, budget {max_loss}%: {claimed}"


@pytest.mark.parametrize("corpus", ["de_dev", "de_held_out", "de_adversarial"])
def test_no_name_is_claimed_on_the_german_name_free_corpora(corpus):
    findings, _loss = _measure(BUDGET[corpus][0])
    assert [f.value for f in findings if f.pii_type is PIIType.NAME] == []


# PRECISION_DE holds the shapes the detectors misread: figures with units,
# greetings to groups, labels without a person, codes, policy pages. Its 8
# spans today are known (a due date taken for a birth date, an order number
# for a phone, keywords redacted as words); none of its texts may block.
PRECISION_BUDGET = (8, 2.90)


def test_business_look_alikes_stay_within_the_precision_budget():
    from corpora_precision import PRECISION_DE
    findings, loss = _measure(PRECISION_DE)
    claimed = sorted((f.pii_type.value, f.value) for f in findings)
    assert len(findings) <= PRECISION_BUDGET[0], f"{len(findings)} spans, budget {PRECISION_BUDGET[0]}: {claimed}"
    assert loss <= PRECISION_BUDGET[1] + 0.005, f"{loss:.2f}% lost, budget {PRECISION_BUDGET[1]}%: {claimed}"


def test_no_business_look_alike_blocks():
    from corpora_precision import PRECISION_DE
    from privacy_shield.gate import PrivacyGate
    blocked = [t for t in PRECISION_DE if not PrivacyGate()._decide_local({"text": t}, "external_llm").allowed]
    assert blocked == []


# ---------------------------------------------------------------------------
# Accuracy: the counterpart. Every value in tests/corpora_accuracy.py leaves
# the overlay, and every text with special-category or card data about a
# person is blocked. A change that loses one fails here.
# ---------------------------------------------------------------------------


def test_every_listed_value_leaves_the_overlay():
    from corpora_accuracy import ACCURACY_DE
    from privacy_shield.runner import scan
    missed = [(cls, value, text) for cls, text, value in ACCURACY_DE
              if value in scan(text).documents[0].overlay]
    assert missed == [], missed


def test_every_must_block_text_is_blocked():
    from corpora_accuracy import ART9_MUST_BLOCK
    from privacy_shield.gate import PrivacyGate
    allowed = [t for t in ART9_MUST_BLOCK if PrivacyGate()._decide_local({"text": t}, "external_llm").allowed]
    assert allowed == []
