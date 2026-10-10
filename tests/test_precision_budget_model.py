"""The precision budget with the optional model on.

Runs only when PII_MODEL_UNDER_TEST names a model on disk (conftest clears
PRIVACY_SHIELD_*). Pinned at fastino/gliner2-privacy-filter-PII-multi revision
1cb4166; the model-off pins live in test_precision_budget.py.
"""

from __future__ import annotations

import os

import pytest

from corpora_english import EN_CLEAN_ADVERSARIAL, EN_CLEAN_DEV, EN_CLEAN_HELD_OUT
from corpora_german import CLEAN_ADVERSARIAL, CLEAN_DEV, CLEAN_HELD_OUT
from corpora_precision import PRECISION_DE
from privacy_shield import pii_model
from privacy_shield.scanner import Confidence, PrivacyScanner

_REAL = os.environ.get("PII_MODEL_UNDER_TEST", "")
pytestmark = pytest.mark.skipif(not _REAL, reason="PII_MODEL_UNDER_TEST not set")

# corpus: (max spans, max character loss in percent)
BUDGET = {
    "de_dev": (CLEAN_DEV, 2, 1.52),
    "de_held_out": (CLEAN_HELD_OUT, 0, 0.0),
    "de_adversarial": (CLEAN_ADVERSARIAL, 3, 1.69),
    "en_dev": (EN_CLEAN_DEV, 5, 3.56),
    "en_held_out": (EN_CLEAN_HELD_OUT, 5, 5.44),
    "en_adversarial": (EN_CLEAN_ADVERSARIAL, 13, 5.68),
    "look_alikes": (PRECISION_DE, 14, 4.33),
}


@pytest.fixture(autouse=True)
def _model(monkeypatch):
    monkeypatch.setenv(pii_model.ENV, _REAL)


@pytest.mark.parametrize("corpus", sorted(BUDGET))
def test_the_model_stays_within_its_precision_budget(corpus):
    docs, max_spans, max_loss = BUDGET[corpus]
    texts = [d if isinstance(d, str) else d[-1] for d in docs]
    scanner = PrivacyScanner(min_confidence=Confidence.MEDIUM)
    findings = [f for t in texts for f in scanner.scan(t).findings]
    loss = 100 * sum(f.end - f.start for f in findings) / sum(len(t) for t in texts)
    claimed = sorted((f.pii_type.value, f.value) for f in findings)
    assert len(findings) <= max_spans, f"{corpus}: {len(findings)} spans, budget {max_spans}: {claimed}"
    assert loss <= max_loss + 0.005, f"{corpus}: {loss:.2f}% lost, budget {max_loss}%: {claimed}"


def test_the_model_blocks_no_business_look_alike():
    from privacy_shield.gate import PrivacyGate
    blocked = [t for t in PRECISION_DE if not PrivacyGate()._decide_local({"text": t}, "external_llm").allowed]
    assert blocked == []
