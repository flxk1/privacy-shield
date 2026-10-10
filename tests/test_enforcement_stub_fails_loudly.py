"""The interface-only enforcement stub must fail loudly when attached (D9).

``ExternalEnforcementAdapter``'s docstring says an accidental attach "fails
loudly rather than silently pretending to govern": its methods raise
``NotImplementedError``. Before the fix, ``PrivacyGate.check`` and
``plan_action`` caught ``Exception`` around every sink call, which includes
``NotImplementedError``, and logged it at debug level — so attaching the
stub was silent, not loud, exactly contrary to the docstring.
"""

from __future__ import annotations

import pytest

from privacy_shield.enforcement import ExternalEnforcementAdapter
from privacy_shield.gate import PrivacyGate


def test_plan_action_raises_when_stub_is_attached():
    gate = PrivacyGate(enforcement_sink=ExternalEnforcementAdapter())

    with pytest.raises(NotImplementedError):
        gate.plan_action({"text": "hello"}, enforce=False)


def test_check_raises_when_stub_is_attached():
    gate = PrivacyGate(enforcement_sink=ExternalEnforcementAdapter())

    with pytest.raises(NotImplementedError):
        gate.check({"text": "hello"}, "openai")
