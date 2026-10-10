"""The Art. 9 rule must be able to decide a verdict (D8).

Before the fix, Rule 2 (classification blocks external destinations) ran
before Rule 3 (Art. 9 special categories), and every Art. 9 hit already
classified the text as at least ``confidential`` (P-6(a)) — so Rule 2 always
returned first and the Art. 9 reason ("tenant policy enforces LOCAL_ONLY")
was never produced through ``PrivacyGate.check``/``_decide_local``. The block
itself was never lost, only its reason.

The later rewrite (see ``_classify``, ``_why`` and ``test_art9_release.py``)
resolved this differently: Rule 3 and the separate per-tenant stub are gone.
Art. 9 is now tied to a person and folded into the ``confidential``
classification itself (``_classify`` returns ``"art9"``/``"art9+secret"``
as the *reason*, not a new tier), and Rule 2's own message calls ``_why()``
to spell out the Art. 9 categories, e.g. "Data classified as 'confidential'
(Art. 9 special categories about a person: health; a recorded release can
lift this) cannot be sent to external destination '...'". The event raised
is ``classification_external_blocked`` (see
``test_art9_release.py::test_a_refused_release_is_still_logged_and_reported``),
not a separate LOCAL_ONLY path, and ``redacted_fields`` is not populated by
this decision at all — it stays the dataclass default ``[]`` for every
Rule 1 / Rule 2 block alike. ``mode`` reflects the tenant's actual privacy
mode (``"standard"`` by default); it is not forced to ``"local_only"`` by
an Art. 9 hit.

That is: the rewrite already carries the original intent — an Art. 9 hit
surfaces its own, specific reason rather than only the generic classification
tier — just through ``_why()`` embedded in Rule 2's message rather than a
dedicated Art. 9 branch. These tests pin that documented behaviour.
"""

from __future__ import annotations

from privacy_shield.gate import PrivacyGate

ART9_TEXT = "patient diagnosis: diabetes; medication prescribed by the doctor"


def test_art9_hit_is_blocked_with_the_art9_reason_not_only_classification():
    gate = PrivacyGate()
    result = gate._decide_local({"text": ART9_TEXT}, "openai")

    assert result.allowed is False
    # The classification alone (confidential) is not all that's surfaced;
    # _why() names the Art. 9 categories in the blocked reason.
    assert "Art. 9" in result.blocked_reason
    assert "health" in result.blocked_reason
    assert result.classification == "confidential"
    # redacted_fields is not populated by this decision (documented default).
    assert result.redacted_fields == []
    # mode reflects the actual (default) privacy mode, not a forced LOCAL_ONLY.
    assert result.mode == "standard"


def test_art9_reason_survives_through_check():
    gate = PrivacyGate()
    result = gate.check({"text": ART9_TEXT}, "openai")

    assert result.allowed is False
    assert "Art. 9" in result.blocked_reason
    assert "health" in result.blocked_reason
    assert result.redacted_fields == []
