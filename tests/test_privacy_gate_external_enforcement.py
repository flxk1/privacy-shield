"""Egress guard supports an optional external enforcement sink.

Proves the two-mode contract of the egress guard (``gate.py``):

(a) **standalone default** — the guard is fully functional with no enforcement
    sink attached: an unsafe egress still raises / blocks, a safe egress passes,
    and the decision is recorded to the standalone ``audit_log``.
(b) **sink attached** — when a stub :class:`EnforcementSink` is attached, it
    receives the SAME decision, and the guard's own decision is unchanged.

The stub stands in for any external enforcement plane.
"""

import json

import pytest

from privacy_shield.audit_log import AuditEvent
from privacy_shield.enforcement import (
    EnforcementDecision,
    EnforcementSink,
    EnforcementVerdict,
    NoOpEnforcementSink,
)
from privacy_shield.gate import (
    PrivacyGate,
    PrivacyGateResult,
    require_privacy_check,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class _RecordingSink:
    """Stub enforcement sink standing in for an external plane."""

    def __init__(self) -> None:
        self.decisions = []
        self.gated = []

    def record_decision(self, decision: EnforcementDecision) -> None:
        self.decisions.append(decision)

    def gate(self, action, *, enforce: bool = False):
        self.gated.append((dict(action), enforce))
        return EnforcementVerdict(
            verdict="permit", gate_verdict="GO", audit_id="stub-1", enforced=enforce
        )


@pytest.fixture()
def temp_audit(tmp_path, monkeypatch):
    """Redirect the standalone audit trail to a temp file (no tree pollution)."""
    audit_file = tmp_path / "audit.jsonl"
    monkeypatch.setattr("privacy_shield.audit_log.AUDIT_LOG_PATH", audit_file)

    def _read():
        if not audit_file.exists():
            return []
        return [
            json.loads(line)
            for line in audit_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    return _read


# ---------------------------------------------------------------------------
# (a) Standalone default — fully functional alone
# ---------------------------------------------------------------------------
def test_default_no_sink_is_inert() -> None:
    gate = PrivacyGate()
    assert gate.enforcement_enabled is False
    # With no sink attached, the optional gate() consult yields nothing.
    assert gate.plan_action({"op": "egress"}) is None


def test_default_unsafe_egress_blocks_without_sink(temp_audit) -> None:
    gate = PrivacyGate()
    result = gate.check(
        {"text": "This document is strictly vertraulich / confidential."},
        destination="external_llm",
    )
    assert isinstance(result, PrivacyGateResult)
    assert result.allowed is False
    assert result.classification in {"confidential", "berufsgeheimnis"}

    events = temp_audit()
    assert len(events) == 1
    assert events[0]["event"] == AuditEvent.AI_PRIVACY_SHIELD_DECISION.value
    assert events[0]["success"] is False
    assert events[0]["details"]["allowed"] is False
    assert events[0]["details"]["destination"] == "external_llm"


def test_default_safe_egress_passes_without_sink(temp_audit) -> None:
    gate = PrivacyGate()
    result = gate.check(
        {"text": "The weather is pleasant and the meeting went well."},
        destination="external_llm",
    )
    assert result.allowed is True

    events = temp_audit()
    assert len(events) == 1
    assert events[0]["success"] is True
    assert events[0]["details"]["allowed"] is True


def test_default_require_privacy_check_raises_without_sink() -> None:
    @require_privacy_check(destination="external_llm")
    def send(data, tenant_id="", user_id=""):
        return "sent"

    # Unsafe payload -> PermissionError with no sink.
    with pytest.raises(PermissionError):
        send(data={"text": "streng vertraulich board minutes"})
    # Safe payload -> passes through.
    assert send(data={"text": "hello there"}) == "sent"


def test_noop_sink_matches_no_sink() -> None:
    gate = PrivacyGate(enforcement_sink=NoOpEnforcementSink())
    # A NoOp sink is treated as inert (indistinguishable from no sink).
    assert gate.enforcement_enabled is False
    assert gate.plan_action({"op": "egress"}) is None


# ---------------------------------------------------------------------------
# (b) Stub sink receives the decision, decision unchanged
# ---------------------------------------------------------------------------
def test_attached_sink_receives_decision(temp_audit) -> None:
    sink = _RecordingSink()
    gate = PrivacyGate()
    gate.attach_enforcement_sink(sink)
    assert gate.enforcement_enabled is True

    result = gate.check(
        {"text": "attorney-client privileged strategy memo"},
        destination="external_llm",
        tenant_id="t1",
        user_id="u1",
    )

    # Core decision is unchanged by attaching the sink.
    assert result.allowed is False

    # The SAME decision reached the sink.
    assert len(sink.decisions) == 1
    surfaced = sink.decisions[0]
    assert isinstance(surfaced, EnforcementDecision)
    assert surfaced.allowed is False
    assert surfaced.destination == "external_llm"
    assert surfaced.classification == result.classification
    assert surfaced.tenant_id == "t1"
    assert surfaced.user_id == "u1"

    # Standalone audit trail still records in enriched mode.
    events = temp_audit()
    assert len(events) == 1
    assert events[0]["event"] == AuditEvent.AI_PRIVACY_SHIELD_DECISION.value


def test_attached_sink_gate_consulted_via_plan_action() -> None:
    sink = _RecordingSink()
    gate = PrivacyGate(enforcement_sink=sink)

    advisory = gate.plan_action({"op": "egress", "dest": "external_llm"})
    assert isinstance(advisory, EnforcementVerdict)
    assert advisory.verdict == "permit"
    assert advisory.enforced is False  # advisory preview, no chain write

    enforced = gate.plan_action({"op": "egress"}, enforce=True)
    assert enforced.enforced is True  # enforce path (would append to chain)
    assert sink.gated == [
        ({"op": "egress", "dest": "external_llm"}, False),
        ({"op": "egress"}, True),
    ]


def test_stub_type_satisfies_protocol() -> None:
    # Structural conformance: the stub is a valid EnforcementSink.
    assert isinstance(_RecordingSink(), EnforcementSink)
    assert isinstance(NoOpEnforcementSink(), EnforcementSink)


def test_faulty_sink_never_breaks_core(temp_audit) -> None:
    class _Boom:
        def record_decision(self, decision):
            raise RuntimeError("sink exploded")

        def gate(self, action, *, enforce=False):
            raise RuntimeError("gate exploded")

    gate = PrivacyGate(enforcement_sink=_Boom())
    # A misbehaving sink must not change the egress decision.
    result = gate.check({"text": "confidential material"}, destination="external_llm")
    assert result.allowed is False
    # plan_action swallows the sink error and returns None.
    assert gate.plan_action({"op": "egress"}) is None
    # Audit still recorded despite the faulty sink.
    assert len(temp_audit()) == 1
