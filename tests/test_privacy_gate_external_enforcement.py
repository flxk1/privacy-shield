"""Egress guard supports an optional external enforcement sink, and
opt-in audit recording / breach escalation.

Proves the contract of the egress guard (``gate.py``):

(a) **standalone default** — the guard is fully functional with no sink,
    no ``audit_log``, no ``breach_detector`` configured: an unsafe egress
    still raises / blocks, a safe egress passes, and NOTHING is written to
    disk.
(b) **sink attached** — when a stub :class:`EnforcementSink` is attached, it
    receives the SAME decision, and the guard's own decision is unchanged;
    this alone still writes nothing to disk.
(c) **audit/breach configured** — ``audit_log=`` records the decision;
    ``breach_detector=`` receives block escalations; ``PRIVACY_SHIELD_AUDIT_LOG``
    is itself an opt-in to the standard path.

The stub stands in for any external enforcement plane.
"""

import json

import pytest

from privacy_shield.audit_log import AuditEvent
from privacy_shield.breach import BreachEvent
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


class _RecordingBreachDetector:
    """Stub breach detector standing in for privacy_shield.breach.breach_detector."""

    def __init__(self) -> None:
        self.events = []

    def detect_anomaly(self, event_type, details):
        self.events.append((event_type, details))
        return None


def _read_jsonl(path):
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ---------------------------------------------------------------------------
# (a) Standalone default — fully functional alone, writes nothing
# ---------------------------------------------------------------------------
def test_default_no_sink_is_inert() -> None:
    gate = PrivacyGate()
    assert gate.enforcement_enabled is False
    # With no sink attached, the optional gate() consult yields nothing.
    assert gate.plan_action({"op": "egress"}) is None


def test_default_unsafe_egress_blocks_and_writes_nothing(tmp_path) -> None:
    gate = PrivacyGate()
    result = gate.check(
        {"text": "This document is strictly vertraulich / confidential."},
        destination="external_llm",
    )
    assert isinstance(result, PrivacyGateResult)
    assert result.allowed is False
    assert result.classification in {"confidential", "berufsgeheimnis"}
    # No path was ever configured; nothing under tmp_path (or anywhere) is written.
    assert list(tmp_path.rglob("*")) == []


def test_default_safe_egress_passes_and_writes_nothing(tmp_path) -> None:
    gate = PrivacyGate()
    result = gate.check(
        {"text": "The weather is pleasant and the meeting went well."},
        destination="external_llm",
    )
    assert result.allowed is True
    assert list(tmp_path.rglob("*")) == []


def test_default_blocks_do_not_reach_a_breach_detector(monkeypatch) -> None:
    from privacy_shield import breach

    detector = _RecordingBreachDetector()
    monkeypatch.setattr(breach, "breach_detector", detector)
    gate = PrivacyGate()
    for _ in range(6):  # past the real escalation threshold
        gate.check({"text": "streng vertraulich"}, destination="external_llm")
    assert detector.events == []


def test_default_require_privacy_check_raises_without_sink(tmp_path) -> None:
    @require_privacy_check(destination="external_llm")
    def send(data, tenant_id="", user_id=""):
        return "sent"

    # Unsafe payload -> PermissionError with no sink.
    with pytest.raises(PermissionError):
        send(data={"text": "streng vertraulich board minutes"})
    # Safe payload -> passes through.
    assert send(data={"text": "hello there"}) == "sent"
    # The module singleton is unconfigured: neither call wrote anything.
    assert list(tmp_path.rglob("*")) == []


def test_noop_sink_matches_no_sink() -> None:
    gate = PrivacyGate(enforcement_sink=NoOpEnforcementSink())
    # A NoOp sink is treated as inert (indistinguishable from no sink).
    assert gate.enforcement_enabled is False
    assert gate.plan_action({"op": "egress"}) is None


# ---------------------------------------------------------------------------
# (b) Stub sink receives the decision, decision unchanged, still no disk write
# ---------------------------------------------------------------------------
def test_attached_sink_receives_decision_writes_nothing_without_audit_log(tmp_path) -> None:
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

    # A sink alone is not audit configuration.
    assert list(tmp_path.rglob("*")) == []


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


def test_faulty_sink_never_breaks_core_or_configured_audit(tmp_path) -> None:
    class _Boom:
        def record_decision(self, decision):
            raise RuntimeError("sink exploded")

        def gate(self, action, *, enforce=False):
            raise RuntimeError("gate exploded")

    audit_file = tmp_path / "audit.jsonl"
    gate = PrivacyGate(enforcement_sink=_Boom(), audit_log=audit_file)
    # A misbehaving sink must not change the egress decision.
    result = gate.check({"text": "confidential material"}, destination="external_llm")
    assert result.allowed is False
    # plan_action swallows the sink error and returns None.
    assert gate.plan_action({"op": "egress"}) is None
    # Configured audit still recorded despite the faulty sink.
    events = _read_jsonl(audit_file)
    assert len(events) == 1


# ---------------------------------------------------------------------------
# (c) Explicit opt-in: audit_log / breach_detector / env var
# ---------------------------------------------------------------------------
def test_audit_log_path_records_decisions(tmp_path) -> None:
    audit_file = tmp_path / "audit.jsonl"
    gate = PrivacyGate(audit_log=audit_file)
    gate.check({"text": "hello there"}, destination="external_llm")
    gate.check({"text": "streng vertraulich board minutes"}, destination="external_llm")

    events = _read_jsonl(audit_file)
    assert len(events) == 2
    assert all(e["event"] == AuditEvent.AI_PRIVACY_SHIELD_DECISION.value for e in events)
    assert events[0]["details"]["allowed"] is True
    assert events[1]["details"]["allowed"] is False


def test_injected_breach_detector_receives_escalations() -> None:
    detector = _RecordingBreachDetector()
    gate = PrivacyGate(breach_detector=detector)
    for _ in range(5):  # crosses BreachDetector's real escalation threshold
        gate.check({"text": "streng vertraulich"}, destination="external_llm")
    assert len(detector.events) == 5
    assert all(evt == "classification_external_blocked" for evt, _ in detector.events)


def test_real_breach_detector_escalates_when_injected(tmp_path, monkeypatch) -> None:
    from privacy_shield.breach import BreachDetector

    detector = BreachDetector()
    monkeypatch.setattr(detector, "_BREACH_LOG_DIR", tmp_path / "breach_log")
    reported = []
    monkeypatch.setattr(detector, "report_breach", lambda b: reported.append(b))

    gate = PrivacyGate(breach_detector=detector)
    for _ in range(5):
        gate.check({"text": "streng vertraulich"}, destination="external_llm")
    assert len(reported) == 1
    assert isinstance(reported[0], BreachEvent)


def test_env_var_is_itself_opt_in_to_the_standard_path(tmp_path, monkeypatch) -> None:
    audit_file = tmp_path / "env-audit.jsonl"
    monkeypatch.setenv("PRIVACY_SHIELD_AUDIT_LOG", str(audit_file))
    gate = PrivacyGate()  # no audit_log kwarg — env var alone is the opt-in
    gate.check({"text": "hello there"}, destination="external_llm")
    events = _read_jsonl(audit_file)
    assert len(events) == 1


def test_env_var_is_resolved_per_call_on_the_preexisting_singleton(tmp_path, monkeypatch) -> None:
    from privacy_shield.gate import privacy_gate

    # The module singleton was constructed at import time, long before this
    # test's env var exists. No configure_audit() call either.
    first = tmp_path / "first.jsonl"
    monkeypatch.setenv("PRIVACY_SHIELD_AUDIT_LOG", str(first))
    privacy_gate.check({"text": "hello there"}, destination="external_llm")
    assert len(_read_jsonl(first)) == 1

    # Point the env var somewhere else: the singleton follows, live, with no
    # reconfiguration call of any kind.
    second = tmp_path / "second.jsonl"
    monkeypatch.setenv("PRIVACY_SHIELD_AUDIT_LOG", str(second))
    privacy_gate.check({"text": "hello again"}, destination="external_llm")
    assert len(_read_jsonl(first)) == 1  # unchanged
    assert len(_read_jsonl(second)) == 1

    # Unset it entirely: back to writing nothing, still with no reconfigure.
    monkeypatch.delenv("PRIVACY_SHIELD_AUDIT_LOG")
    privacy_gate.check({"text": "hello a third time"}, destination="external_llm")
    assert len(_read_jsonl(first)) == 1
    assert len(_read_jsonl(second)) == 1


def test_configure_audit_turns_on_recording_for_an_existing_gate(tmp_path) -> None:
    audit_file = tmp_path / "audit.jsonl"
    gate = PrivacyGate()
    gate.check({"text": "hello there"}, destination="external_llm")
    assert not audit_file.exists()

    gate.configure_audit(audit_log=audit_file)
    gate.check({"text": "hello again"}, destination="external_llm")
    events = _read_jsonl(audit_file)
    assert len(events) == 1


def test_sink_and_audit_log_both_fire_when_both_configured(tmp_path) -> None:
    sink = _RecordingSink()
    audit_file = tmp_path / "audit.jsonl"
    gate = PrivacyGate(enforcement_sink=sink, audit_log=audit_file)

    result = gate.check(
        {"text": "attorney-client privileged strategy memo"},
        destination="external_llm",
        tenant_id="t1",
        user_id="u1",
    )
    assert result.allowed is False
    assert len(sink.decisions) == 1
    events = _read_jsonl(audit_file)
    assert len(events) == 1
    assert events[0]["event"] == AuditEvent.AI_PRIVACY_SHIELD_DECISION.value
