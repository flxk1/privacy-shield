"""Optional enforcement / audit enrichment seam for the egress guard.

Privacy Shield is **RVND-optional**. The core egress guard (``gate.py``) makes
its decision LOCALLY — regex + lexicon floor, embeddings / local-LLM verdict,
classification tiers — and records to the standalone ``audit_log``. That path is
**fully functional with zero RVND present**.

This module defines the ONE optional seam through which an external
enforcement / audit plane (e.g. RVND) may be attached to *add* a governance
verdict and a signed-chain receipt on top of the local decision. It is
**interface-only**: no ``rvnd.*`` import lives here (or anywhere on the core
path). RVND is hands-off and optional; :class:`RvndEnforcementAdapter` below is
a named STUB that documents the intended bindings without importing or calling
RVND.

Contract
--------
- **Default (no adapter attached):** the guard uses :class:`NoOpEnforcementSink`.
  ``record_decision`` is a no-op and ``gate`` returns ``None`` — so the guard's
  own local decision stands unchanged. Behaves exactly as if this seam did not
  exist.
- **Enriched (adapter attached via the capability flag):** the SAME local
  decision is additionally surfaced to the sink through ``record_decision`` (an
  advisory / audit-enrichment call), and ``gate`` MAY return a verdict
  (``permit`` | ``hold`` | ``deny``) plus a signed-chain receipt. Enrichment is
  strictly additive: it never replaces the local decision that already blocked
  or allowed the egress.

Advisory vs enforce (design consequence inherited from the ctrl-desk spec)
--------------------------------------------------------------------------
RVND's ``governance.decide_action`` **APPENDS to the signed chain** — gating is
itself a mutating, governed act. So an adapter MUST distinguish:

- an **advisory preview** — a pure, chain-read gate (``rvnd.action_gate.gate``
  → GO / CONDITIONAL / NO-GO) that does not write the chain; and
- an **enforce** call — ``rvnd.governance.decide_action`` (permit/hold/deny),
  which writes the chain and yields an ``audit_id``.

The ``enforce`` flag on :meth:`EnforcementSink.gate` carries that distinction.
``record_decision`` is always advisory (audit enrichment only).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Mapping, Optional, Protocol, runtime_checkable

__all__ = [
    "EnforcementDecision",
    "EnforcementVerdict",
    "EnforcementSink",
    "NoOpEnforcementSink",
    "RvndEnforcementAdapter",
    "NOOP_SINK",
]


@dataclass(frozen=True)
class EnforcementDecision:
    """The local egress decision, surfaced to an optional enforcement sink.

    This is exactly what the guard already decided locally — the sink only
    observes it (``record_decision``) or is consulted about a prospective
    action (``gate``); it never authors the core decision.
    """

    allowed: bool
    destination: str
    mode: str
    classification: str
    blocked_reason: str = ""
    redacted_fields: List[str] = field(default_factory=list)
    tenant_id: str = ""
    user_id: str = ""


@dataclass(frozen=True)
class EnforcementVerdict:
    """Verdict an attached enforcement plane returns for a prospective action.

    ``verdict`` mirrors RVND's permit/hold/deny; ``gate_verdict`` mirrors the
    structural GO / CONDITIONAL / NO-GO. ``audit_id`` is populated only by an
    ``enforce`` call that wrote the signed chain (``None`` for an advisory
    preview).
    """

    verdict: str  # "permit" | "hold" | "deny"
    gate_verdict: str = ""  # "GO" | "CONDITIONAL" | "NO-GO"
    audit_id: Optional[str] = None
    reason: str = ""
    obligations: List[Any] = field(default_factory=list)
    enforced: bool = False  # True only when the signed chain was appended


@runtime_checkable
class EnforcementSink(Protocol):
    """Optional enforcement / audit enrichment plane.

    A sink is injected into :class:`~brain.privacy_shield.gate.PrivacyGate` via
    the capability flag. The default sink is :class:`NoOpEnforcementSink`; a
    real deployment MAY attach an adapter over RVND. All methods must tolerate
    being called on every egress decision and must never raise into the core
    path (the guard wraps calls defensively regardless).
    """

    def record_decision(self, decision: EnforcementDecision) -> None:
        """Observe a local egress decision (advisory / audit enrichment).

        Always advisory. An RVND-backed sink would append a signed-chain
        receipt for the decision here. A no-op sink does nothing.
        """
        ...

    def gate(
        self,
        action: Mapping[str, Any],
        *,
        enforce: bool = False,
    ) -> Optional[EnforcementVerdict]:
        """Consult the enforcement plane about a prospective *action*.

        Returns ``None`` when no plane is attached (caller proceeds on its own
        local decision). With ``enforce=False`` the sink SHOULD use a pure,
        chain-reading advisory gate; with ``enforce=True`` it MAY append to the
        signed chain and populate ``audit_id`` on the returned verdict.
        """


class NoOpEnforcementSink:
    """Default sink: fully inert. This is what "zero RVND present" means.

    ``record_decision`` does nothing; ``gate`` returns ``None`` so the guard's
    own local decision is authoritative. Attaching this sink is
    indistinguishable from attaching no sink at all.
    """

    def record_decision(self, decision: EnforcementDecision) -> None:  # noqa: D102
        return None

    def gate(
        self,
        action: Mapping[str, Any],
        *,
        enforce: bool = False,
    ) -> Optional[EnforcementVerdict]:  # noqa: D102
        return None


# A shared inert singleton — the guard falls back to this when nothing is attached.
NOOP_SINK = NoOpEnforcementSink()


class RvndEnforcementAdapter:
    """Interface-only STUB of an RVND-backed enforcement sink.

    Ships the *shape* of the seam without importing or calling RVND (RVND is
    hands-off and optional). A real adapter — built and owned elsewhere — would
    bind:

    - :meth:`record_decision` → append an advisory receipt for the egress
      decision to the workspace's signed chain (audit enrichment).
    - :meth:`gate` with ``enforce=False`` → ``rvnd.action_gate.gate(...)``
      (pure GO / CONDITIONAL / NO-GO preview, no chain write).
    - :meth:`gate` with ``enforce=True`` → ``rvnd.governance.decide_action(...)``
      which **APPENDS to the signed chain** and yields an ``audit_id``.

    It is a named stub, not a build: its methods raise :class:`NotImplementedError`
    so that an accidental attach fails loudly rather than silently pretending to
    govern. Do not implement RVND here — attach a real adapter from outside this
    core.
    """

    #: Capability marker so callers can detect the stub without importing rvnd.
    is_stub = True

    def record_decision(self, decision: EnforcementDecision) -> None:
        raise NotImplementedError(
            "RvndEnforcementAdapter is an interface-only stub; attach a real "
            "RVND-backed EnforcementSink implemented outside privacy-shield."
        )

    def gate(
        self,
        action: Mapping[str, Any],
        *,
        enforce: bool = False,
    ) -> Optional[EnforcementVerdict]:
        raise NotImplementedError(
            "RvndEnforcementAdapter is an interface-only stub; attach a real "
            "RVND-backed EnforcementSink implemented outside privacy-shield."
        )
