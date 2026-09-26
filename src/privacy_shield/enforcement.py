"""Optional enforcement and audit-enrichment seam for the egress guard.

The core guard makes its decision locally from the privacy mode, classification
tiers, and scanner result. Nothing is written to disk unless the guard is
configured with an ``audit_log`` path (or ``PRIVACY_SHIELD_AUDIT_LOG`` is set);
see :class:`privacy_shield.gate.PrivacyGate`. This module defines the
interface through which a host may add a verdict and signed receipt,
independent of and additive to that recording. The core imports no host
implementation.

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

Advisory vs enforce
-------------------
Writing a signed-chain receipt is a mutating act. An adapter therefore
distinguishes a pure advisory preview from an enforcing call that may append a
receipt and return its ``audit_id``.

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
    "ExternalEnforcementAdapter",
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

    ``verdict`` uses permit/hold/deny; ``gate_verdict`` uses the
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

    A sink is injected into :class:`~privacy_shield.gate.PrivacyGate` via
    the capability flag. The default sink is :class:`NoOpEnforcementSink`; a
    real deployment may attach a host adapter. All methods must tolerate
    being called on every egress decision and must never raise into the core
    path (the guard wraps calls defensively regardless).
    """

    def record_decision(self, decision: EnforcementDecision) -> None:
        """Observe a local egress decision (advisory / audit enrichment).

        Always advisory. A host sink may append a receipt. A no-op sink does
        nothing.
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
    """Default sink: fully inert.

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


class ExternalEnforcementAdapter:
    """Interface-only stub for a host-owned enforcement sink.

    A real adapter, built and owned by the consuming host, would bind:

    - :meth:`record_decision` → append an advisory receipt for the egress
      decision to the workspace's signed chain (audit enrichment).
    - :meth:`gate` with ``enforce=False`` to a pure preview with no chain write.
    - :meth:`gate` with ``enforce=True`` to a decision that may append to the
      signed chain and return an ``audit_id``.

    It is a named stub, not a build: its methods raise :class:`NotImplementedError`
    so that an accidental attach fails loudly rather than silently pretending to
    govern. Attach a real adapter from outside this core.
    """

    #: Capability marker so callers can detect the interface-only stub.
    is_stub = True

    def record_decision(self, decision: EnforcementDecision) -> None:
        raise NotImplementedError(
            "ExternalEnforcementAdapter is an interface-only stub; attach a real "
            "host EnforcementSink implemented outside privacy-shield."
        )

    def gate(
        self,
        action: Mapping[str, Any],
        *,
        enforce: bool = False,
    ) -> Optional[EnforcementVerdict]:
        raise NotImplementedError(
            "ExternalEnforcementAdapter is an interface-only stub; attach a real "
            "host EnforcementSink implemented outside privacy-shield."
        )
