"""Privacy Gate — mandatory checkpoint before external data transmission.

Every module that handles potentially sensitive data (financial, tax, contract,
personal) MUST call ``privacy_gate.check()`` before:
1. Sending data to an external LLM
2. Sending data to a third-party API (DATEV, ELSTER, etc.)
3. Logging data that may contain PII

This module bridges the existing Privacy Shield (4 modes) with the
data policy guard (4 classification tiers) into a single check point.

Optional external enforcement
-----------------------------
Every entry point behaves in two modes:

- **Default (no host sink):** the gate decides locally (mode + classification
  + Art. 9 tiers, plus the scanner's regex/embeddings/local-LLM verdict upstream)
  and records the decision to the standalone :mod:`brain.audit_log`. Fully
  functional alone; ``require_privacy_check`` raises :class:`PermissionError` on
  an unsafe egress exactly as before.
- **Enriched (an enforcement sink is attached):** the SAME local decision is
  ADDITIONALLY surfaced to the optional
  :class:`~brain.privacy_shield.enforcement.EnforcementSink` (host verdict plus
  signed-chain receipt). Enrichment is strictly additive and
  never overrides the local decision. With no sink attached the default
  :data:`~brain.privacy_shield.enforcement.NOOP_SINK` makes this path inert.

No host implementation is imported here; the seam is defined in
:mod:`brain.privacy_shield.enforcement`.
"""

from __future__ import annotations

import functools
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .enforcement import (
    NOOP_SINK,
    EnforcementDecision,
    EnforcementSink,
    EnforcementVerdict,
    NoOpEnforcementSink,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Art. 9 GDPR special category patterns (mirrored from routes/privacy_shield)
# ---------------------------------------------------------------------------
_ART9_PATTERNS: Dict[str, List[str]] = {
    "health": [
        r"\b(diagnos[ei]s|patient|medical|disease|illness|symptom|treatment|medication|prescription|hospital|clinic|doctor|physician|therapy|surgery|cancer|diabetes|hiv|aids|blood\s*type|allergy)\b",
        r"\b(krankenhaus|arzt|diagnose|krankheit|behandlung|medikament|patient|therapie|symptom)\b",
    ],
    "genetic": [
        r"\b(dna|genetic|genome|hereditary|chromosom|mutation|gene\s*test)\b",
        r"\b(genetisch|erbkrankheit|genom)\b",
    ],
    "biometric": [
        r"\b(fingerprint|retina|iris\s*scan|face\s*recognition|biometric|voice\s*print)\b",
        r"\b(fingerabdruck|biometrisch|gesichtserkennung)\b",
    ],
    "political": [
        r"\b(political\s*party|political\s*opinion|vote|voting|election)\b",
        r"\b(partei|politisch|wahl)\b",
    ],
    "religious": [
        r"\b(religion|religious|church|mosque|synagogue|temple)\b",
        r"\b(kirche|moschee|synagoge|glaube|religiös)\b",
    ],
    "union": [
        r"\b(trade\s*union|union\s*member|labor\s*union|gewerkschaft|betriebsrat)\b",
    ],
    "sexual": [
        r"\b(sexual\s*orientation|gay|lesbian|bisexual|transgender|lgbtq)\b",
        r"\b(sexuelle\s*orientierung|geschlechtsidentität)\b",
    ],
    "criminal": [
        r"\b(criminal\s*record|conviction|offence|offense|felony|misdemeanor)\b",
        r"\b(vorstrafe|strafregister|verurteilung)\b",
    ],
}

# Compiled patterns for performance
_ART9_COMPILED: Dict[str, List[re.Pattern]] = {
    cat: [re.compile(p, re.IGNORECASE) for p in pats]
    for cat, pats in _ART9_PATTERNS.items()
}

# PII patterns for redaction
_PII_REDACT_PATTERNS = [
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), "[EMAIL]"),
    (re.compile(r"\b(\+?\d[\d\s\-()]{6,}\d)\b"), "[PHONE]"),
    (re.compile(r"\b([A-Z]{2}\d{2}[A-Z0-9]{10,30})\b"), "[IBAN]"),
    (re.compile(r"\b\d{2,3}/\d{3}/\d{4,5}\b"), "[STEUERNUMMER]"),
    (re.compile(r"\b\d{11}\b"), "[ID_NUMBER]"),
]

# Destinations considered external (data leaves the machine)
_EXTERNAL_DESTINATIONS = frozenset({
    "external_llm",
    "openai",
    "anthropic",
    "azure_openai",
    "datev",
    "elster",
    "third_party_api",
})


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class PrivacyGateResult:
    """Result of a privacy gate check."""

    allowed: bool
    mode: str
    classification: str
    blocked_reason: str = ""
    redacted_fields: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Main gate class
# ---------------------------------------------------------------------------
class PrivacyGate:
    """Single checkpoint for all privacy-sensitive data flows.

    Bridges the Privacy Shield (4 modes: STANDARD, LOCAL_ONLY,
    ANONYMOUS_JSON, REGEX_ONLY) with the data policy guard
    (4 classification tiers: public, internal, confidential,
    berufsgeheimnis) into one unified gate.

    Both modes are complete:

    - **Default (no sink):** :meth:`check` decides locally and records to
      :mod:`brain.audit_log`. This is the complete standalone gate.
    - **Enriched (sink attached):** the local decision is additionally handed to
      the attached :class:`~brain.privacy_shield.enforcement.EnforcementSink`
      via ``record_decision`` for governance/audit enrichment (verdict +
      signed-chain receipt). Attach one with :meth:`attach_enforcement_sink`;
      :meth:`plan_action` optionally consults the sink's ``gate`` for a
      prospective action. With none attached the sink is inert.
    """

    def __init__(self, enforcement_sink: Optional[EnforcementSink] = None) -> None:
        # Capability flag: default is the inert no-op sink.
        self._sink: EnforcementSink = enforcement_sink or NOOP_SINK

    # ------------------------------------------------------------------
    # Optional enforcement seam
    # ------------------------------------------------------------------
    def attach_enforcement_sink(self, sink: EnforcementSink) -> None:
        """Attach an optional enforcement / audit enrichment sink.

        The core decision is unaffected; the sink only *adds* a governance
        verdict + signed-chain receipt on top. Pass a real host adapter
        (built outside this core) to enrich; pass nothing to stay standalone.
        """
        self._sink = sink or NOOP_SINK

    def detach_enforcement_sink(self) -> None:
        """Detach any sink and revert to the standalone (default) behaviour."""
        self._sink = NOOP_SINK

    @property
    def enforcement_enabled(self) -> bool:
        """True iff a non-inert enforcement sink is attached.

        Any :class:`~brain.privacy_shield.enforcement.NoOpEnforcementSink`
        instance counts as inert, not just the shared
        singleton.
        """
        return not isinstance(self._sink, NoOpEnforcementSink)

    def plan_action(
        self,
        action: Dict[str, Any],
        *,
        enforce: bool = False,
    ) -> Optional[EnforcementVerdict]:
        """Optionally consult the attached sink about a prospective *action*.

        Returns ``None`` when no sink is attached (caller proceeds on its own
        local decision). With ``enforce=False`` a host sink previews a verdict
        without writing the signed chain;
        with ``enforce=True`` it MAY append to the chain (a mutating, governed
        act) and populate ``audit_id``.
        """
        try:
            return self._sink.gate(action, enforce=enforce)
        except Exception as exc:  # never let enrichment break the core path
            logger.debug("Enforcement sink gate() skipped: %s", exc)
            return None

    def check(
        self,
        data: Dict[str, Any],
        destination: str,
        tenant_id: str = "",
        user_id: str = "",
    ) -> PrivacyGateResult:
        """Check whether *data* may be sent to *destination*.

        Behaviour in both modes:

        - **Default (no sink):** decides locally and records the decision to
          :mod:`brain.audit_log`. Returns the local
          :class:`PrivacyGateResult`.
        - **Enriched (sink attached):** additionally surfaces the SAME decision
          to the enforcement sink (``record_decision``) for a governance verdict
          + signed-chain receipt. The returned result is unchanged — enrichment
          is additive.

        Args:
            data: The payload to be transmitted (must contain a ``text``
                  key or be convertible to string for scanning).
            destination: Target system identifier (e.g. ``"external_llm"``,
                         ``"datev"``, ``"elster"``).
            tenant_id: Tenant identifier for per-tenant policy lookup.
            user_id: Acting user (for audit trail).

        Returns:
            :class:`PrivacyGateResult` with the decision and reason.
        """
        result = self._decide_local(data, destination, tenant_id, user_id)
        return self._finalize(result, destination, tenant_id, user_id, data)

    def _decide_local(
        self,
        data: Dict[str, Any],
        destination: str,
        tenant_id: str = "",
        user_id: str = "",
    ) -> PrivacyGateResult:
        """Pure LOCAL egress decision (mode + classification + Art. 9 tiers).

        This is the standalone core of the gate: it consults no sink and has no
        audit side effects. :meth:`check` wraps it with the standalone audit
        record and the optional enforcement-sink surface.
        """
        mode = self._get_privacy_mode(tenant_id)
        text = self._extract_text(data)
        classification = self.classify_data(text)
        is_external = destination in _EXTERNAL_DESTINATIONS

        # --- Rule 1: LOCAL_ONLY blocks all external destinations ----------
        if mode == "local_only" and is_external:
            self._on_blocked(
                "local_only_external_blocked", destination, tenant_id, user_id, data,
            )
            return PrivacyGateResult(
                allowed=False,
                mode=mode,
                classification=classification,
                blocked_reason=(
                    f"Privacy mode LOCAL_ONLY forbids sending data to "
                    f"external destination '{destination}'"
                ),
            )

        # --- Rule 2: berufsgeheimnis / confidential block external LLMs --
        if classification in {"berufsgeheimnis", "confidential"} and is_external:
            self._on_blocked(
                "classification_external_blocked", destination, tenant_id, user_id, data,
            )
            return PrivacyGateResult(
                allowed=False,
                mode=mode,
                classification=classification,
                blocked_reason=(
                    f"Data classified as '{classification}' cannot be sent "
                    f"to external destination '{destination}'"
                ),
            )

        # --- Rule 3: Art. 9 special categories force LOCAL_ONLY ----------
        art9_hits = self.check_art9(text)
        if art9_hits:
            tenant_cfg = self._get_tenant_config(tenant_id)
            if not tenant_cfg.get("art9_dismissible", True):
                if is_external:
                    self._on_blocked(
                        "art9_external_blocked", destination, tenant_id, user_id, data,
                    )
                    return PrivacyGateResult(
                        allowed=False,
                        mode="local_only",
                        classification=classification,
                        blocked_reason=(
                            f"Art. 9 special categories detected "
                            f"({', '.join(art9_hits)}); tenant policy "
                            f"enforces LOCAL_ONLY for this data"
                        ),
                        redacted_fields=art9_hits,
                    )

        # --- Allowed -------------------------------------------------------
        return PrivacyGateResult(
            allowed=True,
            mode=mode,
            classification=classification,
        )

    def _finalize(
        self,
        result: PrivacyGateResult,
        destination: str,
        tenant_id: str,
        user_id: str,
        data: Dict[str, Any],
    ) -> PrivacyGateResult:
        """Record the local decision, then surface it to the optional sink.

        Default: writes the decision to the standalone audit trail
        and returns *result* unchanged. Enriched (sink attached): additionally
        hands the SAME decision to the enforcement sink for a governance verdict
        + signed-chain receipt. Both steps are defensive — enrichment or audit
        failure never changes the egress decision.
        """
        self._record_audit(result, destination, tenant_id, user_id, data)
        try:
            self._sink.record_decision(
                EnforcementDecision(
                    allowed=result.allowed,
                    destination=destination,
                    mode=result.mode,
                    classification=result.classification,
                    blocked_reason=result.blocked_reason,
                    redacted_fields=list(result.redacted_fields),
                    tenant_id=tenant_id,
                    user_id=user_id,
                )
            )
        except Exception as exc:  # never let enrichment break the core path
            logger.debug("Enforcement sink record_decision skipped: %s", exc)
        return result

    @staticmethod
    def _record_audit(
        result: PrivacyGateResult,
        destination: str,
        tenant_id: str,
        user_id: str,
        data: Dict[str, Any],
    ) -> None:
        """Write the egress decision to the standalone audit trail (default)."""
        try:
            from brain.audit_log import AuditEvent, log_audit_event

            log_audit_event(
                AuditEvent.AI_PRIVACY_SHIELD_DECISION,
                user=user_id or None,
                success=result.allowed,
                tenant_id=tenant_id or None,
                details={
                    "destination": destination,
                    "allowed": result.allowed,
                    "mode": result.mode,
                    "classification": result.classification,
                    "blocked_reason": result.blocked_reason,
                    "redacted_fields": list(result.redacted_fields),
                },
            )
        except Exception as exc:  # audit is best-effort, never fatal
            logger.debug("Privacy gate audit record skipped: %s", exc)

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def redact_for_logging(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Return a copy of *data* with PII stripped (safe for audit logs)."""
        out: Dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, str):
                out[key] = self._redact_text(value)
            elif isinstance(value, dict):
                out[key] = self.redact_for_logging(value)
            elif isinstance(value, list):
                out[key] = [
                    self._redact_text(v) if isinstance(v, str) else v
                    for v in value
                ]
            else:
                out[key] = value
        return out

    def check_art9(self, text: str) -> List[str]:
        """Detect GDPR Art. 9 special categories in *text*.

        Returns a list of detected category names (e.g.
        ``["health", "genetic"]``).  Empty list means no special
        categories found.
        """
        if not text:
            return []
        text_lower = text.lower()
        hits: List[str] = []
        for category, patterns in _ART9_COMPILED.items():
            for pat in patterns:
                if pat.search(text_lower):
                    hits.append(category)
                    break
        return hits

    def classify_data(self, text: str) -> str:
        """Classify *text* into a data sensitivity tier.

        Returns one of: ``public``, ``internal``, ``confidential``,
        ``berufsgeheimnis``.
        """
        if not text:
            return "public"

        text_lower = text.lower()

        # Berufsgeheimnis markers (attorney-client, medical, tax secrecy)
        if any(
            kw in text_lower
            for kw in (
                "berufsgeheimnis",
                "mandantengeheimnis",
                "steuergeheimnis",
                "anwaltsgeheimnis",
                "arztgeheimnis",
                "attorney-client",
                "legal privilege",
                "tax secrecy",
            )
        ):
            return "berufsgeheimnis"

        # Confidential markers
        if any(
            kw in text_lower
            for kw in (
                "confidential",
                "vertraulich",
                "geheim",
                "restricted",
                "nicht zur weitergabe",
                "streng vertraulich",
            )
        ):
            return "confidential"

        # Art. 9 special categories → at least confidential
        if self.check_art9(text):
            return "confidential"

        # Financial / tax / personal identifiers → internal
        if any(
            kw in text_lower
            for kw in (
                "steuernummer",
                "steuer-id",
                "sozialversicherung",
                "iban",
                "gehalt",
                "salary",
                "invoice",
                "rechnung",
            )
        ):
            return "internal"

        return "public"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_text(data: Dict[str, Any]) -> str:
        """Pull scannable text out of *data*."""
        if "text" in data:
            return str(data["text"])
        if "content" in data:
            return str(data["content"])
        if "message" in data:
            return str(data["message"])
        # Fallback: concatenate all string values
        parts = [str(v) for v in data.values() if isinstance(v, str)]
        return " ".join(parts)

    @staticmethod
    def _get_privacy_mode(tenant_id: str) -> str:
        """Resolve the effective privacy mode for *tenant_id*."""
        try:
            from brain.privacy_shield.shield import get_global_privacy_mode
            return get_global_privacy_mode().value
        except Exception:
            return "standard"

    @staticmethod
    def _get_tenant_config(tenant_id: str) -> Dict[str, Any]:
        """Load tenant-level privacy config (stub for per-tenant settings, pending
        a dedicated tenant config store)."""
        return {
            "art9_dismissible": False,  # conservative default
        }

    @staticmethod
    def _redact_text(text: str) -> str:
        """Apply PII redaction patterns to *text*."""
        result = text
        for pat, replacement in _PII_REDACT_PATTERNS:
            result = pat.sub(replacement, result)
        return result

    def _on_blocked(
        self,
        event_type: str,
        destination: str,
        tenant_id: str,
        user_id: str,
        data: Dict[str, Any],
    ) -> None:
        """Hook called when a transmission is blocked.

        Logs the event and notifies the breach detector so that
        repeated violations are surfaced.
        """
        logger.warning(
            "PrivacyGate BLOCKED: event=%s dest=%s tenant=%s user=%s",
            event_type, destination, tenant_id, user_id,
        )
        try:
            from brain.privacy_shield.breach import breach_detector
            breach_detector.detect_anomaly(
                event_type=event_type,
                details={
                    "destination": destination,
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "blocked_by": "privacy_gate",
                },
            )
        except Exception as exc:
            logger.debug("Breach detector notification skipped: %s", exc)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
privacy_gate = PrivacyGate()


# ---------------------------------------------------------------------------
# Decorator for route-level enforcement
# ---------------------------------------------------------------------------
def require_privacy_check(
    destination: str = "external_llm",
    data_param: str = "data",
) -> Callable:
    """Decorator that enforces a privacy gate check before the wrapped function.

    Usage::

        @require_privacy_check(destination="datev")
        async def send_to_datev(data: dict, tenant_id: str = "", user_id: str = ""):
            ...

    The decorator inspects the function's keyword arguments for
    ``data`` (or whatever *data_param* names), ``tenant_id``, and
    ``user_id``.  If the gate blocks the call a ``PermissionError``
    is raised with the blocked reason.

    Optional enforcement runs through the module :data:`privacy_gate`
    singleton, so behaviour follows :meth:`PrivacyGate.check` in both modes —
    **default (no sink):** decision is local and recorded to the standalone
    audit trail; an unsafe egress raises :class:`PermissionError`. **Enriched
    (a sink is attached to the singleton):** the same decision is additionally
    surfaced to the enforcement sink. Attaching a sink never changes whether
    the call is blocked.
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            payload = kwargs.get(data_param) or (args[0] if args else {})
            if not isinstance(payload, dict):
                payload = {"text": str(payload)}
            result = privacy_gate.check(
                data=payload,
                destination=destination,
                tenant_id=kwargs.get("tenant_id", ""),
                user_id=kwargs.get("user_id", ""),
            )
            if not result.allowed:
                raise PermissionError(
                    f"Privacy gate blocked: {result.blocked_reason}"
                )
            return await fn(*args, **kwargs)

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            payload = kwargs.get(data_param) or (args[0] if args else {})
            if not isinstance(payload, dict):
                payload = {"text": str(payload)}
            result = privacy_gate.check(
                data=payload,
                destination=destination,
                tenant_id=kwargs.get("tenant_id", ""),
                user_id=kwargs.get("user_id", ""),
            )
            if not result.allowed:
                raise PermissionError(
                    f"Privacy gate blocked: {result.blocked_reason}"
                )
            return fn(*args, **kwargs)

        import asyncio
        if asyncio.iscoroutinefunction(fn):
            return async_wrapper
        return sync_wrapper

    return decorator
