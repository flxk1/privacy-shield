"""Privacy Gate — mandatory checkpoint before external data transmission.

Every module that handles potentially sensitive data (financial, tax, contract,
personal) MUST call ``privacy_gate.check()`` before:
1. Sending data to an external LLM
2. Sending data to a third-party API (DATEV, ELSTER, etc.)
3. Logging data that may contain PII

This module bridges the existing Privacy Shield (4 modes) with the
data policy guard (4 classification tiers) into a single check point.

Optional recording, enforcement and breach escalation
------------------------------------------------------
Every entry point behaves in these layers, each off by default:

- **Default (no sink, no audit config):** the gate decides locally (mode +
  classification + Art. 9 tiers, plus the scanner's regex/embeddings/local-LLM
  verdict upstream) and writes NOTHING to disk — no audit record, no breach
  notification. Fully functional alone; ``require_privacy_check`` raises
  :class:`PermissionError` on an unsafe egress exactly as before.
- **Audit configured (``audit_log=`` a path, or the standard path via
  ``audit_log_path()``, or ``PRIVACY_SHIELD_AUDIT_LOG`` set):** the decision
  is additionally recorded to :mod:`privacy_shield.audit_log` at that path.
- **Breach detector configured (``breach_detector=`` an instance, e.g. the
  module ``breach_detector``):** a block additionally escalates to it.
- **Enriched (an enforcement sink is attached):** the SAME local decision is
  ADDITIONALLY surfaced to the optional
  :class:`~privacy_shield.enforcement.EnforcementSink` (host verdict plus
  signed-chain receipt). Enrichment is strictly additive and
  never overrides the local decision. With no sink attached the default
  :data:`~privacy_shield.enforcement.NOOP_SINK` makes this path inert.

No host implementation is imported here; the seam is defined in
:mod:`privacy_shield.enforcement`.
"""

from __future__ import annotations

import functools
import logging
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Tuple, TYPE_CHECKING, Any, Callable, Dict, List, Optional, Union

from ._legacy_env import reject_legacy_env
from .enforcement import (
    NOOP_SINK,
    EnforcementDecision,
    EnforcementSink,
    EnforcementVerdict,
    ExternalEnforcementAdapter,
    NoOpEnforcementSink,
)

if TYPE_CHECKING:
    from .breach import BreachDetector
    from .release import Release

logger = logging.getLogger(__name__)

# block notices held back while a release is being decided (PrivacyGate.check)
_held = threading.local()

# ---------------------------------------------------------------------------
# Art. 9 GDPR special category patterns (mirrored from routes/privacy_shield)
# ---------------------------------------------------------------------------
# German endings on two words only: "Medikamente", "Vorstrafen". "Diagnosen",
# "Symptome", "Krankenhäuser", "Parteien" and "Wahlen" all have business uses.
_DE = r"(?:e|en|n|s|es|er|em|in|innen)?"
_ART9_PATTERNS: Dict[str, List[str]] = {
    "health": [
        r"\b(diagnos[ei]s|patient|medical|disease|illness|symptom|treatment|medication|prescription|hospital|clinic|doctor|physician|therapy|surgery|cancer|diabetes|hiv|aids|blood\s*type|allergy)\b",
        r"\b(krankenhaus|arzt|diagnose|krankheit|patient|therapie|symptom|behandlung)\b",
        r"\bmedikament" + _DE + r"\b",
        # the words of sick notes, applications and records
        r"\b(krankgeschrieben|krankgemeldet|arbeitsunfähig|arbeitsunfähigkeit|au-bescheinigung|"
        r"reha|rehabilitation|ärztliches attest|schwerbehindert|schwerbehinderung|gdb|medikation|entzug|"
        r"suchterkrankung|suchtklinik)\b",
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
        # "Betriebsrat" alone is the works council, not a person's membership
        r"\b(trade\s*union|union\s*member|labor\s*union|gewerkschaft|betriebsratsmitglied)\b",
        r"\bmitglied\s+(?:des|im)\s+betriebsrat",
    ],
    "sexual": [
        r"\b(sexual\s*orientation|gay|lesbian|bisexual|transgender|lgbtq)\b",
        r"\b(sexuelle\s*orientierung|geschlechtsidentität)\b",
    ],
    "criminal": [
        r"\b(criminal\s*record|conviction|offence|offense|felony|misdemeanor)\b",
        r"\b(vorstrafe|strafregister)" + _DE + r"\b",
        r"\bverurteilung\b",
    ],
}

# Secrecy duties that refuse a release (release.py) without classifying the text.
_RELEASE_REFUSING_MARKERS = ("schweigepflicht", "patientengeheimnis", "ärztliche verschwiegenheit")

# Categories the optional model (pii_model.py) has a label for; genetic and
# biometric stay keyword-only.
_MODEL_CATEGORIES = frozenset({"health", "religious", "political", "union", "sexual", "criminal"})

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

# Destinations that keep data on this machine. Every other destination, an
# unknown or misspelt one included, is external: an allow-list of external
# names failed open on "OpenAI", "gemini" or " openai".
_LOCAL_DESTINATIONS = frozenset({
    "local", "local_only", "local_llm", "on_device", "localhost", "loopback",
    "ollama", "lm_studio", "lmstudio", "llamacpp", "llama_cpp",
})
# Kept for callers that import it; no longer consulted by the gate.
_EXTERNAL_DESTINATIONS = frozenset({
    "external_llm", "openai", "anthropic", "azure_openai", "datev", "elster", "third_party_api",
})


def is_external_destination(destination: Any) -> bool:
    name = str(destination or "").strip().lower().replace("-", "_").replace(" ", "_")
    return name not in _LOCAL_DESTINATIONS


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
    # evidence of special-category data that did not decide the verdict:
    # an ICD-10-GM term or a model hit in a sentence about a person
    art9_suspected: List[str] = field(default_factory=list)
    # the recorded release that lifted an Art. 9 block (release.py), if any
    released: Dict[str, str] = field(default_factory=dict)


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

    - **Default (no sink, no audit config):** :meth:`check` decides locally
      and writes NOTHING to disk — no audit record, no breach-detector
      notification. This is the complete standalone gate.
    - **Enriched (sink attached / audit configured):** the local decision is
      additionally handed to the attached
      :class:`~privacy_shield.enforcement.EnforcementSink` via
      ``record_decision`` for governance/audit enrichment (verdict +
      signed-chain receipt), and/or recorded to the configured ``audit_log``
      path and/or escalated to the configured ``breach_detector``. Attach a
      sink with :meth:`attach_enforcement_sink`; configure audit/breach with
      the constructor or :meth:`configure_audit`. With none configured every
      side channel is inert.
    """

    def __init__(
        self,
        enforcement_sink: Optional[EnforcementSink] = None,
        *,
        audit_log: Optional[Union[str, Path]] = None,
        breach_detector: Optional["BreachDetector"] = None,
    ) -> None:
        # Capability flag: default is the inert no-op sink.
        self._sink: EnforcementSink = enforcement_sink or NOOP_SINK
        # Default: no audit write, no breach escalation. Opt in explicitly,
        # e.g. audit_log=audit_log_path() for the standard user-state path;
        # PRIVACY_SHIELD_AUDIT_LOG, when set, is itself the opt-in (resolved
        # per-call in _resolve_audit_log, so a later-set env var is honoured
        # by the module singleton too).
        self._audit_log: Optional[Path] = Path(audit_log) if audit_log else None
        self._breach_detector: Optional["BreachDetector"] = breach_detector

    def _resolve_audit_log(self) -> Optional[Path]:
        if self._audit_log is not None:
            return self._audit_log
        import os

        from .audit_log import AUDIT_LOG_ENV, audit_log_path

        if str(os.environ.get(AUDIT_LOG_ENV, "")).strip():
            return audit_log_path()
        return None

    def configure_audit(
        self,
        *,
        audit_log: Optional[Union[str, Path]] = None,
        breach_detector: Optional["BreachDetector"] = None,
    ) -> None:
        """Configure audit recording / breach escalation on an existing gate
        (e.g. the module :data:`privacy_gate` singleton). Both default back
        to inert when omitted."""
        self._audit_log = Path(audit_log) if audit_log else None
        self._breach_detector = breach_detector

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

        Any :class:`~privacy_shield.enforcement.NoOpEnforcementSink`
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
        except NotImplementedError:
            # (D9) The interface-only stub must fail loudly when attached,
            # as its docstring promises — an accidental attach of
            # ExternalEnforcementAdapter is a configuration error, not an
            # enrichment failure the core path should swallow.
            if isinstance(self._sink, ExternalEnforcementAdapter):
                raise
            logger.debug("Enforcement sink gate() raised NotImplementedError")
            return None
        except Exception as exc:  # never let enrichment break the core path
            logger.debug("Enforcement sink gate() skipped: %s", exc)
            return None

    def check(
        self,
        data: Dict[str, Any],
        destination: str,
        tenant_id: str = "",
        user_id: str = "",
        release: "Optional[Release]" = None,
    ) -> PrivacyGateResult:
        """Check whether *data* may be sent to *destination*.

        Behaviour:

        - **Default (no sink, no audit config):** decides locally and writes
          nothing to disk. Returns the local :class:`PrivacyGateResult`.
        - **Audit configured:** additionally records the decision to the
          configured ``audit_log`` path via :mod:`privacy_shield.audit_log`.
        - **Sink attached:** additionally surfaces the SAME decision to the
          enforcement sink (``record_decision``) for a governance verdict +
          signed-chain receipt. The returned result is unchanged in every
          case — recording/enrichment is additive.

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
        reject_legacy_env()
        # with a release on the table, a block is not yet a block: hold the
        # notice (log line, breach detector) until the release is decided
        _held.notices = [] if release is not None else None
        try:
            result = self._decide_local(data, destination, tenant_id, user_id)
        finally:
            held, _held.notices = _held.notices, None
        if release is not None and not result.allowed:
            result = self._apply_release(result, data, destination, release, tenant_id, user_id)
        if not result.allowed:
            for notice in held or ():
                self._on_blocked(*notice)
        if result.released:
            return self._finalize(result, destination, tenant_id, user_id, data, audit=False)
        return self._finalize(result, destination, tenant_id, user_id, data)

    def _apply_release(
        self,
        result: PrivacyGateResult,
        data: Dict[str, Any],
        destination: str,
        release: "Release",
        tenant_id: str,
        user_id: str,
    ) -> PrivacyGateResult:
        """Lift an Art. 9 block under a recorded release, or say why not."""
        from dataclasses import replace

        from .release import record

        text = self._extract_text(data)
        why = release.problems(destination)
        if result.mode == "local_only":
            why.append("privacy mode LOCAL_ONLY")
        # a secrecy duty named in the text is the controller's to lift, not a
        # release's; as a marker it would block every Art. 28 contract
        if any(m in text.lower() for m in _RELEASE_REFUSING_MARKERS):
            why.append("the text names a duty of professional secrecy")
        if self._classify(text)[1] != "art9":
            why.append(f"the block is not an Art. 9 block ({result.classification})")
        audit_log = self._resolve_audit_log()
        if audit_log is None:
            why.append("no audit log configured to record it")
        if why:
            return replace(result, blocked_reason=f"{result.blocked_reason}; release refused: {'; '.join(why)}")
        details = {
            "destination": destination,
            "classification": result.classification,
            "art9_categories": self.check_art9(text),
            "release": release.to_dict(),
            "user": user_id or None,
        }
        try:
            record(audit_log, details, tenant_id)
        except Exception as exc:  # unrecorded means unreleased
            return replace(result, blocked_reason=f"{result.blocked_reason}; release refused: not recorded ({exc})")
        return replace(result, allowed=True, blocked_reason="", released=release.to_dict())

    def _decide_local(
        self,
        data: Dict[str, Any],
        destination: str,
        tenant_id: str = "",
        user_id: str = "",
    ) -> PrivacyGateResult:
        """Pure LOCAL egress decision (mode + classification + Art. 9 tiers).

        This is the standalone core of the gate: it consults no sink and
        writes no audit record. On a block it notifies the configured
        ``breach_detector`` (none by default, so inert); :meth:`check` wraps
        it with the audit record and the optional enforcement-sink surface.
        """
        from dataclasses import replace

        text = self._extract_text(data)
        return replace(self._decide(data, destination, tenant_id, user_id, text),
                       art9_suspected=self.art9_evidence(text))

    def _decide(
        self,
        data: Dict[str, Any],
        destination: str,
        tenant_id: str,
        user_id: str,
        text: str,
    ) -> PrivacyGateResult:
        mode = self._get_privacy_mode(tenant_id)
        classification = self.classify_data(text)
        is_external = is_external_destination(destination)

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
                    f"Data classified as '{classification}' ({self._why(text)}) cannot be sent "
                    f"to external destination '{destination}'"
                ),
            )

        # Art. 9 data needs nothing beyond Rule 2: it classifies as confidential
        # there; a recorded release (release.py) is the only way past it.

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
        audit: bool = True,
    ) -> PrivacyGateResult:
        """Record the local decision, then surface it to the optional sink.

        Default (no ``audit_log`` configured): writes nothing, returns
        *result* unchanged. Configured: writes the decision to the given
        audit path. Enriched (sink attached): additionally hands the SAME
        decision to the enforcement sink for a governance verdict +
        signed-chain receipt. All steps are defensive — enrichment or audit
        failure never changes the egress decision.
        """
        audit_log = self._resolve_audit_log() if audit else None
        if audit_log is not None:
            self._record_audit(result, destination, tenant_id, user_id, data, audit_log)
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
        except NotImplementedError:
            # (D9) See the matching comment in plan_action(): the stub must
            # fail loudly rather than be caught by the enrichment-is-never-
            # fatal path below.
            if isinstance(self._sink, ExternalEnforcementAdapter):
                raise
            logger.debug("Enforcement sink record_decision raised NotImplementedError")
        except Exception as exc:  # never let enrichment break the core path
            logger.debug("Enforcement sink record_decision skipped: %s", exc)
        return result

    def _record_audit(
        self,
        result: PrivacyGateResult,
        destination: str,
        tenant_id: str,
        user_id: str,
        data: Dict[str, Any],
        audit_log: Path,
    ) -> None:
        """Write the egress decision to *audit_log*."""
        try:
            from privacy_shield.audit_log import AuditEvent, log_audit_event

            log_audit_event(
                AuditEvent.AI_PRIVACY_SHIELD_DECISION,
                user=user_id or None,
                success=result.allowed,
                tenant_id=tenant_id or None,
                path=audit_log,
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
        """The Art. 9 categories that decide the verdict for *text*."""
        return self._art9(text)[0]

    def art9_evidence(self, text: str) -> List[str]:
        """Special-category evidence in *text* that does not decide the verdict."""
        evidence = self._art9(text)[1]
        return [] if self.check_art9(text) else evidence

    def _art9(self, text: str) -> Tuple[List[str], List[str]]:
        """(deciding categories, evidence) for *text*; one decision is asked for several times."""
        from . import icd10gm, pii_model
        key = (text, pii_model.configured(), str(icd10gm.locate()))
        memo = getattr(self, "_art9_memo", None)
        if memo is None or memo[0] != key:
            memo = (key, self._art9_uncached(text))
            self._art9_memo = memo
        hits, evidence = memo[1]
        return list(hits), list(evidence)

    def _art9_uncached(self, text: str) -> Tuple[List[str], List[str]]:
        if not text:
            return [], []
        from . import art9, icd10gm, pii_model
        text_lower = text.lower()
        keyword_at: Dict[str, List[int]] = {}
        for category, patterns in _ART9_COMPILED.items():
            for pat in patterns:
                keyword_at.setdefault(category, []).extend(m.start() for m in pat.finditer(text_lower))
        model_hits = pii_model.special_hits(text)
        sentences = art9.sentences(text)
        names: List[Tuple[int, int]] = []
        names_read = False

        def person(at: int) -> bool:
            nonlocal names, names_read
            if not names_read:
                from .scanner import PIIType, PrivacyScanner
                names = [(f.start, f.end) for f in PrivacyScanner(layers=[2]).scan(text).findings
                         if f.pii_type is PIIType.NAME]
                names_read = True
            return art9.refers_to_person(text, sentences, at, names)

        hits: List[str] = []
        model_on = pii_model.configured()
        record = art9.is_record(text)
        for category, starts in keyword_at.items():
            if not starts:
                continue
            # with the model on, a keyword the model knows needs a model hit in
            # its own sentence: "Partei im Sinne dieses Vertrages" has the
            # keyword and nothing else
            # ... except in a record, where the subject is given by the document
            if model_on and category in _MODEL_CATEGORIES and not record and not any(
                art9.sentence_of(sentences, k) == art9.sentence_of(sentences, h[0])
                for k in starts for h in model_hits
            ):
                continue
            # Art. 9 covers data about a person: a keyword counts only in a
            # sentence about one ("Die Diagnose der Netzwerkstörung" is not)
            if not any(person(k) for k in starts):
                continue
            hits.append(category)
        # the index and the model's own hits are evidence, not a verdict:
        # figurative use ("Sklerose der Verwaltung") is beyond them
        evidence: List[str] = []
        for s, e, term in icd10gm.find_terms(text):
            if person(s) and not any(ns < e and s < ne for ns, ne in names):
                # in a record a diagnosis is a diagnosis: it decides
                if record and "health" not in hits:
                    hits.append("health")
                evidence.append(f"icd10gm:{term}")
        for start, end, category, score in model_hits:
            # in a sentence about a person, and not on a name ("Nachname: Ostendorf")
            if score >= pii_model.special_threshold() and person(start) and not any(
                    s < end and start < e for s, e in names):
                evidence.append(f"model:{category}")
        return hits, list(dict.fromkeys(evidence))

    def classify_data(self, text: str) -> str:
        return self._classify(text)[0]

    def _classify(self, text: str) -> Tuple[str, str]:
        """Classify *text* into a data sensitivity tier.

        Returns one of: ``public``, ``internal``, ``confidential``,
        ``berufsgeheimnis``.
        """
        if not text:
            return "public", "public"

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
            return "berufsgeheimnis", "berufsgeheimnis"

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
            return "confidential", "confidential_marker"

        # An issuer-shaped or structural credential → confidential: a key that leaves
        # is usable by the recipient. A label-and-entropy guess is redacted, not gated.
        from .scanner import Confidence, PIIType, PrivacyScanner
        secret = any(
            f.pii_type == PIIType.SECRET and f.confidence == Confidence.HIGH
            for f in PrivacyScanner(layers=[1]).scan(text).findings
        )
        # Art. 9 special categories → at least confidential; "art9" alone is
        # what a recorded release may lift (release.py)
        if self.check_art9(text):
            return "confidential", "art9+secret" if secret else "art9"
        if secret:
            return "confidential", "secret"

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
            return "internal", "internal"

        return "public", "public"

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
            from privacy_shield.shield import get_global_privacy_mode
            return get_global_privacy_mode().value
        except Exception:
            return "standard"

    @staticmethod
    def _redact_text(text: str) -> str:
        """Apply PII redaction patterns to *text*."""
        result = text
        for pat, replacement in _PII_REDACT_PATTERNS:
            result = pat.sub(replacement, result)
        return result

    def _why(self, text: str) -> str:
        """The cause of a confidential classification, in words a user can act on."""
        reason = self._classify(text)[1]
        categories = ", ".join(self.check_art9(text))
        return {
            "art9": f"Art. 9 special categories about a person: {categories}; a recorded release can lift this",
            "art9+secret": f"Art. 9 special categories ({categories}) and a credential; no release lifts this",
            "secret": "a credential such as an API key or token",
            "berufsgeheimnis": "a professional-secrecy marker",
            "confidential_marker": "a confidentiality marker",
        }.get(reason, reason)

    def _on_blocked(
        self,
        event_type: str,
        destination: str,
        tenant_id: str,
        user_id: str,
        data: Dict[str, Any],
    ) -> None:
        """Hook called when a transmission is blocked.

        Logs the event (not disk state) and, when a ``breach_detector`` is
        configured, notifies it so that repeated violations are surfaced.
        Default (none configured): logs only, no breach escalation.
        """
        if getattr(_held, "notices", None) is not None:
            _held.notices.append((event_type, destination, tenant_id, user_id, data))
            return
        logger.warning(
            "PrivacyGate BLOCKED: event=%s dest=%s tenant=%s user=%s",
            event_type, destination, tenant_id, user_id,
        )
        if self._breach_detector is None:
            return
        try:
            self._breach_detector.detect_anomaly(
                event_type=event_type,
                details={
                    "destination": destination,
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "blocked_by": "privacy_gate",
                },
            )
        except Exception as exc:
            # Isolates breach-detector failures from the egress decision this
            # method exists to enforce: a broken breach log must not stop
            # PrivacyGate.check() from blocking/allowing correctly. It must,
            # though, be visible — a swallowed critical breach on a read-only
            # install is exactly the signal 1.0.0 gave loudly at
            # construction (see breach.py's _log_breach); debug is invisible
            # at most deployments' log level, so this logs at error instead.
            logger.error("Breach detector notification failed: %s", exc)


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

    Runs through the module :data:`privacy_gate` singleton, so behaviour
    follows :meth:`PrivacyGate.check` — **default:** decision is local and
    nothing is written to disk; an unsafe egress raises
    :class:`PermissionError`. Configure the singleton's audit/breach
    recording or enforcement sink with :meth:`PrivacyGate.configure_audit`
    / :meth:`PrivacyGate.attach_enforcement_sink` before use — neither ever
    changes whether the call is blocked.
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
