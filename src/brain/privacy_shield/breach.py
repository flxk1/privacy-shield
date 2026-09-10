"""Breach detection and GDPR Art. 33(2) notification.

Processor -> Controller breach notification via webhook.
The webhook event type ``security.data_breach`` was defined but never emitted.
This module closes that gap.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Breach event dataclass
# ---------------------------------------------------------------------------

@dataclass
class BreachEvent:
    """Represents a detected or reported data breach."""

    event_id: str = ""
    timestamp: str = ""
    severity: str = "low"  # low | medium | high | critical
    description: str = ""
    affected_data_categories: List[str] = field(default_factory=list)
    affected_count_estimate: int = 0
    detected_by: str = ""
    containment_status: str = "detected"  # detected | contained | resolved
    notification_deadline_utc: str = ""

    def __post_init__(self) -> None:
        if not self.event_id:
            self.event_id = f"breach_{uuid.uuid4().hex[:12]}"
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.notification_deadline_utc:
            # Art. 33(2): notify controller "without undue delay"
            # We set a 72-hour deadline aligned with Art. 33(1) controller->DPA
            deadline = datetime.now(timezone.utc) + timedelta(hours=72)
            self.notification_deadline_utc = deadline.isoformat()


# ---------------------------------------------------------------------------
# Anomaly detection thresholds
# ---------------------------------------------------------------------------

# Number of blocked actions within the time window that triggers escalation
_BLOCK_ESCALATION_THRESHOLD = 5
_BLOCK_WINDOW_SECONDS = 300  # 5 minutes

# Query volume spike (per tenant) that signals mass extraction attempt
_MASS_EXTRACTION_THRESHOLD = 50
_MASS_EXTRACTION_WINDOW_SECONDS = 60


# ---------------------------------------------------------------------------
# Breach detector
# ---------------------------------------------------------------------------

class BreachDetector:
    """Pattern-based breach detection and GDPR Art. 33(2) notification.

    Detects:
    - Unauthorized data access (access without proper RBAC)
    - Data sent to blocked destination (privacy mode violation)
    - Credential exposure (tokens in logs/responses)
    - Mass data extraction (unusual query volume)
    """

    # Persistent breach log directory (append-only JSONL)
    _BREACH_LOG_DIR = Path(__file__).resolve().parent.parent / "data" / "breach_log"

    def __init__(self) -> None:
        # Rolling counters: tenant_id -> list of timestamps
        self._block_events: Dict[str, List[float]] = defaultdict(list)
        self._query_events: Dict[str, List[float]] = defaultdict(list)
        # In-memory cache (populated from disk on first access)
        self._breach_log: List[BreachEvent] = []
        self._loaded = False
        # Ensure log directory exists
        self._BREACH_LOG_DIR.mkdir(parents=True, exist_ok=True)

    def detect_anomaly(
        self,
        event_type: str,
        details: Dict[str, Any],
    ) -> Optional[BreachEvent]:
        """Evaluate an event for breach indicators.

        Args:
            event_type: Category of the event, e.g.
                ``"local_only_external_blocked"``,
                ``"unauthorized_access"``,
                ``"credential_exposure"``,
                ``"query_spike"``.
            details: Contextual information about the event.

        Returns:
            A :class:`BreachEvent` if a breach is detected, else ``None``.
        """
        handler = self._HANDLERS.get(event_type)
        if handler:
            return handler(self, event_type, details)

        # Generic blocked-action handler for privacy gate events
        if "blocked" in event_type:
            return self._handle_blocked_action(event_type, details)

        return None

    def report_breach(self, breach: BreachEvent) -> None:
        """Report a breach: emit webhook and log."""
        self._log_breach(breach)
        self._emit_webhook(breach)
        logger.critical(
            "BREACH REPORTED: id=%s severity=%s desc=%s",
            breach.event_id, breach.severity, breach.description,
        )

    # ------------------------------------------------------------------
    # Detection handlers
    # ------------------------------------------------------------------

    def _handle_blocked_action(
        self, event_type: str, details: Dict[str, Any],
    ) -> Optional[BreachEvent]:
        """Track blocked actions; escalate on repeated violations."""
        tenant_id = details.get("tenant_id", "unknown")
        now = datetime.now(timezone.utc).timestamp()

        # Record this block event
        events = self._block_events[tenant_id]
        events.append(now)

        # Prune old events outside the window
        cutoff = now - _BLOCK_WINDOW_SECONDS
        self._block_events[tenant_id] = [t for t in events if t > cutoff]

        if len(self._block_events[tenant_id]) >= _BLOCK_ESCALATION_THRESHOLD:
            breach = BreachEvent(
                severity="high",
                description=(
                    f"Repeated privacy gate violations ({len(self._block_events[tenant_id])} "
                    f"in {_BLOCK_WINDOW_SECONDS}s) for tenant '{tenant_id}'. "
                    f"Latest event: {event_type}."
                ),
                affected_data_categories=details.get(
                    "affected_data_categories", ["unknown"],
                ),
                detected_by="privacy_gate_escalation",
                containment_status="detected",
            )
            self.report_breach(breach)
            # Reset counter after escalation
            self._block_events[tenant_id] = []
            return breach

        return None

    def _handle_unauthorized_access(
        self, event_type: str, details: Dict[str, Any],
    ) -> Optional[BreachEvent]:
        """Immediate breach on unauthorized data access."""
        breach = BreachEvent(
            severity="critical",
            description=(
                f"Unauthorized data access detected: "
                f"user='{details.get('user_id', 'unknown')}', "
                f"resource='{details.get('resource', 'unknown')}', "
                f"reason='{details.get('reason', 'missing RBAC')}'"
            ),
            affected_data_categories=details.get(
                "affected_data_categories", ["personal_data"],
            ),
            affected_count_estimate=details.get("affected_count_estimate", 1),
            detected_by="rbac_enforcement",
            containment_status="detected",
        )
        self.report_breach(breach)
        return breach

    def _handle_credential_exposure(
        self, event_type: str, details: Dict[str, Any],
    ) -> Optional[BreachEvent]:
        """Immediate breach on credential / token exposure."""
        breach = BreachEvent(
            severity="critical",
            description=(
                f"Credential exposure detected: "
                f"type='{details.get('credential_type', 'token')}', "
                f"location='{details.get('location', 'unknown')}'"
            ),
            affected_data_categories=["credentials", "authentication"],
            detected_by="credential_scanner",
            containment_status="detected",
        )
        self.report_breach(breach)
        return breach

    def _handle_query_spike(
        self, event_type: str, details: Dict[str, Any],
    ) -> Optional[BreachEvent]:
        """Detect mass data extraction via unusual query volume."""
        tenant_id = details.get("tenant_id", "unknown")
        now = datetime.now(timezone.utc).timestamp()

        events = self._query_events[tenant_id]
        events.append(now)

        cutoff = now - _MASS_EXTRACTION_WINDOW_SECONDS
        self._query_events[tenant_id] = [t for t in events if t > cutoff]

        if len(self._query_events[tenant_id]) >= _MASS_EXTRACTION_THRESHOLD:
            breach = BreachEvent(
                severity="high",
                description=(
                    f"Possible mass data extraction: "
                    f"{len(self._query_events[tenant_id])} queries in "
                    f"{_MASS_EXTRACTION_WINDOW_SECONDS}s for tenant "
                    f"'{tenant_id}'"
                ),
                affected_data_categories=details.get(
                    "affected_data_categories", ["unknown"],
                ),
                affected_count_estimate=details.get(
                    "affected_count_estimate",
                    len(self._query_events[tenant_id]),
                ),
                detected_by="query_volume_monitor",
                containment_status="detected",
            )
            self.report_breach(breach)
            self._query_events[tenant_id] = []
            return breach

        return None

    # Handler dispatch table
    _HANDLERS: Dict[str, Any] = {
        "unauthorized_access": _handle_unauthorized_access,
        "credential_exposure": _handle_credential_exposure,
        "query_spike": _handle_query_spike,
    }

    # ------------------------------------------------------------------
    # Notification
    # ------------------------------------------------------------------

    def _emit_webhook(self, breach: BreachEvent) -> None:
        """Emit ``security.data_breach`` webhook event.

        This fulfills the Art. 33(2) processor -> controller notification
        obligation by emitting the webhook that was defined in the platform
        but never previously wired.
        """
        payload = {
            "event_type": "security.data_breach",
            "event_id": breach.event_id,
            "timestamp": breach.timestamp,
            "data": asdict(breach),
        }
        # Try to use the platform webhook emitter if available
        try:
            from brain.services.webhook_service import emit_webhook
            emit_webhook("security.data_breach", payload)
            logger.info(
                "Breach webhook emitted: event_id=%s", breach.event_id,
            )
        except ImportError:
            # Webhook service not available; log the full payload so it
            # can be picked up by log-based alerting.
            logger.warning(
                "Webhook service unavailable. Breach payload logged: %s",
                json.dumps(payload, default=str),
            )
        except Exception as exc:
            logger.error(
                "Failed to emit breach webhook for %s: %s",
                breach.event_id, exc,
            )

    def _log_breach(self, breach: BreachEvent) -> None:
        """Append breach to the persistent audit log (append-only JSONL).

        Each breach is written to a per-month JSONL file for Art. 33(2)
        compliance.  The in-memory cache is also updated for fast reads.
        """
        self._breach_log.append(breach)

        # Persist to append-only JSONL
        try:
            now = datetime.now(timezone.utc)
            log_file = self._BREACH_LOG_DIR / f"breaches_{now.strftime('%Y_%m')}.jsonl"
            with open(log_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(breach), default=str) + "\n")
        except Exception as exc:
            logger.error("Failed to persist breach log: %s", exc)

        logger.warning(
            "BREACH LOGGED: id=%s severity=%s categories=%s deadline=%s",
            breach.event_id,
            breach.severity,
            breach.affected_data_categories,
            breach.notification_deadline_utc,
        )

    # ------------------------------------------------------------------
    # Query / admin helpers
    # ------------------------------------------------------------------

    def get_breach_log(self) -> List[BreachEvent]:
        """Return the breach log, loading from disk on first access."""
        if not self._loaded:
            self._load_from_disk()
            self._loaded = True
        return list(self._breach_log)

    def _load_from_disk(self) -> None:
        """Load all breach events from persistent JSONL files."""
        if not self._BREACH_LOG_DIR.exists():
            return
        for log_file in sorted(self._BREACH_LOG_DIR.glob("breaches_*.jsonl")):
            try:
                for line in log_file.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    # Avoid duplicates (by event_id)
                    if not any(b.event_id == data.get("event_id") for b in self._breach_log):
                        evt = BreachEvent(**{
                            k: v for k, v in data.items()
                            if k in BreachEvent.__dataclass_fields__
                        })
                        self._breach_log.append(evt)
            except Exception as exc:
                logger.warning("Failed to load breach log %s: %s", log_file, exc)

    def clear_breach_log(self) -> int:
        """Clear in-memory breach log cache.  Persistent log files are NOT deleted."""
        count = len(self._breach_log)
        self._breach_log = []
        self._loaded = False
        return count


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
breach_detector = BreachDetector()
