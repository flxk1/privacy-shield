"""Compliance Evidence Export v1 (T-CL13).

Builds comprehensive evidence packs for regulatory compliance reporting.
Integrates with:
- compliance_control_plane.py: Policy evaluations and enforcement
- audit_log.py: Security and AI-specific audit events
- review_queue.py: Human approval records
- governance.py: Governance events and activity logs

Usage:
    from privacy_shield.compliance_evidence_export import ComplianceEvidenceExporter

    exporter = ComplianceEvidenceExporter()

    # Export workspace-scoped evidence
    pack = exporter.export_workspace_evidence(
        tenant_id="acme_corp",
        workspace_id="legal_team",
        start_date="2024-01-01",
        end_date="2024-01-31",
    )

    # Export for specific regulation
    gdpr_pack = exporter.export_regulation_evidence(
        tenant_id="acme_corp",
        regulation="gdpr",
        period_days=30,
    )
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


# =============================================================================
# REGULATORY REFERENCE CONSTANTS
# =============================================================================


class RegulatoryReference:
    """Standard regulatory references for evidence sections."""

    # GDPR References
    GDPR_ART_5 = "GDPR Art. 5 - Principles of processing"
    GDPR_ART_6 = "GDPR Art. 6 - Lawfulness of processing"
    GDPR_ART_24 = "GDPR Art. 24 - Controller responsibility"
    GDPR_ART_25 = "GDPR Art. 25 - Data protection by design"
    GDPR_ART_30 = "GDPR Art. 30 - Records of processing"
    GDPR_ART_32 = "GDPR Art. 32 - Security of processing"
    GDPR_ART_33 = "GDPR Art. 33 - Breach notification"

    # AI Act References
    AI_ACT_ART_9 = "EU AI Act Art. 9 - Risk management"
    AI_ACT_ART_11 = "EU AI Act Art. 11 - Technical documentation"
    AI_ACT_ART_12 = "EU AI Act Art. 12 - Logging and traceability"
    AI_ACT_ART_19 = "EU AI Act Art. 19 - Provider log retention"
    AI_ACT_ART_13 = "EU AI Act Art. 13 - Transparency"
    AI_ACT_ART_14 = "EU AI Act Art. 14 - Human oversight"
    AI_ACT_ART_26_6 = "EU AI Act Art. 26(6) - Deployer log keeping"
    AI_ACT_ART_72 = "EU AI Act Art. 72 - Post-market monitoring"
    AI_ACT_ART_73 = "EU AI Act Art. 73 - Serious incidents"

    # NIS2 References
    NIS2_ART_21 = "NIS2 Art. 21 - Cybersecurity risk management"
    NIS2_ART_23 = "NIS2 Art. 23 - Incident reporting"

    # CRA References (Regulation (EU) 2024/2847)
    CRA_ANNEX_I_PART_I = "CRA Annex I Part I - Essential cybersecurity requirements"
    CRA_ANNEX_I_PART_II = "CRA Annex I Part II - Vulnerability handling requirements"
    CRA_ANNEX_II = "CRA Annex II - Information and instructions to the user"
    CRA_ANNEX_V = "CRA Annex V - EU declaration of conformity"
    CRA_ANNEX_VII = "CRA Annex VII - Technical documentation"
    CRA_ANNEX_VIII = "CRA Annex VIII - Conformity assessment procedures"


# Section to regulatory reference mapping
SECTION_REGULATORY_REFS: Dict[str, List[str]] = {
    "policy_evaluations": [RegulatoryReference.GDPR_ART_24, RegulatoryReference.AI_ACT_ART_9],
    "human_approvals": [RegulatoryReference.AI_ACT_ART_14, RegulatoryReference.GDPR_ART_6],
    "tenant_feedback": [RegulatoryReference.AI_ACT_ART_14, RegulatoryReference.GDPR_ART_24],
    "tenant_review_requests": [RegulatoryReference.AI_ACT_ART_14, RegulatoryReference.GDPR_ART_24],
    "tenant_approval_requests": [RegulatoryReference.AI_ACT_ART_14, RegulatoryReference.GDPR_ART_6],
    "governance_interventions": [RegulatoryReference.AI_ACT_ART_14, RegulatoryReference.AI_ACT_ART_12, RegulatoryReference.GDPR_ART_25],
    "interaction_surfaces": [RegulatoryReference.AI_ACT_ART_14, RegulatoryReference.AI_ACT_ART_12, RegulatoryReference.GDPR_ART_25],
    "interaction_events": [RegulatoryReference.AI_ACT_ART_12, RegulatoryReference.AI_ACT_ART_14],
    "authored_answer_edits": [RegulatoryReference.AI_ACT_ART_12, RegulatoryReference.AI_ACT_ART_14, RegulatoryReference.GDPR_ART_24],
    "persistent_objects": [RegulatoryReference.AI_ACT_ART_12, RegulatoryReference.AI_ACT_ART_14, RegulatoryReference.GDPR_ART_24],
    "persistent_object_events": [RegulatoryReference.AI_ACT_ART_12, RegulatoryReference.AI_ACT_ART_14],
    "delivery_audit_records": [RegulatoryReference.AI_ACT_ART_12, RegulatoryReference.AI_ACT_ART_14, RegulatoryReference.GDPR_ART_24],
    "delivery_audit_events": [RegulatoryReference.AI_ACT_ART_12, RegulatoryReference.AI_ACT_ART_14, RegulatoryReference.GDPR_ART_24],
    "delivery_destination_memory": [RegulatoryReference.AI_ACT_ART_12, RegulatoryReference.GDPR_ART_24],
    "audit_events": [RegulatoryReference.GDPR_ART_32, RegulatoryReference.NIS2_ART_21],
    "ai_audit_events": [
        RegulatoryReference.AI_ACT_ART_12,
        RegulatoryReference.AI_ACT_ART_14,
        RegulatoryReference.AI_ACT_ART_19,
        RegulatoryReference.AI_ACT_ART_26_6,
        RegulatoryReference.AI_ACT_ART_72,
        RegulatoryReference.AI_ACT_ART_73,
    ],
    "governance_events": [RegulatoryReference.GDPR_ART_24, RegulatoryReference.AI_ACT_ART_9],
    "routing_traces": [RegulatoryReference.AI_ACT_ART_13, RegulatoryReference.GDPR_ART_25],
    "flow_scope_completeness": [RegulatoryReference.AI_ACT_ART_12, RegulatoryReference.AI_ACT_ART_13, RegulatoryReference.AI_ACT_ART_14, RegulatoryReference.GDPR_ART_25],
    "all_flow_scope_completeness": [RegulatoryReference.AI_ACT_ART_12, RegulatoryReference.AI_ACT_ART_13, RegulatoryReference.AI_ACT_ART_14, RegulatoryReference.GDPR_ART_25],
    "governance_documentation_inventory": [RegulatoryReference.AI_ACT_ART_11, RegulatoryReference.AI_ACT_ART_14],
    "agent_monitoring_documentation_inventory": [RegulatoryReference.AI_ACT_ART_11, RegulatoryReference.AI_ACT_ART_12, RegulatoryReference.AI_ACT_ART_72],
    "cra_security_incidents": [RegulatoryReference.CRA_ANNEX_I_PART_I, RegulatoryReference.NIS2_ART_21],
    "cra_vulnerability_handling": [RegulatoryReference.CRA_ANNEX_I_PART_II, RegulatoryReference.NIS2_ART_23],
    "cra_sbom_inventory": [RegulatoryReference.CRA_ANNEX_I_PART_II, RegulatoryReference.CRA_ANNEX_VII],
    "cra_user_information": [RegulatoryReference.CRA_ANNEX_II, RegulatoryReference.CRA_ANNEX_V],
}

from privacy_shield.utils import now_iso

PACKAGE_DIR = Path(__file__).parent
PROJECT_ROOT = PACKAGE_DIR.parent
EVIDENCE_DIR = PACKAGE_DIR / "compliance_evidence"

# Alias for backward compatibility
_now_iso = now_iso


def _parse_date(date_str: str) -> Optional[datetime]:
    """Parse date string to datetime."""
    if not date_str:
        return None
    for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z"]:
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _summarize_record_languages(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    for row in records:
        if not isinstance(row, dict):
            continue
        for key in ("output_language", "conversation_language", "language", "voice_language", "export_language"):
            value = str(row.get(key, "")).strip()
            if not value:
                continue
            counts[value] = counts.get(value, 0) + 1
            break
    return {
        "distinct_languages": sorted(counts.keys()),
        "language_counts": counts,
        "recorded_language_count": sum(counts.values()),
    }


def _summarize_record_values(records: List[Dict[str, Any]], field: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    key = str(field or "").strip()
    if not key:
        return counts
    for row in records:
        if not isinstance(row, dict):
            continue
        value = str(row.get(key, "")).strip()
        if not value:
            continue
        counts[value] = counts.get(value, 0) + 1
    return counts


# =============================================================================
# EVIDENCE PACK SCHEMA
# =============================================================================


class ExportFormat(str, Enum):
    """Supported export formats."""
    JSON = "json"
    CSV = "csv"


@dataclass
class DataSourceHealth:
    """Health status of a data source."""
    source_name: str
    available: bool
    record_count: int
    last_record_at: Optional[str] = None
    error: Optional[str] = None


@dataclass
class EvidenceSection:
    """A section of evidence in the pack."""
    section_id: str
    title: str
    description: str
    record_count: int
    records: List[Dict[str, Any]]
    metadata: Dict[str, Any] = field(default_factory=dict)
    regulatory_references: List[str] = field(default_factory=list)
    data_source_health: Optional[DataSourceHealth] = None

    def __post_init__(self):
        """Add default regulatory references if not provided."""
        if not self.regulatory_references and self.section_id in SECTION_REGULATORY_REFS:
            self.regulatory_references = SECTION_REGULATORY_REFS[self.section_id]


@dataclass
class EvidencePack:
    """Complete evidence pack for compliance reporting."""
    pack_id: str
    generated_at: str
    tenant_id: str
    scope: str  # "workspace", "regulation", "package", "audit"
    scope_id: str  # workspace_id, regulation name, package_id
    period_start: str
    period_end: str
    sections: List[EvidenceSection]
    summary: Dict[str, Any]
    integrity_hash: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "generated_at": self.generated_at,
            "tenant_id": self.tenant_id,
            "scope": self.scope,
            "scope_id": self.scope_id,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "sections": [
                {
                    "section_id": s.section_id,
                    "title": s.title,
                    "description": s.description,
                    "record_count": s.record_count,
                    "records": s.records,
                    "metadata": s.metadata,
                    "regulatory_references": s.regulatory_references,
                    "data_source_health": {
                        "source_name": s.data_source_health.source_name,
                        "available": s.data_source_health.available,
                        "record_count": s.data_source_health.record_count,
                        "last_record_at": s.data_source_health.last_record_at,
                        "error": s.data_source_health.error,
                    } if s.data_source_health else None,
                }
                for s in self.sections
            ],
            "summary": self.summary,
            "integrity_hash": self.integrity_hash,
            "metadata": self.metadata,
        }


# =============================================================================
# EVIDENCE SOURCES
# =============================================================================


class PolicyEvaluationSource:
    """Source for policy evaluation records."""

    def __init__(self, ccp=None):
        self._ccp = ccp

    def _get_ccp(self):
        if self._ccp is None:
            from privacy_shield.compliance_control_plane import get_compliance_control_plane
            self._ccp = get_compliance_control_plane()
        return self._ccp

    def get_evaluations(
        self,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Get policy evaluations for the period."""
        ccp = self._get_ccp()
        all_evals = ccp._evaluation_log.get_recent(tenant_id=tenant_id, limit=limit)

        # Filter by date if specified
        filtered = []
        for e in all_evals:
            ts_str = e.get("timestamp", "")
            ts = _parse_date(ts_str)
            if ts:
                if start_date and ts < start_date:
                    continue
                if end_date and ts > end_date:
                    continue
            filtered.append(e)

        return filtered

    def get_policy_status(self, tenant_id: str) -> Dict[str, Any]:
        """Get current policy status for tenant."""
        ccp = self._get_ccp()
        status = ccp.get_enforcement_status(tenant_id)
        return {
            "total_policies": status.total_policies,
            "active_policies": status.active_policies,
            "suspended_policies": status.suspended_policies,
            "health_score": status.health_score,
            "recent_evaluations": status.recent_evaluations,
            "recent_violations": status.recent_violations,
        }


class ApprovalSource:
    """Source for human approval records."""

    def get_approvals(
        self,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Get approval records for the period."""
        try:
            from privacy_shield.review_queue import list_reviews
            all_reviews = list_reviews(tenant_id=tenant_id, limit=limit)
        except ImportError:
            logger.warning("review_queue not available")
            return []

        # Filter by date
        filtered = []
        for r in all_reviews:
            ts_str = r.get("created_at", "") or r.get("decided_at", "")
            ts = _parse_date(ts_str)
            if ts:
                if start_date and ts < start_date:
                    continue
                if end_date and ts > end_date:
                    continue
            filtered.append(r)

        return filtered

    def get_approval_stats(self, tenant_id: str) -> Dict[str, Any]:
        """Get approval statistics."""
        try:
            from privacy_shield.review_queue import get_review_stats
            return get_review_stats(tenant_id)
        except ImportError:
            return {}


class AuditLogSource:
    """Source for audit log records."""

    def get_audit_events(
        self,
        tenant_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        event_types: Optional[List[str]] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Get audit events for the period."""
        try:
            from privacy_shield.audit_log import get_recent_audit_events
            events = get_recent_audit_events(limit=limit, event_types=event_types, tenant_id=tenant_id)
        except ImportError:
            logger.warning("audit_log not available")
            return []

        # Filter by date
        filtered = []
        for e in events:
            ts_str = e.get("timestamp", "")
            ts = _parse_date(ts_str)
            if ts:
                if start_date and ts < start_date:
                    continue
                if end_date and ts > end_date:
                    continue
            filtered.append(e)

        return filtered

    def get_ai_audit_events(
        self,
        tenant_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Get AI-specific audit events (EU AI Act Art. 12)."""
        ai_event_types = [
            "ai_skill_activation",
            "ai_skill_failure",
            "ai_model_selection",
            "ai_confidence_score",
            "ai_user_review_request",
            "ai_processing_cancelled",
            "ai_serious_incident",
            "ai_escalation_triggered",
        ]
        return self.get_audit_events(
            tenant_id=tenant_id,
            event_types=ai_event_types,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
        )


class GovernanceLogSource:
    """Source for governance activity logs."""

    def __init__(self):
        from privacy_shield.services.governance_audit import GOVERNANCE_DIR
        self._governance_dir = GOVERNANCE_DIR

    @staticmethod
    def _resolve_username_tenant(username: str) -> str:
        name = str(username or "").strip()
        if not name:
            return ""
        try:
            from privacy_shield import app as host_app

            row = host_app._load_user_account(name)
            return str((row or {}).get("tenant_id", "")).strip()
        except Exception:
            return ""

    def _record_matches_tenant(self, record: Dict[str, Any], tenant_id: Optional[str]) -> bool:
        requested = str(tenant_id or "").strip()
        if not requested:
            return True
        direct = str(record.get("tenant_id", "")).strip()
        if direct:
            return direct == requested
        details = record.get("details", {})
        if isinstance(details, dict):
            details_tenant = str(details.get("tenant_id", "")).strip()
            if details_tenant:
                return details_tenant == requested
            for key in ("user_id", "initiated_by", "authorized_by"):
                resolved = self._resolve_username_tenant(str(details.get(key, "")).strip())
                if resolved:
                    return resolved == requested
        resolved_user = self._resolve_username_tenant(str(record.get("user", "")).strip())
        if resolved_user:
            return resolved_user == requested
        return False

    def get_governance_events(
        self,
        tenant_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Get governance events for the period."""
        events_file = self._governance_dir / "governance_events.jsonl"
        if not events_file.exists():
            return []

        events = []
        try:
            with open(events_file) as f:
                for line in f:
                    if line.strip():
                        try:
                            event = json.loads(line)
                            ts_str = event.get("timestamp", "")
                            ts = _parse_date(ts_str)
                            if ts:
                                if start_date and ts < start_date:
                                    continue
                                if end_date and ts > end_date:
                                    continue
                            if not self._record_matches_tenant(event, tenant_id):
                                continue
                            events.append(event)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logger.warning(f"Failed to read governance events: {e}")

        return events[-limit:]

    def get_activity_log(
        self,
        tenant_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Get agent activity log."""
        activity_file = self._governance_dir / "activity_log.jsonl"
        if not activity_file.exists():
            return []

        activities = []
        try:
            with open(activity_file) as f:
                for line in f:
                    if line.strip():
                        try:
                            activity = json.loads(line)
                            ts_str = activity.get("timestamp", "")
                            ts = _parse_date(ts_str)
                            if ts:
                                if start_date and ts < start_date:
                                    continue
                                if end_date and ts > end_date:
                                    continue
                            if not self._record_matches_tenant(activity, tenant_id):
                                continue
                            activities.append(activity)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logger.warning(f"Failed to read activity log: {e}")

        return activities[-limit:]


class RoutingTraceSource:
    """Source for router decision traces."""

    def get_routing_traces(
        self,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Get routing decision traces."""
        # Routing traces live in session/conversation logs; derive them here from
        # the governance activity log's routing-tagged events.
        gov = GovernanceLogSource()
        activities = gov.get_activity_log(tenant_id=tenant_id, start_date=start_date, end_date=end_date, limit=limit * 2)

        routing_events = [
            a for a in activities
            if a.get("activity_type", "").startswith("route")
            or "routing" in str(a.get("details", "")).lower()
        ]

        return routing_events[:limit]


class QueryAuditSource:
    """Source for tenant-scoped query-audit evidence including flow/scope metadata."""

    def __init__(self, accounts_dir: Optional[Path] = None, audits_dir: Optional[Path] = None):
        self._accounts_dir = accounts_dir
        self._audits_dir = audits_dir

    def _resolve_dirs(self) -> tuple[Path, Path]:
        if self._accounts_dir is not None and self._audits_dir is not None:
            return self._accounts_dir, self._audits_dir
        try:
            from privacy_shield import app as host_app

            user_root = Path(getattr(host_app, "USER_ROOT", Path(__file__).resolve().parent / "user"))
        except Exception:
            user_root = Path(__file__).resolve().parent / "user"
        return (
            self._accounts_dir or (user_root / "accounts"),
            self._audits_dir or (user_root / "audits"),
        )

    def _tenant_usernames(self, tenant_id: str) -> List[str]:
        tenant = str(tenant_id or "").strip()
        if not tenant:
            return []
        accounts_dir, _ = self._resolve_dirs()
        if not accounts_dir.exists():
            return []
        users: set[str] = set()
        for path in accounts_dir.glob("*.json"):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            account_tenant = str(payload.get("tenant_id", "")).strip()
            if account_tenant != tenant:
                continue
            username = str(payload.get("username", "")).strip() or path.stem
            if username:
                users.add(username)
        return sorted(users)

    def _read_user_audits(
        self,
        username: str,
        *,
        start_date: Optional[datetime],
        end_date: Optional[datetime],
    ) -> List[Dict[str, Any]]:
        _, audits_dir = self._resolve_dirs()
        path = audits_dir / f"{str(username or '').strip()}.jsonl"
        if not path.exists():
            return []
        rows: List[Dict[str, Any]] = []
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    raw = line.strip()
                    if not raw:
                        continue
                    try:
                        row = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(row, dict):
                        continue
                    ts = _parse_date(str(row.get("timestamp", "")))
                    if ts:
                        if start_date and ts < start_date:
                            continue
                        if end_date and ts > end_date:
                            continue
                    rows.append(row)
        except Exception:
            return []
        return rows

    def get_flow_scope_records(
        self,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 2000,
    ) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        max_rows = max(1, min(int(limit or 2000), 10000))
        for username in self._tenant_usernames(tenant_id):
            user_rows = self._read_user_audits(
                username,
                start_date=start_date,
                end_date=end_date,
            )
            for row in user_rows:
                reasoning = row.get("reasoning", {}) if isinstance(row.get("reasoning", {}), dict) else {}
                flow = reasoning.get("flow_compilation", {}) if isinstance(reasoning.get("flow_compilation", {}), dict) else {}
                scope = reasoning.get("scope_enforcement", {}) if isinstance(reasoning.get("scope_enforcement", {}), dict) else {}
                has_flow = bool(flow)
                has_scope = bool(scope)
                if has_flow and has_scope:
                    completeness_status = "complete"
                elif has_flow or has_scope:
                    completeness_status = "partial"
                else:
                    completeness_status = "missing"

                flow_valid_raw = flow.get("valid")
                flow_valid = bool(flow_valid_raw) if flow_valid_raw is not None else None
                blocked_ids = scope.get("blocked_skill_ids", []) if isinstance(scope.get("blocked_skill_ids", []), list) else []
                applied_ids = scope.get("applied_skill_ids", []) if isinstance(scope.get("applied_skill_ids", []), list) else []
                nodes = flow.get("nodes", []) if isinstance(flow.get("nodes", []), list) else []
                execution_mode = reasoning.get("execution_mode", {}) if isinstance(reasoning.get("execution_mode", {}), dict) else {}
                agent_documentation = (
                    reasoning.get("agent_documentation", {})
                    if isinstance(reasoning.get("agent_documentation", {}), dict)
                    else {}
                )
                protocol_rows = (
                    agent_documentation.get("protocols", [])
                    if isinstance(agent_documentation.get("protocols", []), list)
                    else []
                )
                protocol_agent_ids = [
                    str(item.get("protocol_id", "")).strip()
                    for item in protocol_rows
                    if isinstance(item, dict) and str(item.get("protocol_id", "")).strip()
                ]

                records.append(
                    {
                        "audit_id": str(row.get("audit_id", "")).strip(),
                        "timestamp": str(row.get("timestamp", "")).strip(),
                        "user_id": str(row.get("user_id", "")).strip() or username,
                        "session_id": str(row.get("session_id", "")).strip(),
                        "module": str(row.get("module", "")).strip(),
                        "route": str(row.get("route", "")).strip(),
                        "confidence": float(row.get("confidence", 0.0) or 0.0),
                        "output_language": str(row.get("language", "")).strip(),
                        "flow_present": has_flow,
                        "scope_present": has_scope,
                        "completeness_status": completeness_status,
                        "flow_valid": flow_valid,
                        "flow_node_count": len(nodes),
                        "scope_status": str(scope.get("status", "")).strip(),
                        "scope_blocked_skill_count": len(blocked_ids),
                        "scope_applied_skill_count": len(applied_ids),
                        "execution_mode_source": str(execution_mode.get("source", "")).strip(),
                        "agent_documentation_present": bool(agent_documentation),
                        "protocol_agent_ids": protocol_agent_ids[:12],
                    }
                )
                if len(records) >= max_rows:
                    break
            if len(records) >= max_rows:
                break

        records.sort(key=lambda item: str(item.get("timestamp", "")), reverse=True)
        return records[:max_rows]

    def summarize_flow_scope(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        total = len(records)
        complete = sum(1 for row in records if str(row.get("completeness_status", "")) == "complete")
        partial = sum(1 for row in records if str(row.get("completeness_status", "")) == "partial")
        missing = sum(1 for row in records if str(row.get("completeness_status", "")) == "missing")
        with_flow = sum(1 for row in records if bool(row.get("flow_present", False)))
        with_scope = sum(1 for row in records if bool(row.get("scope_present", False)))
        flow_valid_reported = sum(1 for row in records if row.get("flow_valid") is not None)
        flow_valid_true = sum(1 for row in records if row.get("flow_valid") is True)
        scope_blocked = sum(1 for row in records if int(row.get("scope_blocked_skill_count", 0) or 0) > 0)
        with_agent_documentation = sum(1 for row in records if bool(row.get("agent_documentation_present", False)))
        completeness_rate = round((float(complete) / float(total)), 4) if total else 0.0
        flow_valid_rate = round((float(flow_valid_true) / float(flow_valid_reported)), 4) if flow_valid_reported else 0.0
        return {
            "total_records": total,
            "complete_records": complete,
            "partial_records": partial,
            "missing_records": missing,
            "with_flow_compilation": with_flow,
            "with_scope_enforcement": with_scope,
            "completeness_rate": completeness_rate,
            "flow_valid_reported": flow_valid_reported,
            "flow_valid_true": flow_valid_true,
            "flow_valid_rate": flow_valid_rate,
            "scope_blocked_runs": scope_blocked,
            "with_agent_documentation": with_agent_documentation,
            "scope_status_counts": _summarize_record_values(records, "scope_status"),
        }


class AuditDocumentationSource:
    """Source for audit-documentation inventory records."""

    def get_governance_documentation(self) -> List[Dict[str, Any]]:
        from privacy_shield.services.audit_documentation import governance_documentation_inventory

        return governance_documentation_inventory()

    def get_workplane_documentation(self) -> List[Dict[str, Any]]:
        from privacy_shield.services.audit_documentation import workplane_monitoring_inventory

        return workplane_monitoring_inventory()

    def get_summary(self) -> Dict[str, Any]:
        from privacy_shield.services.audit_documentation import build_audit_documentation_summary

        return build_audit_documentation_summary()


class HumanControlSource:
    """Source for tenant-local feedback, review, approval, and intervention records."""

    def _service(self):
        from privacy_shield.services.human_control_service import get_human_control_service

        return get_human_control_service()

    def _filter_by_date(
        self,
        rows: List[Dict[str, Any]],
        *,
        start_date: Optional[datetime],
        end_date: Optional[datetime],
    ) -> List[Dict[str, Any]]:
        filtered: List[Dict[str, Any]] = []
        for row in rows:
            ts = _parse_date(str(row.get("created_at", "") or row.get("decided_at", "") or row.get("updated_at", "")))
            if ts:
                if start_date and ts < start_date:
                    continue
                if end_date and ts > end_date:
                    continue
            filtered.append(row)
        return filtered

    def get_feedback(
        self,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        rows = self._service().list_feedback(tenant_id=tenant_id, limit=limit)
        return self._filter_by_date(rows, start_date=start_date, end_date=end_date)

    def get_reviews(
        self,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        rows = self._service().list_review_requests(tenant_id=tenant_id, limit=limit)
        return self._filter_by_date(rows, start_date=start_date, end_date=end_date)

    def get_approvals(
        self,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        rows = self._service().list_approval_requests(tenant_id=tenant_id, limit=limit)
        return self._filter_by_date(rows, start_date=start_date, end_date=end_date)

    def get_interventions(
        self,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        rows = self._service().list_interventions(tenant_id=tenant_id, limit=limit)
        return self._filter_by_date(rows, start_date=start_date, end_date=end_date)

    def get_interaction_surfaces(
        self,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        rows = self._service().list_interaction_surfaces(tenant_id=tenant_id, status="", limit=limit)
        return self._filter_by_date(rows, start_date=start_date, end_date=end_date)

    def get_interaction_events(
        self,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        rows = self._service().list_interaction_events(tenant_id=tenant_id, limit=limit)
        filtered: List[Dict[str, Any]] = []
        for row in rows:
            ts = _parse_date(str(row.get("timestamp", "")))
            if ts:
                if start_date and ts < start_date:
                    continue
                if end_date and ts > end_date:
                    continue
            filtered.append(row)
        return filtered

    def get_authored_answer_edits(
        self,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        rows = self.get_interaction_events(
            tenant_id=tenant_id,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
        )
        return [
            row for row in rows
            if str(row.get("action_type", "")).strip().lower() == "edit_authored_answer"
        ]

    def get_summary(self, tenant_id: str) -> Dict[str, Any]:
        return self._service().pending_summary(tenant_id=tenant_id)


class PersistentObjectSource:
    def _service(self):
        from privacy_shield.services.persistent_objects import get_persistent_object_service

        return get_persistent_object_service()

    def get_objects(
        self,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        rows = self._service().list_objects(tenant_id=tenant_id, limit=limit)
        filtered: List[Dict[str, Any]] = []
        for row in rows:
            ts = _parse_date(str(row.get("updated_at", row.get("created_at", ""))))
            if ts:
                if start_date and ts < start_date:
                    continue
                if end_date and ts > end_date:
                    continue
            filtered.append(row)
        return filtered

    def get_events(
        self,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        rows = self._service().list_events(tenant_id=tenant_id, limit=limit)
        filtered: List[Dict[str, Any]] = []
        for row in rows:
            ts = _parse_date(str(row.get("timestamp", "")))
            if ts:
                if start_date and ts < start_date:
                    continue
                if end_date and ts > end_date:
                    continue
            filtered.append(row)
        return filtered


class DeliveryAuditSource:
    def _service(self):
        from privacy_shield.services.conversation_delivery_records import get_conversation_delivery_record_service

        return get_conversation_delivery_record_service()

    def get_records(
        self,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        rows = self._service().list_records(tenant_id=tenant_id, limit=limit)
        filtered: List[Dict[str, Any]] = []
        for row in rows:
            ts = _parse_date(str(row.get("timestamp", "")))
            if ts:
                if start_date and ts < start_date:
                    continue
                if end_date and ts > end_date:
                    continue
            filtered.append(row)
        return filtered

    def get_destinations(
        self,
        tenant_id: str,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        return self._service().list_destination_memory(tenant_id=tenant_id, limit=limit)

    def get_events(
        self,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        rows = self._service().list_events(tenant_id=tenant_id, limit=limit)
        filtered: List[Dict[str, Any]] = []
        for row in rows:
            ts = _parse_date(str(row.get("timestamp", "")))
            if ts:
                if start_date and ts < start_date:
                    continue
                if end_date and ts > end_date:
                    continue
            filtered.append(row)
        return filtered


# =============================================================================
# COMPLIANCE EVIDENCE EXPORTER
# =============================================================================


class ComplianceEvidenceExporter:
    """
    Exports comprehensive compliance evidence packs.

    Features:
    - Workspace-scoped exports
    - Regulation-specific exports (GDPR, AI Act, etc.)
    - Period-scoped exports
    - Integrity hashing for tamper detection
    """

    def __init__(self):
        self._policy_source = PolicyEvaluationSource()
        self._approval_source = ApprovalSource()
        self._audit_source = AuditLogSource()
        self._governance_source = GovernanceLogSource()
        self._routing_source = RoutingTraceSource()
        self._query_audit_source = QueryAuditSource()
        self._documentation_source = AuditDocumentationSource()
        self._human_control_source = HumanControlSource()
        self._persistent_object_source = PersistentObjectSource()
        self._delivery_audit_source = DeliveryAuditSource()

    def export_workspace_evidence(
        self,
        tenant_id: str,
        workspace_id: str = "default",
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        period_days: int = 30,
        auto_generated: bool = False,
        trigger: Optional[Dict[str, Any]] = None,
    ) -> EvidencePack:
        """
        Export evidence for a workspace.

        Args:
            tenant_id: Tenant identifier
            workspace_id: Workspace identifier
            start_date: Period start (ISO format)
            end_date: Period end (ISO format)
            period_days: If dates not specified, use last N days

        Returns:
            EvidencePack with all evidence sections

        Raises:
            ValueError: If inputs are invalid
        """
        # Validate inputs
        self._validate_inputs(tenant_id, start_date, end_date, period_days)

        # Resolve dates
        end_dt = _parse_date(end_date) if end_date else datetime.now(timezone.utc)
        start_dt = _parse_date(start_date) if start_date else (end_dt - timedelta(days=period_days))

        sections = []

        # Section 1: Policy Evaluations
        policy_evals = self._policy_source.get_evaluations(
            tenant_id=tenant_id,
            start_date=start_dt,
            end_date=end_dt,
        )
        sections.append(EvidenceSection(
            section_id="policy_evaluations",
            title="Policy Evaluations",
            description="Records of policy enforcement decisions",
            record_count=len(policy_evals),
            records=policy_evals,
            metadata={"policy_status": self._policy_source.get_policy_status(tenant_id)},
            data_source_health=self._check_source_health("compliance_control_plane", policy_evals),
        ))

        # Section 2: Human Approvals
        approvals = self._approval_source.get_approvals(
            tenant_id=tenant_id,
            start_date=start_dt,
            end_date=end_dt,
        )
        sections.append(EvidenceSection(
            section_id="human_approvals",
            title="Human Approval Records",
            description="Records of human review and approval decisions",
            record_count=len(approvals),
            records=approvals,
            metadata={"approval_stats": self._approval_source.get_approval_stats(tenant_id)},
            data_source_health=self._check_source_health("review_queue", approvals),
        ))

        tenant_feedback = self._human_control_source.get_feedback(
            tenant_id=tenant_id,
            start_date=start_dt,
            end_date=end_dt,
        )
        sections.append(EvidenceSection(
            section_id="tenant_feedback",
            title="Tenant Feedback Records",
            description="Tenant-local user feedback on AI answers and workflows.",
            record_count=len(tenant_feedback),
            records=tenant_feedback,
            data_source_health=self._check_source_health("human_control_feedback", tenant_feedback),
        ))

        tenant_reviews = self._human_control_source.get_reviews(
            tenant_id=tenant_id,
            start_date=start_dt,
            end_date=end_dt,
        )
        sections.append(EvidenceSection(
            section_id="tenant_review_requests",
            title="Tenant Review Requests",
            description="Tenant-local expert review requests raised by users or governance.",
            record_count=len(tenant_reviews),
            records=tenant_reviews,
            data_source_health=self._check_source_health("human_control_reviews", tenant_reviews),
        ))

        tenant_approvals = self._human_control_source.get_approvals(
            tenant_id=tenant_id,
            start_date=start_dt,
            end_date=end_dt,
        )
        sections.append(EvidenceSection(
            section_id="tenant_approval_requests",
            title="Tenant Approval Requests",
            description="Tenant-local approval gates raised for governed actions.",
            record_count=len(tenant_approvals),
            records=tenant_approvals,
            metadata={"pending_summary": self._human_control_source.get_summary(tenant_id)},
            data_source_health=self._check_source_health("human_control_approvals", tenant_approvals),
        ))

        interventions = self._human_control_source.get_interventions(
            tenant_id=tenant_id,
            start_date=start_dt,
            end_date=end_dt,
        )
        sections.append(EvidenceSection(
            section_id="governance_interventions",
            title="Governance Intervention Records",
            description="Structured pause, approval, and denial decisions produced by the control plane.",
            record_count=len(interventions),
            records=interventions,
            metadata={"pending_summary": self._human_control_source.get_summary(tenant_id)},
            data_source_health=self._check_source_health("human_control_interventions", interventions),
        ))

        interaction_surfaces = self._human_control_source.get_interaction_surfaces(
            tenant_id=tenant_id,
            start_date=start_dt,
            end_date=end_dt,
        )
        sections.append(EvidenceSection(
            section_id="interaction_surfaces",
            title="Structured Interaction Surfaces",
            description="Inline chat and project control surfaces shown to users for governed or collaborative decisions.",
            record_count=len(interaction_surfaces),
            records=interaction_surfaces,
            metadata={
                "pending_summary": self._human_control_source.get_summary(tenant_id),
                "language_summary": _summarize_record_languages(interaction_surfaces),
            },
            data_source_health=self._check_source_health("human_control_interaction_surfaces", interaction_surfaces),
        ))

        interaction_events = self._human_control_source.get_interaction_events(
            tenant_id=tenant_id,
            start_date=start_dt,
            end_date=end_dt,
        )
        sections.append(EvidenceSection(
            section_id="interaction_events",
            title="Structured Interaction Events",
            description="Recorded user actions taken on structured chat and project surfaces across touch, voice, CLI, or controller inputs.",
            record_count=len(interaction_events),
            records=interaction_events,
            metadata={"language_summary": _summarize_record_languages(interaction_events)},
            data_source_health=self._check_source_health("human_control_interaction_events", interaction_events),
        ))

        authored_edits = self._human_control_source.get_authored_answer_edits(
            tenant_id=tenant_id,
            start_date=start_dt,
            end_date=end_dt,
        )
        sections.append(EvidenceSection(
            section_id="authored_answer_edits",
            title="Living Answer Edit Trail",
            description="Tracked user edits to authored structured answers inside chat and project context.",
            record_count=len(authored_edits),
            records=authored_edits,
            metadata={"language_summary": _summarize_record_languages(authored_edits)},
            data_source_health=self._check_source_health("human_control_authored_answer_edits", authored_edits),
        ))

        persistent_objects = self._persistent_object_source.get_objects(
            tenant_id=tenant_id,
            start_date=start_dt,
            end_date=end_dt,
        )
        sections.append(EvidenceSection(
            section_id="persistent_objects",
            title="Persistent Objects",
            description="Durable dashboards, checklists, and other structured conversation artifacts stored as first-class objects.",
            record_count=len(persistent_objects),
            records=persistent_objects,
            metadata={
                "language_summary": _summarize_record_languages(persistent_objects),
                "object_type_counts": _summarize_record_values(persistent_objects, "object_type"),
            },
            data_source_health=self._check_source_health("persistent_objects", persistent_objects),
        ))

        persistent_object_events = self._persistent_object_source.get_events(
            tenant_id=tenant_id,
            start_date=start_dt,
            end_date=end_dt,
        )
        sections.append(EvidenceSection(
            section_id="persistent_object_events",
            title="Persistent Object Events",
            description="Creation, update, and checklist-state events for durable conversation artifacts.",
            record_count=len(persistent_object_events),
            records=persistent_object_events,
            metadata={
                "language_summary": _summarize_record_languages(persistent_object_events),
                "action_type_counts": _summarize_record_values(persistent_object_events, "action_type"),
                "object_type_counts": _summarize_record_values(persistent_object_events, "object_type"),
            },
            data_source_health=self._check_source_health("persistent_object_events", persistent_object_events),
        ))

        delivery_records = self._delivery_audit_source.get_records(
            tenant_id=tenant_id,
            start_date=start_dt,
            end_date=end_dt,
        )
        sections.append(EvidenceSection(
            section_id="delivery_audit_records",
            title="Outbound Delivery Records",
            description="Audited records of conversation-driven downloads, project-folder saves, and outbound sends via email or MCP.",
            record_count=len(delivery_records),
            records=delivery_records,
            metadata={
                "language_summary": _summarize_record_languages(delivery_records),
                "channel_counts": _summarize_record_values(delivery_records, "channel"),
                "status_counts": _summarize_record_values(delivery_records, "status"),
            },
            data_source_health=self._check_source_health("delivery_audit_records", delivery_records),
        ))

        delivery_events = self._delivery_audit_source.get_events(
            tenant_id=tenant_id,
            start_date=start_dt,
            end_date=end_dt,
        )
        sections.append(EvidenceSection(
            section_id="delivery_audit_events",
            title="Outbound Delivery Events",
            description="Detailed event stream for delivery attempts, successful sends, and destination-memory updates triggered from conversation.",
            record_count=len(delivery_events),
            records=delivery_events,
            metadata={
                "language_summary": _summarize_record_languages(delivery_events),
                "event_type_counts": _summarize_record_values(delivery_events, "event_type"),
                "status_counts": _summarize_record_values(delivery_events, "status"),
            },
            data_source_health=self._check_source_health("delivery_audit_events", delivery_events),
        ))

        delivery_destinations = self._delivery_audit_source.get_destinations(tenant_id=tenant_id)
        sections.append(EvidenceSection(
            section_id="delivery_destination_memory",
            title="Delivery Destination Memory",
            description="Saved delivery aliases and resolved destinations used to map conversation names to real recipients in tenant and project context.",
            record_count=len(delivery_destinations),
            records=delivery_destinations,
            metadata={
                "channel_counts": _summarize_record_values(delivery_destinations, "source"),
            },
            data_source_health=self._check_source_health("delivery_destination_memory", delivery_destinations),
        ))

        # Section 3: Audit Events
        audit_events = self._audit_source.get_audit_events(
            tenant_id=tenant_id,
            start_date=start_dt,
            end_date=end_dt,
        )
        sections.append(EvidenceSection(
            section_id="audit_events",
            title="Security Audit Events",
            description="Security and access audit trail",
            record_count=len(audit_events),
            records=audit_events,
            metadata={"language_summary": _summarize_record_languages(audit_events)},
            data_source_health=self._check_source_health("audit_log", audit_events),
        ))

        # Section 4: AI-Specific Audit (EU AI Act Art. 12)
        ai_events = self._audit_source.get_ai_audit_events(
            tenant_id=tenant_id,
            start_date=start_dt,
            end_date=end_dt,
        )
        sections.append(EvidenceSection(
            section_id="ai_audit_events",
            title="AI System Audit Events (EU AI Act Art. 12)",
            description="AI model selection, activation, and incident records",
            record_count=len(ai_events),
            records=ai_events,
            metadata={
                "regulatory_reference": "EU AI Act Art. 12 - Record-keeping",
                "language_summary": _summarize_record_languages(ai_events),
            },
            data_source_health=self._check_source_health("audit_log_ai", ai_events),
        ))

        # Section 5: Governance Events
        gov_events = self._governance_source.get_governance_events(
            tenant_id=tenant_id,
            start_date=start_dt,
            end_date=end_dt,
        )
        sections.append(EvidenceSection(
            section_id="governance_events",
            title="Governance Control Events",
            description="Governance policy enforcement and control events",
            record_count=len(gov_events),
            records=gov_events,
            data_source_health=self._check_source_health("governance", gov_events),
        ))

        # Section 6: Governance documentation inventory
        governance_docs = self._documentation_source.get_governance_documentation()
        sections.append(EvidenceSection(
            section_id="governance_documentation_inventory",
            title="Governance Documentation Inventory",
            description="Required control-plane audit documents and automatic log artifacts.",
            record_count=len(governance_docs),
            records=governance_docs,
            metadata={"documentation_summary": self._documentation_source.get_summary()},
            data_source_health=self._check_source_health("governance_documentation", governance_docs),
        ))

        # Section 7: Work-plane monitoring documentation inventory
        work_docs = self._documentation_source.get_workplane_documentation()
        sections.append(EvidenceSection(
            section_id="agent_monitoring_documentation_inventory",
            title="Agent Monitoring Documentation Inventory",
            description="Required work-plane monitoring and accountability documentation for normal agents and orchestrators.",
            record_count=len(work_docs),
            records=work_docs,
            metadata={"documentation_summary": self._documentation_source.get_summary()},
            data_source_health=self._check_source_health("workplane_documentation", work_docs),
        ))

        # Section 8: Routing Traces
        routing_traces = self._routing_source.get_routing_traces(
            tenant_id=tenant_id,
            start_date=start_dt,
            end_date=end_dt,
        )
        sections.append(EvidenceSection(
            section_id="routing_traces",
            title="Request Routing Decisions",
            description="AI router decision traces for transparency",
            record_count=len(routing_traces),
            records=routing_traces,
            metadata={"language_summary": _summarize_record_languages(routing_traces)},
            data_source_health=self._check_source_health("routing", routing_traces),
        ))
        sections.append(
            self._build_flow_scope_completeness_section(
                tenant_id=tenant_id,
                start_dt=start_dt,
                end_dt=end_dt,
            )
        )

        # Build summary
        summary = self._build_summary(sections, tenant_id, workspace_id)

        # Generate pack
        pack_id = f"evidence_{tenant_id}_{workspace_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        pack = EvidencePack(
            pack_id=pack_id,
            generated_at=_now_iso(),
            tenant_id=tenant_id,
            scope="workspace",
            scope_id=workspace_id,
            period_start=start_dt.isoformat() if start_dt else "",
            period_end=end_dt.isoformat() if end_dt else "",
            sections=sections,
            summary=summary,
            integrity_hash="",  # Will be set below
            metadata={
                "export_type": "workspace_evidence",
                "period_days": period_days,
                "auto_generated": bool(auto_generated),
                "trigger": dict(trigger or {}),
                "language_preferences_recorded": True,
            },
        )

        # Calculate integrity hash
        pack.integrity_hash = self._calculate_integrity_hash(pack)

        # Save to file
        self._save_pack(pack)

        return pack

    def export_regulation_evidence(
        self,
        tenant_id: str,
        regulation: str,
        period_days: int = 30,
        auto_generated: bool = False,
        trigger: Optional[Dict[str, Any]] = None,
    ) -> EvidencePack:
        """
        Export evidence for a specific regulation (GDPR, AI Act, etc.).

        Args:
            tenant_id: Tenant identifier
            regulation: Regulation code (gdpr, ai_act, nis2, etc.)
            period_days: Period to export

        Returns:
            EvidencePack focused on the regulation
        """
        end_dt = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(days=period_days)

        reg_lower = regulation.lower().strip()
        sections = []

        # Get regulation-specific events based on type
        if reg_lower in ("gdpr", "dsgvo", "data_protection"):
            # GDPR-specific evidence
            policy_evals = self._policy_source.get_evaluations(tenant_id, start_dt, end_dt)
            gdpr_evals = [
                e for e in policy_evals
                if "gdpr" in str(e).lower() or "privacy" in str(e).lower() or "data_protection" in str(e).lower()
            ]
            sections.append(EvidenceSection(
                section_id="gdpr_policy_evaluations",
                title="GDPR Policy Evaluations",
                description="Data protection policy enforcement records",
                record_count=len(gdpr_evals),
                records=gdpr_evals,
                metadata={"regulatory_reference": "GDPR Art. 5, 24, 30"},
            ))

            # Data subject request handling
            approvals = self._approval_source.get_approvals(tenant_id, start_dt, end_dt)
            dsar_records = [
                a for a in approvals
                if any(term in str(a).lower() for term in ["dsar", "access request", "deletion", "erasure", "portability"])
            ]
            sections.append(EvidenceSection(
                section_id="dsar_records",
                title="Data Subject Request Records",
                description="Evidence of data subject rights handling",
                record_count=len(dsar_records),
                records=dsar_records,
                metadata={"regulatory_reference": "GDPR Art. 15-22"},
            ))

        elif reg_lower in ("ai_act", "ai", "eu_ai_act"):
            # AI Act specific evidence
            ai_events = self._audit_source.get_ai_audit_events(tenant_id=tenant_id, start_date=start_dt, end_date=end_dt)
            sections.append(EvidenceSection(
                section_id="ai_system_logs",
                title="AI System Logs (Art. 12)",
                description="Automatic logging of AI system events",
                record_count=len(ai_events),
                records=ai_events,
                metadata={"regulatory_reference": "EU AI Act Art. 12"},
            ))

            # Serious incidents (Art. 73)
            incidents = [e for e in ai_events if e.get("event") == "ai_serious_incident"]
            sections.append(EvidenceSection(
                section_id="serious_incidents",
                title="Serious Incident Reports (Art. 73)",
                description="AI system serious incident records",
                record_count=len(incidents),
                records=incidents,
                metadata={"regulatory_reference": "EU AI Act Art. 73"},
            ))

            # Human oversight evidence (Art. 14)
            oversight = self._approval_source.get_approvals(tenant_id, start_dt, end_dt)
            human_oversight = [
                a for a in oversight
                if any(term in str(a).lower() for term in ["ai", "model", "high-risk", "approval"])
            ]
            human_oversight.extend(self._human_control_source.get_reviews(tenant_id, start_dt, end_dt))
            human_oversight.extend(self._human_control_source.get_approvals(tenant_id, start_dt, end_dt))
            human_oversight.extend(self._human_control_source.get_interventions(tenant_id, start_dt, end_dt))
            human_oversight.extend(self._human_control_source.get_interaction_surfaces(tenant_id, start_dt, end_dt))
            human_oversight.extend(self._human_control_source.get_authored_answer_edits(tenant_id, start_dt, end_dt))
            sections.append(EvidenceSection(
                section_id="human_oversight",
                title="Human Oversight Records (Art. 14)",
                description="Evidence of human oversight and intervention",
                record_count=len(human_oversight),
                records=human_oversight,
                metadata={"regulatory_reference": "EU AI Act Art. 14"},
            ))

            governance_docs = self._documentation_source.get_governance_documentation()
            work_docs = self._documentation_source.get_workplane_documentation()
            sections.append(EvidenceSection(
                section_id="governance_documentation_inventory",
                title="Governance Documentation Inventory",
                description="Control-plane documentation required for AI Act and audit review.",
                record_count=len(governance_docs),
                records=governance_docs,
                metadata={"documentation_summary": self._documentation_source.get_summary()},
            ))
            sections.append(EvidenceSection(
                section_id="agent_monitoring_documentation_inventory",
                title="Agent Monitoring Documentation Inventory",
                description="Work-plane monitoring documentation required for AI Act and audit review.",
                record_count=len(work_docs),
                records=work_docs,
                metadata={"documentation_summary": self._documentation_source.get_summary()},
            ))

        elif reg_lower in ("nis2", "cybersecurity"):
            # NIS2 specific evidence
            security_events = self._audit_source.get_audit_events(
                event_types=["login_failure", "permission_denied", "suspicious_activity", "rate_limited"],
                start_date=start_dt,
                end_date=end_dt,
            )
            sections.append(EvidenceSection(
                section_id="security_incidents",
                title="Security Incident Records",
                description="Cybersecurity incident and access control logs",
                record_count=len(security_events),
                records=security_events,
                metadata={"regulatory_reference": "NIS2 Art. 21, 23"},
            ))
        elif reg_lower in ("cra", "cyber_resilience_act", "eu_cra", "reg_2024_2847", "cyber_resilience"):
            # CRA-specific evidence
            security_events = self._audit_source.get_audit_events(
                event_types=[
                    "login_failure",
                    "permission_denied",
                    "suspicious_activity",
                    "rate_limited",
                    "security_update",
                    "vulnerability_detected",
                ],
                start_date=start_dt,
                end_date=end_dt,
            )
            sections.append(EvidenceSection(
                section_id="cra_security_incidents",
                title="CRA Security Incident and Protection Logs",
                description="Evidence for CRA Annex I Part I requirements (access control, resilience, integrity, confidentiality).",
                record_count=len(security_events),
                records=security_events,
                metadata={"regulatory_reference": "CRA Annex I Part I"},
            ))

            policy_evals = self._policy_source.get_evaluations(tenant_id, start_dt, end_dt)
            vuln_records = [
                row for row in policy_evals
                if any(
                    token in str(row).lower()
                    for token in ("vulnerability", "security_update", "sbom", "coordinated disclosure", "cra")
                )
            ]
            sections.append(EvidenceSection(
                section_id="cra_vulnerability_handling",
                title="CRA Vulnerability Handling Evidence",
                description="Evidence for CRA Annex I Part II vulnerability identification, disclosure, and remediation.",
                record_count=len(vuln_records),
                records=vuln_records,
                metadata={"regulatory_reference": "CRA Annex I Part II"},
            ))

            sbom_records = self._collect_cra_sbom_inventory()
            sections.append(EvidenceSection(
                section_id="cra_sbom_inventory",
                title="CRA SBOM and Dependency Inventory",
                description="SBOM/dependency evidence for CRA vulnerability handling and technical documentation duties.",
                record_count=len(sbom_records),
                records=sbom_records,
                metadata={"regulatory_reference": "CRA Annex I Part II, Annex VII"},
            ))

            user_info_records = self._collect_cra_user_information_records()
            sections.append(EvidenceSection(
                section_id="cra_user_information",
                title="CRA User Information and Instructions Inventory",
                description="Documentation inventory relevant to CRA Annex II user information and secure operation guidance.",
                record_count=len(user_info_records),
                records=user_info_records,
                metadata={"regulatory_reference": "CRA Annex II"},
            ))

        # Add governance events for all regulations
        gov_events = self._governance_source.get_governance_events(tenant_id=tenant_id, start_date=start_dt, end_date=end_dt)
        sections.append(EvidenceSection(
            section_id="governance_controls",
            title="Governance Control Evidence",
            description="Evidence of governance controls and enforcement",
            record_count=len(gov_events),
            records=gov_events,
        ))
        sections.append(
            self._build_flow_scope_completeness_section(
                tenant_id=tenant_id,
                start_dt=start_dt,
                end_dt=end_dt,
            )
        )

        # Build summary
        summary = self._build_summary(sections, tenant_id, regulation)
        summary["regulation"] = regulation
        summary["regulatory_framework"] = self._get_regulatory_framework(regulation)

        # Generate pack
        pack_id = f"evidence_{tenant_id}_{regulation}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        pack = EvidencePack(
            pack_id=pack_id,
            generated_at=_now_iso(),
            tenant_id=tenant_id,
            scope="regulation",
            scope_id=regulation,
            period_start=start_dt.isoformat(),
            period_end=end_dt.isoformat(),
            sections=sections,
            summary=summary,
            integrity_hash="",
            metadata={
                "export_type": "regulation_evidence",
                "regulation": regulation,
                "period_days": period_days,
                "auto_generated": bool(auto_generated),
                "trigger": dict(trigger or {}),
            },
        )

        pack.integrity_hash = self._calculate_integrity_hash(pack)
        self._save_pack(pack)

        return pack

    def export_audit_trail(
        self,
        tenant_id: str,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        period_days: int = 90,
        auto_generated: bool = False,
        trigger: Optional[Dict[str, Any]] = None,
    ) -> EvidencePack:
        """
        Export complete audit trail for compliance reporting.

        This is a comprehensive export suitable for regulatory audits.
        """
        end_dt = _parse_date(end_date) if end_date else datetime.now(timezone.utc)
        start_dt = _parse_date(start_date) if start_date else (end_dt - timedelta(days=period_days))

        sections = []

        # All policy evaluations
        policy_evals = self._policy_source.get_evaluations(tenant_id, start_dt, end_dt, limit=5000)
        sections.append(EvidenceSection(
            section_id="all_policy_evaluations",
            title="Complete Policy Evaluation Log",
            description="All policy enforcement decisions for the period",
            record_count=len(policy_evals),
            records=policy_evals,
        ))

        # All approvals
        approvals = self._approval_source.get_approvals(tenant_id, start_dt, end_dt, limit=5000)
        sections.append(EvidenceSection(
            section_id="all_approvals",
            title="Complete Approval Log",
            description="All human review and approval decisions",
            record_count=len(approvals),
            records=approvals,
        ))

        tenant_feedback = self._human_control_source.get_feedback(tenant_id, start_dt, end_dt, limit=5000)
        sections.append(EvidenceSection(
            section_id="all_tenant_feedback",
            title="Complete Tenant Feedback Log",
            description="All tenant-local feedback captured for AI answers and workflows.",
            record_count=len(tenant_feedback),
            records=tenant_feedback,
        ))

        tenant_reviews = self._human_control_source.get_reviews(tenant_id, start_dt, end_dt, limit=5000)
        sections.append(EvidenceSection(
            section_id="all_tenant_reviews",
            title="Complete Tenant Review Log",
            description="All tenant-local review requests and review decisions.",
            record_count=len(tenant_reviews),
            records=tenant_reviews,
        ))

        tenant_approvals = self._human_control_source.get_approvals(tenant_id, start_dt, end_dt, limit=5000)
        sections.append(EvidenceSection(
            section_id="all_tenant_approvals",
            title="Complete Tenant Approval Log",
            description="All tenant-local approval gates and approval decisions.",
            record_count=len(tenant_approvals),
            records=tenant_approvals,
        ))

        interventions = self._human_control_source.get_interventions(tenant_id, start_dt, end_dt, limit=5000)
        sections.append(EvidenceSection(
            section_id="all_governance_interventions",
            title="Complete Governance Intervention Log",
            description="All structured control-plane interventions for the period.",
            record_count=len(interventions),
            records=interventions,
        ))

        interaction_surfaces = self._human_control_source.get_interaction_surfaces(tenant_id, start_dt, end_dt, limit=5000)
        sections.append(EvidenceSection(
            section_id="all_interaction_surfaces",
            title="Complete Structured Interaction Surface Log",
            description="All structured chat and project control surfaces shown to users.",
            record_count=len(interaction_surfaces),
            records=interaction_surfaces,
        ))

        interaction_events = self._human_control_source.get_interaction_events(tenant_id, start_dt, end_dt, limit=5000)
        sections.append(EvidenceSection(
            section_id="all_interaction_events",
            title="Complete Structured Interaction Event Log",
            description="All user actions taken on structured chat and project surfaces.",
            record_count=len(interaction_events),
            records=interaction_events,
        ))

        authored_edits = self._human_control_source.get_authored_answer_edits(tenant_id, start_dt, end_dt, limit=5000)
        sections.append(EvidenceSection(
            section_id="all_authored_answer_edits",
            title="Complete Living Answer Edit Log",
            description="All authored-answer edits persisted through chat and project workflows.",
            record_count=len(authored_edits),
            records=authored_edits,
        ))

        persistent_objects = self._persistent_object_source.get_objects(tenant_id, start_dt, end_dt, limit=5000)
        sections.append(EvidenceSection(
            section_id="all_persistent_objects",
            title="Complete Persistent Object Log",
            description="All durable dashboards, checklists, and other structured conversation artifacts stored as objects.",
            record_count=len(persistent_objects),
            records=persistent_objects,
        ))

        persistent_object_events = self._persistent_object_source.get_events(tenant_id, start_dt, end_dt, limit=5000)
        sections.append(EvidenceSection(
            section_id="all_persistent_object_events",
            title="Complete Persistent Object Event Log",
            description="All creation, update, and checklist-state events for durable conversation artifacts.",
            record_count=len(persistent_object_events),
            records=persistent_object_events,
        ))

        delivery_records = self._delivery_audit_source.get_records(tenant_id, start_dt, end_dt, limit=5000)
        sections.append(EvidenceSection(
            section_id="all_delivery_audit_records",
            title="Complete Outbound Delivery Record Log",
            description="All conversation-driven download, save, email, and MCP delivery records.",
            record_count=len(delivery_records),
            records=delivery_records,
        ))

        delivery_events = self._delivery_audit_source.get_events(tenant_id, start_dt, end_dt, limit=5000)
        sections.append(EvidenceSection(
            section_id="all_delivery_audit_events",
            title="Complete Outbound Delivery Event Log",
            description="All detailed delivery and destination-memory events produced by conversation-driven delivery actions.",
            record_count=len(delivery_events),
            records=delivery_events,
        ))

        delivery_destinations = self._delivery_audit_source.get_destinations(tenant_id, limit=5000)
        sections.append(EvidenceSection(
            section_id="all_delivery_destination_memory",
            title="Complete Delivery Destination Memory",
            description="All saved recipient aliases and resolved delivery destinations across the tenant.",
            record_count=len(delivery_destinations),
            records=delivery_destinations,
        ))

        # All audit events
        audit_events = self._audit_source.get_audit_events(tenant_id=tenant_id, start_date=start_dt, end_date=end_dt, limit=5000)
        sections.append(EvidenceSection(
            section_id="all_audit_events",
            title="Complete Security Audit Log",
            description="All security and access events",
            record_count=len(audit_events),
            records=audit_events,
        ))

        # All governance events
        gov_events = self._governance_source.get_governance_events(tenant_id=tenant_id, start_date=start_dt, end_date=end_dt, limit=5000)
        sections.append(EvidenceSection(
            section_id="all_governance_events",
            title="Complete Governance Log",
            description="All governance control and enforcement events",
            record_count=len(gov_events),
            records=gov_events,
        ))

        # Activity log
        activities = self._governance_source.get_activity_log(tenant_id=tenant_id, start_date=start_dt, end_date=end_dt, limit=5000)
        sections.append(EvidenceSection(
            section_id="all_activities",
            title="Complete Activity Log",
            description="All agent and system activities",
            record_count=len(activities),
            records=activities,
        ))
        sections.append(
            self._build_flow_scope_completeness_section(
                tenant_id=tenant_id,
                start_dt=start_dt,
                end_dt=end_dt,
                section_id="all_flow_scope_completeness",
                title="Complete Flow/Scope Completeness Log",
                description="Flow compilation and runtime-scope enforcement completeness across audited tenant runs.",
                limit=5000,
            )
        )

        governance_docs = self._documentation_source.get_governance_documentation()
        sections.append(EvidenceSection(
            section_id="governance_documentation_inventory",
            title="Governance Documentation Inventory",
            description="Control-plane documentary evidence expected for audits.",
            record_count=len(governance_docs),
            records=governance_docs,
            metadata={"documentation_summary": self._documentation_source.get_summary()},
        ))

        work_docs = self._documentation_source.get_workplane_documentation()
        sections.append(EvidenceSection(
            section_id="agent_monitoring_documentation_inventory",
            title="Agent Monitoring Documentation Inventory",
            description="Work-plane documentary evidence expected for audits.",
            record_count=len(work_docs),
            records=work_docs,
            metadata={"documentation_summary": self._documentation_source.get_summary()},
        ))

        summary = self._build_summary(sections, tenant_id, "audit_trail")
        summary["audit_type"] = "comprehensive"
        summary["period_days"] = period_days

        pack_id = f"audit_{tenant_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        pack = EvidencePack(
            pack_id=pack_id,
            generated_at=_now_iso(),
            tenant_id=tenant_id,
            scope="audit",
            scope_id="full_audit_trail",
            period_start=start_dt.isoformat(),
            period_end=end_dt.isoformat(),
            sections=sections,
            summary=summary,
            integrity_hash="",
            metadata={
                "export_type": "audit_trail",
                "period_days": period_days,
                "auto_generated": bool(auto_generated),
                "trigger": dict(trigger or {}),
            },
        )

        pack.integrity_hash = self._calculate_integrity_hash(pack)
        self._save_pack(pack)

        return pack

    def _safe_read_json_file(self, path: Path) -> Dict[str, Any]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}

    def _collect_cra_sbom_inventory(self) -> List[Dict[str, Any]]:
        compliance_dir = PROJECT_ROOT / "compliance"
        summary_path = compliance_dir / "FOSS_SUMMARY.json"
        sbom_path = compliance_dir / "SBOM.spdx.json"
        registry_path = compliance_dir / "THIRD_PARTY_CODE_REGISTRY.json"

        records: List[Dict[str, Any]] = []
        if summary_path.exists():
            summary_payload = self._safe_read_json_file(summary_path)
            records.append({
                "artifact_id": "foss_summary",
                "artifact_path": str(summary_path.relative_to(PROJECT_ROOT)),
                "artifact_type": "foss_summary",
                "available": True,
                "generated_at": summary_payload.get("generated_at", ""),
                "summary": summary_payload.get("summary", {}) if isinstance(summary_payload.get("summary", {}), dict) else {},
            })
        else:
            records.append({
                "artifact_id": "foss_summary",
                "artifact_path": str(summary_path.relative_to(PROJECT_ROOT)),
                "artifact_type": "foss_summary",
                "available": False,
            })

        if sbom_path.exists():
            records.append({
                "artifact_id": "sbom_spdx",
                "artifact_path": str(sbom_path.relative_to(PROJECT_ROOT)),
                "artifact_type": "sbom_spdx",
                "available": True,
                "size_bytes": int(sbom_path.stat().st_size),
            })
        else:
            records.append({
                "artifact_id": "sbom_spdx",
                "artifact_path": str(sbom_path.relative_to(PROJECT_ROOT)),
                "artifact_type": "sbom_spdx",
                "available": False,
            })

        if registry_path.exists():
            registry_payload = self._safe_read_json_file(registry_path)
            entries = registry_payload.get("entries", [])
            records.append({
                "artifact_id": "third_party_registry",
                "artifact_path": str(registry_path.relative_to(PROJECT_ROOT)),
                "artifact_type": "third_party_registry",
                "available": True,
                "entry_count": len(entries) if isinstance(entries, list) else 0,
            })
        else:
            records.append({
                "artifact_id": "third_party_registry",
                "artifact_path": str(registry_path.relative_to(PROJECT_ROOT)),
                "artifact_type": "third_party_registry",
                "available": False,
            })

        return records

    def _collect_cra_user_information_records(self) -> List[Dict[str, Any]]:
        docs_dir = PROJECT_ROOT / "docs"
        candidates = [
            ("secure_development_protocol", docs_dir / "secure_development_protocol.md"),
            ("foss_source_compliance", docs_dir / "foss_source_compliance.md"),
            ("task_management_protocol", docs_dir / "task_management_protocol.md"),
        ]
        records: List[Dict[str, Any]] = []
        for doc_id, path in candidates:
            records.append({
                "document_id": doc_id,
                "artifact_path": str(path.relative_to(PROJECT_ROOT)),
                "available": path.exists(),
                "size_bytes": int(path.stat().st_size) if path.exists() else 0,
            })
        return records

    def _validate_inputs(
        self,
        tenant_id: str,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        period_days: int = 30,
    ) -> None:
        """Validate export inputs.

        Raises:
            ValueError: If inputs are invalid
        """
        if not tenant_id or not isinstance(tenant_id, str):
            raise ValueError("tenant_id must be a non-empty string")

        if not isinstance(period_days, int) or period_days < 1 or period_days > 365:
            raise ValueError("period_days must be an integer between 1 and 365")

        if start_date is not None:
            if not isinstance(start_date, str):
                raise ValueError("start_date must be an ISO date string or None")
            if _parse_date(start_date) is None:
                raise ValueError(f"Invalid start_date format: {start_date}")

        if end_date is not None:
            if not isinstance(end_date, str):
                raise ValueError("end_date must be an ISO date string or None")
            if _parse_date(end_date) is None:
                raise ValueError(f"Invalid end_date format: {end_date}")

    def _build_flow_scope_completeness_section(
        self,
        *,
        tenant_id: str,
        start_dt: Optional[datetime],
        end_dt: Optional[datetime],
        section_id: str = "flow_scope_completeness",
        title: str = "Flow/Scope Completeness",
        description: str = "Completeness evidence for flow compilation and runtime scope enforcement metadata across audited responses.",
        limit: int = 2000,
    ) -> EvidenceSection:
        flow_scope_records = self._query_audit_source.get_flow_scope_records(
            tenant_id=tenant_id,
            start_date=start_dt,
            end_date=end_dt,
            limit=limit,
        )
        flow_scope_summary = self._query_audit_source.summarize_flow_scope(flow_scope_records)
        return EvidenceSection(
            section_id=section_id,
            title=title,
            description=description,
            record_count=len(flow_scope_records),
            records=flow_scope_records,
            metadata={
                "flow_scope_summary": flow_scope_summary,
                "language_summary": _summarize_record_languages(flow_scope_records),
                "status_counts": _summarize_record_values(flow_scope_records, "completeness_status"),
                "scope_status_counts": _summarize_record_values(flow_scope_records, "scope_status"),
                "completeness": float(flow_scope_summary.get("completeness_rate", 0.0) or 0.0),
            },
            data_source_health=self._check_source_health("query_audits_flow_scope", flow_scope_records),
        )

    def _check_source_health(
        self,
        source_name: str,
        records: List[Dict[str, Any]],
    ) -> DataSourceHealth:
        """Check health status of a data source based on retrieved records."""
        if not records:
            return DataSourceHealth(
                source_name=source_name,
                available=True,  # Source is available, just no data
                record_count=0,
                last_record_at=None,
                error=None,
            )

        # Find most recent record timestamp
        last_timestamp = None
        for record in records:
            ts = record.get("timestamp") or record.get("created_at") or record.get("decided_at")
            if ts and (last_timestamp is None or ts > last_timestamp):
                last_timestamp = ts

        return DataSourceHealth(
            source_name=source_name,
            available=True,
            record_count=len(records),
            last_record_at=last_timestamp,
            error=None,
        )

    def _build_summary(
        self,
        sections: List[EvidenceSection],
        tenant_id: str,
        scope_id: str,
    ) -> Dict[str, Any]:
        """Build evidence pack summary."""
        total_records = sum(s.record_count for s in sections)

        # Data source health summary
        source_health = {}
        for section in sections:
            if section.data_source_health:
                h = section.data_source_health
                source_health[h.source_name] = {
                    "available": h.available,
                    "record_count": h.record_count,
                    "has_recent_data": h.last_record_at is not None,
                }

        # Count by section
        section_counts = {s.section_id: s.record_count for s in sections}

        # Count violations and approvals
        violations = 0
        approvals_needed = 0
        approvals_granted = 0

        for section in sections:
            for record in section.records:
                if record.get("violations"):
                    violations += 1
                if record.get("requires_approval"):
                    approvals_needed += 1
                if record.get("status") == "approved" or record.get("decision") == "approve":
                    approvals_granted += 1

        return {
            "tenant_id": tenant_id,
            "scope_id": scope_id,
            "total_records": total_records,
            "section_counts": section_counts,
            "violations_count": violations,
            "approvals_needed": approvals_needed,
            "approvals_granted": approvals_granted,
            "sections_count": len(sections),
            "data_source_health": source_health,
        }

    def _calculate_integrity_hash(self, pack: EvidencePack) -> str:
        """Calculate integrity hash for the evidence pack."""
        # Create a deterministic representation
        content = json.dumps({
            "pack_id": pack.pack_id,
            "tenant_id": pack.tenant_id,
            "period_start": pack.period_start,
            "period_end": pack.period_end,
            "sections": [
                {
                    "section_id": s.section_id,
                    "record_count": s.record_count,
                    "records_hash": hashlib.sha256(
                        json.dumps(s.records, sort_keys=True, default=str).encode()
                    ).hexdigest()[:16],
                }
                for s in pack.sections
            ],
        }, sort_keys=True)

        return hashlib.sha256(content.encode()).hexdigest()

    def _save_pack(self, pack: EvidencePack):
        """Save evidence pack to file."""
        filename = f"{pack.pack_id}.json"
        filepath = EVIDENCE_DIR / filename
        try:
            EVIDENCE_DIR.mkdir(exist_ok=True)
            filepath.write_text(json.dumps(pack.to_dict(), indent=2, default=str))
            logger.info(f"Evidence pack saved: {filepath}")
        except Exception as e:
            logger.error(f"Failed to save evidence pack: {e}")

    def _get_regulatory_framework(self, regulation: str) -> Dict[str, Any]:
        """Get regulatory framework details."""
        reg = str(regulation or "").strip().lower()
        aliases = {
            "dsgvo": "gdpr",
            "data_protection": "gdpr",
            "ai": "ai_act",
            "eu_ai_act": "ai_act",
            "cybersecurity": "nis2",
            "eu_cra": "cra",
            "cyber_resilience_act": "cra",
            "cyber_resilience": "cra",
            "reg_2024_2847": "cra",
        }
        canonical = aliases.get(reg, reg)
        frameworks = {
            "gdpr": {
                "full_name": "General Data Protection Regulation",
                "jurisdiction": "EU",
                "key_articles": ["Art. 5", "Art. 6", "Art. 24", "Art. 30", "Art. 32", "Art. 33"],
                "enforcement_authority": "Data Protection Authorities",
            },
            "ai_act": {
                "full_name": "EU Artificial Intelligence Act",
                "jurisdiction": "EU",
                "key_articles": ["Art. 9", "Art. 12", "Art. 13", "Art. 14", "Art. 72", "Art. 73"],
                "enforcement_authority": "National AI Authorities",
            },
            "nis2": {
                "full_name": "Network and Information Security Directive 2",
                "jurisdiction": "EU",
                "key_articles": ["Art. 21", "Art. 23", "Art. 34"],
                "enforcement_authority": "National Cybersecurity Authorities",
            },
            "cra": {
                "full_name": "Cyber Resilience Act (Regulation (EU) 2024/2847)",
                "jurisdiction": "EU",
                "key_articles": [
                    "Art. 13",
                    "Art. 28",
                    "Art. 31",
                    "Annex I Part I",
                    "Annex I Part II",
                    "Annex II",
                    "Annex VII",
                    "Annex VIII",
                ],
                "enforcement_authority": "National Market Surveillance Authorities",
            },
        }
        return frameworks.get(canonical, {"full_name": regulation, "jurisdiction": "Unknown"})

    def list_packs(
        self,
        tenant_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List saved evidence packs.

        Args:
            tenant_id: Filter to packs for this tenant (optional)
            limit: Maximum number of packs to return

        Returns:
            List of pack metadata dicts, sorted by generated_at (newest first)
        """
        packs = []
        # Sort by modification time (newest first) for better relevance
        all_files = sorted(
            EVIDENCE_DIR.glob("*.json"),
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )
        for f in all_files:
            try:
                data = json.loads(f.read_text())
                # Filter by tenant_id if specified
                if tenant_id and data.get("tenant_id") != tenant_id:
                    continue
                packs.append({
                    "pack_id": data.get("pack_id"),
                    "tenant_id": data.get("tenant_id"),
                    "scope": data.get("scope"),
                    "scope_id": data.get("scope_id"),
                    "generated_at": data.get("generated_at"),
                    "period_start": data.get("period_start"),
                    "period_end": data.get("period_end"),
                    "integrity_hash": data.get("integrity_hash", ""),
                    "total_records": data.get("summary", {}).get("total_records", 0),
                    "metadata": data.get("metadata", {}) if isinstance(data.get("metadata"), dict) else {},
                })
                # Apply limit after filtering
                if len(packs) >= limit:
                    break
            except Exception:
                continue
        return packs

    def get_pack(self, pack_id: str, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get a saved evidence pack by ID."""
        filepath = EVIDENCE_DIR / f"{pack_id}.json"
        if filepath.exists():
            try:
                data = json.loads(filepath.read_text())
                requested_tenant = str(tenant_id or "").strip()
                if requested_tenant and str(data.get("tenant_id", "")).strip() != requested_tenant:
                    return None
                return data
            except Exception:
                return None
        return None

    def verify_pack_integrity(self, pack_id: str, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Verify integrity of a saved evidence pack."""
        pack_data = self.get_pack(pack_id, tenant_id=tenant_id)
        if not pack_data:
            return {"verified": False, "error": "Pack not found"}

        # Reconstruct and verify hash
        stored_hash = pack_data.get("integrity_hash", "")

        # Rebuild sections for hash calculation
        sections = []
        for s_data in pack_data.get("sections", []):
            sections.append(EvidenceSection(
                section_id=s_data.get("section_id", ""),
                title=s_data.get("title", ""),
                description=s_data.get("description", ""),
                record_count=s_data.get("record_count", 0),
                records=s_data.get("records", []),
                metadata=s_data.get("metadata", {}),
            ))

        pack = EvidencePack(
            pack_id=pack_data.get("pack_id", ""),
            generated_at=pack_data.get("generated_at", ""),
            tenant_id=pack_data.get("tenant_id", ""),
            scope=pack_data.get("scope", ""),
            scope_id=pack_data.get("scope_id", ""),
            period_start=pack_data.get("period_start", ""),
            period_end=pack_data.get("period_end", ""),
            sections=sections,
            summary=pack_data.get("summary", {}),
            integrity_hash="",
            metadata=pack_data.get("metadata", {}),
        )

        calculated_hash = self._calculate_integrity_hash(pack)

        return {
            "verified": stored_hash == calculated_hash,
            "stored_hash": stored_hash,
            "calculated_hash": calculated_hash,
            "pack_id": pack_id,
        }

    def export_to_csv(
        self,
        pack: Union[EvidencePack, str],
        section_id: Optional[str] = None,
    ) -> str:
        """Export evidence pack or section to CSV format.

        Args:
            pack: EvidencePack object or pack_id string
            section_id: If provided, export only this section

        Returns:
            CSV string content

        Raises:
            ValueError: If pack not found or section not found
        """
        # Resolve pack
        if isinstance(pack, str):
            pack_data = self.get_pack(pack)
            if not pack_data:
                raise ValueError(f"Pack not found: {pack}")
            sections_data = pack_data.get("sections", [])
        else:
            sections_data = [
                {
                    "section_id": s.section_id,
                    "title": s.title,
                    "records": s.records,
                }
                for s in pack.sections
            ]

        # Filter to specific section if requested
        if section_id:
            sections_data = [s for s in sections_data if s.get("section_id") == section_id]
            if not sections_data:
                raise ValueError(f"Section not found: {section_id}")

        output = io.StringIO()

        for section in sections_data:
            records = section.get("records", [])

            # Write section header
            output.write(f"# Section: {section.get('title', section.get('section_id'))}\n")
            if not records:
                output.write("status\n")
                output.write("no_records\n\n")
                continue

            # Collect all unique keys from records
            all_keys: List[str] = []
            for record in records:
                for key in record.keys():
                    if key not in all_keys:
                        all_keys.append(key)

            # Prioritize common keys first
            priority_keys = ["timestamp", "event", "status", "user", "tenant_id", "details"]
            sorted_keys = [k for k in priority_keys if k in all_keys]
            sorted_keys.extend([k for k in all_keys if k not in sorted_keys])

            # Write CSV
            writer = csv.DictWriter(output, fieldnames=sorted_keys, extrasaction='ignore')
            writer.writeheader()

            for record in records:
                # Flatten nested dicts for CSV
                flat_record = {}
                for key, value in record.items():
                    if isinstance(value, (dict, list)):
                        flat_record[key] = json.dumps(value, default=str)
                    else:
                        flat_record[key] = value
                writer.writerow(flat_record)

            output.write("\n")

        return output.getvalue()

    def get_health_report(self, tenant_id: str) -> Dict[str, Any]:
        """Get health report for all data sources.

        Args:
            tenant_id: Tenant identifier

        Returns:
            Health report with source availability and data freshness
        """
        sources = {
            "compliance_control_plane": {
                "description": "Policy enforcement decisions",
                "check": lambda: len(self._policy_source.get_evaluations(tenant_id, limit=1)),
            },
            "review_queue": {
                "description": "Human approval records",
                "check": lambda: len(self._approval_source.get_approvals(tenant_id, limit=1)),
            },
            "audit_log": {
                "description": "Security audit events",
                "check": lambda: len(self._audit_source.get_audit_events(limit=1)),
            },
            "governance": {
                "description": "Governance control events",
                "check": lambda: len(self._governance_source.get_governance_events(limit=1)),
            },
            "routing": {
                "description": "Request routing traces",
                "check": lambda: len(self._routing_source.get_routing_traces(tenant_id, limit=1)),
            },
        }

        report = {
            "tenant_id": tenant_id,
            "checked_at": _now_iso(),
            "sources": {},
            "overall_health": "healthy",
        }

        unhealthy_count = 0
        for name, config in sources.items():
            try:
                count = config["check"]()
                report["sources"][name] = {
                    "description": config["description"],
                    "available": True,
                    "has_data": count > 0,
                    "error": None,
                }
            except Exception as e:
                report["sources"][name] = {
                    "description": config["description"],
                    "available": False,
                    "has_data": False,
                    "error": str(e),
                }
                unhealthy_count += 1

        if unhealthy_count > 0:
            report["overall_health"] = "degraded" if unhealthy_count < 3 else "unhealthy"

        return report


# =============================================================================
# SINGLETON
# =============================================================================

_exporter: Optional[ComplianceEvidenceExporter] = None


def get_evidence_exporter() -> ComplianceEvidenceExporter:
    """Get singleton evidence exporter."""
    global _exporter
    if _exporter is None:
        _exporter = ComplianceEvidenceExporter()
    return _exporter
