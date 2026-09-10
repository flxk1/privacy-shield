"""Centralized audit logging for security events.

This module provides a structured way to log security-relevant events
such as login attempts, permission changes, and suspicious activities.
"""
import json
import logging
import time
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

AUDIT_LOG_PATH = Path(__file__).parent / "logs" / "audit.jsonl"


class AuditEvent(Enum):
    """Security audit event types."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    ROLE_CHANGE = "role_change"
    API_KEY_CREATE = "api_key_create"
    API_KEY_REVOKE = "api_key_revoke"
    PERMISSION_DENIED = "permission_denied"
    RATE_LIMITED = "rate_limited"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SESSION_CREATED = "session_created"
    SESSION_EXPIRED = "session_expired"
    CSRF_VIOLATION = "csrf_violation"
    FILE_UPLOAD = "file_upload"
    FILE_UPLOAD_REJECTED = "file_upload_rejected"
    ACCOUNT_CREATED = "account_created"
    ACCOUNT_LOCKED = "account_locked"

    # RBAC audit events
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REVOKED = "role_revoked"
    TENANT_ACCESS_GRANTED = "tenant_access_granted"
    TENANT_ACCESS_REVOKED = "tenant_access_revoked"
    SKILL_CREATED = "skill_created"
    SKILL_PUBLISHED = "skill_published"
    SKILL_DELETED = "skill_deleted"
    RBAC_PERMISSION_DENIED = "rbac_permission_denied"

    # EU AI Act Art. 12 - AI-specific audit events
    AI_SKILL_ACTIVATION = "ai_skill_activation"
    AI_SKILL_FAILURE = "ai_skill_failure"
    AI_MODEL_SELECTION = "ai_model_selection"
    AI_CONFIDENCE_SCORE = "ai_confidence_score"
    AI_USER_REVIEW_REQUEST = "ai_user_review_request"
    AI_PROCESSING_CANCELLED = "ai_processing_cancelled"
    AI_SERIOUS_INCIDENT = "ai_serious_incident"
    AI_ESCALATION_TRIGGERED = "ai_escalation_triggered"
    AI_PRIVACY_SHIELD_DECISION = "ai_privacy_shield_decision"


def log_audit_event(
    event: AuditEvent,
    user: Optional[str] = None,
    ip: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    success: bool = True,
    tenant_id: Optional[str] = None,
) -> None:
    """Log a security-relevant event.

    Args:
        event: The type of audit event
        user: Username associated with the event (if applicable)
        ip: IP address of the client (if applicable)
        details: Additional event-specific details
        success: Whether the action was successful
    """
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event.value,
        "success": success,
        "user": user,
        "tenant_id": str(tenant_id or (details or {}).get("tenant_id", "")).strip() or None,
        "ip": ip,
        "details": details or {},
    }

    try:
        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.error("Failed to write audit log: %s", exc)


def log_login_success(user: str, ip: str, role: str) -> None:
    """Log a successful login."""
    log_audit_event(
        AuditEvent.LOGIN_SUCCESS,
        user=user,
        ip=ip,
        details={"role": role},
    )


def log_login_failure(user: str, ip: str, reason: str) -> None:
    """Log a failed login attempt."""
    log_audit_event(
        AuditEvent.LOGIN_FAILURE,
        user=user,
        ip=ip,
        success=False,
        details={"reason": reason},
    )


def log_logout(user: str, ip: str) -> None:
    """Log a logout event."""
    log_audit_event(
        AuditEvent.LOGOUT,
        user=user,
        ip=ip,
    )


def log_permission_denied(user: str, ip: str, resource: str, action: str) -> None:
    """Log a permission denied event."""
    log_audit_event(
        AuditEvent.PERMISSION_DENIED,
        user=user,
        ip=ip,
        success=False,
        details={"resource": resource, "action": action},
    )


def log_rate_limited(ip: str, endpoint: str) -> None:
    """Log a rate limit event."""
    log_audit_event(
        AuditEvent.RATE_LIMITED,
        ip=ip,
        success=False,
        details={"endpoint": endpoint},
    )


def log_csrf_violation(ip: str, endpoint: str, user: Optional[str] = None) -> None:
    """Log a CSRF violation."""
    log_audit_event(
        AuditEvent.CSRF_VIOLATION,
        user=user,
        ip=ip,
        success=False,
        details={"endpoint": endpoint},
    )


def log_file_upload(
    user: str,
    ip: str,
    filename: str,
    size: int,
    accepted: bool = True,
    rejection_reason: Optional[str] = None,
) -> None:
    """Log a file upload event."""
    event = AuditEvent.FILE_UPLOAD if accepted else AuditEvent.FILE_UPLOAD_REJECTED
    details: Dict[str, Any] = {"filename": filename, "size": size}
    if rejection_reason:
        details["reason"] = rejection_reason
    log_audit_event(
        event,
        user=user,
        ip=ip,
        success=accepted,
        details=details,
    )


def log_suspicious_activity(
    ip: str,
    activity_type: str,
    details: Optional[Dict[str, Any]] = None,
    user: Optional[str] = None,
) -> None:
    """Log suspicious activity."""
    log_audit_event(
        AuditEvent.SUSPICIOUS_ACTIVITY,
        user=user,
        ip=ip,
        success=False,
        details={"activity_type": activity_type, **(details or {})},
    )


def get_recent_audit_events(
    limit: int = 100,
    event_types: Optional[list] = None,
    user: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> list:
    """Retrieve recent audit events.

    Args:
        limit: Maximum number of events to return
        event_types: Filter by event types (list of AuditEvent values)
        user: Filter by username

    Returns:
        List of audit event dictionaries, most recent first
    """
    if not AUDIT_LOG_PATH.exists():
        return []

    def _tenant_for_username(username: str) -> str:
        name = str(username or "").strip()
        if not name:
            return ""
        try:
            from brain import app as brain_app

            row = brain_app._load_user_account(name)
            return str((row or {}).get("tenant_id", "")).strip()
        except (ImportError, KeyError, AttributeError, TypeError) as exc:
            logger.debug("Failed to resolve tenant for user %s: %s", name, exc)
            return ""

    events = []
    try:
        with AUDIT_LOG_PATH.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    # Apply filters
                    if event_types and entry.get("event") not in event_types:
                        continue
                    if user and entry.get("user") != user:
                        continue
                    if tenant_id:
                        entry_tenant = str(entry.get("tenant_id", "")).strip()
                        if not entry_tenant:
                            details = entry.get("details", {})
                            if isinstance(details, dict):
                                entry_tenant = str(details.get("tenant_id", "")).strip()
                        if not entry_tenant:
                            entry_tenant = _tenant_for_username(str(entry.get("user", "")).strip())
                        if entry_tenant != str(tenant_id).strip():
                            continue
                    events.append(entry)
                except json.JSONDecodeError:
                    continue
    except Exception as exc:
        logger.error("Failed to read audit log: %s", exc)
        return []

    # Return most recent first
    events.reverse()
    return events[:limit]


# ---------------------------------------------------------------------------
# EU AI Act Art. 12 - AI-Specific Audit Logging Helpers
# ---------------------------------------------------------------------------


def log_ai_skill_activation(
    user: str,
    ip: str,
    skill_id: str,
    skill_name: str,
    module: str,
    confidence: float,
    model_used: str,
    session_id: str,
) -> None:
    """Log AI skill activation (EU AI Act Art. 12)."""
    log_audit_event(
        AuditEvent.AI_SKILL_ACTIVATION,
        user=user,
        ip=ip,
        details={
            "skill_id": skill_id,
            "skill_name": skill_name,
            "module": module,
            "confidence": confidence,
            "model_used": model_used,
            "session_id": session_id,
        },
    )


def log_ai_model_selection(
    user: str,
    session_id: str,
    model_id: str,
    selection_reason: str,
    local_model: bool = False,
) -> None:
    """Log AI model selection decision (EU AI Act Art. 12)."""
    log_audit_event(
        AuditEvent.AI_MODEL_SELECTION,
        user=user,
        details={
            "session_id": session_id,
            "model_id": model_id,
            "selection_reason": selection_reason,
            "local_model": local_model,
        },
    )


def log_ai_serious_incident(
    user: str,
    session_id: str,
    severity: str,  # critical, high, medium
    incident_type: str,
    description: str,
    confidence: float,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Log serious incident for EU AI Act Art. 73 reporting."""
    log_audit_event(
        AuditEvent.AI_SERIOUS_INCIDENT,
        user=user,
        success=False,
        details={
            "session_id": session_id,
            "severity": severity,
            "incident_type": incident_type,
            "description": description,
            "confidence": confidence,
            **(details or {}),
        },
    )


def log_ai_processing_cancelled(user: str, session_id: str) -> None:
    """Log user-initiated processing cancellation (EU AI Act Art. 14)."""
    log_audit_event(
        AuditEvent.AI_PROCESSING_CANCELLED,
        user=user,
        details={"session_id": session_id},
    )


def log_ai_escalation_triggered(
    user: str,
    session_id: str,
    ticket_id: str,
    reason: str,
    risk_level: str,
) -> None:
    """Log when AI escalates to human expert."""
    log_audit_event(
        AuditEvent.AI_ESCALATION_TRIGGERED,
        user=user,
        details={
            "session_id": session_id,
            "ticket_id": ticket_id,
            "reason": reason,
            "risk_level": risk_level,
        },
    )


# ---------------------------------------------------------------------------
# RBAC Audit Logging Helpers
# ---------------------------------------------------------------------------


def log_role_change(
    actor: str,
    target_user: str,
    tenant_id: str,
    old_role: Optional[str],
    new_role: str,
    ip: Optional[str] = None,
) -> None:
    """Log a role assignment change.

    Args:
        actor: User making the change
        target_user: User whose role is being changed
        tenant_id: Tenant context
        old_role: Previous role (None if new assignment)
        new_role: New role being assigned
        ip: IP address of actor
    """
    log_audit_event(
        AuditEvent.ROLE_ASSIGNED,
        user=actor,
        ip=ip,
        details={
            "target_user": target_user,
            "tenant_id": tenant_id,
            "old_role": old_role,
            "new_role": new_role,
        },
    )


def log_role_revoked(
    actor: str,
    target_user: str,
    tenant_id: str,
    revoked_role: str,
    ip: Optional[str] = None,
) -> None:
    """Log a role revocation.

    Args:
        actor: User making the change
        target_user: User whose role is being revoked
        tenant_id: Tenant context
        revoked_role: Role being revoked
        ip: IP address of actor
    """
    log_audit_event(
        AuditEvent.ROLE_REVOKED,
        user=actor,
        ip=ip,
        details={
            "target_user": target_user,
            "tenant_id": tenant_id,
            "revoked_role": revoked_role,
        },
    )


def log_tenant_access_change(
    actor: str,
    target_user: str,
    tenant_id: str,
    action: str,
    role: Optional[str] = None,
    ip: Optional[str] = None,
) -> None:
    """Log a tenant access grant or revocation.

    Args:
        actor: User making the change
        target_user: User whose access is changing
        tenant_id: Tenant context
        action: Either "granted" or "revoked"
        role: Role granted/revoked (if applicable)
        ip: IP address of actor
    """
    event = AuditEvent.TENANT_ACCESS_GRANTED if action == "granted" else AuditEvent.TENANT_ACCESS_REVOKED
    log_audit_event(
        event,
        user=actor,
        ip=ip,
        details={
            "target_user": target_user,
            "tenant_id": tenant_id,
            "role": role,
        },
    )


def log_skill_created(
    user: str,
    skill_id: str,
    skill_name: str,
    tenant_id: str,
    ip: Optional[str] = None,
) -> None:
    """Log skill creation.

    Args:
        user: User who created the skill
        skill_id: Unique skill identifier
        skill_name: Human-readable skill name
        tenant_id: Tenant context
        ip: IP address
    """
    log_audit_event(
        AuditEvent.SKILL_CREATED,
        user=user,
        ip=ip,
        details={
            "skill_id": skill_id,
            "skill_name": skill_name,
            "tenant_id": tenant_id,
        },
    )


def log_skill_published(
    user: str,
    skill_id: str,
    skill_name: str,
    tenant_id: str,
    version: Optional[str] = None,
    ip: Optional[str] = None,
) -> None:
    """Log skill publication.

    Args:
        user: User who published the skill
        skill_id: Unique skill identifier
        skill_name: Human-readable skill name
        tenant_id: Tenant context
        version: Skill version being published
        ip: IP address
    """
    log_audit_event(
        AuditEvent.SKILL_PUBLISHED,
        user=user,
        ip=ip,
        details={
            "skill_id": skill_id,
            "skill_name": skill_name,
            "tenant_id": tenant_id,
            "version": version,
        },
    )


def log_skill_deleted(
    user: str,
    skill_id: str,
    skill_name: str,
    tenant_id: str,
    ip: Optional[str] = None,
) -> None:
    """Log skill deletion.

    Args:
        user: User who deleted the skill
        skill_id: Unique skill identifier
        skill_name: Human-readable skill name
        tenant_id: Tenant context
        ip: IP address
    """
    log_audit_event(
        AuditEvent.SKILL_DELETED,
        user=user,
        ip=ip,
        success=True,
        details={
            "skill_id": skill_id,
            "skill_name": skill_name,
            "tenant_id": tenant_id,
        },
    )


def log_rbac_permission_denied(
    user: str,
    tenant_id: str,
    permission: str,
    resource: Optional[str] = None,
    ip: Optional[str] = None,
) -> None:
    """Log RBAC permission denial.

    Args:
        user: User who was denied
        tenant_id: Tenant context
        permission: Permission that was required
        resource: Resource being accessed
        ip: IP address
    """
    log_audit_event(
        AuditEvent.RBAC_PERMISSION_DENIED,
        user=user,
        ip=ip,
        success=False,
        details={
            "tenant_id": tenant_id,
            "permission": permission,
            "resource": resource,
        },
    )
