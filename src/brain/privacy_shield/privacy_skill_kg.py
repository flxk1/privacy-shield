"""Tenant-scoped knowledge graph facts for the Privacy Shield skill.

This module stores runtime issue/solution facts as append-only JSONL.
It is intentionally lightweight and file-based so it works in local-only setups.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from brain.utils.file_io import append_jsonl, load_jsonl

PRIVACY_SKILL_ID = "privacy_shield"
PRIVACY_KG_VERSION = 1


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_tenant_id(tenant_id: str) -> str:
    raw = str(tenant_id or "").strip()
    if not raw:
        return "default"
    cleaned = "".join(ch for ch in raw if ch.isalnum() or ch in ("-", "_", "."))
    return cleaned[:80] or "default"


def _kg_dir() -> Path:
    override = str(os.environ.get("BRAIN_PRIVACY_KG_DIR", "")).strip()
    if override:
        return Path(override)
    return Path(__file__).resolve().parent.parent / "user" / "privacy_skill_kg"


def privacy_kg_path(tenant_id: str) -> Path:
    return _kg_dir() / f"{_normalize_tenant_id(tenant_id)}.jsonl"


def _build_fact_id(
    *,
    tenant_id: str,
    run_id: str,
    approval_event_id: str,
    issue_key: str,
    solution_key: str,
    status: str,
) -> str:
    digest = hashlib.sha256(
        f"{tenant_id}|{run_id}|{approval_event_id}|{issue_key}|{solution_key}|{status}".encode("utf-8")
    ).hexdigest()[:20]
    return f"pskg_{digest}"


def record_privacy_kg_fact(
    *,
    tenant_id: str,
    issue_key: str,
    issue_label: str,
    solution_key: str,
    solution_label: str,
    status: str,
    confidence_value: float,
    confidence_threshold: float,
    scope: str,
    run_id: str,
    approval_event_id: str,
    template_id: str = "",
    template_version: str = "",
    model_version: str = "",
    ruleset_version: str = "",
    input_hash: str = "",
    output_hash: str = "",
    fail_reason: str = "",
    fields_removed_minimized: Optional[List[str]] = None,
    payload_schema: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Append one issue→solution fact into the privacy skill KG."""
    tenant_norm = _normalize_tenant_id(tenant_id)
    issue_key_norm = str(issue_key or "").strip() or "unknown_issue"
    solution_key_norm = str(solution_key or "").strip() or "unknown_solution"
    status_norm = str(status or "").strip() or "unknown"

    record: Dict[str, Any] = {
        "version": PRIVACY_KG_VERSION,
        "fact_id": _build_fact_id(
            tenant_id=tenant_norm,
            run_id=str(run_id or "").strip(),
            approval_event_id=str(approval_event_id or "").strip(),
            issue_key=issue_key_norm,
            solution_key=solution_key_norm,
            status=status_norm,
        ),
        "created_at": _utc_now(),
        "tenant_id": tenant_norm,
        "skill_id": PRIVACY_SKILL_ID,
        "domain": "privacy",
        "co_domain": "compliance",
        "issue_key": issue_key_norm,
        "issue_label": str(issue_label or "").strip() or issue_key_norm,
        "solution_key": solution_key_norm,
        "solution_label": str(solution_label or "").strip() or solution_key_norm,
        "status": status_norm,
        "confidence_value": float(confidence_value or 0.0),
        "confidence_threshold": float(confidence_threshold or 0.0),
        "scope": str(scope or "").strip() or "docs",
        "run_id": str(run_id or "").strip(),
        "approval_event_id": str(approval_event_id or "").strip(),
        "template_id": str(template_id or "").strip(),
        "template_version": str(template_version or "").strip(),
        "model_version": str(model_version or "").strip(),
        "ruleset_version": str(ruleset_version or "").strip(),
        "input_hash": str(input_hash or "").strip(),
        "output_hash": str(output_hash or "").strip(),
        "fail_reason": str(fail_reason or "").strip(),
        "fields_removed_minimized": [
            str(item).strip() for item in (fields_removed_minimized or []) if str(item).strip()
        ],
        "payload_schema": dict(payload_schema or {}),
    }
    append_jsonl(privacy_kg_path(tenant_norm), record)
    return record


def list_privacy_kg_facts(
    *,
    tenant_id: str,
    limit: int = 200,
    issue_key: str = "",
    status: str = "",
) -> List[Dict[str, Any]]:
    rows = [row for row in load_jsonl(privacy_kg_path(tenant_id)) if isinstance(row, dict)]
    issue_key_norm = str(issue_key or "").strip().lower()
    status_norm = str(status or "").strip().lower()
    if issue_key_norm:
        rows = [row for row in rows if str(row.get("issue_key", "")).strip().lower() == issue_key_norm]
    if status_norm:
        rows = [row for row in rows if str(row.get("status", "")).strip().lower() == status_norm]
    if limit > 0:
        return rows[-int(limit):]
    return rows


def summarize_privacy_kg_facts(
    *,
    tenant_id: str,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    rows = list_privacy_kg_facts(tenant_id=tenant_id, limit=limit)
    grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for row in rows:
        issue_key = str(row.get("issue_key", "")).strip()
        solution_key = str(row.get("solution_key", "")).strip()
        if not issue_key or not solution_key:
            continue
        key = (issue_key, solution_key)
        entry = grouped.get(key)
        if entry is None:
            entry = {
                "issue_key": issue_key,
                "issue_label": str(row.get("issue_label", "")).strip() or issue_key,
                "solution_key": solution_key,
                "solution_label": str(row.get("solution_label", "")).strip() or solution_key,
                "facts": 0,
                "applied": 0,
                "low_confidence": 0,
                "not_applied": 0,
                "last_seen_at": "",
            }
            grouped[key] = entry
        entry["facts"] += 1
        status = str(row.get("status", "")).strip().lower()
        if status == "applied":
            entry["applied"] += 1
        elif status == "low_confidence":
            entry["low_confidence"] += 1
        else:
            entry["not_applied"] += 1
        seen = str(row.get("created_at", "")).strip()
        if seen and (not entry["last_seen_at"] or seen > entry["last_seen_at"]):
            entry["last_seen_at"] = seen
    return sorted(grouped.values(), key=lambda item: int(item.get("facts", 0)), reverse=True)

