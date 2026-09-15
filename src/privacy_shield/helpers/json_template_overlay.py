"""Focused JSON template overlay for approved document reviews.

Applies a deterministic structured overlay only when confidence meets threshold.
If confidence is below threshold, this helper performs a no-op.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from privacy_shield.audit_log import AuditEvent, log_audit_event
from privacy_shield.helpers.documents import sanitize_contract_context_excerpt
from privacy_shield.privacy_skill_kg import record_privacy_kg_fact

TEMPLATE_CONFIDENCE_THRESHOLD = 0.9
TEMPLATE_VERSION = "v1"
RULESET_VERSION = "privacy_shield_ruleset_v1"

_CONTRACT_HINT_RE = re.compile(
    r"\b(contract|agreement|nda|msa|sow|clause|terms?|bedingungen|vertrag|vereinbarung)\b",
    re.IGNORECASE,
)
_INVOICE_HINT_RE = re.compile(
    r"\b(invoice|rechnung|bill|total|amount due|vat|mwst|ust)\b",
    re.IGNORECASE,
)
_CLAUSE_HEADER_RE = re.compile(
    r"(?im)^\s*(?:\d+(?:\.\d+)*[.)]?|§\s*\d+[a-z]?)\s+([^\n]{2,180})$|^\s*(?:clause|section|artikel|art\.)\s*[0-9a-z.:-]*\s*([^\n]{0,180})$",
)
_MONEY_RE = re.compile(r"\b\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})\b")

_MINIMIZED_FIELDS_BY_TEMPLATE: Dict[str, List[str]] = {
    "contract_clause_only": [
        "rubrum",
        "party_identity",
        "emails",
        "phones",
        "addresses",
        "id_numbers",
    ],
    "invoice_numeric_aggregate": [
        "counterparty_identity",
        "line_item_descriptions",
        "free_text_notes",
        "emails",
        "phones",
        "addresses",
    ],
}

_KG_TEMPLATE_FACTS: Dict[str, Dict[str, str]] = {
    "contract_clause_only": {
        "issue_key": "secret_contract_clause",
        "issue_label": "Secret contract clause or confidential contract section",
        "solution_key": "contract_clause_json_placeholder",
        "solution_label": "Extract clause-only JSON and replace sensitive identity fields with placeholders",
    },
    "invoice_numeric_aggregate": {
        "issue_key": "invoice_sensitive_data",
        "issue_label": "Invoice contains sensitive counterparty or free-text references",
        "solution_key": "invoice_numeric_json_placeholder",
        "solution_label": "Extract numeric-only invoice JSON and replace identity fields with placeholders",
    },
}

_KG_FAIL_REASON_FACTS: Dict[str, Dict[str, str]] = {
    "review_not_resolved": {
        "issue_key": "review_not_resolved",
        "issue_label": "Privacy review still has unresolved items",
        "solution_key": "resolve_review_first",
        "solution_label": "Resolve or override all review issues before template extraction",
    },
    "empty_input": {
        "issue_key": "empty_input",
        "issue_label": "No eligible content was provided for template extraction",
        "solution_key": "provide_scannable_content",
        "solution_label": "Provide a document body or preview text before running template extraction",
    },
    "template_not_matched": {
        "issue_key": "template_not_matched",
        "issue_label": "No supported privacy template matched the document",
        "solution_key": "manual_review_path",
        "solution_label": "Continue with manual issue-level review and approval",
    },
}


def _hash_text(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _hash_json(payload: Dict[str, Any]) -> str:
    raw = jsonable_dumps(payload)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def jsonable_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _scope_from_record(record: Dict[str, Any]) -> str:
    source_kind = str(record.get("source_kind", "")).strip().lower()
    if source_kind in {"upload", "document", "docs"}:
        return "docs"
    return "folder"


def _model_version_from_record(record: Dict[str, Any]) -> str:
    for key in ("local_model_id", "model_used", "model_version"):
        value = str(record.get(key, "")).strip()
        if value:
            return value
    return "deterministic_template_classifier_v1"


def _emit_controlled_decision_event(
    *,
    approval_event_id: str,
    run_id: str,
    user: str,
    scope: str,
    confidence_value: float,
    confidence_threshold: float,
    selected_template_id: str,
    selected_template_version: str,
    extractor_version: str,
    model_version: str,
    ruleset_version: str,
    payload_schema: Dict[str, Any],
    fields_removed_minimized: List[str],
    input_hash: str,
    output_hash: str,
    fail_reason: str,
    tenant_id: str = "",
) -> None:
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    log_audit_event(
        AuditEvent.AI_PRIVACY_SHIELD_DECISION,
        user=user or None,
        tenant_id=tenant_id or None,
        details={
            "approval_event_id": approval_event_id,
            "run_id": run_id,
            "user": user,
            "timestamp": timestamp,
            "scope": scope,
            "confidence_value": round(float(confidence_value), 4),
            "confidence_threshold": float(confidence_threshold),
            "selected_template_id": selected_template_id,
            "selected_template_version": selected_template_version,
            "extractor_version": extractor_version,
            "model_version": model_version,
            "ruleset_version": ruleset_version,
            "payload_schema": payload_schema,
            "fields_removed_minimized": fields_removed_minimized,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "fail_reason": fail_reason,
            "applied": not bool(fail_reason),
        },
    )


def _kg_labels_for_decision(*, template_id: str, fail_reason: str) -> Tuple[str, str, str, str]:
    template_key = str(template_id or "").strip()
    fail_key = str(fail_reason or "").strip()
    if template_key and template_key in _KG_TEMPLATE_FACTS:
        selected = _KG_TEMPLATE_FACTS[template_key]
        return (
            selected["issue_key"],
            selected["issue_label"],
            selected["solution_key"],
            selected["solution_label"],
        )
    if fail_key and fail_key in _KG_FAIL_REASON_FACTS:
        selected = _KG_FAIL_REASON_FACTS[fail_key]
        return (
            selected["issue_key"],
            selected["issue_label"],
            selected["solution_key"],
            selected["solution_label"],
        )
    return (
        "privacy_decision",
        "Privacy Shield decision event",
        "review_privacy_decision",
        "Review Privacy Shield decision details and proceed with the recommended flow",
    )


def _kg_status_from_fail_reason(fail_reason: str) -> str:
    reason = str(fail_reason or "").strip()
    if not reason:
        return "applied"
    if reason == "below_threshold":
        return "low_confidence"
    return "not_applied"


def _emit_privacy_skill_kg_fact(
    *,
    tenant_id: str,
    scope: str,
    confidence_value: float,
    confidence_threshold: float,
    selected_template_id: str,
    selected_template_version: str,
    model_version: str,
    ruleset_version: str,
    payload_schema: Dict[str, Any],
    fields_removed_minimized: List[str],
    input_hash: str,
    output_hash: str,
    fail_reason: str,
    run_id: str,
    approval_event_id: str,
) -> None:
    try:
        issue_key, issue_label, solution_key, solution_label = _kg_labels_for_decision(
            template_id=selected_template_id,
            fail_reason=fail_reason,
        )
        record_privacy_kg_fact(
            tenant_id=tenant_id or "default",
            issue_key=issue_key,
            issue_label=issue_label,
            solution_key=solution_key,
            solution_label=solution_label,
            status=_kg_status_from_fail_reason(fail_reason),
            confidence_value=confidence_value,
            confidence_threshold=confidence_threshold,
            scope=scope,
            run_id=run_id,
            approval_event_id=approval_event_id,
            template_id=selected_template_id,
            template_version=selected_template_version,
            model_version=model_version,
            ruleset_version=ruleset_version,
            input_hash=input_hash,
            output_hash=output_hash,
            fail_reason=fail_reason,
            fields_removed_minimized=fields_removed_minimized,
            payload_schema=payload_schema,
        )
    except Exception:
        # Privacy KG must be best-effort and never block primary review flow.
        return


def _to_float(value: str) -> Optional[float]:
    text = str(value or "").strip()
    if not text:
        return None
    # 1.234,56 or 1,234.56 or 1234.56
    if "," in text and "." in text:
        if text.rfind(",") > text.rfind("."):
            text = text.replace(".", "").replace(",", ".")
        else:
            text = text.replace(",", "")
    else:
        text = text.replace(",", ".")
    try:
        return float(text)
    except Exception:
        return None


def _split_contract_clauses(text: str) -> List[Dict[str, Any]]:
    source = str(text or "").strip()
    if not source:
        return []

    headers = list(_CLAUSE_HEADER_RE.finditer(source))
    if not headers:
        return []

    clauses: List[Dict[str, Any]] = []
    for idx, match in enumerate(headers):
        start = match.start()
        end = headers[idx + 1].start() if idx + 1 < len(headers) else len(source)
        chunk = source[start:end].strip()
        if not chunk:
            continue
        title = str(match.group(1) or match.group(2) or "").strip()
        cleaned = sanitize_contract_context_excerpt(chunk, max_chars=2400)
        if not cleaned:
            continue
        clauses.append(
            {
                "index": len(clauses),
                "title": title or f"Clause {len(clauses) + 1}",
                "text": cleaned,
            }
        )
    return clauses[:40]


def _extract_invoice_numbers(text: str) -> List[Dict[str, Any]]:
    numbers: List[Dict[str, Any]] = []
    for raw in _MONEY_RE.findall(str(text or "")):
        numeric = _to_float(raw)
        if numeric is None:
            continue
        numbers.append({"raw": raw, "value": numeric})
    # keep deterministic order and bounded payload
    return numbers[:200]


def _estimate_template_confidence(template_id: str, *, filename: str, text: str, payload: Dict[str, Any]) -> float:
    filename_norm = str(filename or "").strip().lower()
    text_norm = str(text or "")

    if template_id == "contract_clause_only":
        score = 0.0
        if _CONTRACT_HINT_RE.search(filename_norm) or _CONTRACT_HINT_RE.search(text_norm):
            score += 0.5
        clause_count = int(payload.get("clause_count", 0) or 0)
        if clause_count >= 3:
            score += 0.35
        elif clause_count >= 1:
            score += 0.2
        if len(text_norm) >= 400:
            score += 0.1
        return min(0.99, max(0.0, score))

    if template_id == "invoice_numeric_aggregate":
        score = 0.0
        if _INVOICE_HINT_RE.search(filename_norm) or _INVOICE_HINT_RE.search(text_norm):
            score += 0.5
        number_count = int(payload.get("number_count", 0) or 0)
        if number_count >= 8:
            score += 0.35
        elif number_count >= 3:
            score += 0.2
        if any(tag in text_norm.lower() for tag in ("total", "summe", "vat", "mwst", "tax")):
            score += 0.1
        return min(0.99, max(0.0, score))

    return 0.0


def _build_template_payload(*, filename: str, text: str) -> Tuple[Optional[str], Dict[str, Any]]:
    filename_norm = str(filename or "").strip().lower()
    text_norm = str(text or "")

    contract_hit = bool(_CONTRACT_HINT_RE.search(filename_norm) or _CONTRACT_HINT_RE.search(text_norm))
    invoice_hit = bool(_INVOICE_HINT_RE.search(filename_norm) or _INVOICE_HINT_RE.search(text_norm))

    if contract_hit:
        clauses = _split_contract_clauses(text_norm)
        if clauses:
            return "contract_clause_only", {
                "clause_count": len(clauses),
                "clauses": clauses,
            }

    if invoice_hit:
        numbers = _extract_invoice_numbers(text_norm)
        if numbers:
            numeric_values = [row["value"] for row in numbers if isinstance(row, dict) and isinstance(row.get("value"), (int, float))]
            top_values = sorted(numeric_values, reverse=True)[:5]
            return "invoice_numeric_aggregate", {
                "number_count": len(numbers),
                "numbers": numbers,
                "largest_values": top_values,
            }

    return None, {}


def maybe_apply_json_template_overlay(
    record: Dict[str, Any],
    *,
    review: Optional[Dict[str, Any]] = None,
    threshold: float = TEMPLATE_CONFIDENCE_THRESHOLD,
    user: str = "",
    scope: str = "",
) -> Dict[str, Any]:
    """Apply focused JSON template overlay if confidence meets threshold.

    Behavior contract:
    - If confidence < threshold: no-op (no overlay added).
    - If confidence >= threshold: persist json_template_overlay payload.
    """
    out = dict(record or {})
    approval_event_id = f"approval_{secrets.token_hex(8)}"
    run_id = f"psrun_{secrets.token_hex(8)}"
    actor = str(user or out.get("uploaded_by", "")).strip()
    scope_value = str(scope or _scope_from_record(out)).strip() or "docs"
    confidence_value = 0.0
    selected_template_id = ""
    extractor_version = "none"
    payload_schema: Dict[str, Any] = {"type": "object", "fields": []}
    fields_removed_minimized: List[str] = []
    model_version = _model_version_from_record(out)
    tenant_id = str(out.get("tenant_id", "")).strip()
    source_text_for_hash = str(out.get("text_preview", "") or "")
    input_hash = _hash_text(source_text_for_hash)
    output_hash = input_hash
    fail_reason = ""

    review_state = review if isinstance(review, dict) else {}
    if not review_state:
        privacy = out.get("privacy_review", {}) if isinstance(out.get("privacy_review"), dict) else {}
        # all_resolved can be passed by caller via normalized review or inferred from status
        status = str(privacy.get("status", "")).strip().lower()
        review_state = {"all_resolved": status in {"approved", "approved_override"}}

    if not bool(review_state.get("all_resolved", False)):
        out.pop("json_template_overlay", None)
        fail_reason = "review_not_resolved"
        _emit_controlled_decision_event(
            approval_event_id=approval_event_id,
            run_id=run_id,
            user=actor,
            scope=scope_value,
            confidence_value=confidence_value,
            confidence_threshold=threshold,
            selected_template_id=selected_template_id,
            selected_template_version=TEMPLATE_VERSION,
            extractor_version=extractor_version,
            model_version=model_version,
            ruleset_version=RULESET_VERSION,
            payload_schema=payload_schema,
            fields_removed_minimized=fields_removed_minimized,
            input_hash=input_hash,
            output_hash=output_hash,
            fail_reason=fail_reason,
            tenant_id=tenant_id,
        )
        _emit_privacy_skill_kg_fact(
            tenant_id=tenant_id,
            scope=scope_value,
            confidence_value=confidence_value,
            confidence_threshold=threshold,
            selected_template_id=selected_template_id,
            selected_template_version=TEMPLATE_VERSION,
            model_version=model_version,
            ruleset_version=RULESET_VERSION,
            payload_schema=payload_schema,
            fields_removed_minimized=fields_removed_minimized,
            input_hash=input_hash,
            output_hash=output_hash,
            fail_reason=fail_reason,
            run_id=run_id,
            approval_event_id=approval_event_id,
        )
        return out

    filename = str(out.get("filename", "") or "").strip()
    text = str(out.get("text_preview", "") or "").strip()
    if not filename and not text:
        out.pop("json_template_overlay", None)
        fail_reason = "empty_input"
        _emit_controlled_decision_event(
            approval_event_id=approval_event_id,
            run_id=run_id,
            user=actor,
            scope=scope_value,
            confidence_value=confidence_value,
            confidence_threshold=threshold,
            selected_template_id=selected_template_id,
            selected_template_version=TEMPLATE_VERSION,
            extractor_version=extractor_version,
            model_version=model_version,
            ruleset_version=RULESET_VERSION,
            payload_schema=payload_schema,
            fields_removed_minimized=fields_removed_minimized,
            input_hash=input_hash,
            output_hash=output_hash,
            fail_reason=fail_reason,
            tenant_id=tenant_id,
        )
        _emit_privacy_skill_kg_fact(
            tenant_id=tenant_id,
            scope=scope_value,
            confidence_value=confidence_value,
            confidence_threshold=threshold,
            selected_template_id=selected_template_id,
            selected_template_version=TEMPLATE_VERSION,
            model_version=model_version,
            ruleset_version=RULESET_VERSION,
            payload_schema=payload_schema,
            fields_removed_minimized=fields_removed_minimized,
            input_hash=input_hash,
            output_hash=output_hash,
            fail_reason=fail_reason,
            run_id=run_id,
            approval_event_id=approval_event_id,
        )
        return out

    template_id, payload = _build_template_payload(filename=filename, text=text)
    if not template_id or not payload:
        out.pop("json_template_overlay", None)
        fail_reason = "template_not_matched"
        _emit_controlled_decision_event(
            approval_event_id=approval_event_id,
            run_id=run_id,
            user=actor,
            scope=scope_value,
            confidence_value=confidence_value,
            confidence_threshold=threshold,
            selected_template_id=selected_template_id,
            selected_template_version=TEMPLATE_VERSION,
            extractor_version=extractor_version,
            model_version=model_version,
            ruleset_version=RULESET_VERSION,
            payload_schema=payload_schema,
            fields_removed_minimized=fields_removed_minimized,
            input_hash=input_hash,
            output_hash=output_hash,
            fail_reason=fail_reason,
            tenant_id=tenant_id,
        )
        _emit_privacy_skill_kg_fact(
            tenant_id=tenant_id,
            scope=scope_value,
            confidence_value=confidence_value,
            confidence_threshold=threshold,
            selected_template_id=selected_template_id,
            selected_template_version=TEMPLATE_VERSION,
            model_version=model_version,
            ruleset_version=RULESET_VERSION,
            payload_schema=payload_schema,
            fields_removed_minimized=fields_removed_minimized,
            input_hash=input_hash,
            output_hash=output_hash,
            fail_reason=fail_reason,
            run_id=run_id,
            approval_event_id=approval_event_id,
        )
        return out

    selected_template_id = template_id
    extractor_version = f"{template_id}_extractor_v1"
    payload_schema = {"type": "object", "fields": sorted([str(k) for k in payload.keys()])}
    fields_removed_minimized = list(_MINIMIZED_FIELDS_BY_TEMPLATE.get(template_id, []))
    confidence = _estimate_template_confidence(
        template_id,
        filename=filename,
        text=text,
        payload=payload,
    )
    confidence_value = float(confidence)
    if float(confidence) < float(threshold):
        out.pop("json_template_overlay", None)
        fail_reason = "below_threshold"
        _emit_controlled_decision_event(
            approval_event_id=approval_event_id,
            run_id=run_id,
            user=actor,
            scope=scope_value,
            confidence_value=confidence_value,
            confidence_threshold=threshold,
            selected_template_id=selected_template_id,
            selected_template_version=TEMPLATE_VERSION,
            extractor_version=extractor_version,
            model_version=model_version,
            ruleset_version=RULESET_VERSION,
            payload_schema=payload_schema,
            fields_removed_minimized=fields_removed_minimized,
            input_hash=input_hash,
            output_hash=output_hash,
            fail_reason=fail_reason,
            tenant_id=tenant_id,
        )
        _emit_privacy_skill_kg_fact(
            tenant_id=tenant_id,
            scope=scope_value,
            confidence_value=confidence_value,
            confidence_threshold=threshold,
            selected_template_id=selected_template_id,
            selected_template_version=TEMPLATE_VERSION,
            model_version=model_version,
            ruleset_version=RULESET_VERSION,
            payload_schema=payload_schema,
            fields_removed_minimized=fields_removed_minimized,
            input_hash=input_hash,
            output_hash=output_hash,
            fail_reason=fail_reason,
            run_id=run_id,
            approval_event_id=approval_event_id,
        )
        return out

    output_hash = _hash_json(payload)
    out["json_template_overlay"] = {
        "template_id": template_id,
        "template_version": TEMPLATE_VERSION,
        "confidence": round(float(confidence), 4),
        "threshold": float(threshold),
        "approval_event_id": approval_event_id,
        "run_id": run_id,
        "applied_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "payload": payload,
    }
    _emit_controlled_decision_event(
        approval_event_id=approval_event_id,
        run_id=run_id,
        user=actor,
        scope=scope_value,
        confidence_value=confidence_value,
        confidence_threshold=threshold,
        selected_template_id=selected_template_id,
        selected_template_version=TEMPLATE_VERSION,
        extractor_version=extractor_version,
        model_version=model_version,
        ruleset_version=RULESET_VERSION,
        payload_schema=payload_schema,
        fields_removed_minimized=fields_removed_minimized,
        input_hash=input_hash,
        output_hash=output_hash,
        fail_reason="",
        tenant_id=tenant_id,
    )
    _emit_privacy_skill_kg_fact(
        tenant_id=tenant_id,
        scope=scope_value,
        confidence_value=confidence_value,
        confidence_threshold=threshold,
        selected_template_id=selected_template_id,
        selected_template_version=TEMPLATE_VERSION,
        model_version=model_version,
        ruleset_version=RULESET_VERSION,
        payload_schema=payload_schema,
        fields_removed_minimized=fields_removed_minimized,
        input_hash=input_hash,
        output_hash=output_hash,
        fail_reason="",
        run_id=run_id,
        approval_event_id=approval_event_id,
    )
    return out
