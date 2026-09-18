"""Document helper functions.

This module contains shared document-related functions used across multiple route modules:
- Document storage and retrieval
- Document serialization
- Document context building for chat
- Folder context building
"""

from __future__ import annotations

import json
import hashlib
import logging
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Domain-agnostic document context pattern — triggers for any document reference
DOCUMENT_CONTEXT_PATTERN = re.compile(
    r"\b(document|file|attachment|uploaded|pdf|docx|report|analysis|review|"
    r"nda|contract|agreement|policy|manual|guide|specification|proposal|"
    r"brief|memo|letter|invoice|receipt|record|data|spreadsheet|csv|"
    r"image|photo|screenshot|diagram|chart)\b",
    re.IGNORECASE,
)

CONTRACT_JSON_REQUEST_RE = re.compile(
    r"\b("
    r"contract|agreement|nda|msa|clause|term sheet|purchase order|statement of work|"
    r"vertrag|vereinbarung|klausel|"
    r"contrat|accord|clause"
    r")\b",
    re.IGNORECASE,
)

STRUCTURED_OUTPUT_RE = re.compile(
    r"\b("
    r"json|schema|structured|fields?|keys?|extract|parse|convert|transform|map|output|return|"
    r"extrahier|strukturiert|felder|schlüssel|"
    r"extraire|structuré|champs?|clés?"
    r")\b",
    re.IGNORECASE,
)

_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PHONE_RE = re.compile(r"\+?\d[\d\-\s().]{7,}\d")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", re.IGNORECASE)
_LONG_NUMERIC_RE = re.compile(r"\b\d{10,}\b")
_SIGNATORY_RE = re.compile(
    r"\b(signed by|signature|executed by|signatory|unterschrift|unterzeichnet|signé par)\b[^\n]{0,160}",
    re.IGNORECASE,
)


def is_contract_json_extraction_request(message: str) -> bool:
    """Detect contract-to-JSON extraction intent for stricter safeguards."""
    text = str(message or "").strip()
    if not text:
        return False
    return bool(CONTRACT_JSON_REQUEST_RE.search(text) and STRUCTURED_OUTPUT_RE.search(text))


def sanitize_contract_context_excerpt(text: str, *, max_chars: int = 6000) -> str:
    """Redact high-risk identifiers before injecting contract excerpts into prompts."""
    excerpt = str(text or "").strip()
    if not excerpt:
        return ""
    excerpt = _EMAIL_RE.sub("[EMAIL]", excerpt)
    excerpt = _PHONE_RE.sub("[PHONE]", excerpt)
    excerpt = _IBAN_RE.sub("[IBAN]", excerpt)
    excerpt = _LONG_NUMERIC_RE.sub("[ID]", excerpt)
    excerpt = _SIGNATORY_RE.sub("[SIGNATURE REDACTED]", excerpt)
    return excerpt[: max(1, int(max_chars or 6000))]


def merge_contract_json_human_review_policy(
    policy_filter: Dict[str, Any],
    *,
    message: str,
    language: str = "en",
) -> Dict[str, Any]:
    """Force HITL review for contract-to-JSON extraction workflows."""
    out = dict(policy_filter) if isinstance(policy_filter, dict) else {}
    if not is_contract_json_extraction_request(message):
        return out

    reasons = out.get("decision_reasons", [])
    if not isinstance(reasons, list):
        reasons = []
    if "contract_json_human_oversight" not in reasons:
        reasons.append("contract_json_human_oversight")

    warnings = out.get("warnings", [])
    if not isinstance(warnings, list):
        warnings = []
    warning_text = (
        "Human oversight enforced for contract JSON extraction."
        if str(language or "en").strip().lower() != "de"
        else "Menschliche Aufsicht ist für die Vertrags-JSON-Extraktion verpflichtend."
    )
    if warning_text not in warnings:
        warnings.append(warning_text)

    matched = out.get("matched_rules", [])
    if not isinstance(matched, list):
        matched = []
    if not any(str(row.get("id", "")).strip() == "contract_json_human_oversight" for row in matched if isinstance(row, dict)):
        matched.append(
            {
                "id": "contract_json_human_oversight",
                "severity": "high",
                "description": "Contract JSON extraction requires mandatory human oversight.",
                "pattern": "contract+json",
                "jurisdictions": ["GLOBAL"],
                "skill_scopes": [],
                "module_scopes": [],
                "source": "builtin",
            }
        )

    existing_severity = str(out.get("decision_severity", "")).strip().lower()
    severity_rank = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    target_severity = "high" if severity_rank.get(existing_severity, 0) < severity_rank["high"] else existing_severity

    out["matched_rules"] = matched
    out["matched_count"] = len(matched)
    out["requires_human_review"] = True
    out["decision"] = "review_required"
    out["decision_severity"] = target_severity
    out["decision_reasons"] = reasons
    out["warnings"] = warnings
    out["contract_json_human_oversight"] = True
    if not str(out.get("sensitive_domain", "")).strip():
        out["sensitive_domain"] = "contract_json_extraction"
    return out


def load_document_rows(host_app: Any) -> List[Dict[str, Any]]:
    """Load document rows for the current user, including temporary intake documents."""
    return build_document_context_rows(host_app, include_deleted=False, include_temporary=True)


def documents_store_path(host_app: Any) -> Path:
    """Get the path to the documents store JSON file."""
    host_app._ensure_user_store()
    return host_app.USER_ROOT / "documents.json"


def temporary_documents_store_path(host_app: Any) -> Path:
    """Get the path to the temporary documents store JSON file."""
    host_app._ensure_user_store()
    return host_app.USER_ROOT / "temporary_documents.json"


def document_row_id(row: Dict[str, Any]) -> str:
    """Extract the document ID from a row."""
    return str(row.get("id", row.get("document_id", ""))).strip()


def is_document_soft_deleted(row: Dict[str, Any]) -> bool:
    """Check if a document row is soft-deleted."""
    return bool(str(row.get("deleted_at", "")).strip())


def load_documents_store(host_app: Any) -> List[Dict[str, Any]]:
    """Load all documents from the store file."""
    docs_path = documents_store_path(host_app)
    if not docs_path.exists():
        return []
    try:
        payload = json.loads(docs_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(payload, list):
        return []
    return [row for row in payload if isinstance(row, dict)]


def _cleanup_expired_temporary_document_rows(host_app: Any, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc)
    kept: List[Dict[str, Any]] = []
    removed = False
    for row in rows:
        expires_at = str(row.get("expires_at", "")).strip()
        if not expires_at:
            kept.append(row)
            continue
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except Exception:
            kept.append(row)
            continue
        if expiry > now:
            kept.append(row)
            continue
        removed = True
        path_raw = str(row.get("path", "")).strip()
        if path_raw:
            try:
                Path(path_raw).unlink(missing_ok=True)
            except Exception:
                logger.debug("Failed deleting expired temporary document %s", path_raw)
    if removed:
        save_temporary_documents_store(host_app, kept)
    return kept


def load_temporary_documents_store(host_app: Any, *, cleanup_expired: bool = True) -> List[Dict[str, Any]]:
    """Load all temporary documents from the store file."""
    docs_path = temporary_documents_store_path(host_app)
    if not docs_path.exists():
        return []
    try:
        payload = json.loads(docs_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(payload, list):
        return []
    rows = [row for row in payload if isinstance(row, dict)]
    if cleanup_expired:
        return _cleanup_expired_temporary_document_rows(host_app, rows)
    return rows


def save_documents_store(
    host_app: Any,
    rows: List[Dict[str, Any]],
    *,
    snapshot_reason: str = "",
) -> None:
    """Save documents to the store file with optional snapshot backup."""
    docs_path = documents_store_path(host_app)
    docs_path.parent.mkdir(parents=True, exist_ok=True)

    safe_reason = re.sub(r"[^A-Za-z0-9._-]+", "_", str(snapshot_reason or "").strip())[:40]
    if safe_reason and docs_path.exists():
        try:
            recovery_dir = host_app.USER_ROOT / "documents_recovery"
            recovery_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            snapshot = recovery_dir / f"documents_{stamp}_{safe_reason}.json"
            shutil.copy2(docs_path, snapshot)
            snapshots = sorted(
                recovery_dir.glob("documents_*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for old in snapshots[30:]:
                old.unlink(missing_ok=True)
        except Exception as exc:
            # `base_path` is not a name in this function, so a failed snapshot -
            # an unwritable recovery directory, a host_app with no USER_ROOT -
            # raised NameError out of save_documents_store and the store was
            # never written at all. The handler exists precisely so a snapshot
            # failure does not cost the save.
            logger.debug("Failed rotating document snapshot files for %s: %s", docs_path, exc)

    tmp_file = None
    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix="documents_",
            suffix=".json.tmp",
            dir=str(docs_path.parent),
        )
        tmp_file = Path(tmp_name)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(rows, ensure_ascii=False, indent=2) + "\n")
        os.replace(tmp_name, docs_path)
    finally:
        if tmp_file and tmp_file.exists():
            try:
                tmp_file.unlink()
            except Exception as exc:
                logger.debug("Failed deleting temporary document file %s: %s", tmp_file, exc)


def save_temporary_documents_store(host_app: Any, rows: List[Dict[str, Any]]) -> None:
    """Save temporary documents to the store file."""
    docs_path = temporary_documents_store_path(host_app)
    docs_path.parent.mkdir(parents=True, exist_ok=True)
    docs_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def serialize_document_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Serialize a document row for API response."""
    review = normalize_document_privacy_review(row)
    return {
        "id": document_row_id(row),
        "filename": str(row.get("filename", row.get("name", ""))).strip(),
        "uploaded_at": str(row.get("uploaded_at", row.get("created_at", ""))).strip(),
        "module": str(row.get("module", "")).strip(),
        "generated": bool(row.get("generated", False)),
        "generated_by": str(row.get("generated_by", "")).strip(),
        "validation_status": str(row.get("validation_status", "")).strip(),
        "citations": row.get("citations", []) if isinstance(row.get("citations"), list) else [],
        "validation": row.get("validation", {}) if isinstance(row.get("validation"), dict) else {},
        "content_origin": row.get("content_origin", {}) if isinstance(row.get("content_origin"), dict) else {},
        "disclaimer": str(row.get("disclaimer", "")).strip(),
        "security_scanned": bool(row.get("security_scanned", False)),
        "security_threats_detected": bool(row.get("security_threats_detected", False)),
        "security_sanitized": bool(row.get("security_sanitized", False)),
        "security_threat_types": row.get("security_threat_types", []) if isinstance(row.get("security_threat_types"), list) else [],
        "security_max_severity": str(row.get("security_max_severity", "")).strip(),
        "pii_detected": bool(row.get("pii_detected", False)),
        "pii_finding_count": int(row.get("pii_finding_count", 0) or 0),
        "pii_types": row.get("pii_types", []) if isinstance(row.get("pii_types"), list) else [],
        "pii_high_risk": row.get("pii_high_risk", []) if isinstance(row.get("pii_high_risk"), list) else [],
        "privacy_review": review,
        "deleted_at": str(row.get("deleted_at", "")).strip(),
        "deleted_by": str(row.get("deleted_by", "")).strip(),
        "restored_at": str(row.get("restored_at", "")).strip(),
        "storage_kind": str(row.get("storage_kind", "persistent")).strip() or "persistent",
        "project_id": str(row.get("project_id", "")).strip(),
        "temporary": bool(row.get("temporary", False)),
        "expires_at": str(row.get("expires_at", "")).strip(),
        "json_template_overlay": row.get("json_template_overlay", {}) if isinstance(row.get("json_template_overlay"), dict) else {},
    }


def serialize_document_detail_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Serialize a document row with review payload for exact-span inspection."""
    data = serialize_document_row(row)
    review = normalize_document_privacy_review(row)
    data.update({
        "text_preview": str(row.get("text_preview", "")).strip(),
        "redacted_preview": str(row.get("redacted_preview", "")).strip(),
        "pii_findings": serialize_review_findings(row.get("pii_findings", []), review),
        "json_template_overlay": row.get("json_template_overlay", {}) if isinstance(row.get("json_template_overlay"), dict) else {},
    })
    return data


def finding_review_key(finding: Dict[str, Any]) -> str:
    """Create a stable review key for a finding."""
    pii_type = str(finding.get("type", "")).strip().lower()
    value = str(finding.get("value", "")).strip()
    start = int(finding.get("start", 0) or 0)
    end = int(finding.get("end", 0) or 0)
    digest = hashlib.sha1(f"{pii_type}|{start}|{end}|{value}".encode("utf-8")).hexdigest()[:12]
    return f"psf_{digest}"


def normalize_document_privacy_review(row: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize persisted privacy review state for a document row."""
    findings = row.get("pii_findings", []) if isinstance(row.get("pii_findings"), list) else []
    raw = row.get("privacy_review", {}) if isinstance(row.get("privacy_review"), dict) else {}
    issue_states = raw.get("issue_states", {}) if isinstance(raw.get("issue_states"), dict) else {}
    valid_keys = {finding_review_key(f) for f in findings if isinstance(f, dict)}
    normalized_states: Dict[str, Dict[str, Any]] = {}
    approved_count = 0
    override_count = 0

    for key, value in issue_states.items():
        key_norm = str(key or "").strip()
        if key_norm not in valid_keys or not isinstance(value, dict):
            continue
        decision = str(value.get("decision", "")).strip().lower()
        if decision not in {"approved", "overridden"}:
            continue
        normalized_states[key_norm] = {
            "decision": decision,
            "approved_at": str(value.get("approved_at", "")).strip(),
            "approved_by": str(value.get("approved_by", "")).strip(),
            "rationale": str(value.get("rationale", "")).strip(),
        }
        if decision == "approved":
            approved_count += 1
        else:
            override_count += 1

    finding_count = len(valid_keys)
    resolved_count = approved_count + override_count
    if finding_count == 0 or resolved_count >= finding_count:
        status = "approved_override" if override_count > 0 else "approved"
    elif resolved_count > 0:
        status = "partially_approved"
    else:
        status = "pending"

    approved_at = str(raw.get("approved_at", "")).strip()
    approved_by = str(raw.get("approved_by", "")).strip()
    if status not in {"approved", "approved_override"}:
        approved_at = ""
        approved_by = ""

    return {
        "status": status,
        "issue_states": normalized_states,
        "approved_count": approved_count,
        "override_count": override_count,
        "resolved_count": resolved_count,
        "finding_count": finding_count,
        "all_approved": finding_count == 0 or approved_count >= finding_count,
        "all_resolved": finding_count == 0 or resolved_count >= finding_count,
        "approved_at": approved_at,
        "approved_by": approved_by,
    }


def serialize_review_findings(findings: Any, review: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Attach stable ids and approval state to persisted findings."""
    rows = findings if isinstance(findings, list) else []
    review_state = review if isinstance(review, dict) else {}
    issue_states = review_state.get("issue_states", {}) if isinstance(review_state.get("issue_states", {}), dict) else {}
    serialized: List[Dict[str, Any]] = []
    for finding in rows:
        if not isinstance(finding, dict):
            continue
        key = finding_review_key(finding)
        issue_state = issue_states.get(key, {}) if isinstance(issue_states.get(key), dict) else {}
        payload = dict(finding)
        payload["id"] = key
        payload["approved"] = str(issue_state.get("decision", "")).strip().lower() == "approved"
        payload["overridden"] = str(issue_state.get("decision", "")).strip().lower() == "overridden"
        payload["approved_at"] = str(issue_state.get("approved_at", "")).strip()
        payload["approved_by"] = str(issue_state.get("approved_by", "")).strip()
        payload["rationale"] = str(issue_state.get("rationale", "")).strip()
        serialized.append(payload)
    return serialized


def load_document_rows_filtered(host_app: Any, *, include_deleted: bool = False) -> List[Dict[str, Any]]:
    """Load document rows with optional deleted filter and user isolation."""
    host_app._ensure_user_store()
    current_user = str(host_app.CURRENT_USER.get() or "").strip()
    if not current_user:
        return []
    rows = load_documents_store(host_app)
    # Strict user isolation: only expose rows uploaded by current user.
    rows = [row for row in rows if str(row.get("uploaded_by", "")).strip() == current_user]
    if not include_deleted:
        rows = [row for row in rows if not is_document_soft_deleted(row)]
    rows.sort(key=lambda row: str(row.get("uploaded_at", "")).strip(), reverse=True)
    return rows


def load_temporary_document_rows_filtered(host_app: Any) -> List[Dict[str, Any]]:
    """Load temporary document rows for the current user."""
    host_app._ensure_user_store()
    current_user = str(host_app.CURRENT_USER.get() or "").strip()
    if not current_user:
        return []
    rows = load_temporary_documents_store(host_app)
    rows = [row for row in rows if str(row.get("uploaded_by", "")).strip() == current_user]
    rows.sort(key=lambda row: str(row.get("uploaded_at", "")).strip(), reverse=True)
    return rows


def find_document_row_by_id(
    host_app: Any,
    document_id: str,
    *,
    include_deleted: bool = False,
    include_temporary: bool = True,
) -> Optional[Dict[str, Any]]:
    """Find a document by id across persistent and temporary stores."""
    target_id = str(document_id or "").strip()
    if not target_id:
        return None
    for row in load_document_rows_filtered(host_app, include_deleted=include_deleted):
        if document_row_id(row) == target_id:
            return row
    if not include_temporary:
        return None
    for row in load_temporary_document_rows_filtered(host_app):
        if document_row_id(row) == target_id:
            return row
    return None


def build_document_context_rows(
    host_app: Any,
    *,
    include_deleted: bool = False,
    include_temporary: bool = True,
) -> List[Dict[str, Any]]:
    """Load document rows available for chat/document context."""
    rows = load_document_rows_filtered(host_app, include_deleted=include_deleted)
    if include_temporary:
        rows.extend(load_temporary_document_rows_filtered(host_app))
        rows.sort(key=lambda row: str(row.get("uploaded_at", "")).strip(), reverse=True)
    return rows


def document_preview_for_row(
    host_app: Any,
    row: Dict[str, Any],
    max_chars: int,
    *,
    prefer_redacted: bool = False,
    sanitize_contract_excerpt: bool = False,
) -> str:
    """Get a text preview for a document row."""
    if prefer_redacted:
        preview = str(row.get("redacted_preview", "")).strip()
        if preview:
            if sanitize_contract_excerpt:
                preview = sanitize_contract_context_excerpt(preview, max_chars=max_chars)
            return preview[:max_chars]

    preview = str(row.get("text_preview", "")).strip()
    if preview:
        if sanitize_contract_excerpt:
            preview = sanitize_contract_context_excerpt(preview, max_chars=max_chars)
        return preview[:max_chars]

    path_raw = str(row.get("path", "")).strip()
    if not path_raw:
        return ""
    path = Path(path_raw)
    if not path.exists():
        return ""
    try:
        text, _err = host_app._read_contract_file_text(path)
    except Exception:
        return ""
    text_preview = str(text or "").strip()
    if sanitize_contract_excerpt:
        text_preview = sanitize_contract_context_excerpt(text_preview, max_chars=max_chars)
    return text_preview[:max_chars]


def should_attach_document_context(message: str, module: str, has_documents: bool = False) -> bool:
    """
    Domain-agnostic document context decision.
    Attaches context when:
    - Documents are explicitly provided (has_documents=True)
    - Message mentions document-related keywords
    - Module is document-focused (doc_studio, any _review, any _analysis module)
    """
    # Always attach if documents are explicitly provided
    if has_documents:
        return True

    # Check for document-focused modules (domain-agnostic)
    module_key = str(module or "").strip().lower()
    doc_modules = {"doc_studio", "document_review", "file_analysis"}
    if module_key in doc_modules or module_key.endswith("_review") or module_key.endswith("_analysis"):
        return True

    # Check for document-related keywords in message
    return bool(DOCUMENT_CONTEXT_PATTERN.search(str(message or "")))


def build_document_context(
    host_app: Any, message: str, module: str, max_chars: int = 12000,
    document_ids: Optional[List[str]] = None,
) -> str:
    """Build document context string for RAG injection."""
    # When specific document_ids are provided, always attach context (bulk skill mode)
    if not document_ids and not should_attach_document_context(message, module):
        return ""
    rows = build_document_context_rows(host_app, include_deleted=False, include_temporary=True)
    if not rows:
        return ""

    # Filter to selected documents if specified
    if document_ids:
        id_set = set(document_ids)
        rows = [r for r in rows if str(r.get("document_id", r.get("id", ""))).strip() in id_set]

    contract_json_request = is_contract_json_extraction_request(message)
    parts: List[str] = []
    used = 0
    max_per_doc_default = min(6000, max_chars // max(len(rows), 1)) if document_ids else 6000
    max_per_doc = min(max_per_doc_default, 3200) if contract_json_request else max_per_doc_default
    for row in (rows if document_ids else rows[:2]):
        remaining = max_chars - used
        if remaining <= 0:
            break
        excerpt = document_preview_for_row(
            host_app,
            row,
            max_chars=min(max_per_doc, remaining),
            prefer_redacted=contract_json_request,
            sanitize_contract_excerpt=contract_json_request,
        )
        if not excerpt:
            continue
        doc_id = str(row.get("document_id", row.get("id", ""))).strip()
        filename = str(row.get("filename", row.get("name", ""))).strip() or "document"
        prefix = "[Sanitized excerpt for structured contract extraction]\n" if contract_json_request else ""
        block = f"Document: {filename} ({doc_id or 'n/a'})\n{prefix}{excerpt}"
        parts.append(block)
        used += len(block)
    return "\n\n".join(parts)


def build_folder_context(host_app: Any, folder_path: str, max_chars: int = 20000) -> str:
    """Read text-parseable files from a folder and build context for RAG injection."""
    target = Path(folder_path)
    if not target.is_dir():
        return ""

    TEXT_EXTS = {".txt", ".md", ".csv", ".json", ".jsonl", ".py", ".js", ".ts", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".xml", ".html", ".css"}
    PARSEABLE_EXTS = {".pdf", ".docx", ".doc"}

    # Collect files sorted by mtime desc (most recent first)
    file_entries = []
    try:
        for entry in target.iterdir():
            if entry.name.startswith(".") or not entry.is_file():
                continue
            try:
                st = entry.stat()
                file_entries.append((entry, st.st_mtime, st.st_size))
            except (PermissionError, OSError):
                continue
    except (PermissionError, OSError):
        return ""

    file_entries.sort(key=lambda x: x[1], reverse=True)  # newest first

    parts: List[str] = []
    used = 0
    for entry, _mtime, size in file_entries:
        if used >= max_chars:
            break
        remaining = max_chars - used
        suffix = entry.suffix.lower()
        text = ""
        try:
            if suffix in TEXT_EXTS:
                text = entry.read_text(errors="replace")[:remaining]
            elif suffix in PARSEABLE_EXTS and hasattr(host_app, "_read_contract_file_text"):
                text = str(host_app._read_contract_file_text(str(entry)) or "")[:remaining]
        except Exception as exc:
            # A file that cannot be read drops out of the context with no trace
            # in the returned string, so the caller cannot tell a folder of
            # three documents from a folder of three where two failed to open.
            # The return type is a str and cannot carry that, so the log is the
            # only channel there is - it must at least exist.
            logger.debug("skipping unreadable folder-context file %s: %s", entry, exc)
            continue
        if not text.strip():
            continue
        size_label = f"{size}" if size < 1024 else f"{size / 1024:.1f}KB"
        block = f"File: {entry.name} ({size_label})\n{text.strip()}"
        parts.append(block)
        used += len(block)

    return "\n\n".join(parts)


# Aliases with underscore prefix for backward compatibility
_DOCUMENT_CONTEXT_PATTERN = DOCUMENT_CONTEXT_PATTERN
_load_document_rows = load_document_rows
_documents_store_path = documents_store_path
_document_row_id = document_row_id
_is_document_soft_deleted = is_document_soft_deleted
_load_documents_store = load_documents_store
_save_documents_store = save_documents_store
_serialize_document_row = serialize_document_row
_load_document_rows_filtered = load_document_rows_filtered
_document_preview_for_row = document_preview_for_row
_should_attach_document_context = should_attach_document_context
_build_document_context = build_document_context
_build_folder_context = build_folder_context
_is_contract_json_extraction_request = is_contract_json_extraction_request
_sanitize_contract_context_excerpt = sanitize_contract_context_excerpt
_merge_contract_json_human_review_policy = merge_contract_json_human_review_policy
