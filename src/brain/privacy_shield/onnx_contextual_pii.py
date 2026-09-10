"""Feature contract for the first Privacy Shield ONNX model.

Model: ps-contextual-pii-v1
Task: sequence-level contextual PII classification in shadow mode

The contract is intentionally simple and stable:
- one float input tensor with shape [1, feature_count]
- output score interpreted as probability of contextual PII
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

import numpy as np

from .scanner import Finding, PIIType, ScanResult


FEATURE_NAMES: List[str] = [
    "text_length_log",
    "token_count_log",
    "digit_ratio",
    "uppercase_ratio",
    "direct_identifier_count",
    "name_finding_count",
    "address_finding_count",
    "special_category_count",
    "name_label_hit",
    "email_label_hit",
    "phone_label_hit",
    "address_label_hit",
    "honorific_hit",
    "sensitive_lexicon_hit",
    "project_context_hit",
    "internal_reference_hit",
]

_NAME_LABELS = {"name", "full name", "vorname", "nachname", "nom", "nombre"}
_EMAIL_LABELS = {"email", "e-mail", "mail", "correo"}
_PHONE_LABELS = {"phone", "telefon", "mobile", "tel", "telefono"}
_ADDRESS_LABELS = {"address", "adresse", "dirección", "endereço"}
_HONORIFICS = {"mr", "mrs", "ms", "dr", "prof", "herr", "frau", "madame", "monsieur", "sr", "sra"}
_SENSITIVE_TERMS = {
    "health",
    "medical",
    "patient",
    "diagnosis",
    "religion",
    "political",
    "union",
    "biometric",
    "criminal",
    "genetic",
    "krankheit",
    "diagnose",
    "religion",
    "politique",
    "salud",
}
_PROJECT_TERMS = {"project", "projekt", "product", "initiative", "codename", "code name"}
_INTERNAL_TERMS = {"ticket", "jira", "asana", "linear", "internal", "confidential", "draft", "version"}


def _count_findings(findings: List[Finding], pii_types: set[PIIType]) -> int:
    return sum(1 for finding in findings if finding.pii_type in pii_types)


def _contains_any(text_lower: str, phrases: set[str]) -> float:
    return 1.0 if any(phrase in text_lower for phrase in phrases) else 0.0


def extract_contextual_pii_features(text: str, regex_result: ScanResult) -> np.ndarray:
    text = text or ""
    text_lower = text.lower()
    tokens = re.findall(r"\w+", text, re.UNICODE)
    token_count = len(tokens)
    text_length = len(text)

    digits = sum(1 for ch in text if ch.isdigit())
    uppers = sum(1 for ch in text if ch.isupper())

    direct_identifier_types = {
        PIIType.EMAIL,
        PIIType.PHONE,
        PIIType.IBAN,
        PIIType.CREDIT_CARD,
        PIIType.IP_ADDRESS,
        PIIType.STEUER_ID,
        PIIType.SVNR,
        PIIType.PASSPORT,
        PIIType.ID_CARD,
    }
    special_category_types = {
        PIIType.HEALTH_DATA,
        PIIType.ICD_CODE,
        PIIType.BIOMETRIC,
        PIIType.POLITICAL,
        PIIType.RELIGIOUS,
        PIIType.UNION,
        PIIType.SEXUAL,
        PIIType.CRIMINAL,
        PIIType.GENETIC,
    }

    features = np.array(
        [
            np.log1p(text_length),
            np.log1p(token_count),
            digits / max(text_length, 1),
            uppers / max(text_length, 1),
            float(_count_findings(regex_result.findings, direct_identifier_types)),
            float(_count_findings(regex_result.findings, {PIIType.NAME})),
            float(_count_findings(regex_result.findings, {PIIType.ADDRESS, PIIType.PLZ_CITY})),
            float(_count_findings(regex_result.findings, special_category_types)),
            _contains_any(text_lower, _NAME_LABELS),
            _contains_any(text_lower, _EMAIL_LABELS),
            _contains_any(text_lower, _PHONE_LABELS),
            _contains_any(text_lower, _ADDRESS_LABELS),
            _contains_any(text_lower, _HONORIFICS),
            _contains_any(text_lower, _SENSITIVE_TERMS),
            _contains_any(text_lower, _PROJECT_TERMS),
            _contains_any(text_lower, _INTERNAL_TERMS),
        ],
        dtype=np.float32,
    )
    return features.reshape(1, len(FEATURE_NAMES))


def run_contextual_pii_session(session: Any, features: np.ndarray) -> Dict[str, Any]:
    inputs = session.get_inputs()
    outputs = session.get_outputs()
    if not inputs:
        raise ValueError("onnx_session_missing_inputs")
    input_name = inputs[0].name
    raw_outputs = session.run(None, {input_name: features})

    score = 0.0
    label = "no_contextual_pii"
    if raw_outputs:
        first = raw_outputs[0]
        if hasattr(first, "tolist"):
            first = first.tolist()
        if isinstance(first, list):
            if first and isinstance(first[0], list):
                row = first[0]
                if row:
                    score = float(row[-1])
            elif first:
                score = float(first[-1])
        else:
            score = float(first)

    if len(raw_outputs) > 1:
        second = raw_outputs[1]
        if hasattr(second, "tolist"):
            second = second.tolist()
        if isinstance(second, list) and second:
            maybe_label = second[0]
            if isinstance(maybe_label, bytes):
                maybe_label = maybe_label.decode("utf-8", errors="ignore")
            label = str(maybe_label)

    contextual_pii = score >= 0.5 or label == "contextual_pii"
    return {
        "contextual_pii": contextual_pii,
        "score": score,
        "label": "contextual_pii" if contextual_pii else label,
        "input_count": len(inputs),
        "output_count": len(outputs),
        "feature_count": int(features.shape[1]),
    }
