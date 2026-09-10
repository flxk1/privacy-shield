"""ONNX shadow-evaluation hook for Privacy Shield.

This module does not alter live Privacy Shield findings. It loads an ONNX
session in shadow mode, records runtime metadata, and leaves promotion
decisions to the scorecard/evidence process.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional

from .scanner import ScanResult


def _truthy(value: str) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class OnnxShadowResult:
    mode: str = "off"
    available: bool = False
    executed: bool = False
    model_id: Optional[str] = None
    model_path: Optional[str] = None
    provider: str = "onnxruntime"
    execution_provider: Optional[str] = None
    device_class: str = "desktop"
    available_execution_providers: List[str] = field(default_factory=list)
    candidate_count: int = 0
    processing_time_ms: float = 0.0
    input_count: int = 0
    output_count: int = 0
    score: Optional[float] = None
    label: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "available": self.available,
            "executed": self.executed,
            "model_id": self.model_id,
            "model_path": self.model_path,
            "provider": self.provider,
            "execution_provider": self.execution_provider,
            "device_class": self.device_class,
            "available_execution_providers": self.available_execution_providers,
            "candidate_count": self.candidate_count,
            "processing_time_ms": self.processing_time_ms,
            "input_count": self.input_count,
            "output_count": self.output_count,
            "score": self.score,
            "label": self.label,
            "error": self.error,
        }


def get_onnx_shadow_mode() -> str:
    mode = str(os.getenv("BRAIN_PRIVACY_SHIELD_ONNX_MODE", "off")).strip().lower()
    if mode not in {"off", "shadow"}:
        return "off"
    return mode


def get_device_class() -> str:
    device_class = str(os.getenv("BRAIN_DEVICE_CLASS", "desktop")).strip().lower()
    if device_class not in {"desktop", "mobile", "tablet"}:
        return "desktop"
    return device_class


def is_onnx_runtime_available() -> bool:
    if _truthy(os.getenv("BRAIN_PRIVACY_SHIELD_ONNX_AVAILABLE", "")):
        return True
    return importlib.util.find_spec("onnxruntime") is not None


def get_onnx_model_id() -> Optional[str]:
    model_id = str(os.getenv("BRAIN_PRIVACY_SHIELD_ONNX_MODEL_ID", "")).strip()
    return model_id or None


def get_onnx_model_path() -> Optional[str]:
    model_path = str(os.getenv("BRAIN_PRIVACY_SHIELD_ONNX_MODEL_PATH", "")).strip()
    return model_path or None


def _get_onnxruntime_module() -> Any:
    return importlib.import_module("onnxruntime")


def get_available_onnx_execution_providers() -> List[str]:
    if not is_onnx_runtime_available():
        return []
    try:
        ort = _get_onnxruntime_module()
        providers = ort.get_available_providers()
        return [str(provider) for provider in providers]
    except Exception:
        return []


def choose_onnx_execution_provider(
    *,
    device_class: Optional[str] = None,
    platform: Optional[str] = None,
    available_providers: Optional[List[str]] = None,
) -> Optional[str]:
    device = device_class or get_device_class()
    current_platform = platform or sys.platform
    providers = available_providers or get_available_onnx_execution_providers()
    provider_set = set(providers)

    preference_order: List[str]
    if current_platform == "darwin":
        preference_order = ["CoreMLExecutionProvider", "XNNPACKExecutionProvider", "CPUExecutionProvider"]
    elif current_platform.startswith("win"):
        preference_order = ["DmlExecutionProvider", "CPUExecutionProvider"]
    elif device in {"mobile", "tablet"} and "NNAPIExecutionProvider" in provider_set:
        preference_order = ["NNAPIExecutionProvider", "XNNPACKExecutionProvider", "CPUExecutionProvider"]
    else:
        preference_order = ["XNNPACKExecutionProvider", "QNNExecutionProvider", "CPUExecutionProvider"]

    for provider in preference_order:
        if provider in provider_set:
            return provider
    return providers[0] if providers else None


def load_onnx_shadow_session(
    *,
    model_path: str,
    execution_provider: Optional[str] = None,
) -> Any:
    ort = _get_onnxruntime_module()
    providers = [execution_provider] if execution_provider else None
    session_options = ort.SessionOptions()
    return ort.InferenceSession(model_path, sess_options=session_options, providers=providers)


def run_onnx_shadow_scan(text: str, regex_result: ScanResult) -> OnnxShadowResult:
    start = time.perf_counter()
    available_providers = get_available_onnx_execution_providers()
    device_class = get_device_class()
    result = OnnxShadowResult(
        mode=get_onnx_shadow_mode(),
        available=is_onnx_runtime_available(),
        model_id=get_onnx_model_id(),
        model_path=get_onnx_model_path(),
        device_class=device_class,
        available_execution_providers=available_providers,
    )

    if result.mode != "shadow":
        result.processing_time_ms = (time.perf_counter() - start) * 1000
        return result

    if not result.available:
        result.error = "onnxruntime_unavailable"
        result.processing_time_ms = (time.perf_counter() - start) * 1000
        return result

    if not result.model_id:
        result.error = "onnx_model_unconfigured"
        result.processing_time_ms = (time.perf_counter() - start) * 1000
        return result

    if not result.model_path:
        result.error = "onnx_model_path_unconfigured"
        result.processing_time_ms = (time.perf_counter() - start) * 1000
        return result

    model_file = Path(result.model_path)
    if not model_file.exists():
        result.error = "onnx_model_path_missing"
        result.processing_time_ms = (time.perf_counter() - start) * 1000
        return result

    execution_provider = choose_onnx_execution_provider(
        device_class=device_class,
        available_providers=available_providers,
    )
    result.execution_provider = execution_provider
    result.candidate_count = max(len(regex_result.findings), 1 if text.strip() else 0)

    try:
        session = load_onnx_shadow_session(
            model_path=str(model_file),
            execution_provider=execution_provider,
        )
        result.executed = True
        if result.model_id == "ps-contextual-pii-v1":
            from .onnx_contextual_pii import (
                extract_contextual_pii_features,
                run_contextual_pii_session,
            )

            features = extract_contextual_pii_features(text, regex_result)
            prediction = run_contextual_pii_session(session, features)
            result.input_count = prediction["input_count"]
            result.output_count = prediction["output_count"]
            result.score = prediction["score"]
            result.label = prediction["label"]
            result.candidate_count = 1 if prediction["contextual_pii"] else 0
        else:
            result.input_count = len(getattr(session, "get_inputs")())
            result.output_count = len(getattr(session, "get_outputs")())
    except Exception as exc:
        result.error = f"onnx_session_load_failed:{exc}"

    result.processing_time_ms = (time.perf_counter() - start) * 1000
    return result
