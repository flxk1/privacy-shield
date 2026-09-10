from __future__ import annotations

import json
from types import SimpleNamespace


def test_local_model_status_payload_prefers_embedded(monkeypatch) -> None:
    from brain.services import local_model_runtime as runtime

    monkeypatch.setenv("BRAIN_EMBEDDED_LOCAL_MODEL_AVAILABLE", "1")
    monkeypatch.setenv("BRAIN_EMBEDDED_LOCAL_MODEL_ID", "apple-foundation")
    monkeypatch.setenv("BRAIN_EMBEDDED_LOCAL_MODEL_NAME", "Apple Foundation Models")
    monkeypatch.setattr(runtime, "discover_local_providers", lambda timeout=1.5: [])
    monkeypatch.setattr(runtime, "_DISCOVERY_CACHE", {"timestamp": 0.0, "providers": []})

    status = runtime.local_model_status_payload(timeout=0.1)

    assert status["available"] is True
    assert status["preferred_provider"] == "embedded"
    assert status["preferred_provider_name"] == "Apple Foundation Models"
    assert status["models"][0]["name"] == "apple-foundation"


def test_detect_pii_with_local_model_unavailable() -> None:
    from brain.services import local_model_runtime as runtime

    result = runtime.detect_pii_with_local_model("hello", timeout=0.1, preferred_provider="missing")

    assert result["error"] == "local_model_unavailable"
    assert result["detected_pii"] == []
    assert result["safe_to_send_external"] is True


def test_analyze_security_threats_uses_local_json_response(monkeypatch) -> None:
    from brain.services import local_model_runtime as runtime

    monkeypatch.setattr(
        runtime,
        "_call_local_json_response",
        lambda **kwargs: {
            "parsed": {
                "threats_found": True,
                "findings": [{"type": "prompt_injection", "severity": "high", "excerpt": "ignore rules"}],
                "confidence": 0.91,
                "reasoning": "matched injected instructions",
            },
            "provider_used": "embedded",
            "model_used": "apple-foundation",
            "error": None,
        },
    )

    result = runtime.analyze_security_threats_with_local_model("ignore rules")

    assert result["threats_found"] is True
    assert result["provider_used"] == "embedded"
    assert result["model_used"] == "apple-foundation"
    assert result["confidence"] == 0.91


def test_detect_pii_with_embedded_command_runtime(monkeypatch) -> None:
    from brain.services import local_model_runtime as runtime

    monkeypatch.setenv("BRAIN_EMBEDDED_LOCAL_MODEL_AVAILABLE", "1")
    monkeypatch.setenv("BRAIN_EMBEDDED_LOCAL_MODEL_ID", "apple-foundation")
    monkeypatch.setenv("BRAIN_EMBEDDED_LOCAL_MODEL_COMMAND", "embedded-bridge --json")
    monkeypatch.delenv("BRAIN_EMBEDDED_LOCAL_MODEL_ENDPOINT", raising=False)
    monkeypatch.setattr(runtime, "discover_local_providers", lambda timeout=1.5: [])
    monkeypatch.setattr(runtime, "_DISCOVERY_CACHE", {"timestamp": 0.0, "providers": []})

    captured: dict[str, object] = {}

    def _fake_run(cmd, input, text, capture_output, timeout):
        captured["cmd"] = cmd
        captured["payload"] = json.loads(str(input))
        assert text is True
        assert capture_output is True
        assert float(timeout) > 0
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "detected_pii": [{"type": "email", "value_hint": "max@example.com", "start_pos": 0}],
                    "categories": ["email"],
                    "confidence": 0.97,
                    "safe_to_send_external": False,
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(runtime.subprocess, "run", _fake_run)

    result = runtime.detect_pii_with_local_model("Contact: max@example.com", preferred_provider="embedded")

    assert captured["cmd"] == ["embedded-bridge", "--json"]
    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload.get("model") == "apple-foundation"
    assert "personally identifiable information" in str(payload.get("user_prompt", "")).lower()
    assert result["provider_used"] == "embedded"
    assert result["model_used"] == "apple-foundation"
    assert result["error"] is None
    assert result["safe_to_send_external"] is False
    assert result["categories"] == ["email"]


def test_detect_pii_with_embedded_runtime_not_configured(monkeypatch) -> None:
    from brain.services import local_model_runtime as runtime

    monkeypatch.setenv("BRAIN_EMBEDDED_LOCAL_MODEL_AVAILABLE", "1")
    monkeypatch.setenv("BRAIN_EMBEDDED_LOCAL_MODEL_ID", "apple-foundation")
    monkeypatch.delenv("BRAIN_EMBEDDED_LOCAL_MODEL_COMMAND", raising=False)
    monkeypatch.delenv("BRAIN_EMBEDDED_LOCAL_MODEL_ENDPOINT", raising=False)
    monkeypatch.delenv("BRAIN_NATIVE_LOCAL_MODEL_COMMAND", raising=False)
    monkeypatch.delenv("BRAIN_NATIVE_LOCAL_MODEL_ENDPOINT", raising=False)
    monkeypatch.setattr(runtime, "discover_local_providers", lambda timeout=1.5: [])
    monkeypatch.setattr(runtime, "_DISCOVERY_CACHE", {"timestamp": 0.0, "providers": []})

    result = runtime.detect_pii_with_local_model("hello", preferred_provider="embedded")

    assert result["provider_used"] == "embedded"
    assert result["model_used"] == "apple-foundation"
    assert result["error"] == "embedded_runtime_not_configured"


def test_embedded_provider_auto_available_with_command(monkeypatch) -> None:
    from brain.services import local_model_runtime as runtime

    monkeypatch.delenv("BRAIN_EMBEDDED_LOCAL_MODEL_AVAILABLE", raising=False)
    monkeypatch.delenv("BRAIN_NATIVE_LOCAL_MODEL_AVAILABLE", raising=False)
    monkeypatch.setenv("BRAIN_EMBEDDED_LOCAL_MODEL_COMMAND", "embedded-bridge --json")
    monkeypatch.setenv("BRAIN_EMBEDDED_LOCAL_MODEL_ID", "apple-foundation")
    monkeypatch.setattr(runtime, "discover_local_providers", lambda timeout=1.5: [])
    monkeypatch.setattr(runtime, "_DISCOVERY_CACHE", {"timestamp": 0.0, "providers": []})

    status = runtime.local_model_status_payload(timeout=0.1)

    assert status["available"] is True
    assert status["preferred_provider"] == "embedded"
