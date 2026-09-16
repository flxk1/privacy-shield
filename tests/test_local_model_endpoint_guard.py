"""`PRIVACY_SHIELD_{NATIVE,EMBEDDED}_LOCAL_MODEL_ENDPOINT` names a host the
operator supplies; nothing in the name enforces it actually being local.
`resolve_embedded_endpoint()` is the one choke point every caller in
`local_model_runtime.py` must go through before sending scan text anywhere —
these tests prove a remote endpoint is refused, that refusal never reaches
the network, that the scan still completes on the regex/lexicon floor, and
that the explicit escape hatch works and is loud about it.
"""
import logging

import pytest

from privacy_shield.services.local_model_runtime import resolve_embedded_endpoint

ENV_VARS = (
    "PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_ENDPOINT",
    "PRIVACY_SHIELD_EMBEDDED_LOCAL_MODEL_ENDPOINT",
    "PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_AVAILABLE",
    "PRIVACY_SHIELD_EMBEDDED_LOCAL_MODEL_AVAILABLE",
    "PRIVACY_SHIELD_MODEL_ENDPOINT_ALLOW_REMOTE",
)


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.mark.parametrize("endpoint", [
    "http://127.0.0.1:1234",
    "http://127.0.0.1:1234/v1",
    "https://127.0.0.1:1234",
    "http://localhost:1234",
    "http://[::1]:1234",
])
def test_loopback_endpoints_are_accepted(endpoint, monkeypatch):
    monkeypatch.setenv("PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_ENDPOINT", endpoint)
    assert resolve_embedded_endpoint() == endpoint


def test_unix_socket_endpoint_is_accepted(monkeypatch):
    monkeypatch.setenv("PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_ENDPOINT", "unix:///tmp/local-model.sock")
    assert resolve_embedded_endpoint() == "unix:///tmp/local-model.sock"


@pytest.mark.parametrize("endpoint", [
    "http://evil.example.com",
    "https://10.0.0.5:8080",
    "http://8.8.8.8",
])
def test_remote_endpoint_is_rejected(endpoint, monkeypatch, caplog):
    monkeypatch.setenv("PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_ENDPOINT", endpoint)
    with caplog.at_level(logging.ERROR, logger="privacy_shield.services.local_model_runtime"):
        result = resolve_embedded_endpoint()
    assert result is None
    assert any("PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_ENDPOINT" in r.message for r in caplog.records)


def test_remote_endpoint_allowed_with_the_escape_hatch(monkeypatch, caplog):
    monkeypatch.setenv("PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_ENDPOINT", "http://evil.example.com")
    monkeypatch.setenv("PRIVACY_SHIELD_MODEL_ENDPOINT_ALLOW_REMOTE", "1")
    with caplog.at_level(logging.WARNING, logger="privacy_shield.services.local_model_runtime"):
        result = resolve_embedded_endpoint()
    assert result == "http://evil.example.com"
    assert any("raw un-redacted scan text will be sent to evil.example.com" in r.message
               for r in caplog.records)


def test_remote_endpoint_never_reaches_the_network(monkeypatch):
    """PROOF, not inference: instrument the OpenAI client constructor to
    RECORD any attempt rather than raise inside it — scanner.py's Layer-5
    call is wrapped in a broad `except Exception`, so a raise here would be
    silently swallowed either way and prove nothing; a recorded-calls list
    checked after the scan cannot be masked by that swallow."""
    monkeypatch.setenv("PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_ENDPOINT", "http://evil.example.com")
    monkeypatch.setenv("PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_AVAILABLE", "1")
    openai = pytest.importorskip("openai")

    constructed = []

    class _TripWireClient:
        def __init__(self, *args, **kwargs):
            constructed.append(kwargs.get("base_url"))
            raise RuntimeError("must never be reached — the endpoint is remote and unauthorised")

    monkeypatch.setattr(openai, "OpenAI", _TripWireClient)

    from privacy_shield.scanner import scan_text_with_local_llm

    result = scan_text_with_local_llm("Contact me at jane.roe@example.org")

    assert constructed == [], f"OpenAI client was constructed for the blocked endpoint: {constructed}"
    # regex/lexicon floor (layers 1-4) still ran; layer 5 (LLM enhancement)
    # is marked unavailable by its absence, the existing degradation shape —
    # not a silent drop in findings, and no exception propagated either.
    assert 5 not in result.layers_used
    assert any(f.pii_type.value == "email" for f in result.findings)


def test_remote_endpoint_allowed_reaches_the_client_construction(monkeypatch):
    """The mirror of the tripwire test: with the escape hatch set, the send
    path does reach the OpenAI client (and then fails on an unreachable
    host, which is fine — the point is the attempt itself is authorised)."""
    monkeypatch.setenv("PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_ENDPOINT", "http://evil.example.com")
    monkeypatch.setenv("PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_AVAILABLE", "1")
    monkeypatch.setenv("PRIVACY_SHIELD_MODEL_ENDPOINT_ALLOW_REMOTE", "1")
    openai = pytest.importorskip("openai")

    constructed = []

    class _RecordingClient:
        def __init__(self, *args, **kwargs):
            constructed.append(kwargs.get("base_url"))
            raise RuntimeError("simulated network failure — construction is what we are proving")

    monkeypatch.setattr(openai, "OpenAI", _RecordingClient)

    from privacy_shield.scanner import scan_text_with_local_llm

    scan_text_with_local_llm("Contact me at jane.roe@example.org")  # must not raise
    assert constructed, "expected the OpenAI client to be constructed once the escape hatch is set"
    assert "evil.example.com" in constructed[0]
