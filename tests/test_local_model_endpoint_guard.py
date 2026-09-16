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

from privacy_shield.services import local_model_runtime as lmr
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


@pytest.fixture(autouse=True)
def _reset_discovery_cache():
    """`_DISCOVERY_CACHE` is a module-level dict with a 2-second TTL, never
    reset between tests. Left alone, a test run after another test file
    (or another test in this one) reads a stale `providers` list — under
    which a tripwire's `assert constructed == []` passes vacuously because
    the (stale, cached) discovery never reaches the send path at all, not
    because the guard refused it. Reset before AND after every test."""
    lmr._DISCOVERY_CACHE["timestamp"] = 0.0
    lmr._DISCOVERY_CACHE["providers"] = []
    yield
    lmr._DISCOVERY_CACHE["timestamp"] = 0.0
    lmr._DISCOVERY_CACHE["providers"] = []


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


def test_unix_scheme_with_a_host_component_is_not_a_socket_path(monkeypatch):
    """`unix://evil.example.com` parses with scheme="unix" but names a host,
    not a filesystem path — a blanket "scheme == unix" accept let this
    through (latent, since httpx happens to refuse it; tightened anyway to
    require no netloc, matching a genuine `unix:///path` socket form)."""
    monkeypatch.setenv("PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_ENDPOINT", "unix://evil.example.com/v1")
    assert resolve_embedded_endpoint() is None


def test_a_malformed_endpoint_degrades_rather_than_raising(monkeypatch):
    """`http://[::1]:11434@evil.example.com/` makes Python's own `urlsplit`
    raise ValueError (a bracketed netloc followed by `@host` fails its
    IPv6-literal check) — unguarded, that propagated out of scan() instead
    of degrading to the regex/lexicon floor as the CHANGELOG promises."""
    monkeypatch.setenv("PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_ENDPOINT",
                        "http://[::1]:11434@evil.example.com/")
    monkeypatch.setenv("PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_AVAILABLE", "1")

    assert resolve_embedded_endpoint() is None  # refused, not raised

    from privacy_shield import scan
    from privacy_shield.shield import PrivacyMode

    report = scan("Contact me at jane.roe@example.org", mode=PrivacyMode.REGEX_ONLY,
                   force_text=True)  # must not raise
    assert report.documents and "email" in report.documents[0].findings_by_type


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


def test_refused_endpoint_does_not_shadow_a_running_loopback_provider(monkeypatch):
    """A refused remote endpoint with AVAILABLE=1 and no command used to
    still return {"running": True, "endpoint": None}: a ghost "embedded"
    entry that get_preferred_local_runtime() prefers first (embedded leads
    _PREFERRED_PROVIDER_ORDER), shadowing a genuinely running loopback
    provider discover_local_providers() found separately — and
    is_local_model_available() reported True for a layer that could never
    actually answer."""
    monkeypatch.setenv("PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_ENDPOINT", "http://evil.example.com")
    monkeypatch.setenv("PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_AVAILABLE", "1")

    running_ollama = {
        "provider": "ollama", "name": "Ollama (Local - CLI)", "running": True,
        "endpoint": "http://localhost:11434", "models": ["llama3"], "error": None,
        "setup_url": "", "setup_instructions": "", "openai_compatible": False,
    }
    monkeypatch.setattr(lmr, "discover_local_providers", lambda timeout=2.0: [running_ollama])

    from privacy_shield.services.local_model_runtime import (
        discover_local_model_runtimes,
        get_preferred_local_runtime,
        is_local_model_available,
    )

    providers = discover_local_model_runtimes(force_refresh=True)
    assert not any(p.get("provider") == "embedded" for p in providers), \
        f"a ghost embedded entry was returned: {providers}"

    preferred = get_preferred_local_runtime()
    assert preferred is not None and preferred["provider"] == "ollama"
    assert is_local_model_available() is True  # true, but for the real ollama, not the ghost


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


def test_get_local_client_refuses_an_unchecked_endpoint_url_parameter(monkeypatch):
    """llm_client.get_local_client takes an arbitrary endpoint_url parameter
    with no loopback check of its own — the embedded-path guard above does
    not cover this second, separate send path."""
    openai = pytest.importorskip("openai")
    constructed = []

    class _RecordingClient:
        def __init__(self, *args, **kwargs):
            constructed.append(kwargs.get("base_url"))

    monkeypatch.setattr(openai, "OpenAI", _RecordingClient)

    from privacy_shield.llm_client import get_local_client

    get_local_client(provider="lm_studio", endpoint_url="http://evil.example.com")

    assert constructed and "evil.example.com" not in constructed[0], (
        f"get_local_client sent a remote endpoint_url straight to the client: {constructed}"
    )
