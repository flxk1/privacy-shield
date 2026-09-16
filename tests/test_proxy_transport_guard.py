"""The endpoint guard checks an address; these check the transport.

`is_loopback_or_unix_endpoint` proves the URL names loopback. It says nothing
about where the bytes actually go: `httpx` and the `openai` client built on it
default to `trust_env=True`, so with `HTTP_PROXY` set the client's transport is
an `HTTPProxy` pointing at the remote proxy, and raw un-redacted text bound for
an approved 127.0.0.1 endpoint leaves the machine anyway. A managed workstation
with a proxy configured is the deployment this package targets.
"""

import urllib.request

import pytest

from privacy_shield.utils.network import no_proxy_http_client, no_proxy_url_opener

httpx = pytest.importorskip("httpx")

PROXY_VARS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)

PROXY = "http://proxy.corp.example.com:3128"


@pytest.fixture
def proxied_env(monkeypatch):
    for var in PROXY_VARS:
        monkeypatch.setenv(var, PROXY)
    return PROXY


def _proxy_mounts(client):
    """The proxy transports httpx built for *client*, if any."""
    return [
        transport
        for transport in client._mounts.values()
        if type(transport).__name__ == "HTTPTransport"
        and getattr(getattr(transport, "_pool", None), "__class__", type(None)).__name__
        == "HTTPProxy"
    ]


def test_trust_env_default_would_have_proxied(proxied_env):
    """The defect, stated as a test: the default client routes to the proxy."""
    with httpx.Client() as client:
        assert client._mounts, (
            "httpx no longer honours proxy env vars by default; the guard under "
            "test is still correct but this baseline needs rewriting"
        )


def test_no_proxy_http_client_ignores_proxy_env(proxied_env):
    with no_proxy_http_client() as client:
        assert client._mounts == {}
        pool = client._transport._pool
        assert type(pool).__name__ != "HTTPProxy", type(pool).__name__


def test_no_proxy_http_client_carries_timeout(proxied_env):
    with no_proxy_http_client(timeout=1.5) as client:
        assert client.timeout.connect == 1.5


def test_local_client_transport_is_not_proxied(proxied_env):
    """`get_local_client` builds the client that carries raw text."""
    pytest.importorskip("openai")
    from privacy_shield.llm_client import get_local_client

    client = get_local_client("lm_studio").client
    assert str(client.base_url).startswith("http://localhost:1234")
    assert client._client._mounts == {}
    assert type(client._client._transport._pool).__name__ != "HTTPProxy"


def test_embedded_send_path_client_is_not_proxied(proxied_env, monkeypatch):
    """The embedded native endpoint path builds its own OpenAI client."""
    openai = pytest.importorskip("openai")
    from privacy_shield.services import local_model_runtime as lmr

    monkeypatch.setenv(
        "PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_ENDPOINT", "http://127.0.0.1:1234"
    )
    constructed = []
    real_openai = openai.OpenAI

    def _record(*args, **kwargs):
        client = real_openai(*args, **kwargs)
        constructed.append(client)
        raise RuntimeError("stop before the network")

    monkeypatch.setattr(openai, "OpenAI", _record)
    # The client is built outside the send path's try/except, so the sentinel
    # propagates - which is the point: it stops before any network call.
    with pytest.raises(RuntimeError, match="stop before the network"):
        lmr._call_embedded_local_json_response(
            system_prompt="s", user_prompt="u", timeout=1.0, model="m", runtime=None
        )

    assert constructed, "the embedded path did not build a client to inspect"
    for client in constructed:
        assert client._client._mounts == {}
        assert type(client._client._transport._pool).__name__ != "HTTPProxy"


def _registered_proxy_handlers(opener):
    return [
        handler
        for handlers in opener.handle_open.values()
        for handler in handlers
        if isinstance(handler, urllib.request.ProxyHandler)
    ]


def test_no_proxy_url_opener_registers_no_proxy_handler(proxied_env):
    """An empty ProxyHandler({}) registers no protocol hook at all.

    `build_opener` skips the default env-reading ProxyHandler because one of
    the same class was supplied, and an empty one has no `<scheme>_open`
    method to register - so the opener ends up with no proxy hook.
    """
    assert _registered_proxy_handlers(no_proxy_url_opener()) == []


def test_default_url_opener_would_have_proxied(proxied_env):
    """The defect, stated as a test, for the urllib probe."""
    assert urllib.request.getproxies(), (
        "urllib no longer reads proxy env vars; the guard is still correct but "
        "this baseline needs rewriting"
    )
    assert _registered_proxy_handlers(urllib.request.build_opener()), (
        "the default opener no longer installs a proxy hook; this baseline "
        "needs rewriting"
    )


def test_local_provider_probe_does_not_use_the_env_proxy(proxied_env, monkeypatch):
    """`_check_local_provider` must not report a proxy as a running provider."""
    from privacy_shield.services import local_model_runtime as lmr

    seen = {}

    class _Recorder:
        def __init__(self, *args, **kwargs):
            seen["trust_env"] = kwargs.get("trust_env")
            seen["mounts"] = getattr(self, "_mounts", {})

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url):
            seen["url"] = url
            raise httpx.ConnectError("refused")

    monkeypatch.setattr(lmr.httpx, "Client", _Recorder)
    result = lmr._check_local_provider("lm_studio", timeout=0.2)

    assert seen["trust_env"] is False
    assert seen["url"].startswith("http://localhost:1234")
    assert result["running"] is False
