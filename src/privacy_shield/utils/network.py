"""Shared "is this endpoint actually local" check.

Lives here, not in `services/local_model_runtime.py`, so `llm_client.py` can
use the same check without a circular import (`local_model_runtime.py`
already imports from `llm_client.py`). Any caller that would send raw,
un-redacted text to a caller-supplied address should go through this.
"""

from __future__ import annotations

from urllib.parse import urlsplit

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def is_loopback_or_unix_endpoint(endpoint: str) -> bool:
    """A loopback http(s) address (127.0.0.1, ::1, localhost) or a genuine
    unix-socket form (`unix:///path/to/socket`, no host component — a
    `unix://` URL that names a host, e.g. `unix://evil.example.com`, is
    not a socket path and is not accepted).

    A malformed endpoint (e.g. a bracketed-IPv6-looking netloc followed by
    an `@host`, which Python's own `urlsplit` rejects with a `ValueError`
    rather than returning an unparsed result) is not local either — treated
    the same as any other non-loopback address, refused, never raised.
    """
    try:
        parsed = urlsplit(endpoint)
    except ValueError:
        return False
    if parsed.scheme == "unix":
        return not parsed.netloc
    if parsed.scheme in ("http", "https"):
        try:
            hostname = parsed.hostname
        except ValueError:
            return False
        return (hostname or "").lower() in LOOPBACK_HOSTS
    return False


#: Default send-path timeout, in seconds.
#:
#: The helper defaulted to None, which `httpx` reads as "wait forever" and
#: which the `openai` client adopts, so none of the three send paths had a
#: timeout at all. A local model that accepts the connection and never answers
#: hung the scan indefinitely - and this is the path the privacy gate sits on,
#: so hanging it is a denial of the gate rather than of a feature.
DEFAULT_SEND_TIMEOUT = 30.0


def no_proxy_http_client(timeout: float | None = DEFAULT_SEND_TIMEOUT):
    """An `httpx.Client` that ignores the environment's proxy settings.

    Checking the endpoint STRING is only half the guard. `httpx` (and the
    `openai` client built on it) default to `trust_env=True`, so with
    `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` set the client's transport is an
    `HTTPProxy` pointing at the remote proxy: an endpoint that passed
    `is_loopback_or_unix_endpoint` still sends raw, un-redacted text to a
    corporate proxy. A managed workstation with a proxy configured is exactly
    the deployment this package targets, so no send path may trust the
    environment. Returns None when httpx is not installed.
    """
    try:
        import httpx
    except ImportError:
        return None
    # An explicit None from a caller still means "no timeout"; the DEFAULT is
    # what changed.
    return httpx.Client(trust_env=False, timeout=timeout)


def no_proxy_url_opener():
    """A `urllib` opener with an empty `ProxyHandler` - no environment proxy.

    `urllib.request.urlopen` consults `http_proxy` / `https_proxy` through the
    default opener. An empty `ProxyHandler({})` disables that lookup entirely.
    """
    import urllib.request

    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def safe_hostname(endpoint: str) -> str:
    """The host portion of `endpoint`, for a log message only — never
    raises, even on a malformed URL that makes `urlsplit`/`.hostname`
    raise `ValueError`; falls back to the raw endpoint string."""
    try:
        return urlsplit(endpoint).hostname or endpoint
    except ValueError:
        return endpoint
