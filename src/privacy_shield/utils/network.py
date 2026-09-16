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


def safe_hostname(endpoint: str) -> str:
    """The host portion of `endpoint`, for a log message only — never
    raises, even on a malformed URL that makes `urlsplit`/`.hostname`
    raise `ValueError`; falls back to the raw endpoint string."""
    try:
        return urlsplit(endpoint).hostname or endpoint
    except ValueError:
        return endpoint
