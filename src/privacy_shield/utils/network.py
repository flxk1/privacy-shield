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
    not a socket path and is not accepted)."""
    parsed = urlsplit(endpoint)
    if parsed.scheme == "unix":
        return not parsed.netloc
    if parsed.scheme in ("http", "https"):
        return (parsed.hostname or "").lower() in LOOPBACK_HOSTS
    return False
