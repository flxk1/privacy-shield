"""Local LLM client factory.

Only the local-provider path (Ollama, LM Studio, Jan, GPT4All) lives here —
`services/local_model_runtime.py`'s Layer 5 detector is the one internal
caller. The BYOK/cloud-provider factories (OpenAI, Anthropic, Google) this
module used to also provide were removed with `user_credentials.py`: they
had no caller inside this package, no test, and no doc, and existed to
serve the credential store the 2.0.0 split removed from the distribution —
see the CHANGELOG.

Usage:
    from privacy_shield.llm_client import get_local_client

    result = get_local_client(provider="lm_studio")
    client = result.client
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

from privacy_shield.utils.network import is_loopback_or_unix_endpoint

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Client Result Container
# ---------------------------------------------------------------------------


@dataclass
class LLMClientResult:
    """Result of client acquisition."""

    client: Any
    provider: str
    user_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Current User Resolution
# ---------------------------------------------------------------------------


def _get_current_user() -> Optional[str]:
    """Get the currently authenticated user from context, for the returned
    LLMClientResult's usage-attribution field only — this package does not
    use it to gate anything."""
    try:
        from privacy_shield import app as host_app

        user = host_app.CURRENT_USER.get()
        role = host_app.CURRENT_ROLE.get()
        if user and role != "guest":
            return user
    except Exception as exc:
        logger.warning(
            "Cannot resolve current user: privacy_shield.app not provided "
            "by this host (%s); an authenticated user will be treated as none",
            exc,
        )
    return None


# ---------------------------------------------------------------------------
# Local Provider Client Factory (Ollama, LM Studio, Jan, GPT4All)
# ---------------------------------------------------------------------------


# Default endpoints for local providers
LOCAL_PROVIDER_ENDPOINTS = {
    "ollama": "http://localhost:11434",
    "lm_studio": "http://localhost:1234/v1",
    "jan": "http://localhost:1337/v1",
    "gpt4all": "http://localhost:4891/v1",
}


def get_local_client(
    provider: str = "lm_studio",
    user_id: Optional[str] = None,
    endpoint_url: Optional[str] = None,
    model: Optional[str] = None,
) -> LLMClientResult:
    """Get a client for a local LLM provider.

    Local providers (LM Studio, Jan, GPT4All) expose OpenAI-compatible APIs,
    so we use the OpenAI client with a custom base_url.

    Ollama has its own API format but also supports OpenAI compatibility mode.

    Args:
        provider: Local provider ID (ollama, lm_studio, jan, gpt4all)
        user_id: User ID, for the returned result's usage-attribution field only.
        endpoint_url: Custom endpoint URL. If None, uses default for provider.
            Must resolve to loopback or a unix socket (see
            `privacy_shield.utils.network.is_loopback_or_unix_endpoint`); a
            non-local address is refused and the provider default is used
            instead. There is no credential-store override any more (that
            was `user_credentials.py`, removed with the BYOK store) — this
            is now the only source for a non-default endpoint besides this
            parameter itself.
        model: Model to use (provider-specific)

    Returns:
        LLMClientResult with OpenAI-compatible client configured for local endpoint.

    Raises:
        ValueError: If provider is not a supported local provider.
    """
    from openai import OpenAI

    provider = provider.lower().strip()

    if provider not in LOCAL_PROVIDER_ENDPOINTS:
        raise ValueError(
            f"Unknown local provider: {provider}. "
            f"Supported: {', '.join(LOCAL_PROVIDER_ENDPOINTS.keys())}"
        )

    if user_id is None:
        user_id = _get_current_user()

    if not endpoint_url:
        endpoint_url = LOCAL_PROVIDER_ENDPOINTS[provider]
    elif not is_loopback_or_unix_endpoint(endpoint_url):
        # Same guard as services/local_model_runtime.py's embedded path: a
        # caller-supplied endpoint_url could otherwise name any host on the
        # internet with nothing checking it before this "local" client
        # sends raw text to it.
        logger.error(
            "get_local_client(%s): endpoint_url=%r is not a loopback address "
            "or a unix socket; refusing it and using the provider default "
            "(%s) instead",
            provider, endpoint_url, LOCAL_PROVIDER_ENDPOINTS[provider],
        )
        endpoint_url = LOCAL_PROVIDER_ENDPOINTS[provider]

    # Ensure endpoint has /v1 suffix for OpenAI compatibility (except raw Ollama)
    if provider == "ollama" and not endpoint_url.endswith("/v1"):
        base_url = endpoint_url.rstrip("/") + "/v1"
    else:
        base_url = endpoint_url.rstrip("/")

    # Create OpenAI client pointing to local endpoint
    # No API key needed, but OpenAI client requires one - use dummy
    client = OpenAI(
        api_key="not-needed",
        base_url=base_url,
    )

    logger.debug(f"Created local client for {provider} at {base_url}")

    return LLMClientResult(
        client=client,
        provider=provider,
        user_id=user_id,
    )


def get_local_client_simple(
    provider: str = "lm_studio",
    endpoint_url: Optional[str] = None,
) -> Any:
    """Convenience function returning just the local client object."""
    result = get_local_client(provider=provider, endpoint_url=endpoint_url)
    return result.client
