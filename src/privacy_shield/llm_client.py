"""Centralized LLM Client Factory with BYOK Support.

This module provides a unified interface for obtaining LLM clients that:
1. Check if the user has BYOK credentials for the provider
2. Use user's key if available (no platform credit cost)
3. Fall back to platform key if no user credentials
4. Track usage for billing/analytics

Usage:
    from privacy_shield.llm_client import get_openai_client, get_anthropic_client

    # Get client for current authenticated user
    client = get_openai_client()

    # Specify user explicitly
    client = get_openai_client(user_id="testuser")

    # Force platform key (skip BYOK check)
    client = get_openai_client(use_platform_key=True)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional, Tuple

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Client Result Container
# ---------------------------------------------------------------------------


@dataclass
class LLMClientResult:
    """Result of client acquisition."""

    client: Any
    provider: str
    is_byok: bool  # True if using user's own key
    credential_id: Optional[str] = None  # Set if using BYOK
    user_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Current User Resolution
# ---------------------------------------------------------------------------


def _get_current_user() -> Optional[str]:
    """Get the currently authenticated user from context."""
    try:
        from privacy_shield import app as host_app

        user = host_app.CURRENT_USER.get()
        role = host_app.CURRENT_ROLE.get()
        if user and role != "guest":
            return user
    except Exception as exc:
        # Loud, not debug: this makes a real authenticated user look
        # anonymous to every caller of _get_current_user (BYOK credential
        # lookups, usage attribution) rather than visibly unavailable.
        logger.warning(
            "Cannot resolve current user: privacy_shield.app not provided "
            "by this host (%s); an authenticated user will be treated as none",
            exc,
        )
    return None


# ---------------------------------------------------------------------------
# BYOK Credential Lookup
# ---------------------------------------------------------------------------


def _get_byok_key(
    user_id: str, provider: str
) -> Tuple[Optional[str], Optional[str]]:
    """Get decrypted BYOK key for user and provider.

    Returns:
        Tuple of (api_key, credential_id) or (None, None) if not found.
    """
    try:
        from privacy_shield.user_credentials import (
            get_credential_for_provider,
            get_decrypted_key,
            record_usage,
        )

        credential = get_credential_for_provider(user_id, provider)
        if credential and credential.is_valid:
            api_key = get_decrypted_key(user_id, credential.credential_id)
            if api_key:
                # Record usage for analytics
                record_usage(user_id, credential.credential_id)
                return api_key, credential.credential_id
    except Exception as e:
        logger.debug(f"BYOK lookup failed for {provider}: {e}")

    return None, None


# ---------------------------------------------------------------------------
# OpenAI Client Factory
# ---------------------------------------------------------------------------


def get_openai_client(
    user_id: Optional[str] = None,
    use_platform_key: bool = False,
    model: Optional[str] = None,
) -> LLMClientResult:
    """Get an OpenAI client, preferring user's BYOK credentials.

    Args:
        user_id: User ID to check credentials for. If None, uses current auth context.
        use_platform_key: If True, skip BYOK lookup and use platform key directly.
        model: Preferred model (for logging/analytics).

    Returns:
        LLMClientResult with the client and metadata.

    Raises:
        ImportError: If openai package is not installed.
        ValueError: If no API key available (no BYOK and no platform key).
    """
    from openai import OpenAI

    provider = "openai"

    # Resolve user
    if user_id is None:
        user_id = _get_current_user()

    # Try BYOK first (unless forced to use platform key)
    api_key = None
    credential_id = None
    is_byok = False

    if not use_platform_key and user_id:
        api_key, credential_id = _get_byok_key(user_id, provider)
        if api_key:
            is_byok = True
            logger.debug(f"Using BYOK key for user {user_id}, provider {provider}")

    # Fall back to platform key
    if not api_key:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(
                f"No API key available for {provider}. "
                "User has no BYOK credential and no platform key configured."
            )
        logger.debug(f"Using platform key for provider {provider}")

    # Create client
    client = OpenAI(api_key=api_key)

    return LLMClientResult(
        client=client,
        provider=provider,
        is_byok=is_byok,
        credential_id=credential_id,
        user_id=user_id,
    )


def get_openai_client_simple(
    user_id: Optional[str] = None,
    use_platform_key: bool = False,
) -> Any:
    """Convenience function returning just the OpenAI client object.

    For drop-in replacement of existing `OpenAI()` calls.
    """
    result = get_openai_client(user_id=user_id, use_platform_key=use_platform_key)
    return result.client


# ---------------------------------------------------------------------------
# Anthropic Client Factory
# ---------------------------------------------------------------------------


def get_anthropic_client(
    user_id: Optional[str] = None,
    use_platform_key: bool = False,
    model: Optional[str] = None,
) -> LLMClientResult:
    """Get an Anthropic client, preferring user's BYOK credentials.

    Args:
        user_id: User ID to check credentials for. If None, uses current auth context.
        use_platform_key: If True, skip BYOK lookup and use platform key directly.
        model: Preferred model (for logging/analytics).

    Returns:
        LLMClientResult with the client and metadata.

    Raises:
        ImportError: If anthropic package is not installed.
        ValueError: If no API key available.
    """
    from anthropic import Anthropic

    provider = "anthropic"

    # Resolve user
    if user_id is None:
        user_id = _get_current_user()

    # Try BYOK first
    api_key = None
    credential_id = None
    is_byok = False

    if not use_platform_key and user_id:
        api_key, credential_id = _get_byok_key(user_id, provider)
        if api_key:
            is_byok = True
            logger.debug(f"Using BYOK key for user {user_id}, provider {provider}")

    # Fall back to platform key
    if not api_key:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                f"No API key available for {provider}. "
                "User has no BYOK credential and no platform key configured."
            )
        logger.debug(f"Using platform key for provider {provider}")

    # Create client
    client = Anthropic(api_key=api_key)

    return LLMClientResult(
        client=client,
        provider=provider,
        is_byok=is_byok,
        credential_id=credential_id,
        user_id=user_id,
    )


def get_anthropic_client_simple(
    user_id: Optional[str] = None,
    use_platform_key: bool = False,
) -> Any:
    """Convenience function returning just the Anthropic client object."""
    result = get_anthropic_client(user_id=user_id, use_platform_key=use_platform_key)
    return result.client


# ---------------------------------------------------------------------------
# Google/Gemini Client Factory
# ---------------------------------------------------------------------------


def get_google_client(
    user_id: Optional[str] = None,
    use_platform_key: bool = False,
    model: Optional[str] = None,
) -> LLMClientResult:
    """Get a Google Generative AI client, preferring user's BYOK credentials.

    Args:
        user_id: User ID to check credentials for. If None, uses current auth context.
        use_platform_key: If True, skip BYOK lookup and use platform key directly.
        model: Preferred model (for logging/analytics).

    Returns:
        LLMClientResult with the configured genai module and metadata.

    Raises:
        ImportError: If google-generativeai package is not installed.
        ValueError: If no API key available.
    """
    import google.generativeai as genai

    provider = "google"

    # Resolve user
    if user_id is None:
        user_id = _get_current_user()

    # Try BYOK first
    api_key = None
    credential_id = None
    is_byok = False

    if not use_platform_key and user_id:
        api_key, credential_id = _get_byok_key(user_id, provider)
        if api_key:
            is_byok = True
            logger.debug(f"Using BYOK key for user {user_id}, provider {provider}")

    # Fall back to platform key
    if not api_key:
        api_key = os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError(
                f"No API key available for {provider}. "
                "User has no BYOK credential and no platform key configured."
            )
        logger.debug(f"Using platform key for provider {provider}")

    # Configure genai with key
    genai.configure(api_key=api_key)

    return LLMClientResult(
        client=genai,  # Return the configured module
        provider=provider,
        is_byok=is_byok,
        credential_id=credential_id,
        user_id=user_id,
    )


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
        user_id: User ID (for credential lookup if configured)
        endpoint_url: Custom endpoint URL. If None, uses default for provider.
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

    # Resolve user
    if user_id is None:
        user_id = _get_current_user()

    # Check if user has a configured credential with custom endpoint
    credential_id = None
    is_byok = False

    if user_id:
        try:
            from privacy_shield.user_credentials import get_credential_for_provider

            credential = get_credential_for_provider(user_id, provider)
            if credential:
                credential_id = credential.credential_id
                is_byok = True
                # Use configured endpoint if available
                if credential.endpoint_url:
                    endpoint_url = credential.endpoint_url
                # Use configured model if available and none specified
                if not model and credential.default_model:
                    model = credential.default_model
        except Exception as e:
            logger.debug(f"Error checking credential for {provider}: {e}")

    # Fall back to default endpoint
    if not endpoint_url:
        endpoint_url = LOCAL_PROVIDER_ENDPOINTS[provider]

    # Ensure endpoint has /v1 suffix for OpenAI compatibility (except raw Ollama)
    if provider == "ollama" and not endpoint_url.endswith("/v1"):
        # Ollama OpenAI compatibility endpoint
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
        is_byok=is_byok,
        credential_id=credential_id,
        user_id=user_id,
    )


def get_local_client_simple(
    provider: str = "lm_studio",
    endpoint_url: Optional[str] = None,
) -> Any:
    """Convenience function returning just the local client object."""
    result = get_local_client(provider=provider, endpoint_url=endpoint_url)
    return result.client


# ---------------------------------------------------------------------------
# Generic Client Factory
# ---------------------------------------------------------------------------


def get_llm_client(
    provider: str,
    user_id: Optional[str] = None,
    use_platform_key: bool = False,
    model: Optional[str] = None,
    endpoint_url: Optional[str] = None,
) -> LLMClientResult:
    """Get an LLM client for any supported provider.

    Args:
        provider: Provider ID (openai, anthropic, google, ollama, lm_studio, etc.)
        user_id: User ID to check credentials for.
        use_platform_key: If True, skip BYOK lookup (cloud providers only).
        model: Preferred model.
        endpoint_url: Custom endpoint URL (for local providers).

    Returns:
        LLMClientResult with the client and metadata.

    Raises:
        ValueError: If provider is not supported.
    """
    provider = provider.lower().strip()

    # Cloud providers
    if provider == "openai":
        return get_openai_client(user_id, use_platform_key, model)
    elif provider == "anthropic":
        return get_anthropic_client(user_id, use_platform_key, model)
    elif provider == "google":
        return get_google_client(user_id, use_platform_key, model)
    # Local providers
    elif provider in LOCAL_PROVIDER_ENDPOINTS:
        return get_local_client(provider, user_id, endpoint_url, model)
    else:
        raise ValueError(f"Unsupported provider: {provider}")


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------


def check_byok_available(user_id: Optional[str] = None, provider: str = "openai") -> bool:
    """Check if user has valid BYOK credentials for a provider.

    Args:
        user_id: User to check. If None, uses current auth context.
        provider: Provider to check for.

    Returns:
        True if user has valid BYOK credentials.
    """
    if user_id is None:
        user_id = _get_current_user()

    if not user_id:
        return False

    try:
        from privacy_shield.user_credentials import get_credential_for_provider

        credential = get_credential_for_provider(user_id, provider)
        return credential is not None and credential.is_valid
    except Exception:
        return False


def list_available_providers(user_id: Optional[str] = None) -> dict:
    """List all providers and their availability status for a user.

    Returns:
        Dict mapping provider ID to availability info:
        {
            "openai": {"available": True, "source": "byok"},
            "anthropic": {"available": True, "source": "platform"},
            ...
        }
    """
    if user_id is None:
        user_id = _get_current_user()

    providers = {
        "openai": {"env_var": "OPENAI_API_KEY"},
        "anthropic": {"env_var": "ANTHROPIC_API_KEY"},
        "google": {"env_var": "GOOGLE_API_KEY"},
    }

    result = {}
    for provider_id, config in providers.items():
        has_byok = check_byok_available(user_id, provider_id) if user_id else False
        has_platform = bool(os.environ.get(config["env_var"]))

        if has_byok:
            result[provider_id] = {"available": True, "source": "byok"}
        elif has_platform:
            result[provider_id] = {"available": True, "source": "platform"}
        else:
            result[provider_id] = {"available": False, "source": None}

    return result
