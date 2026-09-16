"""
BYOK (Bring Your Own Key) - User LLM Provider Credentials Storage.

Securely stores user-provided API keys for LLM providers (OpenAI, Anthropic, etc.)
so users can use their own API quota instead of platform credits.

Storage: privacy_shield/user/credentials/{username}.json (encrypted)
Master key: PRIVACY_SHIELD_CREDENTIALS_MASTER_KEY env var or auto-generated

Security:
- API keys encrypted at rest using Fernet (AES-128-CBC + HMAC)
- Keys derived from master secret + per-user salt
- Only credential metadata exposed in API responses (never raw keys)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ._legacy_env import LegacyEnvironmentError, reject_legacy_env

try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    Fernet = None  # type: ignore[assignment]
    InvalidToken = Exception  # type: ignore[assignment]

try:
    import httpx
except Exception:
    httpx = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


class CredentialEncryptionUnavailable(RuntimeError):
    """Raised instead of silently storing or reading a credential in cleartext."""


_DEFAULT_USER_ROOT = Path(__file__).resolve().parent / "user"
_CREDENTIALS_DIR = "credentials"
_MASTER_KEY_FILENAME = ".credentials_master.key"

# Supported LLM providers with their validation endpoints and key patterns
PROVIDERS = {
    "openai": {
        "name": "OpenAI",
        "key_prefix": "sk-",
        "key_pattern": r"^sk-[a-zA-Z0-9_-]{20,}$",
        "test_url": "https://api.openai.com/v1/models",
        "auth_header": "Authorization",
        "auth_format": "Bearer {key}",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"],
    },
    "anthropic": {
        "name": "Anthropic",
        "key_prefix": "sk-ant-",
        "key_pattern": r"^sk-ant-[a-zA-Z0-9_-]{20,}$",
        "test_url": "https://api.anthropic.com/v1/messages",
        "auth_header": "x-api-key",
        "auth_format": "{key}",
        "extra_headers": {"anthropic-version": "2023-06-01"},
        "models": ["claude-sonnet-4-20250514", "claude-3-5-haiku-20241022", "claude-3-opus-20240229"],
    },
    "google": {
        "name": "Google AI (Gemini)",
        "key_prefix": "AI",
        "key_pattern": r"^AI[a-zA-Z0-9_-]{30,}$",
        "test_url": "https://generativelanguage.googleapis.com/v1/models",
        "auth_param": "key",
        "models": ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash"],
    },
    "groq": {
        "name": "Groq",
        "key_prefix": "gsk_",
        "key_pattern": r"^gsk_[a-zA-Z0-9_-]{20,}$",
        "test_url": "https://api.groq.com/openai/v1/models",
        "auth_header": "Authorization",
        "auth_format": "Bearer {key}",
        "models": ["llama-3.3-70b-versatile", "mixtral-8x7b-32768"],
    },
    "mistral": {
        "name": "Mistral AI",
        "key_prefix": "",
        "key_pattern": r"^[a-zA-Z0-9]{32,}$",
        "test_url": "https://api.mistral.ai/v1/models",
        "auth_header": "Authorization",
        "auth_format": "Bearer {key}",
        "models": ["mistral-large-latest", "mistral-medium-latest", "mistral-small-latest"],
    },
    "azure_openai": {
        "name": "Azure OpenAI",
        "key_prefix": "",
        "key_pattern": r"^[a-f0-9]{32}$",
        "requires_endpoint": True,
        "models": ["gpt-4o", "gpt-4", "gpt-35-turbo"],
    },
    "ollama": {
        "name": "Ollama (Local - CLI)",
        "key_prefix": "",
        "key_pattern": r".*",  # No key needed
        "test_url": "http://localhost:11434/api/tags",
        "no_auth": True,
        "local": True,
        "default_endpoint": "http://localhost:11434",
        "setup_instructions": "Install via: brew install ollama (Mac) or https://ollama.ai",
        "models": [],  # Auto-detected from running instance
    },
    "lm_studio": {
        "name": "LM Studio (Local - GUI)",
        "key_prefix": "",
        "key_pattern": r".*",  # No key needed
        "test_url": "http://localhost:1234/v1/models",
        "no_auth": True,
        "local": True,
        "default_endpoint": "http://localhost:1234/v1",
        "setup_url": "https://lmstudio.ai",
        "setup_instructions": "Download from lmstudio.ai, pick a model, click 'Start Server'",
        "openai_compatible": True,
        "models": [],  # Auto-detected from running instance
    },
    "jan": {
        "name": "Jan (Local - GUI)",
        "key_prefix": "",
        "key_pattern": r".*",  # No key needed
        "test_url": "http://localhost:1337/v1/models",
        "no_auth": True,
        "local": True,
        "default_endpoint": "http://localhost:1337/v1",
        "setup_url": "https://jan.ai",
        "setup_instructions": "Download from jan.ai, install a model, enable API server in settings",
        "openai_compatible": True,
        "models": [],  # Auto-detected from running instance
    },
    "gpt4all": {
        "name": "GPT4All (Local - GUI)",
        "key_prefix": "",
        "key_pattern": r".*",  # No key needed
        "test_url": "http://localhost:4891/v1/models",
        "no_auth": True,
        "local": True,
        "default_endpoint": "http://localhost:4891/v1",
        "setup_url": "https://gpt4all.io",
        "setup_instructions": "Download from gpt4all.io, enable API server in settings",
        "openai_compatible": True,
        "models": [],  # Auto-detected from running instance
    },
}


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------


@dataclass
class UserCredential:
    """A stored LLM provider credential."""
    credential_id: str
    provider: str
    label: str
    created_at: str
    updated_at: str
    last_used_at: str = ""
    last_validated_at: str = ""
    is_valid: bool = True
    validation_error: str = ""
    usage_count: int = 0
    # Encrypted fields (not exposed in API responses)
    encrypted_key: str = ""
    key_salt: str = ""
    # Optional provider-specific config
    endpoint_url: str = ""  # For Azure OpenAI
    organization_id: str = ""  # For OpenAI org
    default_model: str = ""

    def to_safe_dict(self) -> Dict[str, Any]:
        """Return dict without sensitive fields."""
        return {
            "credential_id": self.credential_id,
            "provider": self.provider,
            "provider_name": PROVIDERS.get(self.provider, {}).get("name", self.provider),
            "label": self.label,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_used_at": self.last_used_at,
            "last_validated_at": self.last_validated_at,
            "is_valid": self.is_valid,
            "validation_error": self.validation_error,
            "usage_count": self.usage_count,
            "endpoint_url": self.endpoint_url,
            "organization_id": self.organization_id,
            "default_model": self.default_model,
            "available_models": PROVIDERS.get(self.provider, {}).get("models", []),
            "is_local": PROVIDERS.get(self.provider, {}).get("local", False),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_username(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]", "_", str(value or "").strip().lower()).strip("._-")
    return cleaned[:64] if cleaned else ""


def _normalize_provider(value: str) -> str:
    p = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return p if p in PROVIDERS else ""


def _store_root(user_root: Optional[Path] = None) -> Path:
    root = Path(user_root) if user_root else _DEFAULT_USER_ROOT
    out = root / _CREDENTIALS_DIR
    out.mkdir(parents=True, exist_ok=True)
    return out


def _store_file(user_id: str, *, user_root: Optional[Path] = None) -> Path:
    uid = _normalize_username(user_id)
    if not uid:
        raise ValueError("user_id_required")
    return _store_root(user_root=user_root) / f"{uid}.json"


def _master_secret_bytes() -> bytes:
    """Get or generate the master encryption key.

    The one choke point every credential encrypt/decrypt call passes through
    (via _derive_user_key/_get_fernet); guarding here, not at each public
    function, covers add/get/update/delete/revalidate/get_decrypted_key in one
    place. A legacy master-key name here is not a silent-degrade case like the
    lower-level scan primitives: falling through to the persisted-or-generate
    path below MINTS A NEW RANDOM KEY, so every credential encrypted under the
    operator's intended (but misnamed) seed becomes permanently undecryptable.
    That is irreversible, unlike a weaker detection default, so it is raised
    loudly here rather than merely documented.
    """
    reject_legacy_env()
    seed = (
        str(os.environ.get("PRIVACY_SHIELD_CREDENTIALS_MASTER_KEY", "")).strip()
        or str(os.environ.get("PRIVACY_SHIELD_SKILL_INTAKE_MASTER_KEY", "")).strip()
        or str(os.environ.get("COCKPIT_SESSION_SECRET", "")).strip()
    )
    if seed:
        return hashlib.sha256(seed.encode("utf-8")).digest()

    # Fallback: generate and persist an instance-local master secret
    key_path = _DEFAULT_USER_ROOT / _MASTER_KEY_FILENAME
    key_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if key_path.exists():
            raw = key_path.read_text(encoding="utf-8").strip()
            if raw:
                return hashlib.sha256(raw.encode("utf-8")).digest()
    except Exception as exc:
        logger.debug("Failed to read persisted credentials master key %s: %s", key_path, exc)

    # Generate new master key
    new_key = secrets.token_hex(32)
    try:
        key_path.write_text(new_key + "\n", encoding="utf-8")
        key_path.chmod(0o600)
    except Exception as exc:
        logger.debug("Failed to persist credentials master key %s: %s", key_path, exc)
    return hashlib.sha256(new_key.encode("utf-8")).digest()


def _derive_user_key(user_id: str, salt: bytes) -> bytes:
    """Derive a user-specific encryption key."""
    master = _master_secret_bytes()
    combined = master + user_id.encode("utf-8") + salt
    return hashlib.sha256(combined).digest()


def _get_fernet(user_id: str, salt_hex: str) -> Any:
    """Get a Fernet instance for a user.

    Raises rather than degrading: there is no silent path back to plaintext
    here any more. `Fernet is None` (cryptography not installed) and
    `LegacyEnvironmentError` (from `_master_secret_bytes` via
    `_derive_user_key`) both propagate as raises, same as any other
    unexpected failure deriving the key. `_encrypt_key`/`_decrypt_key` no
    longer catch anything from this call — see their docstrings.
    """
    if Fernet is None:
        raise CredentialEncryptionUnavailable(
            "cryptography is not installed; credentials cannot be encrypted "
            "or decrypted without it"
        )
    salt = bytes.fromhex(salt_hex)
    key = _derive_user_key(user_id, salt)
    fernet_key = base64.urlsafe_b64encode(key)
    return Fernet(fernet_key)


def _encrypt_key(user_id: str, api_key: str) -> Tuple[str, str]:
    """Encrypt an API key. Returns (encrypted_key, salt_hex).

    Raises (LegacyEnvironmentError / CredentialEncryptionUnavailable) instead
    of writing the key in cleartext when encryption is not available for any
    reason: a credential store must never silently persist a secret
    unencrypted. There is no `key_salt="fallback"` write path any more; that
    value is still accepted on read (`_decrypt_key`), for credentials a
    pre-fix install already wrote insecurely.
    """
    salt = secrets.token_bytes(16)
    salt_hex = salt.hex()
    fernet = _get_fernet(user_id, salt_hex)
    encrypted = fernet.encrypt(api_key.encode("utf-8"))
    return encrypted.decode("utf-8"), salt_hex


def _decrypt_key(user_id: str, encrypted_key: str, salt_hex: str) -> Optional[str]:
    """Decrypt an API key.

    `key_salt="fallback"` is only ever read here now, never written by
    `_encrypt_key` — it is the marker a pre-fix install left on disk.
    Genuine decrypt failure (wrong/rotated master key, corrupted data)
    returns None, same as before; a legacy env var or a missing
    `cryptography` install raises out of `_get_fernet`, unchanged from there.
    """
    if salt_hex == "fallback":
        try:
            return base64.b64decode(encrypted_key.encode("utf-8")).decode("utf-8")
        except Exception:
            return None

    fernet = _get_fernet(user_id, salt_hex)
    try:
        decrypted = fernet.decrypt(encrypted_key.encode("utf-8"))
        return decrypted.decode("utf-8")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Storage Operations
# ---------------------------------------------------------------------------


def _load_user_credentials(user_id: str, *, user_root: Optional[Path] = None) -> Dict[str, UserCredential]:
    """Load all credentials for a user."""
    try:
        path = _store_file(user_id, user_root=user_root)
        if not path.exists():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        result = {}
        for cid, rec in data.items():
            result[cid] = UserCredential(
                credential_id=str(rec.get("credential_id", cid)),
                provider=str(rec.get("provider", "")),
                label=str(rec.get("label", "")),
                created_at=str(rec.get("created_at", "")),
                updated_at=str(rec.get("updated_at", "")),
                last_used_at=str(rec.get("last_used_at", "")),
                last_validated_at=str(rec.get("last_validated_at", "")),
                is_valid=bool(rec.get("is_valid", True)),
                validation_error=str(rec.get("validation_error", "")),
                usage_count=int(rec.get("usage_count", 0)),
                encrypted_key=str(rec.get("encrypted_key", "")),
                key_salt=str(rec.get("key_salt", "")),
                endpoint_url=str(rec.get("endpoint_url", "")),
                organization_id=str(rec.get("organization_id", "")),
                default_model=str(rec.get("default_model", "")),
            )
        return result
    except Exception:
        return {}


def _save_user_credentials(
    user_id: str,
    credentials: Dict[str, UserCredential],
    *,
    user_root: Optional[Path] = None,
) -> None:
    """Save all credentials for a user."""
    path = _store_file(user_id, user_root=user_root)
    data = {cid: asdict(cred) for cid, cred in credentials.items()}
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except Exception as exc:
        logger.debug("Failed to apply permissions for credentials file %s: %s", path, exc)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_key_format(provider: str, api_key: str) -> Tuple[bool, str]:
    """Validate API key format without making network requests."""
    prov = _normalize_provider(provider)
    if not prov:
        return False, f"Unknown provider: {provider}"

    config = PROVIDERS[prov]
    pattern = config.get("key_pattern", "")

    if config.get("no_auth"):
        return True, ""

    if not api_key:
        return False, "API key is required"

    if pattern and not re.match(pattern, api_key):
        prefix = config.get("key_prefix", "")
        if prefix:
            return False, f"Invalid key format. {config['name']} keys should start with '{prefix}'"
        return False, f"Invalid key format for {config['name']}"

    return True, ""


def validate_key_live(
    provider: str,
    api_key: str,
    *,
    endpoint_url: str = "",
    timeout: float = 10.0,
) -> Tuple[bool, str, List[str]]:
    """
    Validate API key by making a test request to the provider.

    Returns: (is_valid, error_message, available_models)
    """
    if httpx is None:
        return True, "httpx not available - skipping live validation", []

    prov = _normalize_provider(provider)
    if not prov:
        return False, f"Unknown provider: {provider}", []

    config = PROVIDERS[prov]

    # Format validation first
    valid, err = validate_key_format(provider, api_key)
    if not valid:
        return False, err, []

    # Local providers (Ollama)
    if config.get("local"):
        test_url = config.get("test_url", "")
        if not test_url:
            return True, "", config.get("models", [])
        try:
            resp = httpx.get(test_url, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                return True, "", models if models else config.get("models", [])
            return False, f"Ollama not responding (status {resp.status_code})", []
        except Exception as e:
            return False, f"Cannot connect to Ollama: {e}", []

    # Azure OpenAI needs custom endpoint
    if prov == "azure_openai":
        if not endpoint_url:
            return False, "Azure OpenAI requires an endpoint URL", []
        test_url = f"{endpoint_url.rstrip('/')}/openai/models?api-version=2024-02-01"
        try:
            resp = httpx.get(
                test_url,
                headers={"api-key": api_key},
                timeout=timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("id", "") for m in data.get("data", [])]
                return True, "", models
            elif resp.status_code == 401:
                return False, "Invalid API key", []
            else:
                return False, f"Azure API error (status {resp.status_code})", []
        except Exception as e:
            return False, f"Cannot connect to Azure: {e}", []

    # Standard providers
    test_url = config.get("test_url", "")
    if not test_url:
        return True, "", config.get("models", [])

    headers = {}
    params = {}

    # Auth header
    if config.get("auth_header"):
        auth_format = config.get("auth_format", "{key}")
        headers[config["auth_header"]] = auth_format.format(key=api_key)

    # Auth param (Google)
    if config.get("auth_param"):
        params[config["auth_param"]] = api_key

    # Extra headers (Anthropic)
    if config.get("extra_headers"):
        headers.update(config["extra_headers"])

    try:
        resp = httpx.get(test_url, headers=headers, params=params, timeout=timeout)

        if resp.status_code == 200:
            data = resp.json()
            # Extract models from response
            models = []
            if "data" in data:
                models = [m.get("id", "") for m in data.get("data", [])]
            elif "models" in data:
                models = [m.get("name", m.get("id", "")) for m in data.get("models", [])]
            return True, "", models if models else config.get("models", [])

        elif resp.status_code in (401, 403):
            return False, "Invalid or expired API key", []

        elif resp.status_code == 429:
            # Rate limited but key is valid
            return True, "", config.get("models", [])

        else:
            return False, f"API error (status {resp.status_code})", []

    except httpx.ConnectError:
        return False, f"Cannot connect to {config['name']} API", []
    except httpx.TimeoutException:
        return False, f"Connection to {config['name']} timed out", []
    except Exception as e:
        return False, f"Validation error: {e}", []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def add_credential(
    user_id: str,
    provider: str,
    api_key: str,
    *,
    label: str = "",
    endpoint_url: str = "",
    organization_id: str = "",
    default_model: str = "",
    validate: bool = True,
    user_root: Optional[Path] = None,
) -> Tuple[Optional[UserCredential], str]:
    """
    Add a new credential for a user.

    Returns: (credential, error_message)
    """
    uid = _normalize_username(user_id)
    if not uid:
        return None, "Invalid user ID"

    prov = _normalize_provider(provider)
    if not prov:
        return None, f"Unknown provider: {provider}. Supported: {', '.join(PROVIDERS.keys())}"

    # Validate format
    valid, err = validate_key_format(prov, api_key)
    if not valid:
        return None, err

    # Live validation if requested
    available_models: List[str] = []
    validation_error = ""
    is_valid = True

    if validate and not PROVIDERS[prov].get("no_auth"):
        is_valid, validation_error, available_models = validate_key_live(
            prov, api_key, endpoint_url=endpoint_url
        )
        if not is_valid:
            return None, validation_error

    # Generate credential ID
    credential_id = secrets.token_hex(8)
    now = _utc_now()

    # Encrypt the API key
    encrypted_key, key_salt = _encrypt_key(uid, api_key)

    # Create credential
    credential = UserCredential(
        credential_id=credential_id,
        provider=prov,
        label=label.strip() or f"{PROVIDERS[prov]['name']} Key",
        created_at=now,
        updated_at=now,
        last_validated_at=now if validate else "",
        is_valid=is_valid,
        validation_error=validation_error,
        encrypted_key=encrypted_key,
        key_salt=key_salt,
        endpoint_url=endpoint_url.strip(),
        organization_id=organization_id.strip(),
        default_model=default_model.strip() or (available_models[0] if available_models else ""),
    )

    # Save
    credentials = _load_user_credentials(uid, user_root=user_root)
    credentials[credential_id] = credential
    _save_user_credentials(uid, credentials, user_root=user_root)

    return credential, ""


def get_credential(
    user_id: str,
    credential_id: str,
    *,
    user_root: Optional[Path] = None,
) -> Optional[UserCredential]:
    """Get a specific credential."""
    uid = _normalize_username(user_id)
    if not uid:
        return None
    credentials = _load_user_credentials(uid, user_root=user_root)
    return credentials.get(credential_id)


def list_credentials(
    user_id: str,
    *,
    provider: str = "",
    user_root: Optional[Path] = None,
) -> List[UserCredential]:
    """List all credentials for a user."""
    uid = _normalize_username(user_id)
    if not uid:
        return []
    credentials = _load_user_credentials(uid, user_root=user_root)
    result = list(credentials.values())

    if provider:
        prov = _normalize_provider(provider)
        result = [c for c in result if c.provider == prov]

    result.sort(key=lambda c: c.created_at, reverse=True)
    return result


def delete_credential(
    user_id: str,
    credential_id: str,
    *,
    user_root: Optional[Path] = None,
) -> bool:
    """Delete a credential. Returns True if found and deleted."""
    uid = _normalize_username(user_id)
    if not uid:
        return False

    credentials = _load_user_credentials(uid, user_root=user_root)
    if credential_id not in credentials:
        return False

    del credentials[credential_id]
    _save_user_credentials(uid, credentials, user_root=user_root)
    return True


def update_credential(
    user_id: str,
    credential_id: str,
    *,
    label: str = None,
    default_model: str = None,
    endpoint_url: str = None,
    organization_id: str = None,
    user_root: Optional[Path] = None,
) -> Optional[UserCredential]:
    """Update credential metadata (not the key itself)."""
    uid = _normalize_username(user_id)
    if not uid:
        return None

    credentials = _load_user_credentials(uid, user_root=user_root)
    credential = credentials.get(credential_id)
    if not credential:
        return None

    if label is not None:
        credential.label = label.strip()
    if default_model is not None:
        credential.default_model = default_model.strip()
    if endpoint_url is not None:
        credential.endpoint_url = endpoint_url.strip()
    if organization_id is not None:
        credential.organization_id = organization_id.strip()

    credential.updated_at = _utc_now()
    _save_user_credentials(uid, credentials, user_root=user_root)
    return credential


def revalidate_credential(
    user_id: str,
    credential_id: str,
    *,
    user_root: Optional[Path] = None,
) -> Tuple[bool, str]:
    """Re-validate a stored credential."""
    uid = _normalize_username(user_id)
    if not uid:
        return False, "Invalid user ID"

    credentials = _load_user_credentials(uid, user_root=user_root)
    credential = credentials.get(credential_id)
    if not credential:
        return False, "Credential not found"

    # Decrypt key
    api_key = _decrypt_key(uid, credential.encrypted_key, credential.key_salt)
    if not api_key:
        credential.is_valid = False
        credential.validation_error = "Cannot decrypt key"
        credential.updated_at = _utc_now()
        _save_user_credentials(uid, credentials, user_root=user_root)
        return False, "Cannot decrypt key"

    # Validate
    is_valid, error, _ = validate_key_live(
        credential.provider,
        api_key,
        endpoint_url=credential.endpoint_url,
    )

    credential.is_valid = is_valid
    credential.validation_error = error
    credential.last_validated_at = _utc_now()
    credential.updated_at = _utc_now()
    _save_user_credentials(uid, credentials, user_root=user_root)

    return is_valid, error


def get_decrypted_key(
    user_id: str,
    credential_id: str,
    *,
    user_root: Optional[Path] = None,
) -> Optional[str]:
    """
    Get the decrypted API key for internal use (LLM gateway).

    WARNING: Only call this from trusted internal code paths.
    Never expose this in API responses.
    """
    uid = _normalize_username(user_id)
    if not uid:
        return None

    credentials = _load_user_credentials(uid, user_root=user_root)
    credential = credentials.get(credential_id)
    if not credential:
        return None

    return _decrypt_key(uid, credential.encrypted_key, credential.key_salt)


def record_usage(
    user_id: str,
    credential_id: str,
    *,
    user_root: Optional[Path] = None,
) -> None:
    """Record that a credential was used."""
    uid = _normalize_username(user_id)
    if not uid:
        return

    credentials = _load_user_credentials(uid, user_root=user_root)
    credential = credentials.get(credential_id)
    if not credential:
        return

    credential.usage_count += 1
    credential.last_used_at = _utc_now()
    _save_user_credentials(uid, credentials, user_root=user_root)


def get_credential_for_provider(
    user_id: str,
    provider: str,
    *,
    user_root: Optional[Path] = None,
) -> Optional[UserCredential]:
    """Get the first valid credential for a provider."""
    uid = _normalize_username(user_id)
    prov = _normalize_provider(provider)
    if not uid or not prov:
        return None

    credentials = list_credentials(uid, provider=prov, user_root=user_root)
    for cred in credentials:
        if cred.is_valid:
            return cred
    return None


def list_providers() -> List[Dict[str, Any]]:
    """List all supported providers with their metadata."""
    return [
        {
            "id": pid,
            "name": config["name"],
            "key_prefix": config.get("key_prefix", ""),
            "requires_endpoint": config.get("requires_endpoint", False),
            "is_local": config.get("local", False),
            "no_auth": config.get("no_auth", False),
            "setup_url": config.get("setup_url", ""),
            "setup_instructions": config.get("setup_instructions", ""),
            "models": config.get("models", []),
        }
        for pid, config in PROVIDERS.items()
    ]


# ---------------------------------------------------------------------------
# Local Provider Discovery
# ---------------------------------------------------------------------------


def _check_local_provider(provider_id: str, timeout: float = 2.0) -> Dict[str, Any]:
    """Check if a local provider is running and get its models.

    Returns:
        Dict with status info:
        {
            "provider": "ollama",
            "running": True/False,
            "endpoint": "http://localhost:11434",
            "models": ["llama3.2", "mistral"],
            "error": None or error message
        }
    """
    config = PROVIDERS.get(provider_id)
    if not config or not config.get("local"):
        return {
            "provider": provider_id,
            "running": False,
            "endpoint": None,
            "models": [],
            "error": "Not a local provider",
        }

    test_url = config.get("test_url", "")
    endpoint = config.get("default_endpoint", "")

    if not test_url:
        return {
            "provider": provider_id,
            "running": False,
            "endpoint": endpoint,
            "models": [],
            "error": "No test URL configured",
        }

    try:
        if httpx is None:
            import urllib.request
            import urllib.error

            req = urllib.request.Request(test_url, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        else:
            resp = httpx.get(test_url, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()

        # Extract models based on provider format
        models = _extract_models_from_response(provider_id, data)

        return {
            "provider": provider_id,
            "running": True,
            "endpoint": endpoint,
            "models": models,
            "error": None,
        }

    except Exception as e:
        return {
            "provider": provider_id,
            "running": False,
            "endpoint": endpoint,
            "models": [],
            "error": str(e),
        }


def _extract_models_from_response(provider_id: str, data: Any) -> List[str]:
    """Extract model names from provider's API response."""
    models = []

    if provider_id == "ollama":
        # Ollama returns {"models": [{"name": "llama3.2:latest", ...}]}
        for m in data.get("models", []):
            name = m.get("name", "")
            if name:
                # Remove :latest suffix for cleaner display
                models.append(name.replace(":latest", ""))

    elif provider_id in ("lm_studio", "jan", "gpt4all"):
        # OpenAI-compatible format: {"data": [{"id": "model-name"}]}
        for m in data.get("data", []):
            model_id = m.get("id", "")
            if model_id:
                models.append(model_id)

    return models


def discover_local_providers(timeout: float = 2.0) -> List[Dict[str, Any]]:
    """Discover all running local LLM providers.

    Checks each local provider endpoint and returns status info.

    Returns:
        List of status dicts for each local provider
    """
    local_providers = [
        pid for pid, config in PROVIDERS.items()
        if config.get("local", False)
    ]

    results = []
    for provider_id in local_providers:
        status = _check_local_provider(provider_id, timeout=timeout)
        config = PROVIDERS.get(provider_id, {})
        status["name"] = config.get("name", provider_id)
        status["setup_url"] = config.get("setup_url", "")
        status["setup_instructions"] = config.get("setup_instructions", "")
        status["openai_compatible"] = config.get("openai_compatible", False)
        results.append(status)

    return results


def get_local_provider_status(provider_id: str, timeout: float = 2.0) -> Dict[str, Any]:
    """Get status of a specific local provider.

    Args:
        provider_id: Provider to check (ollama, lm_studio, jan, gpt4all)
        timeout: Connection timeout in seconds

    Returns:
        Status dict with running state, models, etc.
    """
    status = _check_local_provider(provider_id, timeout=timeout)
    config = PROVIDERS.get(provider_id, {})
    status["name"] = config.get("name", provider_id)
    status["setup_url"] = config.get("setup_url", "")
    status["setup_instructions"] = config.get("setup_instructions", "")
    status["openai_compatible"] = config.get("openai_compatible", False)
    return status


def auto_configure_local_provider(
    user_id: str,
    provider_id: str,
    *,
    label: Optional[str] = None,
    default_model: Optional[str] = None,
    user_root: Optional[Path] = None,
) -> Tuple[Optional[UserCredential], str]:
    """Auto-configure a local provider if it's running.

    Checks if the provider is running and creates a credential entry
    for it (local providers don't need API keys but we track them
    for consistency).

    Args:
        user_id: User to configure for
        provider_id: Local provider (ollama, lm_studio, etc.)
        label: Optional friendly name
        default_model: Optional default model to use

    Returns:
        Tuple of (credential, error_message)
    """
    config = PROVIDERS.get(provider_id)
    if not config:
        return None, f"Unknown provider: {provider_id}"

    if not config.get("local"):
        return None, f"Not a local provider: {provider_id}"

    # Check if running
    status = _check_local_provider(provider_id)
    if not status["running"]:
        setup_instructions = config.get("setup_instructions", "")
        setup_url = config.get("setup_url", "")
        error_parts = [f"{config['name']} is not running."]
        if setup_instructions:
            error_parts.append(setup_instructions)
        if setup_url:
            error_parts.append(f"Download: {setup_url}")
        return None, " ".join(error_parts)

    # Pick default model if not specified
    if not default_model and status["models"]:
        default_model = status["models"][0]

    # Create credential entry
    endpoint = status["endpoint"] or config.get("default_endpoint", "")

    return add_credential(
        user_id=user_id,
        provider=provider_id,
        api_key="",  # No key needed for local
        label=label or config["name"],
        endpoint_url=endpoint,
        default_model=default_model or "",
        validate=False,  # Already validated by checking if running
        user_root=user_root,
    )
