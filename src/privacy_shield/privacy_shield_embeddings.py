"""
Privacy Shield Embeddings - Semantic PII context matching.

Complements the regex-based Privacy Shield with embedding-based
detection of PII contexts.  Instead of matching PII values directly,
this module matches the **contexts** in which PII typically appears
(e.g. "employee named ...", "patient diagnosed with ...") using
cosine similarity against pre-embedded context patterns.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit_log import _STATE_APP_DIR, _user_state_home
from .utils.network import (
    is_loopback_or_unix_endpoint,
    no_proxy_http_client,
    safe_hostname,
)

logger = logging.getLogger(__name__)

DEFAULT_EMBEDDING_BASE_URL = "https://api.openai.com/v1"


def _configured_base_url() -> str:
    """The endpoint the embedding client will actually talk to.

    Read here rather than left to the SDK's own environment lookup, so the
    endpoint guard below checks the same address the request will use.
    """
    return (
        os.environ.get("OPENAI_BASE_URL")
        or os.environ.get("OPENAI_API_BASE")
        or DEFAULT_EMBEDDING_BASE_URL
    ).strip()

CONTEXT_EMBEDDINGS_ENV = "PRIVACY_SHIELD_CONTEXT_EMBEDDINGS"
_CONTEXT_EMBEDDINGS_FILE: Optional[Path] = None
_LEGACY_PACKAGE_FILE = (
    Path(__file__).resolve().parent / "data" / "privacy_shield" / "pii_context_embeddings.json"
)


def context_embeddings_path() -> Path:
    """The context-embeddings cache, resolved at call time, outside the package."""
    override = str(os.environ.get(CONTEXT_EMBEDDINGS_ENV, "")).strip()
    if override:
        return Path(override)
    return _user_state_home() / _STATE_APP_DIR / "pii_context_embeddings.json"


def _resolved_context_embeddings_path() -> Path:
    return Path(_CONTEXT_EMBEDDINGS_FILE) if _CONTEXT_EMBEDDINGS_FILE else context_embeddings_path()


# ---- Pre-defined PII context patterns ----
# These are the *contexts* around PII, not PII values themselves.

PII_CONTEXT_PATTERNS: Dict[str, List[str]] = {
    "name": [
        "employee named",
        "the artist known as",
        "client name is",
        "contact person:",
        "signed by",
        "payee:",
        "account holder",
        "represented by attorney",
        "Herr/Frau",
    ],
    "email": [
        "email address:",
        "reach them at",
        "send correspondence to",
        "contact email",
        "reply to",
        "e-mail:",
    ],
    "phone": [
        "phone number",
        "call them at",
        "mobile:",
        "Telefonnummer:",
        "Fax:",
        "reach by phone",
    ],
    "address": [
        "residing at",
        "home address:",
        "office located at",
        "mailing address",
        "Anschrift:",
        "registered address:",
        "delivery address",
    ],
    "financial": [
        "IBAN:",
        "bank account number",
        "credit card ending in",
        "salary of",
        "annual compensation",
        "payment to account",
        "BIC/SWIFT:",
        "routing number",
        "Kontonummer:",
    ],
    "health": [
        "diagnosed with",
        "patient suffering from",
        "medical condition:",
        "treatment for",
        "health insurance ID",
        "prescription for",
        "Krankenversicherungsnummer:",
    ],
    "id_document": [
        "passport number",
        "ID card number",
        "social security number",
        "Personalausweisnummer:",
        "Steuer-ID:",
        "tax identification number",
        "driver license number",
    ],
    "date_of_birth": [
        "born on",
        "date of birth:",
        "Geburtsdatum:",
        "DOB:",
        "age:",
    ],
    "location": [
        "GPS coordinates",
        "located at latitude",
        "current location:",
        "Standort:",
        "tracking data shows",
    ],
}


@dataclass
class PIIMatch:
    """A detected PII context match."""
    chunk_text: str
    pii_category: str
    matched_pattern: str
    similarity_score: float
    suggested_redaction: str
    chunk_index: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chunk_text": self.chunk_text,
            "pii_category": self.pii_category,
            "matched_pattern": self.matched_pattern,
            "similarity_score": self.similarity_score,
            "suggested_redaction": self.suggested_redaction,
            "chunk_index": self.chunk_index,
        }


# ---- Redaction placeholders by category ----
REDACTION_MAP = {
    "name": "[NAME]",
    "email": "[EMAIL]",
    "phone": "[PHONE]",
    "address": "[ADDRESS]",
    "financial": "[ACCOUNT_NUMBER]",
    "health": "[HEALTH_DATA]",
    "id_document": "[ID_NUMBER]",
    "date_of_birth": "[DOB]",
    "location": "[LOCATION]",
}


def _chunk_text(text: str, chunk_size: int = 200, overlap: int = 50) -> List[str]:
    """Split text into overlapping chunks for scanning."""
    if len(text) <= chunk_size:
        return [text] if text.strip() else []
    chunks = []
    start = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        start = end - overlap if end < len(text) else len(text)
    return chunks


def _compute_cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
    """Compute cosine similarity between two vectors."""
    try:
        import numpy as np
        a = np.array(vec1)
        b = np.array(vec2)
        denom = np.linalg.norm(a) * np.linalg.norm(b)
        return float(np.dot(a, b) / denom) if denom > 0 else 0.0
    except ImportError:
        # Fallback without numpy
        dot = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = sum(a * a for a in vec1) ** 0.5
        norm2 = sum(b * b for b in vec2) ** 0.5
        return dot / (norm1 * norm2) if norm1 > 0 and norm2 > 0 else 0.0


class PIIContextMatcher:
    """Semantic PII context detection using embeddings.

    Embeds a set of known PII context patterns, then scans input
    text by comparing chunk embeddings against those patterns.
    """

    def __init__(
        self,
        model: str = "text-embedding-3-small",
        embeddings_path: Optional[str | Path] = None,
    ) -> None:
        self.model = model
        self.embeddings_path = (
            Path(embeddings_path) if embeddings_path else _resolved_context_embeddings_path()
        )
        self._client = None
        self._refused_remote_endpoint = False
        self._context_embeddings: Dict[str, List[Dict[str, Any]]] = {}
        self._load_context_embeddings()

    def _get_client(self):
        """Get or create the OpenAI client for embeddings.

        `trust_env=False` on the transport, like every other send path in this
        package. The three that were fixed carried scan text to a checked
        loopback address; this one was left building a client with the
        environment's proxy mounts, so with HTTP_PROXY set its requests went to
        the corporate proxy regardless of the endpoint. See utils.network.
        """
        if self._client is None:
            try:
                import openai
            except ImportError:
                logger.warning("OpenAI not available for PII embeddings")
                return None
            api_key = os.environ.get("OPENAI_API_KEY", "")
            if api_key:
                self._client = openai.OpenAI(
                    api_key=api_key,
                    base_url=_configured_base_url(),
                    http_client=no_proxy_http_client(),
                )
        return self._client

    def _embed(self, text: str) -> List[float]:
        """Generate embedding for a single text string.

        Callers that pass DOCUMENT text must go through `_embed_document_chunk`
        instead. This one is for the fixed context phrases defined in this
        module's source, which are not anybody's personal data.
        """
        client = self._get_client()
        if not client:
            return []
        try:
            response = client.embeddings.create(
                model=self.model,
                input=text[:8000],
            )
            return response.data[0].embedding
        except Exception as e:
            logger.error("Embedding failed: %s", e)
            return []

    def _embed_document_chunk(self, text: str) -> List[float]:
        """Embed a chunk of the scanned document, if the endpoint is local.

        This is the one call in the package that hands raw, pre-redaction
        document text to an embedding service, 8000 characters at a time. It is
        on the main scan path - `shield._get_semantic_context_matcher` reaches
        it from `process_text`, and PRIVACY_SHIELD_SEMANTIC_ENABLED defaults to
        "1" - and it is silent today only because the context store ships
        empty. Run the documented `embed_pii_contexts()` setup once and every
        chunk of every scanned document starts leaving the machine.

        Sending it to a remote endpoint is `egress_original_unredacted_text`,
        which the skill's own governance block prohibits. So the same endpoint
        guard the local-model send paths use applies here: a loopback address
        or a unix socket, or the semantic layer declines and the scan proceeds
        on the regex floor.
        """
        endpoint = _configured_base_url()
        if not is_loopback_or_unix_endpoint(endpoint):
            if not self._refused_remote_endpoint:
                self._refused_remote_endpoint = True
                logger.error(
                    "semantic context scan disabled: embedding endpoint %s is not "
                    "loopback or a unix socket, and this call would send raw "
                    "pre-redaction document text to it. Point OPENAI_BASE_URL at a "
                    "local embedding server to re-enable it.",
                    safe_hostname(endpoint),
                )
            return []
        return self._embed(text)

    def _load_context_embeddings(self) -> None:
        """Load pre-computed PII context embeddings from disk."""
        if self.embeddings_path.exists():
            try:
                self._context_embeddings = json.loads(
                    self.embeddings_path.read_text(encoding="utf-8")
                )
            except Exception:
                self._context_embeddings = {}
        elif _LEGACY_PACKAGE_FILE.exists():
            # 2.0.0 and earlier wrote the cache here; it is no longer read.
            logger.warning(
                "ignoring context embeddings inside the package at %s; the cache now "
                "lives at %s - re-run embed_pii_contexts() to rebuild it there",
                _LEGACY_PACKAGE_FILE,
                self.embeddings_path,
            )

    def _save_context_embeddings(self) -> None:
        """Persist PII context embeddings to disk."""
        self.embeddings_path.parent.mkdir(parents=True, exist_ok=True)
        self.embeddings_path.write_text(
            json.dumps(self._context_embeddings, ensure_ascii=False),
            encoding="utf-8",
        )

    def embed_pii_contexts(
        self,
        patterns: Optional[Dict[str, List[str]]] = None,
    ) -> int:
        """Embed all PII context patterns and persist.

        Should be called once at setup or when patterns change.

        Args:
            patterns: Override default PII_CONTEXT_PATTERNS.

        Returns:
            Number of patterns embedded.
        """
        patterns = patterns or PII_CONTEXT_PATTERNS
        count = 0
        for category, phrases in patterns.items():
            cat_embeddings = []
            for phrase in phrases:
                embedding = self._embed(phrase)
                if embedding:
                    cat_embeddings.append({
                        "phrase": phrase,
                        "embedding": embedding,
                    })
                    count += 1
            self._context_embeddings[category] = cat_embeddings

        self._save_context_embeddings()
        logger.info("Embedded %d PII context patterns across %d categories", count, len(patterns))
        return count

    def scan_for_pii_contexts(
        self,
        text: str,
        *,
        threshold: float = 0.75,
        chunk_size: int = 200,
    ) -> List[PIIMatch]:
        """Scan text for PII contexts using embedding similarity.

        Args:
            text: The text to scan.
            threshold: Minimum cosine similarity to flag a match.
            chunk_size: Size of text chunks to scan.

        Returns:
            List of PIIMatch objects for chunks exceeding threshold.
        """
        if not self._context_embeddings:
            logger.warning("No PII context embeddings loaded. Run embed_pii_contexts() first.")
            return []

        chunks = _chunk_text(text, chunk_size=chunk_size)
        matches: List[PIIMatch] = []

        for chunk_idx, chunk in enumerate(chunks):
            chunk_embedding = self._embed_document_chunk(chunk)
            if not chunk_embedding:
                continue

            best_score = 0.0
            best_category = ""
            best_pattern = ""

            for category, cat_embeddings in self._context_embeddings.items():
                for pat_data in cat_embeddings:
                    pat_embedding = pat_data.get("embedding", [])
                    if not pat_embedding:
                        continue
                    sim = _compute_cosine_similarity(chunk_embedding, pat_embedding)
                    if sim > best_score:
                        best_score = sim
                        best_category = category
                        best_pattern = pat_data.get("phrase", "")

            if best_score >= threshold:
                matches.append(PIIMatch(
                    chunk_text=chunk,
                    pii_category=best_category,
                    matched_pattern=best_pattern,
                    similarity_score=best_score,
                    suggested_redaction=REDACTION_MAP.get(best_category, "[REDACTED]"),
                    chunk_index=chunk_idx,
                ))

        return matches

    def scan_quick(self, text: str) -> List[PIIMatch]:
        """Quick scan with default settings (threshold=0.75).

        Convenience wrapper for pipeline integration.
        """
        return self.scan_for_pii_contexts(text)

    @property
    def is_ready(self) -> bool:
        """Whether PII context embeddings are loaded and available."""
        return bool(self._context_embeddings)
