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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parent / "data" / "privacy_shield"
_CONTEXT_EMBEDDINGS_FILE = _DATA_DIR / "pii_context_embeddings.json"


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

    def __init__(self, model: str = "text-embedding-3-small") -> None:
        self.model = model
        self._client = None
        self._context_embeddings: Dict[str, List[Dict[str, Any]]] = {}
        self._load_context_embeddings()

    def _get_client(self):
        """Get or create OpenAI client for embeddings."""
        if self._client is None:
            try:
                import os
                import openai
                api_key = os.environ.get("OPENAI_API_KEY", "")
                if api_key:
                    self._client = openai.OpenAI(api_key=api_key)
            except ImportError:
                logger.warning("OpenAI not available for PII embeddings")
        return self._client

    def _embed(self, text: str) -> List[float]:
        """Generate embedding for a single text string."""
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

    def _load_context_embeddings(self) -> None:
        """Load pre-computed PII context embeddings from disk."""
        if _CONTEXT_EMBEDDINGS_FILE.exists():
            try:
                self._context_embeddings = json.loads(
                    _CONTEXT_EMBEDDINGS_FILE.read_text(encoding="utf-8")
                )
            except Exception:
                self._context_embeddings = {}

    def _save_context_embeddings(self) -> None:
        """Persist PII context embeddings to disk."""
        _CONTEXT_EMBEDDINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CONTEXT_EMBEDDINGS_FILE.write_text(
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
            chunk_embedding = self._embed(chunk)
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
