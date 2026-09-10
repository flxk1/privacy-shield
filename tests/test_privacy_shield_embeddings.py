"""
Tests for Privacy Shield Embeddings — semantic PII context matching.

Covers:
- PIIContextMatcher: embed_pii_contexts, scan_for_pii_contexts, scan_quick
- Text chunking: _chunk_text utility
- Cosine similarity: _compute_cosine_similarity utility
- PIIMatch dataclass serialization
- Readiness checking (is_ready property)
- Offline mode (no OpenAI key available)
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ===========================================================================
# Utility Function Tests
# ===========================================================================

class TestChunkText:
    def test_short_text_single_chunk(self):
        from brain.privacy_shield_embeddings import _chunk_text

        chunks = _chunk_text("Hello world", chunk_size=200)
        assert len(chunks) == 1
        assert chunks[0] == "Hello world"

    def test_empty_text(self):
        from brain.privacy_shield_embeddings import _chunk_text

        assert _chunk_text("") == []
        assert _chunk_text("   ") == []

    def test_long_text_multiple_chunks(self):
        from brain.privacy_shield_embeddings import _chunk_text

        text = "A" * 500
        chunks = _chunk_text(text, chunk_size=200, overlap=50)
        assert len(chunks) >= 3
        # Each chunk should be <= 200 chars
        for chunk in chunks:
            assert len(chunk) <= 200

    def test_overlap_creates_redundancy(self):
        from brain.privacy_shield_embeddings import _chunk_text

        text = "word " * 100  # 500 chars
        chunks = _chunk_text(text, chunk_size=100, overlap=20)
        # With overlap, more chunks are created
        no_overlap = _chunk_text(text, chunk_size=100, overlap=0)
        assert len(chunks) >= len(no_overlap)


class TestCosineSimilarity:
    def test_identical_vectors(self):
        from brain.privacy_shield_embeddings import _compute_cosine_similarity

        vec = [1.0, 2.0, 3.0]
        sim = _compute_cosine_similarity(vec, vec)
        assert abs(sim - 1.0) < 0.001

    def test_orthogonal_vectors(self):
        from brain.privacy_shield_embeddings import _compute_cosine_similarity

        a = [1.0, 0.0, 0.0]
        b = [0.0, 1.0, 0.0]
        sim = _compute_cosine_similarity(a, b)
        assert abs(sim) < 0.001

    def test_opposite_vectors(self):
        from brain.privacy_shield_embeddings import _compute_cosine_similarity

        a = [1.0, 2.0, 3.0]
        b = [-1.0, -2.0, -3.0]
        sim = _compute_cosine_similarity(a, b)
        assert abs(sim + 1.0) < 0.001

    def test_zero_vector(self):
        from brain.privacy_shield_embeddings import _compute_cosine_similarity

        a = [0.0, 0.0, 0.0]
        b = [1.0, 2.0, 3.0]
        sim = _compute_cosine_similarity(a, b)
        assert sim == 0.0


# ===========================================================================
# PIIMatch Dataclass Tests
# ===========================================================================

class TestPIIMatch:
    def test_to_dict(self):
        from brain.privacy_shield_embeddings import PIIMatch

        m = PIIMatch(
            chunk_text="employee named John Smith",
            pii_category="name",
            matched_pattern="employee named",
            similarity_score=0.92,
            suggested_redaction="[NAME]",
            chunk_index=0,
        )
        d = m.to_dict()
        assert d["pii_category"] == "name"
        assert d["similarity_score"] == 0.92
        assert d["suggested_redaction"] == "[NAME]"


# ===========================================================================
# PIIContextMatcher Tests
# ===========================================================================

class TestPIIContextMatcher:
    def test_is_ready_false_without_embeddings(self):
        from brain.privacy_shield_embeddings import PIIContextMatcher

        with patch("brain.privacy_shield_embeddings._CONTEXT_EMBEDDINGS_FILE",
                    Path("/nonexistent/file.json")):
            matcher = PIIContextMatcher()
            assert matcher.is_ready is False

    def test_is_ready_true_with_embeddings(self, tmp_path):
        embeddings_file = tmp_path / "pii_context_embeddings.json"
        embeddings_file.write_text(json.dumps({
            "name": [{"phrase": "employee named", "embedding": [0.1, 0.2, 0.3]}],
        }))

        with patch("brain.privacy_shield_embeddings._CONTEXT_EMBEDDINGS_FILE", embeddings_file):
            from brain.privacy_shield_embeddings import PIIContextMatcher
            matcher = PIIContextMatcher()
            assert matcher.is_ready is True

    def test_scan_returns_empty_without_embeddings(self):
        from brain.privacy_shield_embeddings import PIIContextMatcher

        with patch("brain.privacy_shield_embeddings._CONTEXT_EMBEDDINGS_FILE",
                    Path("/nonexistent/file.json")):
            matcher = PIIContextMatcher()
            results = matcher.scan_for_pii_contexts("Some text with employee named John")
            assert results == []

    def test_embed_pii_contexts_with_mock_client(self, tmp_path):
        """Test that embed_pii_contexts calls OpenAI and persists results."""
        embeddings_file = tmp_path / "pii_embeddings.json"

        mock_response = MagicMock()
        mock_response.data = [MagicMock(embedding=[0.1, 0.2, 0.3])]

        mock_client = MagicMock()
        mock_client.embeddings.create.return_value = mock_response

        with patch("brain.privacy_shield_embeddings._CONTEXT_EMBEDDINGS_FILE", embeddings_file):
            from brain.privacy_shield_embeddings import PIIContextMatcher
            matcher = PIIContextMatcher()
            matcher._client = mock_client

            count = matcher.embed_pii_contexts({
                "name": ["employee named", "signed by"],
                "email": ["email address:"],
            })

            assert count == 3
            assert mock_client.embeddings.create.call_count == 3
            assert matcher.is_ready is True

            # Verify persisted to disk
            assert embeddings_file.exists()
            data = json.loads(embeddings_file.read_text())
            assert "name" in data
            assert len(data["name"]) == 2

    def test_scan_with_preloaded_embeddings(self, tmp_path):
        """Test scanning with pre-computed embeddings (mocked embed calls)."""
        embeddings_file = tmp_path / "pii_embeddings.json"

        # Pre-populate embeddings for "name" category
        preloaded = {
            "name": [
                {"phrase": "employee named", "embedding": [0.9, 0.1, 0.0]},
            ],
            "email": [
                {"phrase": "email address:", "embedding": [0.0, 0.1, 0.9]},
            ],
        }
        embeddings_file.write_text(json.dumps(preloaded))

        # Mock the embed function to return vectors similar to "name" category
        mock_response = MagicMock()

        with patch("brain.privacy_shield_embeddings._CONTEXT_EMBEDDINGS_FILE", embeddings_file):
            from brain.privacy_shield_embeddings import PIIContextMatcher
            matcher = PIIContextMatcher()

            # Mock _embed to return a vector very close to the "name" pattern
            def fake_embed(text):
                if "employee" in text.lower() or "named" in text.lower():
                    return [0.85, 0.15, 0.05]  # Close to name pattern
                return [0.33, 0.33, 0.33]  # Generic

            matcher._embed = fake_embed

            matches = matcher.scan_for_pii_contexts(
                "The employee named John Smith works at ACME Corp.",
                threshold=0.7,
            )

            assert len(matches) >= 1
            assert matches[0].pii_category == "name"
            assert matches[0].suggested_redaction == "[NAME]"

    def test_scan_quick_delegates_to_scan(self, tmp_path):
        """scan_quick should be a convenience wrapper."""
        embeddings_file = tmp_path / "pii_embeddings.json"
        embeddings_file.write_text(json.dumps({}))

        with patch("brain.privacy_shield_embeddings._CONTEXT_EMBEDDINGS_FILE", embeddings_file):
            from brain.privacy_shield_embeddings import PIIContextMatcher
            matcher = PIIContextMatcher()
            # With empty embeddings, both should return empty
            assert matcher.scan_quick("test") == []


# ===========================================================================
# PII Context Patterns Tests
# ===========================================================================

class TestPIIContextPatterns:
    def test_all_categories_present(self):
        from brain.privacy_shield_embeddings import PII_CONTEXT_PATTERNS

        expected = {"name", "email", "phone", "address", "financial",
                    "health", "id_document", "date_of_birth", "location"}
        assert set(PII_CONTEXT_PATTERNS.keys()) == expected

    def test_each_category_has_patterns(self):
        from brain.privacy_shield_embeddings import PII_CONTEXT_PATTERNS

        for category, patterns in PII_CONTEXT_PATTERNS.items():
            assert len(patterns) >= 3, f"Category {category} should have at least 3 patterns"

    def test_redaction_map_covers_all_categories(self):
        from brain.privacy_shield_embeddings import PII_CONTEXT_PATTERNS, REDACTION_MAP

        for category in PII_CONTEXT_PATTERNS:
            assert category in REDACTION_MAP, f"Missing redaction for {category}"
