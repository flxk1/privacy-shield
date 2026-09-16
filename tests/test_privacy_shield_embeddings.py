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
        from privacy_shield.privacy_shield_embeddings import _chunk_text

        chunks = _chunk_text("Hello world", chunk_size=200)
        assert len(chunks) == 1
        assert chunks[0] == "Hello world"

    def test_empty_text(self):
        from privacy_shield.privacy_shield_embeddings import _chunk_text

        assert _chunk_text("") == []
        assert _chunk_text("   ") == []

    def test_long_text_multiple_chunks(self):
        from privacy_shield.privacy_shield_embeddings import _chunk_text

        text = "A" * 500
        chunks = _chunk_text(text, chunk_size=200, overlap=50)
        assert len(chunks) >= 3
        # Each chunk should be <= 200 chars
        for chunk in chunks:
            assert len(chunk) <= 200

    def test_overlap_creates_redundancy(self):
        from privacy_shield.privacy_shield_embeddings import _chunk_text

        text = "word " * 100  # 500 chars
        chunks = _chunk_text(text, chunk_size=100, overlap=20)
        # With overlap, more chunks are created
        no_overlap = _chunk_text(text, chunk_size=100, overlap=0)
        assert len(chunks) >= len(no_overlap)


class TestCosineSimilarity:
    def test_identical_vectors(self):
        from privacy_shield.privacy_shield_embeddings import _compute_cosine_similarity

        vec = [1.0, 2.0, 3.0]
        sim = _compute_cosine_similarity(vec, vec)
        assert abs(sim - 1.0) < 0.001

    def test_orthogonal_vectors(self):
        from privacy_shield.privacy_shield_embeddings import _compute_cosine_similarity

        a = [1.0, 0.0, 0.0]
        b = [0.0, 1.0, 0.0]
        sim = _compute_cosine_similarity(a, b)
        assert abs(sim) < 0.001

    def test_opposite_vectors(self):
        from privacy_shield.privacy_shield_embeddings import _compute_cosine_similarity

        a = [1.0, 2.0, 3.0]
        b = [-1.0, -2.0, -3.0]
        sim = _compute_cosine_similarity(a, b)
        assert abs(sim + 1.0) < 0.001

    def test_zero_vector(self):
        from privacy_shield.privacy_shield_embeddings import _compute_cosine_similarity

        a = [0.0, 0.0, 0.0]
        b = [1.0, 2.0, 3.0]
        sim = _compute_cosine_similarity(a, b)
        assert sim == 0.0


# ===========================================================================
# PIIMatch Dataclass Tests
# ===========================================================================

class TestPIIMatch:
    def test_to_dict(self):
        from privacy_shield.privacy_shield_embeddings import PIIMatch

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
        from privacy_shield.privacy_shield_embeddings import PIIContextMatcher

        with patch("privacy_shield.privacy_shield_embeddings._CONTEXT_EMBEDDINGS_FILE",
                    Path("/nonexistent/file.json")):
            matcher = PIIContextMatcher()
            assert matcher.is_ready is False

    def test_is_ready_true_with_embeddings(self, tmp_path):
        embeddings_file = tmp_path / "pii_context_embeddings.json"
        embeddings_file.write_text(json.dumps({
            "name": [{"phrase": "employee named", "embedding": [0.1, 0.2, 0.3]}],
        }))

        with patch("privacy_shield.privacy_shield_embeddings._CONTEXT_EMBEDDINGS_FILE", embeddings_file):
            from privacy_shield.privacy_shield_embeddings import PIIContextMatcher
            matcher = PIIContextMatcher()
            assert matcher.is_ready is True

    def test_scan_returns_empty_without_embeddings(self):
        from privacy_shield.privacy_shield_embeddings import PIIContextMatcher

        with patch("privacy_shield.privacy_shield_embeddings._CONTEXT_EMBEDDINGS_FILE",
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

        with patch("privacy_shield.privacy_shield_embeddings._CONTEXT_EMBEDDINGS_FILE", embeddings_file):
            from privacy_shield.privacy_shield_embeddings import PIIContextMatcher
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

    def test_scan_with_preloaded_embeddings(self, tmp_path, monkeypatch):
        """Test scanning with pre-computed embeddings (mocked embed calls).

        The local endpoint is now a precondition of the scan path, not scenery:
        embedding a document chunk sends raw pre-redaction text, so it is
        refused unless the endpoint is loopback or a unix socket.
        """
        monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:1234/v1")
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

        with patch("privacy_shield.privacy_shield_embeddings._CONTEXT_EMBEDDINGS_FILE", embeddings_file):
            from privacy_shield.privacy_shield_embeddings import PIIContextMatcher
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

        with patch("privacy_shield.privacy_shield_embeddings._CONTEXT_EMBEDDINGS_FILE", embeddings_file):
            from privacy_shield.privacy_shield_embeddings import PIIContextMatcher
            matcher = PIIContextMatcher()
            # With empty embeddings, both should return empty
            assert matcher.scan_quick("test") == []


# ===========================================================================
# PII Context Patterns Tests
# ===========================================================================

class TestPIIContextPatterns:
    def test_all_categories_present(self):
        from privacy_shield.privacy_shield_embeddings import PII_CONTEXT_PATTERNS

        expected = {"name", "email", "phone", "address", "financial",
                    "health", "id_document", "date_of_birth", "location"}
        assert set(PII_CONTEXT_PATTERNS.keys()) == expected

    def test_each_category_has_patterns(self):
        from privacy_shield.privacy_shield_embeddings import PII_CONTEXT_PATTERNS

        for category, patterns in PII_CONTEXT_PATTERNS.items():
            assert len(patterns) >= 3, f"Category {category} should have at least 3 patterns"

    def test_redaction_map_covers_all_categories(self):
        from privacy_shield.privacy_shield_embeddings import PII_CONTEXT_PATTERNS, REDACTION_MAP

        for category in PII_CONTEXT_PATTERNS:
            assert category in REDACTION_MAP, f"Missing redaction for {category}"


# ===========================================================================
# The embedding send path: raw pre-redaction document text
# ===========================================================================

class TestEmbeddingEgressGuard:
    """`_embed` sends the first 8000 characters of the scanned document.

    It is reachable from the main path - shield._get_semantic_context_matcher
    is called from process_text and PRIVACY_SHIELD_SEMANTIC_ENABLED defaults to
    "1" - and silent only because the context store ships empty. Run the
    documented embed_pii_contexts() setup once and every chunk of every scanned
    document goes out.
    """

    def _matcher(self, tmp_path, monkeypatch, base_url):
        embeddings_file = tmp_path / "pii_embeddings.json"
        embeddings_file.write_text(json.dumps({
            "name": [{"phrase": "employee named", "embedding": [0.9, 0.1, 0.0]}],
        }))
        monkeypatch.setenv("OPENAI_BASE_URL", base_url)
        monkeypatch.setenv("OPENAI_API_KEY", "not-a-real-key")
        with patch("privacy_shield.privacy_shield_embeddings._CONTEXT_EMBEDDINGS_FILE",
                   embeddings_file):
            from privacy_shield.privacy_shield_embeddings import PIIContextMatcher
            return PIIContextMatcher()

    @pytest.mark.parametrize("base_url", [
        "https://api.openai.com/v1",
        "https://embeddings.vendor.example/v1",
        "http://10.0.0.5:8080/v1",
    ])
    def test_document_chunks_are_not_sent_to_a_remote_endpoint(
        self, tmp_path, monkeypatch, base_url
    ):
        matcher = self._matcher(tmp_path, monkeypatch, base_url)
        sent = []
        matcher._embed = lambda text: sent.append(text) or [0.85, 0.15, 0.05]

        matches = matcher.scan_for_pii_contexts("The employee named Erika Mustermann")

        assert sent == [], "raw document text was handed to a remote endpoint"
        assert matches == []

    def test_document_chunks_are_sent_to_a_loopback_endpoint(
        self, tmp_path, monkeypatch
    ):
        """Refusing everything would be safe and useless - the layer must work."""
        matcher = self._matcher(tmp_path, monkeypatch, "http://127.0.0.1:1234/v1")
        sent = []
        matcher._embed = lambda text: sent.append(text) or [0.85, 0.15, 0.05]

        matches = matcher.scan_for_pii_contexts(
            "The employee named Erika Mustermann", threshold=0.7
        )

        assert sent, "the semantic layer refused a local endpoint too"
        assert matches and matches[0].pii_category == "name"

    def test_setup_may_still_use_a_remote_endpoint(self, tmp_path, monkeypatch):
        """The setup call embeds the fixed phrases in this module's source.

        Those are not anybody's personal data, so the guard does not apply to
        them - only to document chunks.
        """
        matcher = self._matcher(tmp_path, monkeypatch, "https://api.openai.com/v1")
        sent = []
        matcher._embed = lambda text: sent.append(text) or [0.1, 0.2, 0.3]

        count = matcher.embed_pii_contexts({"name": ["employee named"]})

        assert count == 1
        assert sent == ["employee named"]

    def test_client_is_built_off_the_environment_proxy(self, tmp_path, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "not-a-real-key")
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp.example.com:3128")
        monkeypatch.setenv("HTTP_PROXY", "http://proxy.corp.example.com:3128")
        pytest.importorskip("openai")
        pytest.importorskip("httpx")

        from privacy_shield.privacy_shield_embeddings import PIIContextMatcher

        client = PIIContextMatcher()._get_client()
        assert client is not None
        assert client._client._mounts == {}, (
            "the embedding client mounted the environment's proxy"
        )
