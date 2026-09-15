from __future__ import annotations

from types import SimpleNamespace


def test_standard_mode_adds_semantic_context_findings(monkeypatch) -> None:
    from privacy_shield import PrivacyMode, PrivacyShield

    calls = {"count": 0}

    class _Matcher:
        is_ready = True

        def scan_for_pii_contexts(self, text: str, *, threshold: float = 0.75, chunk_size: int = 200):
            calls["count"] += 1
            return [
                SimpleNamespace(
                    pii_category="name",
                    similarity_score=0.88,
                    chunk_index=0,
                    chunk_text=text[:80],
                )
            ]

    monkeypatch.setattr("privacy_shield.shield._get_semantic_context_matcher", lambda: _Matcher())
    monkeypatch.setattr(PrivacyShield, "check_local_model_available", lambda self: False)
    monkeypatch.delenv("PRIVACY_SHIELD_SEMANTIC_ENABLED", raising=False)

    shield = PrivacyShield(privacy_mode=PrivacyMode.STANDARD)
    result = shield.process_text("zxqk")

    assert calls["count"] == 1
    assert any(f.layer == 6 and f.pii_type.value == "name" for f in result.findings)


def test_local_only_mode_skips_semantic_context_scan(monkeypatch) -> None:
    from privacy_shield import PrivacyMode, PrivacyShield

    calls = {"count": 0}

    def _matcher_factory():
        calls["count"] += 1
        return None

    monkeypatch.setattr("privacy_shield.shield._get_semantic_context_matcher", _matcher_factory)
    monkeypatch.setattr(PrivacyShield, "check_local_model_available", lambda self: False)
    monkeypatch.delenv("PRIVACY_SHIELD_SEMANTIC_ENABLED", raising=False)

    shield = PrivacyShield(privacy_mode=PrivacyMode.LOCAL_ONLY)
    result = shield.process_text("employee named jxqk requested account access")

    assert calls["count"] == 0
    assert all(f.layer != 6 for f in result.findings)


def test_regex_only_mode_skips_semantic_context_scan(monkeypatch) -> None:
    from privacy_shield import PrivacyMode, PrivacyShield

    calls = {"count": 0}

    def _matcher_factory():
        calls["count"] += 1
        return None

    monkeypatch.setattr("privacy_shield.shield._get_semantic_context_matcher", _matcher_factory)
    monkeypatch.setattr(PrivacyShield, "check_local_model_available", lambda self: False)
    monkeypatch.delenv("PRIVACY_SHIELD_SEMANTIC_ENABLED", raising=False)

    shield = PrivacyShield(privacy_mode=PrivacyMode.REGEX_ONLY)
    result = shield.process_text("employee named jxqk requested account access")

    assert calls["count"] == 0
    assert all(f.layer != 6 for f in result.findings)
