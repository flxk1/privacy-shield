from __future__ import annotations

from pathlib import Path

import yaml


def test_review_profiles_config_has_expected_defaults() -> None:
    path = Path(__file__).resolve().parents[1] / "configs" / "privacy_shield" / "review_profiles.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))

    profiles = data["profiles"]
    defaults = data["defaults"]

    assert "all" in profiles
    assert "auto_not_recommended" in profiles
    assert "high_only" in profiles
    assert "high_and_medium_recommended" in profiles
    assert defaults["chat_inline"] == "high_and_medium_recommended"
    assert defaults["folder_batch"] == "high_only"
