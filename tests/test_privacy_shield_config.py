from __future__ import annotations

from pathlib import Path

import yaml

from privacy_shield.scanner import PIIType


CONFIG_ROOT = Path(__file__).resolve().parent.parent / "configs" / "privacy_shield"


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_taxonomy_covers_current_pii_types() -> None:
    data = _load_yaml(CONFIG_ROOT / "taxonomy.yaml")
    entity_ids = {entity["id"] for entity in data["entities"]}
    assert entity_ids == {member.value for member in PIIType}


def test_patterns_reference_known_taxonomy_types() -> None:
    taxonomy = _load_yaml(CONFIG_ROOT / "taxonomy.yaml")
    known_types = {entity["id"] for entity in taxonomy["entities"]}
    patterns = _load_yaml(CONFIG_ROOT / "patterns.yaml")
    for rule in patterns["rules"]:
        assert rule["type"] in known_types


def test_lexica_have_required_sections() -> None:
    lexica_dir = CONFIG_ROOT / "lexica"
    required_keys = {
        "pack_id",
        "jurisdictions",
        "languages",
        "field_label_semantics",
        "field_labels",
        "honorifics",
        "weak_name_context",
        "sensitive_terms",
        "negative_terms",
    }
    for path in lexica_dir.glob("*.yaml"):
        data = _load_yaml(path)
        assert required_keys.issubset(data.keys()), path.name
        assert data["field_label_semantics"] == "context_only"
        assert data["field_labels"]
        assert data["sensitive_terms"]


def test_onnx_targets_define_outputs() -> None:
    data = _load_yaml(CONFIG_ROOT / "onnx_targets.yaml")
    assert data["execution_order"][0] == "regex_patterns"
    for target in data["targets"]:
        assert target["outputs"]


def test_pattern_policy_marks_labels_as_context_only() -> None:
    data = _load_yaml(CONFIG_ROOT / "patterns.yaml")
    assert data["policy"]["never_match_labels_as_findings"] is True
    assert data["policy"]["label_matching_mode"] == "contextual_window_only"


def test_onnx_policy_preserves_regex_authority() -> None:
    data = _load_yaml(CONFIG_ROOT / "onnx_policy.yaml")
    assert "regex_direct_identifiers_remain_authoritative" in data["principles"]
    direct_case = next(
        item for item in data["decision_matrix"]
        if item["case"] == "hard_regex_direct_identifier"
    )
    assert "suppress" in direct_case["onnx_must_not"]
    assert "clear" in direct_case["onnx_must_not"]
    assert data["language_policy"]["threshold_strategy"] == "per_language"
