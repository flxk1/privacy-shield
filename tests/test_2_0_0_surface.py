"""Backs the CHANGELOG's 2.0.0 claims that are otherwise only asserted in prose:
the import root, the console script, and the removal of the two modules that
left the distribution in the split. Each test fails if the claim it backs
stops being true.
"""

import importlib
import tomllib
from pathlib import Path

import pytest

import privacy_shield

REPO_ROOT = Path(privacy_shield.__file__).resolve().parents[2]


def test_the_import_root_is_privacy_shield_not_brain():
    import privacy_shield  # noqa: F401 — already imported above; re-assert the name resolves

    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("brain.privacy_shield")


def test_the_console_script_is_privacy_shield_cli_main():
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    scripts = pyproject["project"]["scripts"]
    assert scripts["privacy-shield"] == "privacy_shield.cli:main"

    from privacy_shield.cli import main

    assert callable(main)


REMOVED_MODULES = [
    "privacy_shield.user_credentials",
    "privacy_shield.compliance_evidence_export",
    "privacy_shield.utils.datetime",
]

# Public names that went with the removed modules but survive as importable
# module attributes if nobody checks. The CHANGELOG discloses each one; this is
# what makes the disclosure a claim rather than a sentence.
REMOVED_PUBLIC_NAMES = [
    ("privacy_shield.llm_client", "get_openai_client"),
    ("privacy_shield.llm_client", "get_anthropic_client"),
    ("privacy_shield.llm_client", "get_google_client"),
    ("privacy_shield.llm_client", "get_llm_client"),
    ("privacy_shield.llm_client", "check_byok_available"),
    ("privacy_shield.llm_client", "list_available_providers"),
    ("privacy_shield.llm_client", "get_openai_client_simple"),
    ("privacy_shield.llm_client", "get_anthropic_client_simple"),
    ("privacy_shield.enforcement", "RvndEnforcementAdapter"),
]


@pytest.mark.parametrize("module", REMOVED_MODULES)
def test_the_split_removed_modules_stay_removed(module):
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(module)


@pytest.mark.parametrize("module_name,attribute", REMOVED_PUBLIC_NAMES)
def test_the_split_removed_public_names_stay_removed(module_name, attribute):
    module = importlib.import_module(module_name)
    assert not hasattr(module, attribute), (
        f"{module_name}.{attribute} is back; the CHANGELOG says 2.0.0 removed it"
    )
    assert attribute not in getattr(module, "__all__", [])


def test_the_removed_public_names_are_disclosed_in_the_changelog():
    """A removal nobody can find in the CHANGELOG is an undisclosed break."""
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    for _, attribute in REMOVED_PUBLIC_NAMES:
        assert attribute in changelog, f"{attribute} removed but never disclosed"
    for module in REMOVED_MODULES:
        assert module.rsplit(".", 1)[-1] in changelog, module
