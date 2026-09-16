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


@pytest.mark.parametrize(
    "module",
    ["privacy_shield.user_credentials", "privacy_shield.compliance_evidence_export"],
)
def test_the_split_removed_modules_stay_removed(module):
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(module)
