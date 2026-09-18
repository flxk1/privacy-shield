"""Backs the CHANGELOG's 2.0.0 claims that are otherwise only asserted in prose:
the import root, the console script, and the removal of the two modules that
left the distribution in the split. Each test fails if the claim it backs
stops being true.
"""

import importlib
from pathlib import Path

try:  # tomllib is stdlib from 3.11; the package supports 3.10
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib

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


# ---------------------------------------------------------------------------
# Every test the CHANGELOG cites has to exist
# ---------------------------------------------------------------------------
#
# The CHANGELOG backs each claim with a "Tested: path::name" citation. A
# citation that names a test which does not exist is worse than no citation:
# it reads as evidence and is not. This round found the CHANGELOG declaring the
# overlapping-span defect fixed while the ANONYMOUS_JSON copy of it was
# untouched, so the prose has to be checkable too.

import ast
import re as _re


#: Every document that cites a test as evidence. `docs/limits.md` was not in
#: this list, and it is the document a reader consults to find out what the
#: product does NOT do - so a citation in it going stale is exactly as bad as
#: one in the CHANGELOG. Round 19 renamed four tests it cites.
CITING_DOCUMENTS = ["CHANGELOG.md", "docs/limits.md"]


def _cited_tests(document="CHANGELOG.md"):
    changelog = (REPO_ROOT / document).read_text(encoding="utf-8")
    cited = set()
    for match in _re.finditer(
        r"`(tests/[A-Za-z0-9_./]+\.py)((?:::(?:Test|test)[A-Za-z0-9_]*)*)`", changelog
    ):
        path, trailer = match.group(1), match.group(2)
        cited.add((path, tuple(trailer.split("::")[1:])))
    # Bare "::name" continuation citations inherit the file above them.
    current = None
    for line in changelog.splitlines():
        for match in _re.finditer(r"`(tests/[A-Za-z0-9_./]+\.py)", line):
            current = match.group(1)
        if current:
            # "::1" is the IPv6 loopback address in the endpoint-guard prose,
            # not a citation - names must look like tests.
            for match in _re.finditer(r"`((?:::(?:Test|test)[A-Za-z0-9_]*)+)`", line):
                cited.add((current, tuple(match.group(1).split("::")[1:])))
    return cited


def _names_defined_in(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
    return names


@pytest.mark.parametrize("document", CITING_DOCUMENTS)
def test_every_test_a_document_cites_exists(document):
    missing = []
    for path, names in sorted(_cited_tests(document)):
        target = REPO_ROOT / path
        if not target.exists():
            missing.append(path)
            continue
        defined = _names_defined_in(target)
        for name in names:
            if name not in defined:
                missing.append(f"{path}::{name}")
    assert not missing, (
        f"{document} cites tests that do not exist, so those claims are "
        f"unbacked prose: {missing}"
    )
