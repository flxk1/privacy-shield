"""The skill's tool grant must stay inside its own governance block.

`SKILL.md` declares `prohibited: egress_original_unredacted_text`. A grant of
unrestricted `Bash` hands the same skill a shell that can `curl` the original
file anywhere - the declaration and the grant contradicting each other in one
file. These tests make the grant a checked claim rather than a line nobody
reads.
"""

from pathlib import Path

import pytest

SKILL_MD = Path(__file__).resolve().parents[1] / "skills" / "privacy-shield" / "SKILL.md"


def _front_matter() -> dict:
    yaml = pytest.importorskip("yaml")
    text = SKILL_MD.read_text(encoding="utf-8")
    assert text.startswith("---\n")
    return yaml.safe_load(text.split("---\n", 2)[1])


def _allowed_tools() -> list[str]:
    raw = _front_matter()["allowed-tools"]
    if isinstance(raw, str):
        return [part.strip() for part in raw.split(",") if part.strip()]
    return [str(part).strip() for part in raw]


def test_skill_md_exists_and_parses():
    assert SKILL_MD.is_file()
    assert _front_matter()["name"] == "privacy-shield"


def test_bash_is_never_granted_unscoped():
    tools = _allowed_tools()
    assert "Bash" not in tools, (
        f"unrestricted Bash granted to a skill that prohibits "
        f"egress_original_unredacted_text: {tools}"
    )


def test_any_bash_grant_is_scoped_to_this_package_cli():
    bash_grants = [t for t in _allowed_tools() if t.startswith("Bash")]
    for grant in bash_grants:
        assert grant == "Bash(privacy-shield:*)", (
            f"{grant!r} is broader than the console script this package "
            f"installs; scope it or drop it"
        )


def test_the_grant_is_exactly_what_is_justified_in_the_body():
    """Every granted tool has to be named and justified in the prose below."""
    body = SKILL_MD.read_text(encoding="utf-8").split("---\n", 2)[2]
    for tool in _allowed_tools():
        assert tool in body, f"{tool!r} is granted but never justified in SKILL.md"


def test_the_prohibition_the_grant_is_scoped_against_is_still_declared():
    prohibited = _front_matter()["governance"]["prohibited"]
    assert "egress_original_unredacted_text" in prohibited
    obligations = _front_matter()["governance"].get("obligations", [])
    assert any("overlay" in str(item) for item in obligations), obligations
