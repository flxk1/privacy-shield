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


def test_the_base_package_declares_no_runtime_dependencies():
    """`dependencies = []` was a claim, not a property.

    The skill's governance block obliges
    ``degrade_gracefully_without_optional_extras``; README, SKILL.md and the
    limits document all say the base package installs with nothing. Until this
    test existed the string appeared in one docstring and nowhere else - no
    assertion anywhere in tests/ or .github/ read
    ``pyproject.toml``'s ``project.dependencies``, so a dependency added to the
    base package would have shipped green.

    Every optional layer belongs in ``optional-dependencies`` behind an
    availability check. That is what makes each Loomground plane optional and
    what lets a consumer with none of them installed see no change.
    """
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    declared = pyproject["project"].get("dependencies", [])

    assert declared == [], (
        "the base package has grown runtime dependencies: "
        f"{declared}. Move them to [project.optional-dependencies] and reach "
        "them behind an availability check, or this package stops being "
        "installable with nothing."
    )


#: Import names of the distributions the optional extras install. Two things
#: this list is NOT used for, both of which give the wrong answer:
#:
#: - a static scan for top-level imports. `onnx_contextual_pii` imports numpy at
#:   module level and that is CORRECT: the module IS the semantic layer and is
#:   only ever reached from an already-guarded call site.
#: - "did importing the package reach it". `security_scanner` imports yaml
#:   inside a try/except and degrades when it is absent; reaching a guarded
#:   import when the extra happens to be installed is correct behaviour.
#:
#: The property that actually matters is absence: with every one of these made
#: unimportable, the package still imports and the floor still detects.
EXTRA_IMPORT_NAMES = frozenset(
    {"numpy", "onnxruntime", "fitz", "PIL", "cv2", "openai", "stdnum",
     "yaml", "schwifty", "hypothesis"}
)

#: Runs before anything else in the probe subprocess: makes every extra
#: unimportable, whatever is installed, so the check does not depend on the
#: environment it runs in. This is what lets a developer with the full dev
#: extra reproduce the base-install CI job locally.
#:
#: `sys.path.insert(0, REPO_ROOT/"src")` FIRST, unconditionally: this runs in
#: a brand-new child process that does not inherit pytest's `pythonpath` ini
#: patch (that only touches the parent process's `sys.path`), so without this
#: `import privacy_shield` here resolves through the ambient PYTHONPATH and
#: site-packages exactly like any other Python invocation - and on a machine
#: with no per-checkout virtualenv, site-packages can hold a build from
#: BEFORE this worktree's own fix (a sibling session's `pip install .`, or an
#: earlier run in this same one). Measured: with this line absent, every
#: `_probe` call below silently exercised whatever was last `pip install`ed
#: system-wide - `national.PERSON_NUMBER_MODULES["be"]` printed the
#: PRE-REPAIR tuple while this file's own `import privacy_shield` at module
#: level correctly saw the worktree, because that import runs in THIS
#: process, which pytest's `pythonpath` ini option does patch.
_SRC_ON_PATH = (
    "import sys\n"
    f"sys.path.insert(0, {str(REPO_ROOT / 'src')!r})\n"
)

_BLOCK_EXTRAS = (
    "import sys\n"
    f"_blocked = {sorted(EXTRA_IMPORT_NAMES)!r}\n"
    "class _Blocker:\n"
    "    def find_module(self, name, path=None):\n"
    "        return self.find_spec(name, path) and self\n"
    "    def find_spec(self, name, path=None, target=None):\n"
    "        if name.split('.')[0] in _blocked:\n"
    "            raise ImportError(f'{name} blocked by the optionality probe')\n"
    "        return None\n"
    "for _m in list(sys.modules):\n"
    "    if _m.split('.')[0] in _blocked:\n"
    "        del sys.modules[_m]\n"
    "sys.meta_path.insert(0, _Blocker())\n"
)


def _probe(body: str) -> str:
    """Run *body* in a subprocess where every optional extra is unimportable
    and `privacy_shield` resolves to THIS worktree, not whatever else might
    be installed."""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-c", _SRC_ON_PATH + _BLOCK_EXTRAS + body],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        "the package does not work with the optional extras absent:\n"
        f"{result.stdout}\n{result.stderr}"
    )
    return result.stdout.strip()


def test_the_probe_subprocess_resolves_the_worktree_not_a_stale_install(tmp_path):
    """The regression this file's own subprocess design was exposed to.

    `_probe` launches a NEW process; `import privacy_shield` inside it does
    not inherit pytest's `pythonpath` patch, so on a machine with no
    per-checkout virtualenv it fell back to the ambient PYTHONPATH / site-
    packages - a build from BEFORE this checkout's own fix, if one happens to
    be installed there. Simulated deterministically here with a decoy package
    on `PYTHONPATH`, rather than depending on whatever this machine's
    site-packages actually contains right now.
    """
    import os
    import subprocess
    import sys

    decoy_root = tmp_path / "decoy"
    (decoy_root / "privacy_shield").mkdir(parents=True)
    (decoy_root / "privacy_shield" / "__init__.py").write_text(
        "DECOY = True\n", encoding="utf-8"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(decoy_root)

    result = subprocess.run(
        [sys.executable, "-c", _SRC_ON_PATH + (
            "import privacy_shield\n"
            "print(getattr(privacy_shield, 'DECOY', False))\n"
        )],
        capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False", (
        "the probe subprocess imported a decoy package ahead of the "
        "worktree - _SRC_ON_PATH construction regressed"
    )


def test_the_package_imports_with_every_optional_extra_absent():
    """`dependencies = []` is satisfiable by a package that cannot be imported.

    If a module the import graph reaches imports an extra unguarded, then
    ``pip install privacy-shield`` installs something that raises on import.
    Every extra is blocked here, so this fails exactly when that happens.
    """
    out = _probe(
        "import privacy_shield\n"
        "print(privacy_shield.__name__)\n"
    )
    assert out == "privacy_shield"


def test_the_regex_floor_still_detects_with_every_extra_absent():
    """The floor has to WORK without the extras, not merely import.

    An import that succeeds and a scan that returns nothing is the same silent
    absence this programme keeps finding, so the floor is exercised too. This
    is the local reproduction of the base-install CI job.
    """
    out = _probe(
        "from privacy_shield import scan_text\n"
        "r = scan_text('Kontakt erika.mustermann@example.com Konto "
        "DE89370400440532013000')\n"
        "print(','.join(sorted({f.pii_type.value for f in r.findings})))\n"
    )
    assert "email" in out and "iban" in out, (
        f"the regex/lexicon floor stopped detecting without the extras: {out!r}"
    )


def test_the_egress_gate_still_decides_with_every_extra_absent():
    """The gate is the part a consumer relies on; it must not need an extra."""
    out = _probe(
        "from privacy_shield.gate import PrivacyGate\n"
        "g = PrivacyGate()\n"
        "r = g._decide_local({'text': 'streng vertraulich'}, 'openai')\n"
        "print(r.allowed, r.classification)\n"
    )
    assert out.startswith("False "), (
        f"a confidential document was not blocked without the extras: {out!r}"
    )


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

def test_dunder_version_agrees_with_the_packaging_metadata():
    """`__version__` is a second source of truth for the version, hardcoded beside the
    one in pyproject. Nothing compared them, so bumping the release for 2.1.0 moved the
    metadata and left `__version__` reporting 2.0.0 — an install of the 2.1.0 tag told
    you it was 2.0.0. They are compared here so the two cannot drift apart again."""
    import importlib.metadata

    import privacy_shield

    assert privacy_shield.__version__ == importlib.metadata.version("privacy-shield")
