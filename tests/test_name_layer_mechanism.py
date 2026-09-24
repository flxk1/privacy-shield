"""The mechanism that is supposed to carry twenty-five languages.

Two languages are measured. The claim being tested here is not about the other
twenty-three - `docs/limits.md` calls them `unmeasured` and means it - it is
about the SEAM: that a language is one module registering one ruleset, that
adding one cannot widen what another claims, that a model can be plugged in
without this package depending on one, and that the zero-dependency floor
survives all of it.
"""

from __future__ import annotations

import ast
import pathlib
import sys

import pytest

from privacy_shield.name_layer import (
    Exclusions,
    Ruleset,
    detect,
    find_names,
    find_names_by_language,
    languages,
    recogniser,
    registry,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
NAME_LAYER = ROOT / "src" / "privacy_shield" / "name_layer"


def test_the_measured_languages_are_the_registered_languages():
    """Two. Anything else in this list is a claim `docs/limits.md` has to
    back with a corpus."""
    assert languages() == ["de", "en"]


def test_a_language_is_one_module_and_nothing_imports_another_language():
    """The isolation the twenty-five-language claim rests on.

    If `en.py` imported `de.py`, "add a language" would mean "edit the
    languages that are already measured", and the German numbers would be at
    risk every time somebody adds Finnish.
    """
    for module in ("de.py", "en.py"):
        tree = ast.parse((NAME_LAYER / module).read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        other = {"de", "en"} - {module[:2]}
        assert not (imported & other), (module, imported & other)


def test_adding_a_language_cannot_widen_what_another_language_claims():
    """A new ruleset contributes evidence for ITS OWN language and exclusions
    for every language. Exclusions can only narrow."""
    document = "Dear Mr Ashcroft,\n"
    before = find_names(document)

    toy = Ruleset(
        language="zz",
        find=lambda text: [(0, 4, text[:4])],
        probes={},
        exclusions=Exclusions(organisational=frozenset({"Ashcroft"})),
        markers=frozenset({"zzz"}),
    )
    try:
        registry.register(toy)
        assert "zz" in languages()
        # The toy language is not evidenced by this document, so its find()
        # never runs...
        assert "zz" not in find_names_by_language(document)
        # ...but its exclusions do apply, and they can only remove.
        after = find_names(document)
        assert before == [(8, 16, "Ashcroft")]
        assert after == []
    finally:
        registry._RULESETS.pop("zz", None)
        registry._EXCLUSIONS = None

    assert find_names(document) == before


def test_a_registered_recogniser_is_held_to_the_same_exclusions_as_the_rules():
    """A statistical claim is not privileged over a measured one.

    A model that returns PERSON for `Accounts Payable` is wrong in exactly the
    way the rules are stopped from being wrong.
    """
    text = "Accounts Payable processed the invoice for Nils Berg.\n"

    def model(document, language):
        start = document.index("Nils Berg")
        return [(0, 16, "Accounts Payable"), (start, start + 9, "Nils Berg")]

    try:
        recogniser.register_recogniser("en", model)
        claimed = [value for _s, _e, value in find_names(text, "en")]
    finally:
        recogniser.clear_recognisers("en")

    assert claimed == ["Nils Berg"], claimed
    assert recogniser.registered_languages() == []


def test_a_recogniser_that_raises_does_not_take_the_scan_down():
    """The rule floor is a correct answer; an exception is not."""

    def broken(document, language):
        raise RuntimeError("model file missing")

    try:
        recogniser.register_recogniser("en", broken)
        assert [v for _s, _e, v in find_names("Dear Mr Ashcroft,\n", "en")] == [
            "Ashcroft"
        ]
    finally:
        recogniser.clear_recognisers("en")


def test_a_recogniser_cannot_return_offsets_outside_the_document():
    def sloppy(document, language):
        return [(0, 10_000, "everything")]

    try:
        recogniser.register_recogniser("en", sloppy)
        assert find_names("Dear Sir or Madam,\n", "en") == []
    finally:
        recogniser.clear_recognisers("en")


def test_with_no_recogniser_registered_the_layer_is_the_rule_floor():
    """The documented degradation, asserted: absent a model, nothing changes
    and nothing warns. A user who installs the base package gets the rules,
    which is what `docs/limits.md` promises them."""
    assert recogniser.registered_languages() == []
    assert [v for _s, _e, v in find_names("Dear Mr Ashcroft,\n")] == ["Ashcroft"]


# ---------------------------------------------------------------------------
# The zero-dependency floor
# ---------------------------------------------------------------------------

STDLIB = set(sys.stdlib_module_names)


def test_the_package_declares_no_runtime_dependencies():
    """`dependencies = []` was a property nobody tested. It is tested now.

    This change adds no dependency at all - the licence and size evaluation in
    `docs/limits.md` is why there is no model behind the `semantic` extra to
    add one for - but the property has to be enforced rather than remembered.
    """
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert "\ndependencies = []\n" in pyproject


@pytest.mark.parametrize(
    "module",
    sorted(path.name for path in NAME_LAYER.glob("*.py")),
)
def test_every_name_layer_module_imports_only_the_standard_library(module):
    """The floor, checked at the import graph rather than at runtime.

    A `numpy` import inside the name layer would make the regex floor depend
    on the `semantic` extra, and the failure would only show on a machine
    without it.
    """
    tree = ast.parse((NAME_LAYER / module).read_text())
    third_party = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root not in STDLIB:
                    third_party.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative: inside this package
                continue
            root = (node.module or "").split(".")[0]
            if root not in STDLIB and root != "privacy_shield":
                third_party.add(node.module)
    assert not third_party, (module, third_party)


def test_the_name_layer_works_with_the_optional_extras_blocked():
    """Imported fresh with numpy and onnxruntime made unimportable.

    The extras are installed in this environment, so "it works here" proves
    nothing about the floor unless they are taken away.
    """
    import importlib

    blocked = {"numpy": None, "onnxruntime": None}
    saved = {name: sys.modules.get(name) for name in blocked}
    dropped = [
        name for name in list(sys.modules)
        if name.startswith("privacy_shield.name_layer")
    ]
    saved_layer = {name: sys.modules.pop(name) for name in dropped}
    try:
        sys.modules.update(blocked)
        layer = importlib.import_module("privacy_shield.name_layer")
        assert layer.languages() == ["de", "en"]
        assert [v for _s, _e, v in layer.find_names("Dear Mr Ashcroft,\n")] == [
            "Ashcroft"
        ]
        assert [
            v for _s, _e, v in layer.find_names("Sehr geehrte Frau Schneider,\n")
        ] == ["Schneider"]
    finally:
        for name, value in saved.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value
        for name in list(sys.modules):
            if name.startswith("privacy_shield.name_layer"):
                del sys.modules[name]
        sys.modules.update(saved_layer)


def test_detection_needs_no_language_identification_library():
    """Marker counting, not a model. Also part of the floor."""
    tree = ast.parse((NAME_LAYER / "detect.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            for name in names:
                assert "langdetect" not in name and "lingua" not in name
    assert detect.marker_scores("Sehr geehrte Damen und Herren")["de"] > 0


# ---------------------------------------------------------------------------
# The layer reads documents it does not trust
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "label, text",
    [
        ("a line of 200 capitalised words", " ".join(["Alpha"] * 200) + "\n"),
        ("a 300-link hyphen chain", "A" + "-Aa" * 300 + "\n"),
        ("a 300-link apostrophe chain", "O'Aa" * 300 + "\n"),
        ("postcode-line bait", " ".join(["Alpha"] * 200) + " X\n"),
        ("attn-line bait", "Attn: " + " ".join(["Alpha"] * 200) + "\n"),
        ("agency-frame bait", "prepared by " + " ".join(["Alpha"] * 200) + "\n"),
        ("label-value bait", "Caseworker: " + " ".join(["Alpha"] * 200) + "\n"),
    ],
)
def test_a_pathological_line_does_not_make_the_name_layer_hang(label, text):
    """The English word shape has a quantifier inside a quantifier.

    `[A-Z](?:[a-z]+|'[A-Z][a-z]+)(?:[-']...)*` repeated one to three times, and
    the postcode line makes the whole word run optional in front of an
    alternation - which is the shape that backtracks exponentially when it
    fails to match. This layer reads documents nobody in this package wrote,
    so a line that makes it hang is a denial of service and not a curiosity.

    The bound is generous on purpose: it catches an exponential blowup, which
    is seconds-to-minutes, and not the millisecond jitter of a loaded machine.
    Measured here at well under 10 ms per case.
    """
    import time

    started = time.perf_counter()
    find_names(text)
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0, f"{label}: {elapsed:.1f}s"
