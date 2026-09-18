"""The national-number table, checked against the library that maintains it.

`national.PERSON_NUMBER_MODULES` is a transcription. It was written from the EU
country list rather than from what `python-stdnum` ships, and nothing inside
this package can notice it going stale: the layer validates what the table
names and is silent about everything the table forgot. `stdnum.at.svnr` - a
module that does not exist - made `at` a dead country whose code still passed
as configurable, and an adoption measurement over a dead validator reads zero
false positives and means nothing.

So the check comes from outside the transcription, exactly as
`test_iban_registry.py` does for ISO 13616. The oracle here is the installed
`stdnum` package.

What these tests hold is not "the table is complete" - it is not, and six
countries have no validator at all. It is that every gap is REVIEWED. A
validator the library ships and the table ignores is either in
`REVIEWED_UNUSED` with a reason, or it is drift and this file fails. That is
the difference between a known limit and a silent one.
"""

from __future__ import annotations

import importlib
import random
import re
import zlib

import pytest

from privacy_shield import freshness
from privacy_shield.national import PERSON_NUMBER_MODULES

STDNUM_PRESENT = freshness.stdnum_available()
PLANE_PRESENT = freshness.available()

needs_stdnum = pytest.mark.skipif(
    not STDNUM_PRESENT,
    reason="reported as a failure by test_the_external_source_is_actually_present",
)


def test_the_external_source_is_actually_present():
    """A quiet skip is not a check.

    `python-stdnum` is in the dev extra and both CI test jobs install it, so its
    absence is a broken environment and fails here rather than making the whole
    module vanish. Without it this table is UNVERIFIED against anything.
    """
    assert STDNUM_PRESENT, (
        "python-stdnum is not installed, so PERSON_NUMBER_MODULES is unverified "
        "against any external source in this run. It is in the dev extra; "
        "install it. Nothing inside this package can notice that table going "
        "stale."
    )


def test_which_mode_this_run_is_in():
    """Neither mode is a failure; an unreported mode is."""
    print(
        "\nnorm-freshness "
        + ("PRESENT: the verdict is exercised" if PLANE_PRESENT
           else "ABSENT: the verdict is not offered, the staleness check still runs")
    )
    assert isinstance(PLANE_PRESENT, bool)


# ---------------------------------------------------------------------------
# the table against the library
# ---------------------------------------------------------------------------

@needs_stdnum
def test_no_declared_module_is_missing_from_the_library():
    """The `at.svnr` class. Always a hard error, never a reviewable gap.

    A table entry naming a module that is not there is a country that validates
    nothing while reporting itself as configured.
    """
    state = freshness.observe()
    assert not state.dead_paths, (
        "PERSON_NUMBER_MODULES names modules the installed python-stdnum does "
        f"not have: {state.dead_paths}. Each is a country that silently "
        "validates nothing."
    )


@needs_stdnum
def test_every_shipped_validator_we_ignore_has_been_reviewed():
    """THE staleness check, and the one that makes a new release loud.

    `python-stdnum` adds person-number validators between releases. One that
    lands for a country this layer already declares is a decision - adopt it or
    write down why not - and until somebody makes it, this fails.
    """
    state = freshness.observe()
    assert not state.undeclared_unused, (
        "python-stdnum ships person-number validators for countries this layer "
        f"declares, which the table does not look for and nobody has reviewed: "
        f"{state.undeclared_unused}. Either add them to PERSON_NUMBER_MODULES "
        f"or record the reason in freshness.REVIEWED_UNUSED. Pin "
        f"{state.pinned_version}, installed {state.observed_version}."
    )


@needs_stdnum
def test_no_review_outlives_the_validator_it_excused():
    """An exception for something the library no longer ships is stale too."""
    state = freshness.observe()
    assert not state.retired_reviews, (
        "freshness.REVIEWED_UNUSED excuses validators python-stdnum no longer "
        f"ships: {state.retired_reviews}. Remove them - a stale exception hides "
        "the next real one."
    )


@needs_stdnum
def test_the_set_of_countries_with_no_validator_has_not_grown():
    """Six countries are admitted as configurable and validate nothing.

    Loud at runtime already (`find_national_ids` warns and excludes them). Pinned
    here so a seventh cannot arrive quietly - which is what would happen if a
    country were added to the table with an empty tuple as a placeholder.
    """
    state = freshness.observe()
    assert set(state.without_validator) == freshness.COUNTRIES_WITHOUT_VALIDATOR, (
        f"countries with no validator changed: {sorted(state.without_validator)} "
        f"vs pinned {sorted(freshness.COUNTRIES_WITHOUT_VALIDATOR)}"
    )


@needs_stdnum
def test_the_pin_matches_the_installed_release():
    """The pin is the claim "somebody reconciled the table against this version".

    A bump means the reconciliation has to be redone, which is what the tests
    above do. This fails on a version change so the bump is a decision rather
    than something that happens to a lockfile.
    """
    state = freshness.observe()
    assert not state.moved, (
        f"python-stdnum moved {state.pinned_version} -> {state.observed_version}. "
        f"Re-run the checks in this file, then bump freshness.STDNUM_PIN in the "
        f"same commit that reconciles the table."
    )


def test_every_reviewed_entry_names_a_country_the_table_declares():
    """A review for a country we do not configure is a review of nothing."""
    for (country, basename), reason in freshness.REVIEWED_UNUSED.items():
        assert country in PERSON_NUMBER_MODULES, f"{country} is not declared"
        assert len(reason) > 20, f"({country},{basename}) has no real reason"


# ---------------------------------------------------------------------------
# honest degradation - undecidable, never "fresh"
# ---------------------------------------------------------------------------

def test_without_the_library_the_state_is_unresolved_not_fresh(monkeypatch):
    """The failure this whole file exists against, in miniature.

    A check that cannot reach its source must not report a clean bill of health.
    """
    monkeypatch.setattr(freshness, "stdnum_available", lambda: False)
    state = freshness.observe()

    assert state.resolved is False
    assert state.observed_version is None
    assert state.moved is False  # unknown, not "unchanged"
    assert state.dead_paths == ()
    assert state.undeclared_unused == ()


@pytest.mark.skipif(not PLANE_PRESENT, reason="norm-freshness absent")
def test_an_unreachable_source_is_unresolvable_rather_than_current(monkeypatch):
    from norm_freshness import Freshness

    monkeypatch.setattr(freshness, "stdnum_available", lambda: False)
    report = freshness.assess()

    assert report is not None
    verdict = report.verdicts[0]
    assert verdict.freshness is Freshness.UNRESOLVABLE, (
        f"an unreachable source produced {verdict.freshness}"
    )
    assert verdict.requires_determination
    assert not verdict.enforceable


@pytest.mark.skipif(not PLANE_PRESENT, reason="norm-freshness absent")
def test_the_verdict_is_current_while_the_pin_matches():
    from norm_freshness import Freshness

    report = freshness.assess()
    assert report is not None
    verdict = report.verdicts[0]
    assert verdict.rule_id == freshness.RULE_ID
    assert verdict.freshness is Freshness.CURRENT, (
        f"{verdict.freshness}: {verdict.detail}"
    )
    assert verdict.enforceable


@pytest.mark.skipif(not PLANE_PRESENT, reason="norm-freshness absent")
def test_a_moved_source_with_a_substantive_change_needs_a_person():
    """The verdict a new stdnum release with a new validator has to produce."""
    from norm_freshness import Freshness

    state = freshness.observe()
    moved = freshness.TableState(
        resolved=True,
        observed_version="99.9",
        dead_paths=(),
        unused=state.unused + (("de", "svnr"),),  # a validator nobody reviewed
        without_validator=state.without_validator,
    )
    report = freshness.assess(moved)
    verdict = report.verdicts[0]

    assert verdict.freshness is Freshness.SUPERSEDED, verdict.detail
    assert verdict.requires_determination
    assert report.determinations, "a superseded pin produced no question for a person"


def test_assess_returns_none_rather_than_raising_without_the_plane():
    """A consumer may call this unconditionally."""
    if PLANE_PRESENT:
        assert freshness.assess() is not None
    else:
        assert freshness.assess() is None


# ---------------------------------------------------------------------------
# one-way: the plane learns nothing about national identification numbers
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not PLANE_PRESENT, reason="norm-freshness absent")
def test_nothing_crossing_into_the_plane_names_a_domain_concept():
    """The sharp test. If norm-freshness had to know what a national ID is,
    the mapping would be wrong and a universal repo would have become a PII one.

    What crosses is a rule id, two opaque version strings and a change kind.
    Which modules count as a person-number validator is decided in this package
    and stays here.
    """
    report = freshness.assess()
    verdict = report.verdicts[0]

    crossed = " ".join(
        str(part) for part in (
            verdict.rule_id, verdict.pinned_version, verdict.current_version,
            freshness.STDNUM_URI, verdict.detail,
        )
    ).lower()

    for concept in ("iban", "credit_card", "email", "bsn", "amka", "emso",
                    "person number", "national id", "pii", "identifier"):
        assert concept not in crossed, (
            f"{concept!r} crossed into norm-freshness: {crossed!r}"
        )


def test_the_domain_judgement_stays_on_this_side():
    """`PERSON_NUMBER_BASENAMES` is the judgement the plane must not make.

    Deciding that `nn` identifies a natural person and `vat` does not is
    knowledge about personal data. It lives here, in privacy-shield, which is
    what keeps norm-freshness a version comparator.
    """
    assert "nn" in freshness.PERSON_NUMBER_BASENAMES
    assert "vat" not in freshness.PERSON_NUMBER_BASENAMES
    assert "bic" not in freshness.PERSON_NUMBER_BASENAMES


# ---------------------------------------------------------------------------
# an "alias of X" entry asserts a set relation - falsify it, do not read it
# ---------------------------------------------------------------------------
#
# `REVIEWED_UNUSED[(country, basename)] = "alias of X, which is already
# validated"` claims: every input the excluded module accepts, X accepts too.
# That is a set-containment claim about two modules of the INSTALLED library
# and it is mechanically checkable - the same move `test_iban_registry.py`
# makes for the IBAN table, oracle instead of transcription.
#
# `("be", "ssn")` read "alias of be.nn" for a round. `be.ssn` is `be.nn` OR
# `be.bis`, and BIS numbers - issued to non-residents, month field +20/+40 -
# validate under `ssn` and not under `nn`. The claim was false and nothing
# here checked it; a corpus with a BIS number in it would pass a BIS number
# straight into the overlay.
#
# The search below does not know that. It reads the claimed pair out of
# `REVIEWED_UNUSED` by pattern, not by name, and falsifies it against the
# FORMAT SPACE of the excluded module: a length taken from the module's own
# documented examples (`test_national_ids.py` uses the same technique to
# catch a dead validator), random payload digits, and a brute-forced 1- and
# 2-digit trailing check suffix - not a computed checksum, because this file
# is not supposed to know these schemes are mod 97.

_ALIAS_OF = re.compile(r"^alias of ([a-z]{2}\.[a-z_]+), which is already validated$")


def _alias_claims():
    """(country, basename) -> adopted module path, read from REVIEWED_UNUSED.

    Whatever the table claims today is what gets checked; nothing is written
    down twice.
    """
    claims = {}
    for (country, basename), reason in freshness.REVIEWED_UNUSED.items():
        match = _ALIAS_OF.match(reason)
        if match:
            claims[(country, basename)] = f"stdnum.{match.group(1)}"
    return claims


def _shortest_documented_length(path):
    """The length of the module's own shortest valid doctest example.

    Read at runtime from the installed library's docstring, the same source
    `test_national_ids.py::_documented_examples` uses - not a length this file
    keeps for the country by hand.
    """
    module = importlib.import_module(path)
    text = (module.__doc__ or "") + (getattr(module, "validate", None).__doc__ or "")
    quoted = re.findall(r">>> (?:validate|is_valid|compact)\('([^']+)'\)", text)
    valid = [value for value in quoted if module.is_valid(value)]
    assert valid, f"{path} documents no valid example to size a search on"
    return min(sum(character.isalnum() for character in value) for value in valid)


def _falsify_alias(excluded_path, adopted_path, *, seed):
    """Search for a value the excluded module accepts and the adopted one
    rejects. Returns that value, or None if none turned up in the budget.

    Deliberately blind to WHICH digits are payload and WHICH are check: both
    are generated and thrown at the two validators, the same as every other
    input this package hands a checksum. A candidate the excluded module
    itself rejects is not a counterexample and is skipped without inspecting
    what it is.
    """
    excluded = importlib.import_module(excluded_path)
    adopted = importlib.import_module(adopted_path)
    length = _shortest_documented_length(excluded_path)
    rng = random.Random(seed)
    for _trial in range(500):
        for suffix_len in (1, 2):
            if suffix_len >= length:
                continue
            prefix = "".join(str(rng.randrange(10)) for _ in range(length - suffix_len))
            for suffix_value in range(10 ** suffix_len):
                candidate = prefix + str(suffix_value).zfill(suffix_len)
                try:
                    if not excluded.is_valid(candidate):
                        continue
                except Exception:
                    continue
                try:
                    accepted_by_adopted = adopted.is_valid(candidate)
                except Exception:
                    accepted_by_adopted = False
                if not accepted_by_adopted:
                    return candidate
    return None


@needs_stdnum
@pytest.mark.parametrize(
    "country, basename, adopted_path",
    [(c, b, p) for (c, b), p in sorted(_alias_claims().items())],
    ids=lambda value: value if isinstance(value, str) else str(value),
)
def test_an_alias_claim_is_falsified_against_the_installed_library_not_read(
    country, basename, adopted_path
):
    """Every "alias of X" entry in REVIEWED_UNUSED, checked mechanically.

    A reviewer reading the docstrings found this table's other seven entries
    holding. Reading is exactly the mode that missed `be.ssn`. This does not
    read; it searches the excluded module's format space for the one thing
    that would make the claim false, against today's installed `stdnum`.
    """
    excluded_path = f"stdnum.{country}.{basename}"
    seed = zlib.crc32(f"{country}.{basename}->{adopted_path}".encode())
    counterexample = _falsify_alias(excluded_path, adopted_path, seed=seed)
    assert counterexample is None, (
        f"{excluded_path} accepts {counterexample!r} and {adopted_path} does "
        f"not - REVIEWED_UNUSED[{(country, basename)!r}] calls this an alias "
        f"and the installed library disagrees. Adopt {excluded_path} (or "
        f"replace whichever side is actually redundant), and show the value "
        f"this found reaches the overlay redacted."
    )


def test_the_search_itself_finds_a_known_non_alias():
    """The search has to work, demonstrated on a pair it is NOT told about by
    name: the search machinery is exercised against `be.ssn` / `be.nn`
    directly, independent of whatever REVIEWED_UNUSED says on this checkout.

    This is the falsifiability check on the checker: if this starts passing
    (finds nothing), the search has stopped working, not the claim become
    true - `be.bis` numbers are a real, standard, currently-issued form.
    """
    if not STDNUM_PRESENT:
        pytest.skip("reported as a failure by test_the_external_source_is_actually_present")
    counterexample = _falsify_alias(
        "stdnum.be.ssn", "stdnum.be.nn", seed=zlib.crc32(b"known-non-alias-probe")
    )
    assert counterexample is not None, (
        "the differential search found no be.ssn/be.nn counterexample; it "
        "should find a BIS number (month field +20/+40) every time"
    )
    import stdnum.be.ssn as ssn
    import stdnum.be.nn as nn

    assert ssn.is_valid(counterexample) and not nn.is_valid(counterexample)


@needs_stdnum
def test_the_reproduced_niss_case_is_closed(monkeypatch):
    """The exact values from the reproduction: a resident NN and a BIS
    number, both printed as "NISS" - the label the Belgian SSN uses for
    either subtype - both now claimed by the validator this layer adopts.

    `85063000153` (formatted `85.06.30-001.53`) is a resident national
    number; `85273000106` (formatted `85.27.30-001.06`) is the same person's
    shape with the month field advanced into the BIS range for a
    non-resident. Both validate as `be.ssn`; only the first validated as the
    superseded `be.nn`.
    """
    resident_nn = "85063000153"
    bis_number = "85273000106"

    import stdnum.be.ssn as ssn

    assert ssn.is_valid(resident_nn)
    assert ssn.is_valid(bis_number)

    from privacy_shield import national

    found = {
        value
        for _s, _e, value, _country, _scheme in national.find_national_ids(
            f"NISS: {resident_nn} / NISS: {bis_number}", countries=["be"]
        )
    }
    assert resident_nn in found, "the resident number regressed"
    assert bis_number in found, (
        "the BIS number is still not found - the alias entry, or the table, "
        "was not actually corrected"
    )

    monkeypatch.setenv("PRIVACY_SHIELD_NATIONAL_COUNTRIES", "be")
    from privacy_shield import scan

    result = scan(f"NISS: {resident_nn} rest NISS: {bis_number}", force_text=True)

    overlay = result.documents[0].overlay
    assert resident_nn not in overlay
    assert bis_number not in overlay, (
        "a checksum-valid BIS number reached the overlay in the clear"
    )
