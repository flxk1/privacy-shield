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
