"""Is the national-number table still the table `python-stdnum` ships?

`national.PERSON_NUMBER_MODULES` is a hand-written map from country code to
stdnum validator module. It was written from the EU country list rather than
from what the library actually ships, and nothing inside this package can
notice it going stale - the layer validates what the table names and is silent
about everything the table forgot. That is how `stdnum.at.svnr`, a module which
does not exist, made `at` a dead country whose code still passed as
configurable, and how `gr.amka`, `pt.cc` and `si.emso` were never looked for.

The same shape as the IBAN registry check, and for the same reason: the oracle
has to come from outside the transcription. Here the oracle is the installed
`stdnum` package itself.

Three layers, each degrading on its own:

  - the PIN is a plain constant. No dependency, always readable.
  - the OBSERVATION walks the installed `stdnum`. Needs the `national` extra;
    without it the state is UNRESOLVABLE, never "fresh".
  - the VERDICT comes from `norm-freshness`. Needs the `freshness` extra;
    without it `available()` is False and the check is simply not offered.

Direction is one-way. `norm-freshness` is handed a rule id, two opaque version
strings and a change kind. Which modules count as a person-number validator,
what a national identification number is, and how to read the table are decided
here and stay here. The plane never learns what a national ID is.
"""

from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from typing import Optional

from .national import PERSON_NUMBER_MODULES

#: The `python-stdnum` release `PERSON_NUMBER_MODULES` was last reconciled
#: against. Bump it in the same commit that reconciles the table, never on its
#: own: this constant is the claim "somebody looked at this version".
STDNUM_PIN = "2.2"

#: The identifier the freshness verdict is about. Opaque to the plane.
STDNUM_URI = "pypi:python-stdnum"

RULE_ID = "table.person_number_modules"

#: Module basenames that are a person-number validator rather than a company,
#: VAT or tax-entity number. This judgement is privacy-shield's and is the
#: reason the plane cannot make it: deciding that `nn` identifies a natural
#: person and `vat` does not is domain knowledge about personal data.
PERSON_NUMBER_BASENAMES = frozenset({
    "amka", "cc", "cf", "cnp", "cpr", "cui", "dni", "egn", "emso", "fodselsnummer",
    "hetu", "idnr", "ik", "nie", "nif", "nir", "nn", "oib", "personnummer", "pesel",
    "pps", "rc", "rrn", "ssn", "svnr", "tin", "vnr",
})

#: Validators `stdnum` ships for a country this layer declares, which the table
#: deliberately does NOT look for, with the reason. An entry here is a reviewed
#: decision; anything observed that is not here is drift and fails loudly.
#:
#: The distinction that matters: none of these is "we forgot". Each is either a
#: tax number that is not a person identifier in the sense this layer detects,
#: or a second national number whose adoption would change the false-positive
#: rate and has not been measured.
REVIEWED_UNUSED = {
    ("at", "tin"): "tax number, not the social-insurance person number",
    ("be", "ssn"): "alias of be.nn, which is already validated",
    ("es", "nif"): "covers companies as well as persons; dni/nie are the person forms",
    ("fr", "nif"): "tax number; fr.nir is the person number",
    ("pt", "cc"): "candidate - would give pt a validator it has none of; FP rate unmeasured",
    ("pt", "nif"): "tax number, covers companies",
    ("ro", "cf"): "fiscal code, covers companies",
    ("ro", "cui"): "company identifier, not a person number",
}

#: Countries this layer admits as configurable while validating nothing for
#: them. Already loud at runtime - `national.find_national_ids` warns and
#: excludes them - and pinned here so the set cannot grow unnoticed.
COUNTRIES_WITHOUT_VALIDATOR = frozenset({"cy", "hu", "lu", "lv", "mt", "pt"})


@dataclass
class TableState:
    """What the installed `stdnum` says about the table, as an observation.

    `resolved` is False when `stdnum` is absent. Then every other field is
    empty and the verdict is UNRESOLVABLE - not "fresh". A check that cannot
    reach its source has not cleared anything.
    """

    resolved: bool
    observed_version: Optional[str] = None
    pinned_version: str = STDNUM_PIN
    #: Module paths the table names that the installed library does not have.
    #: This is the `at.svnr` class of defect and is always a hard error.
    dead_paths: tuple[tuple[str, str], ...] = ()
    #: (country, basename) shipped for a declared country and not looked for.
    unused: tuple[tuple[str, str], ...] = ()
    #: Declared countries with an empty validator tuple.
    without_validator: tuple[str, ...] = ()

    @property
    def moved(self) -> bool:
        return bool(self.resolved and self.observed_version != self.pinned_version)

    @property
    def undeclared_unused(self) -> tuple[tuple[str, str], ...]:
        """Validators shipped and unused that nobody has reviewed."""
        return tuple(sorted(set(self.unused) - set(REVIEWED_UNUSED)))

    @property
    def retired_reviews(self) -> tuple[tuple[str, str], ...]:
        """Reviewed entries the library no longer ships - a stale exception."""
        if not self.resolved:
            return ()
        return tuple(sorted(set(REVIEWED_UNUSED) - set(self.unused)))


def stdnum_available() -> bool:
    try:
        import stdnum  # noqa: F401
    except ImportError:
        return False
    return True


def available() -> bool:
    """True when the optional `norm-freshness` plane is importable."""
    try:
        import norm_freshness  # noqa: F401
    except ImportError:
        return False
    return True


def observe() -> TableState:
    """Walk the installed `stdnum` and report the table's state against it."""
    if not stdnum_available():
        return TableState(resolved=False)

    import stdnum

    dead: list[tuple[str, str]] = []
    for country, entries in PERSON_NUMBER_MODULES.items():
        for path, _minimum in entries:
            try:
                importlib.import_module(path)
            except ImportError:
                dead.append((country, path))

    shipped: dict[str, set[str]] = {}
    for module in pkgutil.iter_modules(stdnum.__path__):
        if not module.ispkg or len(module.name) != 2:
            continue
        package = importlib.import_module(f"stdnum.{module.name}")
        shipped[module.name] = {sub.name for sub in pkgutil.iter_modules(package.__path__)}

    unused: list[tuple[str, str]] = []
    for country in PERSON_NUMBER_MODULES:
        ours = {path.rsplit(".", 1)[1] for path, _ in PERSON_NUMBER_MODULES[country]}
        for basename in sorted(shipped.get(country, set()) & PERSON_NUMBER_BASENAMES):
            if basename not in ours:
                unused.append((country, basename))

    return TableState(
        resolved=True,
        observed_version=getattr(stdnum, "__version__", None) or _installed_version(),
        dead_paths=tuple(sorted(dead)),
        unused=tuple(sorted(unused)),
        without_validator=tuple(
            sorted(c for c, entries in PERSON_NUMBER_MODULES.items() if not entries)
        ),
    )


def _installed_version() -> Optional[str]:
    try:
        from importlib.metadata import version

        return version("python-stdnum")
    except Exception:
        return None


def assess(state: Optional[TableState] = None):
    """The freshness verdict from `norm-freshness`. None when it is absent.

    Everything domain-specific has already happened in :func:`observe`. What
    crosses into the plane is a rule id, two opaque version strings and a change
    kind - nothing that says what a national identification number is.
    """
    if not available():
        return None

    from norm_freshness import ChangeKind, RulePin, SourceRef, SourceState, assess as _assess

    state = observe() if state is None else state
    pin = RulePin(RULE_ID, SourceRef(STDNUM_URI, state.pinned_version))

    if not state.resolved:
        # current_version=None is the plane's UNRESOLVABLE, which is what an
        # unreachable source has to produce. Never CURRENT.
        observed = SourceState(STDNUM_URI, None)
    else:
        # A version bump that changed nothing this table reads is editorial for
        # our purposes; a new or withdrawn validator is an amendment. Deciding
        # which is ours to make - the plane is told the kind, not how we got it.
        substantive = bool(
            state.dead_paths or state.undeclared_unused or state.retired_reviews
        )
        observed = SourceState(
            STDNUM_URI,
            state.observed_version,
            ChangeKind.AMENDMENT if substantive else ChangeKind.EDITORIAL,
        )

    return _assess([pin], {STDNUM_URI: observed})
