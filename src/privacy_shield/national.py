"""National identifiers, validated by `python-stdnum` when it is installed.

Optional. The base package keeps `dependencies = []` and the regex/lexicon
floor is correct without this module: with `python-stdnum` absent, nothing here
runs, `find_national_ids` returns nothing, and no other layer changes
behaviour. What is lost is stated in `docs/limits.md` rather than implied.

Why a library and not more patterns: 27 EU national-identifier validators with
real check digits, maintained upstream, against per-country regexes we would
write and then fail to maintain - the IBAN registry in identifiers.py is a
transcription that was missing 40 countries and could not tell anyone.

TWO THINGS IT DOES NOT GET FOR FREE, and both are the whole of the work here.

TOKEN-LEVEL CANDIDATES. `identifiers.identifier_runs` is the wrong input: it
joins over every non-alphanumeric character including line terminators, so an
ordinary four-line letter is ONE run of 79 characters. stdnum's validators take
a whole identifier and answer yes or no; handed a 79-character run they answer
no, every time, and an adoption measurement would read "0 false positives"
while testing nothing at all. Candidates here are TOKENS - short, bounded, and
split on exactly the characters that do not appear inside a national number.

COUNTRY SCOPING. `111222333` is a valid Dutch BSN *and* a valid Czech birth
number *and* a valid Slovak one; all three validators return True. Running
every country's validators over every token manufactures false positives in
proportion to how many countries are enabled, and calls them detections. So
nothing is enabled by default: the caller says which countries a document could
plausibly belong to, via ``PRIVACY_SHIELD_NATIONAL_COUNTRIES`` or the
``countries`` argument. With none set, this layer is off.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

Span = Tuple[int, int, str]

#: Country -> the stdnum modules whose numbers identify a PERSON.
#:
#: Person identifiers only. VAT and company registration numbers are
#: identifiers of an organisation, they are published in public registers, and
#: treating them as personal data is what made the Layer-1 IBAN pattern claim
#: a VAT number. `de.stnr` is a tax number issued to individuals and is
#: included; `de.vat` is not.
#: Country -> (stdnum module, minimum digits) for numbers identifying a PERSON.
#:
#: MEASURED, not adopted as evaluated. The OSS evaluation reported 0 false
#: positives over 951 tokens from 119 clean documents. That did not reproduce
#: here: over 136 candidate tokens from 62 clean German business documents,
#: three validators accounted for 20 false positives and the other 21 for
#: none.
#:
#:   de.stnr   14  "2026-004871", "4400218836" - a regional tax number whose
#:                 check is weak enough to accept invoice and order numbers.
#:                 DROPPED on the measurement.
#:   si.ddv     3  "12345679" - and it is Slovenian VAT, an identifier of an
#:                 organisation. DROPPED: it contradicted this table's own
#:                 stated rule, which was my error, not the library's.
#:   lv.pvn     -  Latvian VAT, dropped for the same reason.
#:   nl.bsn     3  "10023847" - stdnum accepts the eight-digit legacy form, and
#:                 an eight-digit customer number passes an eleven-test about
#:                 one time in eleven. KEPT at nine digits, which is the
#:                 current BSN length, and zero false positives there.
#:
#: The minimum column is this module's own and not stdnum's: a validator may
#: accept a shorter legacy form than the scheme now issues, and a shorter
#: number means a weaker check.
#:
#: It is a minimum ALPHANUMERIC LENGTH. It used to be read as a minimum digit
#: COUNT while four of the values had been taken from the scheme's total
#: length, so those four could not fire for a person at any input:
#:
#:   ie.pps            seven digits and one or two letters, minimum 8 digits
#:   es.nie            a letter, seven digits and a letter, minimum 8 digits
#:   it.codicefiscale  eleven letters short of its own minimum of 11 digits
#:   fi.hetu           nine digits and a check character, minimum 10 digits
#:
#: Every value below is now checked against the lengths in `python-stdnum`'s
#: own documented examples, by test_every_configured_validator_can_actually_
#: fire, so a minimum that makes a validator dead fails the suite instead of
#: reporting no false positives.
#:
#: DROPPED, because the scheme cannot tell a person from a company:
#:
#:   es.nif   accepts the CIF, which is a company identifier
#:   pt.nif   the NIPC, a company number, shares the format AND the check
#:   si.ddv, lv.pvn   VAT, dropped in round 18 for the same reason
#:   de.stnr  14 false positives on 62 clean documents: invoice and order
#:            numbers pass it
#:
#: it.codicefiscale is KEPT at sixteen characters, which is the personal form.
#: Its eleven-digit form is a partita IVA - the company one - so the length is
#: what separates them.
#: Minimums deliberately set ABOVE a form the library documents, with the
#: reason. Every one of them excludes a real but weaker variant, and each is
#: the same judgement: a form with a weaker check, or no check at all, cannot
#: carry a claim against arbitrary business text.
#:
#: Named here so that "this validator cannot fire on its own documented
#: example" stays a test failure everywhere else.
DELIBERATELY_ABOVE_A_DOCUMENTED_FORM: Dict[str, str] = {
    "stdnum.nl.bsn": "the eight-digit legacy BSN; nine is the current length",
    "stdnum.cz.rc": "the nine-digit pre-1954 form, which has NO check digit "
                    "at all - 19 false positives on 200 clean documents, one "
                    "after this floor",
    "stdnum.sk.rc": "the nine-digit pre-1954 form; identical scheme to cz.rc",
    "stdnum.it.codicefiscale": "the eleven-digit form, which is a partita IVA "
                               "- a company. Sixteen is the personal one",
}

PERSON_NUMBER_MODULES: Dict[str, Tuple[Tuple[str, int], ...]] = {
    "at": (("stdnum.at.vnr", 10),),
    # be.nn AND be.bis, not be.ssn. `stdnum.be.ssn` IS `be.nn` OR `be.bis` - a
    # resident national number OR a BIS number (issued to non-residents,
    # month field advanced by 20 or 40) - and `be.nn` alone rejects every BIS
    # number, which a differential search against the installed library found
    # and the table missed for a round. `be.ssn` was the first fix here and
    # does not exist below `python-stdnum` 2.0 - `national`'s declared floor
    # is `python-stdnum>=1.19` (see pyproject.toml), and both `be.nn` and
    # `be.bis` exist there, so the pair reaches the identical acceptance set
    # (bis.validate falls through to nn's own check on every non-BIS month;
    # see stdnum.be.ssn's own source) without raising the floor for every
    # consumer. See `freshness.REVIEWED_UNUSED[("be", "ssn")]` and
    # `tests/test_national_table_freshness.py` / `tests/test_stdnum_floor.py`.
    "be": (("stdnum.be.nn", 11), ("stdnum.be.bis", 11)),
    "bg": (("stdnum.bg.egn", 10),),
    "cy": (),
    "cz": (("stdnum.cz.rc", 10),),
    "de": (("stdnum.de.idnr", 11),),
    "dk": (("stdnum.dk.cpr", 10),),
    "ee": (("stdnum.ee.ik", 11),),
    "es": (("stdnum.es.dni", 9), ("stdnum.es.nie", 9)),
    "fi": (("stdnum.fi.hetu", 10),),
    "fr": (("stdnum.fr.nir", 15),),
    "gr": (("stdnum.gr.amka", 11),),
    "hr": (("stdnum.hr.oib", 11),),
    "hu": (),
    "ie": (("stdnum.ie.pps", 8),),
    "it": (("stdnum.it.codicefiscale", 16),),
    "lt": (("stdnum.lt.asmens", 11),),
    "lu": (),
    "lv": (),
    "mt": (),
    "nl": (("stdnum.nl.bsn", 9),),
    "pl": (("stdnum.pl.pesel", 11),),
    "pt": (),
    "ro": (("stdnum.ro.cnp", 13),),
    "se": (("stdnum.se.personnummer", 10),),
    "si": (("stdnum.si.emso", 13),),
    "sk": (("stdnum.sk.rc", 10),),
}

#: Countries this layer knows and CANNOT validate, with the reason.
#:
#: An empty tuple in the table above is a country whose code `configured_countries`
#: used to accept in silence, so a caller who set PRIVACY_SHIELD_NATIONAL_COUNTRIES=pt
#: got a layer that validated as configured and detected nothing - which is
#: precisely the defect `stdnum.at.svnr` was fixed for, sitting in the same
#: table. Eight codes were in that state and `pt` joined them in round 19 when
#: `pt.nif` was dropped.
#:
#: Three of the eight were not limitations at all. `python-stdnum` ships a
#: PERSON number for Greece (`gr.amka`, the social security number), for
#: Portugal (`pt.cc`, the citizen card) and for Slovenia (`si.emso`, the unique
#: master citizen number); none had been looked for, because the table was
#: written from the country list rather than from what the library has. Greece
#: and Slovenia are configured above and measured like the rest. Portugal is
#: not, on a measurement - see below.
NO_PERSON_NUMBER_VALIDATOR: Dict[str, str] = {
    "cy": "python-stdnum has only cy.vat",
    "hu": "python-stdnum has only hu.anum, which is VAT",
    "lu": "python-stdnum has only lu.tva, which is VAT",
    "lv": "python-stdnum has only lv.pvn, which is VAT",
    "mt": "python-stdnum has only mt.vat",
    # MEASURED, not assumed. stdnum.pt.cc is a person number and it is dropped
    # anyway, for the reason de.stnr was: its check cannot carry a claim. It
    # accepts a REPEATED DIGIT at every one of the ten digits across lengths
    # twelve to twenty, including twelve zeros, so it matched a 15-digit IMEI
    # and a contract number written in groups - 6 false positives on 200 clean
    # documents and 2 on the 62-document set, where every other validator
    # accepts at most one or two repeated strings at a single length.
    "pt": "stdnum.pt.cc accepts a repeated-digit string at every digit and "
          "every length from 12 to 20, including all zeros; dropped on that "
          "measurement, as de.stnr was",
}

#: The shortest and longest national number worth offering to a validator.
#: Below eight characters the space is small enough that a check digit means
#: very little; above twenty nothing in the registry is that long.
MIN_TOKEN = 8
MAX_TOKEN = 20

#: A candidate TOKEN: alphanumerics, optionally with single internal spaces,
#: hyphens, dots or slashes, which is how these numbers are printed. It stops
#: at anything else - and critically at a line terminator, unlike the run pass,
#: because a national number is one field on one line.
_TOKEN = re.compile(r"[0-9A-Za-z]+(?:[ ./-][0-9A-Za-z]+)*")

_ENV_COUNTRIES = "PRIVACY_SHIELD_NATIONAL_COUNTRIES"


def available() -> bool:
    """Is `python-stdnum` installed?"""
    try:
        import stdnum  # noqa: F401
    except ImportError:
        return False
    return True


def configured_countries(countries: Optional[Sequence[str]] = None) -> Tuple[str, ...]:
    """Which countries to validate against. Empty means this layer is OFF.

    Nothing is enabled by default, on purpose. `111222333` validates as a
    Dutch, a Czech AND a Slovak person number, so enabling everything
    manufactures false positives in proportion to the number of countries and
    reports them as detections.
    """
    if countries is None:
        raw = os.environ.get(_ENV_COUNTRIES, "")
        countries = [part for part in re.split(r"[,\s]+", raw) if part]
    seen = []
    for country in countries:
        code = country.strip().lower()
        if not code:
            continue
        if code not in PERSON_NUMBER_MODULES:
            logger.warning(
                "%s: %r is not a country this layer knows; ignoring it",
                _ENV_COUNTRIES, country,
            )
            continue
        if not PERSON_NUMBER_MODULES[code]:
            # LOUD, and excluded. "Configured" has to mean "will be validated",
            # otherwise this function reports a country it does nothing about
            # and the caller reads the empty result as "no national numbers in
            # this document". A warning rather than an exception because the
            # scan itself is still correct: what is missing is a validator, not
            # the caller's judgement, and failing an egress scan over a
            # documented gap trades a silent absence for a dead product.
            logger.warning(
                "%s: %r is known but has no person-number validator (%s); "
                "nothing will be detected for it",
                _ENV_COUNTRIES, country,
                NO_PERSON_NUMBER_VALIDATOR.get(code, "no reason recorded"),
            )
            continue
        if code not in seen:
            seen.append(code)
    return tuple(seen)


def candidate_tokens(text: str) -> List[Span]:
    """Every token in *text* short enough to be a national number.

    This is the pass the library cannot supply. `identifier_runs` joins across
    every non-alphanumeric character, terminators included, so a four-line
    letter is a single 79-character run and every validator says no to it.
    """
    tokens: List[Span] = []
    seen = set()
    for match in _TOKEN.finditer(text):
        # Every CONTIGUOUS RUN of sub-tokens, not just the maximal join.
        #
        # These numbers are printed with spaces and dots ("44 123 456 789"), so
        # a candidate has to be able to span them - but joining maximally glues
        # the label on, and "BSN 111222333" is not a Dutch BSN, it is a label
        # and a BSN. Every validator says no to it, which is exactly how an
        # adoption measurement reads "0 false positives" while testing nothing.
        parts = [
            (piece.start(), piece.end(), piece.group())
            for piece in re.finditer(r"[0-9A-Za-z]+", match.group())
        ]
        base = match.start()
        sizes = [len(piece) for _s, _e, piece in parts]
        digit_counts = [
            sum(character.isdigit() for character in piece)
            for _s, _e, piece in parts
        ]
        for first in range(len(parts)):
            # BREAK, not continue. Extending `last` can only make the candidate
            # longer, so once it is past MAX_TOKEN every remaining pair is too -
            # and the old loop went on building a slice and running a regex
            # substitution over every one of them BEFORE testing the length.
            # Quadratic pairs times a linear slice each: 8.7 KB of text took
            # 9.17 seconds here and 17 KB took 72.5, on the egress path, which
            # is the third time this repo has shipped a gate too slow to run.
            # A gate nobody can afford to run is a gate that gets bypassed.
            total = 0
            digits = 0
            for last in range(first, len(parts)):
                total += sizes[last]
                if total > MAX_TOKEN:
                    break
                digits += digit_counts[last]
                if total < MIN_TOKEN:
                    continue
                # Every national number in the registry is mostly digits, so a
                # candidate that is mostly letters is prose. Without this the
                # pass offered "Sehr geehrte Damen" to twenty-seven validators.
                if digits < MIN_TOKEN - 2:
                    continue
                start = base + parts[first][0]
                end = base + parts[last][1]
                if (start, end) in seen:
                    continue
                seen.add((start, end))
                tokens.append((start, end, text[start:end]))
    return tokens


class MissingValidator(RuntimeError):
    """A module this table names is not in the installed `python-stdnum`."""


def _validators(countries: Sequence[str]):
    import importlib

    for country in countries:
        for path, minimum in PERSON_NUMBER_MODULES.get(country, ()):
            try:
                module = importlib.import_module(path)
            except ImportError as error:
                # LOUD. This was a debug line, and `stdnum.at.svnr` - which
                # does not exist, the module is `stdnum.at.vnr` - made "at" a
                # silently dead country whose code still passed validation as
                # configurable. An adoption measurement over a dead validator
                # reads zero false positives and means nothing, which is the
                # same failure as a validator that can never fire.
                raise MissingValidator(
                    f"{path} is not in the installed python-stdnum; "
                    "PERSON_NUMBER_MODULES names a module that is not there"
                ) from error
            checker = getattr(module, "is_valid", None)
            if checker is None:
                raise MissingValidator(f"{path} has no is_valid()")
            yield country, path.rsplit(".", 1)[-1], checker, minimum


def find_national_ids(
    text: str,
    countries: Optional[Sequence[str]] = None,
) -> List[Tuple[int, int, str, str, str]]:
    """Validated national person numbers in *text*.

    Returns ``(start, end, value, country, scheme)``. Empty when
    `python-stdnum` is absent or no country is configured - the two ways this
    layer is legitimately off.
    """
    enabled = configured_countries(countries)
    if not enabled or not available():
        return []

    checkers = list(_validators(enabled))
    if not checkers:
        return []

    found: List[Tuple[int, int, str, str, str]] = []
    for start, end, value in candidate_tokens(text):
        # LENGTH, not digit count. The column below was read as "minimum
        # digits" and four validators were given a minimum taken from the
        # scheme's TOTAL length, so they could never fire for a person at all:
        # an Irish PPS number is seven digits and a letter, a Spanish NIE is a
        # letter, seven digits and a letter, a Finnish HETU is nine digits and
        # a check character, and an Italian codice fiscale is eleven letters
        # short of its own minimum. Four dead validators reporting no false
        # positives, for the same reason a dead country does.
        size = sum(character.isalnum() for character in value)
        for country, scheme, is_valid, minimum in checkers:
            if size < minimum:
                continue
            try:
                if is_valid(value):
                    found.append((start, end, value, country, scheme))
                    break
            except Exception:  # a validator may reject malformed input loudly
                continue
    return found
