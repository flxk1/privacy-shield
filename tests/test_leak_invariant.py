"""The leak invariant: what the product certifies as sendable must not contain PII.

This is the release gate, not a unit test beside the others. Everything else in
this suite checks a component; this checks the one promise the skill's
governance block makes:

    prohibited: egress_original_unredacted_text
    obligation: only_the_overlay_egresses

Invariant, for every input: when ``egress_allowed`` is True, neither any
detected finding's raw ``value`` nor any independently validated IBAN, card
number or email address present in the input may appear anywhere in ``overlay``.

The validators here are deliberately re-implemented rather than imported from
the package: an oracle that shares the code under test cannot catch the code
under test being wrong. 253 tests were green while a "Ref " prefix switched the
product off, because every one of them asked the scanner what it had found
instead of reading the bytes that came out.

Re-implementing a validator is not enough on its own. The first version of this
oracle re-implemented mod-97 and Luhn correctly and still reported "no
identifiers present" for every leaking input, because it looked for candidates
the same way the code under test did - with a ``\\b``-anchored regex. One word
character glued in front of an identifier hid it from the oracle and from the
detector simultaneously, so the assertion passed vacuously while a
checksum-valid IBAN went out in the payload.

So the oracle shares no anchoring assumption with the detectors. It walks every
maximal run of identifier characters and tests every candidate substring. What
it may share is a published SPECIFICATION - the Luhn algorithm, mod-97, the
ISO 13616 country/length registry - because those define what the identifier IS.
What it must never share is a heuristic: there is deliberately no issuer-prefix
table here, so a card the package's issuer table does not recognise still fails
this gate.
"""

from __future__ import annotations

import random
import re
import unicodedata

import pytest

from privacy_shield import scan
from privacy_shield.shield import PrivacyMode

# ---------------------------------------------------------------------------
# Published test vectors. Both are documentation examples, not live
# credentials: the ECBS specimen IBAN quoted in the IBAN registry examples and
# the reserved test card number every payment SDK documents. They are the only
# identifier literals in this file; everything else is synthesised at runtime
# with a real check digit.
# ---------------------------------------------------------------------------

EXAMPLE_IBAN = "DE89370400440532013000"
EXAMPLE_IBAN_SPACED = "DE89 3704 0044 0532 0130 00"
EXAMPLE_CARD = "4111111111111111"
EXAMPLE_CARD_SPACED = "4111 1111 1111 1111"

# ---------------------------------------------------------------------------
# Independent oracle - no privacy_shield imports below this line
# ---------------------------------------------------------------------------

# ISO 13616: the registered IBAN length per country. This is the specification,
# not a heuristic - a 23-character string beginning "NG20" is not an IBAN
# because Nigeria has no IBAN, however the checksum comes out.
_IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
    "BG": 22, "BH": 22, "BI": 27, "BR": 29, "BY": 28, "CH": 21, "CR": 22,
    "CY": 28, "CZ": 24, "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20,
    "EG": 29, "ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27, "GB": 22,
    "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28,
    "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30,
    "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21,
    "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20, "MR": 27,
    "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33,
    "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27,
    "SO": 23, "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29,
    "VA": 22, "VG": 24, "XK": 20,
}

_ORACLE_LINE_BREAKS = "\n\r\v\f  "


def _oracle_transparent(char: str) -> bool:
    """Invisible: soft hyphen, zero-width space, joiners, BOM."""
    return unicodedata.category(char) == "Cf"


def _oracle_separator(char: str) -> bool:
    """Any horizontal space or hyphen a document extractor might emit."""
    if char in _ORACLE_LINE_BREAKS:
        return False
    return char == "\t" or unicodedata.category(char) in ("Zs", "Pd")


def _luhn_ok(digits: str) -> bool:
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _iban_ok(candidate: str) -> bool:
    compact = candidate.replace(" ", "").upper()
    if not 15 <= len(compact) <= 34 or not compact[:2].isalpha():
        return False
    if not compact[2:4].isdigit() or not compact[4:].isalnum():
        return False
    rotated = compact[4:] + compact[:4]
    expanded = "".join(
        str(int(ch, 36)) if ch.isalpha() else ch for ch in rotated
    )
    return int(expanded) % 97 == 1


def _oracle_runs(text: str) -> list[tuple[str, list[int]]]:
    """Every maximal run of identifier characters, compacted to alphanumerics.

    No word boundary is consulted anywhere. A run grows over ASCII
    alphanumerics and single internal spaces, tabs or hyphens - the separators
    people actually write inside an IBAN or a card number - and ends at
    anything else, including a newline. ``offsets[i]`` is where ``compact[i]``
    sits in *text*.
    """
    runs: list[tuple[str, list[int]]] = []
    visible = [
        (char, index)
        for index, char in enumerate(text)
        if not _oracle_transparent(char)
    ]
    compact: list[str] = []
    offsets: list[int] = []
    position = 0
    count = len(visible)
    while position < count:
        char, origin = visible[position]
        if char.isascii() and char.isalnum():
            compact.append(char)
            offsets.append(origin)
            position += 1
            continue
        if compact and _oracle_separator(char):
            ahead = position
            while ahead < count and _oracle_separator(visible[ahead][0]):
                ahead += 1
            if ahead - position == 1 and ahead < count:
                following = visible[ahead][0]
                if following.isascii() and following.isalnum():
                    position = ahead
                    continue
        if compact:
            runs.append(("".join(compact), offsets))
            compact, offsets = [], []
        position += 1
    if compact:
        runs.append(("".join(compact), offsets))
    return runs


def _oracle_ibans(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for compact, offsets in _oracle_runs(text):
        position = 0
        while position < len(compact) - 14:
            window = compact[position:position + 4]
            if not (window[:2].isalpha() and window[2:].isdigit()):
                position += 1
                continue
            registered = _IBAN_LENGTHS.get(compact[position:position + 2].upper())
            if registered is None or position + registered > len(compact):
                position += 1
                continue
            candidate = compact[position:position + registered]
            if _iban_ok(candidate):
                start = offsets[position]
                end = offsets[position + registered - 1] + 1
                found.append((candidate, text[start:end]))
                position += registered
                continue
            position += 1
    return found


def _oracle_cards(text: str) -> list[tuple[str, str]]:
    """Every Luhn-valid 13-19 digit window, at every offset.

    Deliberately no issuer-prefix table. The package has one; if this oracle
    had the same one, a card whose prefix the package does not know would be
    invisible to both at once - which is the failure mode this whole file
    exists to prevent.
    """
    found: list[tuple[str, str]] = []
    for compact, offsets in _oracle_runs(text):
        for digits in re.finditer(r"\d+", compact):
            run_start, run_end = digits.start(), digits.end()
            position = run_start
            while position < run_end:
                claimed = 0
                for size in range(19, 12, -1):
                    if position + size > run_end:
                        continue
                    candidate = compact[position:position + size]
                    if _luhn_ok(candidate):
                        start = offsets[position]
                        end = offsets[position + size - 1] + 1
                        found.append((candidate, text[start:end]))
                        claimed = size
                        break
                position += claimed if claimed else 1
    return found


_ORACLE_LOCAL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-"
_ORACLE_DOMAIN = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-"
_ORACLE_EMAIL_SHAPE = re.compile(
    r"\A[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\Z"
)


def _oracle_emails(text: str) -> list[tuple[str, str]]:
    """Every RFC-shaped address, found by expanding outwards from each '@'.

    Expanding from the '@' rather than matching from a word boundary is the
    point: a word character the local-part class does not cover - a German
    umlaut, say - glued in front of an address makes a ``\\b``-anchored pattern
    miss the whole thing.
    """
    found: list[tuple[str, str]] = []
    for at in (index for index, char in enumerate(text) if char == "@"):
        left = at
        while left > 0 and text[left - 1] in _ORACLE_LOCAL:
            left -= 1
        right = at + 1
        while right < len(text) and text[right] in _ORACLE_DOMAIN:
            right += 1
        for start in range(left, at):
            matched = None
            for end in range(right, at + 1, -1):
                candidate = text[start:end]
                if _ORACLE_EMAIL_SHAPE.match(candidate) and len(candidate) <= 254:
                    matched = candidate
                    break
            if matched:
                found.append((matched, matched))
                break
    return found


def validated_identifiers(text: str) -> list[tuple[str, str, str]]:
    """Every IBAN / card / email in *text* an independent check confirms.

    Returns ``(kind, canonical, as_written)``: the compacted identifier and the
    exact substring of *text* it came from, which differ whenever the input
    groups the number with spaces.
    """
    found: list[tuple[str, str, str]] = []
    for canonical, as_written in _oracle_emails(text):
        found.append(("email", canonical, as_written))
    for canonical, as_written in _oracle_ibans(text):
        found.append(("iban", canonical, as_written))
    for canonical, as_written in _oracle_cards(text):
        found.append(("credit_card", canonical, as_written))
    return found


# ---------------------------------------------------------------------------
# The invariant
# ---------------------------------------------------------------------------

#: Residue shorter than this is coincidence, not a surviving fragment. Eight
#: alphanumerics of a specific identifier colliding with unrelated overlay text
#: is a one-in-a-hundred-million event; eight digits of the identifier itself
#: standing in the payload is a leak of most of the account number.
RESIDUE_RUN = 8


def _compact(value: str) -> str:
    return "".join(char for char in value if char.isascii() and char.isalnum())


def _residue_run(identifier: str, overlay: str, text: str) -> str:
    """The longest contiguous stretch of *identifier* that SURVIVED.

    Whole-value containment is not enough on its own: a spliced placeholder or
    a span applied at a stale offset leaves most of the number behind while the
    complete string is gone, and a check that only asks "is the whole value in
    there" calls that clean.

    Survival is counted, not merely found. A stretch that occurs in the input
    more often than it remains in the overlay has lost an occurrence, and the
    identifier's own copy is the one that went. Hypothesis is what forced this:
    given two identical UUIDs, the first allowlisted and kept, a Luhn-valid
    window inside the second was correctly redacted and then "found" again in
    the retained first copy. Nothing had leaked.
    """
    needle = _compact(identifier)
    haystack = _compact(overlay)
    source = _compact(text)
    for size in range(len(needle), RESIDUE_RUN - 1, -1):
        for start in range(0, len(needle) - size + 1):
            fragment = needle[start:start + size]
            remaining = haystack.count(fragment)
            if remaining and remaining >= source.count(fragment):
                return fragment
    return ""


def leaks_in(text: str, document) -> list[str]:
    """Every way *document* breaks the leak invariant for input *text*."""
    if not document.egress_allowed:
        return []

    overlay = document.overlay
    leaks: list[str] = []

    # Was every DETECTED span's own occurrence actually removed?
    #
    # Counted, not tested for containment. A plain `value in overlay` conflates
    # occurrences: hypothesis found two identical UUIDs run together, where the
    # first is allowlisted and kept, the tail of the second is matched as a
    # phone number and redacted, and the retained first copy then makes the
    # redacted one look like a survivor. The finding's own occurrence had gone.
    #
    # So: the overlay may keep no more copies than the input had minus the ones
    # that were claimed. Nothing is softened for a real leak - a value detected
    # once and present once in the overlay still fails.
    counted: dict[str, int] = {}
    for span in document.spans:
        value = (span.value or "").strip()
        if value:
            counted[value] = counted.get(value, 0) + 1
    for value, claimed in counted.items():
        allowed = max(0, text.count(value) - claimed)
        if overlay.count(value) > allowed:
            leaks.append(
                f"a detected span survived: overlay keeps "
                f"{overlay.count(value)} copies, at most {allowed} expected"
            )

    for kind, canonical, as_written in validated_identifiers(text):
        if canonical in overlay or as_written in overlay:
            leaks.append(f"validated {kind} survived whole in overlay")
            continue
        if kind == "email":
            local = canonical.split("@", 1)[0]
            if len(local) >= 4 and local in overlay:
                leaks.append(f"validated {kind} local part survived in overlay")
            continue
        residue = _residue_run(canonical, overlay, text)
        if residue:
            leaks.append(
                f"validated {kind} left {len(residue)} of {len(canonical)} "
                "characters of residue in overlay"
            )

    return leaks


#: The four modes. LOCAL_ONLY never clears an external egress, so the invariant
#: is vacuous there by construction - it is in the list so that a change which
#: quietly starts clearing it shows up here rather than in production.
ALL_MODES = [
    PrivacyMode.STANDARD,
    PrivacyMode.REGEX_ONLY,
    PrivacyMode.ANONYMOUS_JSON,
    PrivacyMode.LOCAL_ONLY,
]

#: The three modes that can actually clear a payload for egress.
EGRESS_MODES = [
    PrivacyMode.STANDARD,
    PrivacyMode.REGEX_ONLY,
    PrivacyMode.ANONYMOUS_JSON,
]


def assert_no_leak(text: str, mode: PrivacyMode = PrivacyMode.STANDARD) -> None:
    report = scan(text, mode=mode)
    for document in report.documents:
        leaks = leaks_in(text, document)
        assert not leaks, (
            "LEAK INVARIANT VIOLATED\n"
            f"  mode      : {mode.value}\n"
            f"  overlay   : {document.overlay!r}\n"
            f"  pii       : {document.pii_detected}\n"
            f"  egress    : {document.egress_allowed}\n"
            "  leaks     : " + "\n              ".join(leaks)
        )


def assert_no_leak_any_mode(text: str) -> None:
    for mode in ALL_MODES:
        assert_no_leak(text, mode=mode)


# ---------------------------------------------------------------------------
# Named regressions - the five reproductions that rejected 2.0.0
# ---------------------------------------------------------------------------

REJECTION_REPRODUCTIONS = [
    pytest.param(EXAMPLE_IBAN, id="bare_iban"),
    pytest.param(f"Ref {EXAMPLE_IBAN}", id="iban_behind_ref_prefix"),
    pytest.param(EXAMPLE_CARD, id="bare_card"),
    pytest.param(f"ID {EXAMPLE_CARD}", id="card_behind_id_prefix"),
    pytest.param("Kontakt: ref abcdef1234@example.com", id="email_behind_ref_hex_local_part"),
]


@pytest.mark.parametrize("text", REJECTION_REPRODUCTIONS)
def test_release_gate_rejection_reproductions(text):
    assert_no_leak(text)


# ---------------------------------------------------------------------------
# The class behind those five: a word character glued to the identifier
# ---------------------------------------------------------------------------
#
# Every pattern in Layer 1 starts with \b. A word boundary exists between a
# word character and a non-word character, so ONE word character in front of an
# identifier means no boundary exists at its first character - and because the
# rest of an IBAN or a card number is also word characters, no boundary exists
# anywhere inside it either. The pattern therefore never matches, the validator
# is never offered the candidate, and the caller is told pii_detected=False
# while a mod-97-valid account number goes out verbatim.
#
# These are the shapes that arise in real documents, not exotic ones.

GLUED_PREFIX_SHAPES = [
    pytest.param("acct_{identifier}", id="underscore_prefixed_account_reference"),
    pytest.param("Rechnung2026{identifier}", id="document_number_run_together"),
    pytest.param("id-a3f{identifier}", id="id_dash_hex_prefix"),
    # Quoted-printable encodes a space as =20 and every non-ASCII byte as =XX.
    # Any MIME body with German umlauts is transfer-encoded this way, and .txt,
    # .eml and .log are all in the default extension set.
    pytest.param("Konto=20{identifier}", id="quoted_printable_space"),
    pytest.param("Gesch=E4ftskonto=20{identifier}", id="quoted_printable_umlaut_line"),
    pytest.param("x{identifier}", id="single_letter_glued"),
    pytest.param("7{identifier}", id="single_digit_glued"),
    pytest.param("A;B{identifier};C", id="csv_field_run_together"),
]


@pytest.mark.parametrize("shape", GLUED_PREFIX_SHAPES)
@pytest.mark.parametrize("identifier", [EXAMPLE_IBAN, EXAMPLE_CARD], ids=["iban", "card"])
@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_release_gate_glued_prefix_class(shape, identifier, mode):
    """A checksum-valid identifier must be found whatever is glued to it."""
    assert_no_leak(shape.format(identifier=identifier), mode=mode)


@pytest.mark.parametrize("shape", GLUED_PREFIX_SHAPES)
@pytest.mark.parametrize("identifier", [EXAMPLE_IBAN, EXAMPLE_CARD], ids=["iban", "card"])
def test_glued_prefix_is_reported_not_merely_removed(shape, identifier):
    """The caller must also be WARNED, not silently handed a clean overlay.

    The original defect at least set pii_detected. The glued-prefix class did
    not: it returned False, so a caller deciding on that flag had no signal at
    all.
    """
    document = scan(shape.format(identifier=identifier)).documents[0]
    assert document.pii_detected, document.overlay


def test_glued_prefix_keeps_the_prefix_and_loses_the_number():
    """Precision: the placeholder replaces the identifier, not its neighbours.

    A prefixed account reference keeps its prefix. Redacting the surrounding
    characters too would be safe and useless - the overlay is what the cloud
    model reads.
    """
    document = scan(f"acct_{EXAMPLE_IBAN} freigegeben").documents[0]
    assert document.overlay == "acct_[IBAN] freigegeben", document.overlay


def test_umlaut_glued_to_an_email_does_not_hide_it():
    """The same class, on the email pattern.

    An umlaut is a word character that the local-part class does not cover, so
    \\b finds no boundary and the address is invisible - while the address
    itself is perfectly valid and perfectly readable to a human.
    """
    assert_no_leak("Gruesse an Frau Muelleräerika@example.com")


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            "Unter Art. 6 DSGVO: erika.mustermann@example.com",
            id="email_beside_legal_citation",
        ),
        pytest.param(
            "Gemaess GDPR schreiben Sie an erika@firma.de",
            id="email_beside_regulation_name",
        ),
        pytest.param(
            "UUID 550e8400-e29b-41d4-a716-446655440000 und IBAN DE89370400440532013000",
            id="iban_beside_real_uuid",
        ),
        pytest.param(
            "Kunde Max Mueller, IBAN DE89 3704 0044 0532 0130 00, "
            "Karte 4111 1111 1111 1111",
            id="overlapping_spans_in_one_line",
        ),
        pytest.param(
            "REF: 4012888888881881 / rechnung@kanzlei.de",
            id="card_and_email_behind_ref",
        ),
    ],
)
def test_release_gate_suppressor_adjacency(text):
    """A suppressor pattern near a validated identifier must not switch it off."""
    assert_no_leak(text)


@pytest.mark.parametrize("text", REJECTION_REPRODUCTIONS)
def test_structural_guard_holds_with_the_broken_regex_restored(text, monkeypatch):
    """The regex narrowing is depth. The restructure is what carries the fix.

    Puts the exact pre-fix suppressor back - IGNORECASE hex class and all, the
    pattern that let 'Ref ' switch the product off - and asserts the invariant
    still holds, because suppression now runs after the validating detectors
    and may not discard what they claimed.
    """
    from privacy_shield import scanner as scanner_module

    broken = re.compile(r"\b(?:UUID|ID|REF)[-:]?\s*[a-f0-9-]{8,}\b", re.IGNORECASE)
    assert broken.search("Ref DE89370400440532013000"), (
        "the pre-fix pattern must still be the over-broad one this guards against"
    )
    monkeypatch.setattr(
        scanner_module,
        "ALLOWLIST_PATTERNS",
        list(scanner_module.ALLOWLIST_PATTERNS) + [broken],
    )
    assert_no_leak(text)


def test_overlay_is_not_corrupted_by_overlapping_spans():
    """Overlapping findings must not splice placeholder fragments into the overlay."""
    text = "Kunde Max Mueller, IBAN DE89 3704 0044 0532 0130 00, Karte 4111 1111 1111 1111"
    document = scan(text).documents[0]
    overlay = document.overlay
    assert not leaks_in(text, document)
    # A spliced placeholder leaves an orphan "]" with no opening "[" before it.
    assert overlay.count("[") == overlay.count("]"), overlay
    assert not re.search(r"\][A-Z_]+\]", overlay), overlay


def test_a_trimmed_identifier_does_not_blank_out_its_neighbour():
    """Precision, not safety: a greedy match must not take the next line with it.

    The IBAN pattern matches whitespace, so it absorbs the token after the
    number ("DE71...550\\nID "). Trimming it back to the validating prefix is
    only half the job - the untrimmed candidate has to go, or the redactor
    merges the two and blanks the neighbour out as well.
    """
    text = f"Ref {EXAMPLE_IBAN}\nID {EXAMPLE_CARD}\n"
    document = scan(text).documents[0]

    assert not leaks_in(text, document)
    assert document.overlay == "Ref [IBAN]\nID [CREDIT_CARD]\n", document.overlay


# ---------------------------------------------------------------------------
# Generated documents
# ---------------------------------------------------------------------------

_NAMES = ["Erika Mustermann", "Max Mueller", "Anna Schmidt", "Klaus Weber"]
# Separated prefixes and glued ones. The glued half is the class the five named
# reproductions belonged to: a word character immediately before the first
# character of the identifier.
_PREFIXES = [
    "", "Ref ", "REF: ", "ID ", "id-", "UUID ", "Referenz: ", "Nr. ",
    "acct_", "Rechnung2026", "id-a3f", "Konto=20", "Gesch=E4ftskonto=20",
    "x", "7", "Beleg-", "KTO/",
]
_NOISE = [
    "Art. 6 DSGVO",
    "Gemaess GDPR",
    "§ 203 StGB",
    "Case C-311/18",
    "CEO Meyer",
    "Version 2.1.0",
    "UUID 550e8400-e29b-41d4-a716-446655440000",
    "Sehr geehrte Damen und Herren,",
    "mit freundlichen Gruessen",
]


# A spread of registered IBAN countries and their registered total lengths, so
# the battery is not all one national format.
_IBAN_COUNTRIES = {"DE": 22, "AT": 20, "NL": 18, "BE": 16, "ES": 24, "IT": 27, "NO": 15}


def _make_iban(rng: random.Random, country: str = "DE") -> str:
    """A syntactically real IBAN for *country*, with a computed check digit."""
    bban = "".join(rng.choice("0123456789") for _ in range(_IBAN_COUNTRIES[country] - 4))
    rotated = bban + "".join(str(int(ch, 36)) for ch in country) + "00"
    check = 98 - int(rotated) % 97
    return f"{country}{check:02d}{bban}"


def _make_card(rng: random.Random) -> str:
    body = "4" + "".join(rng.choice("0123456789") for _ in range(14))
    total = 0
    for index, char in enumerate(reversed(body)):
        value = int(char)
        if index % 2 == 0:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return body + str((10 - total % 10) % 10)


def _make_email(rng: random.Random) -> str:
    local = rng.choice(["abcdef1234", "erika.mustermann", "m.mueller", "deadbeef99"])
    return f"{local}@{rng.choice(['example.com', 'kanzlei.de', 'firma.org'])}"


def _spaced(rng: random.Random, digits: str) -> str:
    if rng.random() < 0.5:
        return digits
    size = rng.choice([4, 4, 5])
    return " ".join(digits[i:i + size] for i in range(0, len(digits), size))


def generate_document(rng: random.Random) -> tuple[str, list[str], list[str]]:
    """A short realistic document carrying at least one validated identifier.

    Returns ``(text, planted, shapes)``. *planted* is ground truth - the exact
    identifiers this document was built from, which no pattern had to find -
    and *shapes* names how each was glued in, so a failure can be reported
    without quoting the identifier itself.
    """
    lines: list[str] = []
    planted: list[str] = []
    shapes: list[str] = []
    for _ in range(rng.randint(1, 4)):
        kind = rng.choice(["iban", "card", "email", "name", "noise"])
        prefix = rng.choice(_PREFIXES)
        if kind in ("iban", "card", "email"):
            if kind == "iban":
                value = _make_iban(rng, rng.choice(list(_IBAN_COUNTRIES)))
                written = _spaced(rng, value)
            elif kind == "card":
                value = _make_card(rng)
                written = _spaced(rng, value)
            else:
                value = _make_email(rng)
                written = value
            planted.append(value)
            shapes.append(f"{kind}/{prefix.strip() or 'bare'}/{'spaced' if written != value else 'compact'}")
            lines.append(f"{prefix}{written}")
        elif kind == "name":
            lines.append(f"{rng.choice(_NAMES)}, Tel. +49 170 {rng.randint(1000000, 9999999)}")
        else:
            lines.append(rng.choice(_NOISE))
    rng.shuffle(lines)
    joiner = rng.choice(["\n", " ", ", "])
    return joiner.join(lines), planted, shapes


GENERATED_DOCUMENT_COUNT = 300


@pytest.mark.parametrize("mode", ALL_MODES, ids=lambda m: m.value)
def test_release_gate_generated_battery(mode):
    """No generated document may egress carrying its own PII, in any mode.

    Failures are reported by SHAPE and count. The identifiers are synthesised
    here with real check digits and are never printed - a gate that pastes the
    account numbers it just caught into a CI log is its own kind of leak.
    """
    rng = random.Random(20260916)
    failures: list[str] = []
    for index in range(GENERATED_DOCUMENT_COUNT):
        text, planted, shapes = generate_document(rng)
        document = scan(text, mode=mode).documents[0]
        leaks = leaks_in(text, document)
        # Ground truth, independent of any pattern on either side: the exact
        # identifier this document was BUILT from must not be in the payload.
        if document.egress_allowed:
            for value in planted:
                if value in document.overlay:
                    leaks.append("planted identifier survived whole in overlay")
        if leaks:
            failures.append(f"[{index}] shapes={shapes} -> {'; '.join(sorted(set(leaks)))}")
    assert not failures, (
        f"{len(failures)}/{GENERATED_DOCUMENT_COUNT} generated documents leaked "
        f"in {mode.value} mode:\n" + "\n".join(failures[:15])
    )


try:  # pragma: no cover - exercised only where hypothesis is installed
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st
except ImportError:  # pragma: no cover
    given = None


if given is not None:  # pragma: no branch
    _fragment = st.one_of(
        st.sampled_from(_PREFIXES),
        st.sampled_from(_NOISE),
        st.sampled_from(_NAMES),
        st.sampled_from(
            [
                EXAMPLE_IBAN,
                EXAMPLE_IBAN_SPACED,
                EXAMPLE_CARD,
                EXAMPLE_CARD_SPACED,
                "abcdef1234@example.com",
                "erika.mustermann@example.com",
                "+49 170 1234567",
            ]
        ),
        st.text(alphabet="abcdefABCDEF0123456789 .:,-/_=", max_size=24),
    )

    @settings(max_examples=250, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(
        st.lists(_fragment, min_size=1, max_size=8),
        st.sampled_from([" ", "\n", ", ", ""]),
        st.sampled_from(EGRESS_MODES),
    )
    def test_release_gate_property(fragments, joiner, mode):
        text = joiner.join(fragments)
        if not text.strip():
            return
        document = scan(text, mode=mode).documents[0]
        leaks = leaks_in(text, document)
        assert not leaks, (
            f"mode={mode.value}\ninput={text!r}\noverlay={document.overlay!r}\n"
            + "; ".join(leaks)
        )


def test_anonymous_json_overlay_is_not_spliced_by_overlapping_spans():
    """The cloud-egress mode had its own, unfixed copy of the overlap bug.

    `anonymous_json.anonymize_text` applied findings computed on ORIGINAL
    offsets to an already-mutated string. The redactor was fixed for exactly
    this; this path was byte-identical to the pre-fix tip while the CHANGELOG
    declared the defect fixed - and it is the mode whose entire purpose is
    sending the result to a cloud model.

    The phone pattern overlaps the IBAN's digit groups here, so the two
    replacements collide. Applied on stale offsets, the tail of the account
    number is spliced back in directly behind its own placeholder.
    """
    text = (
        f"Kunde Max Mueller, IBAN {EXAMPLE_IBAN_SPACED}, "
        f"Karte {EXAMPLE_CARD_SPACED}, Tel. 0170 1234567"
    )
    document = scan(text, mode=PrivacyMode.ANONYMOUS_JSON).documents[0]
    overlay = document.overlay

    assert not leaks_in(text, document)
    assert overlay.count("[") == overlay.count("]"), overlay
    # The signal of a replacement applied at an offset that had already moved:
    # digits of the value standing immediately behind its own placeholder.
    # Pre-fix this read "[ANON_IBAN_1]30 00, Karte ...".
    assert not re.search(r"\]\s?\d", overlay), overlay
    assert overlay == (
        "[ANON_NAME_1], IBAN [ANON_IBAN_1], Karte [ANON_CC_1], "
        "Tel. [ANON_PHONE_4]"
    ), overlay


def test_allowlist_cannot_suppress_a_validated_identifier(monkeypatch):
    """The rule that made the placeholder-email allowlist entry dead code.

    That entry listed (example|test|noreply|info|contact)@(example|test).com
    and had no effect, because a validating detector claims an RFC-shaped
    address before any suppressor is consulted. It was deleted rather than
    revived: reviving it means letting a suppressor overrule a validated
    identifier, which is the structure the 2.0.0 rejection was about.

    Asserted here as a property rather than a spelling. An allowlist entry that
    covers a real identifier exactly - the strongest form a suppressor can take
    - still must not switch detection off.
    """
    from privacy_shield import scanner as scanner_module

    greedy = re.compile(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+|[A-Z]{2}[0-9A-Z ]+|[0-9 ]{13,}"
    )
    monkeypatch.setattr(
        scanner_module,
        "ALLOWLIST_PATTERNS",
        list(scanner_module.ALLOWLIST_PATTERNS) + [greedy],
    )
    for text in (
        "erika.mustermann@example.com",
        EXAMPLE_IBAN,
        EXAMPLE_IBAN_SPACED,
        EXAMPLE_CARD,
        EXAMPLE_CARD_SPACED,
    ):
        assert_no_leak(text)


def test_placeholder_addresses_are_reported_rather_than_allowlisted():
    """The accepted cost of deleting the entry, stated so it is not a surprise."""
    document = scan("Schreiben Sie an test@example.com").documents[0]
    assert document.pii_detected
    assert "test@example.com" not in document.overlay


# ---------------------------------------------------------------------------
# Separators, by property rather than by a remembered list
# ---------------------------------------------------------------------------
#
# The first version of the run scan enumerated " \t-". An adversarial pass went
# straight through it: a no-break space between the groups of an IBAN, a soft
# hyphen out of a justified paragraph, a zero-width space out of an HTML paste.
# Each ended the run early and the identifier behind a glued prefix went out
# again, pii_detected False. Enumerating separators from memory is the same
# mistake as enumerating leak inputs from memory, so the rule is now a
# character property - Cf is invisible, Zs is a space, Pd is a hyphen.

INVISIBLE_CHARACTERS = [
    pytest.param("­", id="soft_hyphen"),
    pytest.param("​", id="zero_width_space"),
    pytest.param("‌", id="zero_width_non_joiner"),
    pytest.param("‍", id="zero_width_joiner"),
    pytest.param("﻿", id="byte_order_mark"),
]

INLINE_SPACES = [
    pytest.param(" ", id="no_break_space"),
    pytest.param(" ", id="figure_space"),
    pytest.param(" ", id="thin_space"),
    pytest.param(" ", id="narrow_no_break_space"),
    pytest.param("‑", id="non_breaking_hyphen"),
    pytest.param("\t", id="tab"),
]


@pytest.mark.parametrize("filler", INVISIBLE_CHARACTERS + INLINE_SPACES)
@pytest.mark.parametrize("identifier", [EXAMPLE_IBAN, EXAMPLE_CARD], ids=["iban", "card"])
@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_a_separator_inside_an_identifier_does_not_hide_it(filler, identifier, mode):
    """Split the identifier with the character AND glue a prefix to it.

    Either alone was survivable - the boundary-anchored pattern still caught a
    spaced identifier standing on its own. It is the combination that got
    through both.
    """
    text = "acct_" + identifier[:4] + filler + identifier[4:]
    assert_no_leak(text, mode=mode)

    document = scan(text, mode=mode).documents[0]
    if document.egress_allowed:
        assert document.pii_detected, document.overlay


@pytest.mark.parametrize("filler", INVISIBLE_CHARACTERS)
def test_an_invisible_character_does_not_split_a_run(filler):
    """Cf characters are not there. They must not use up the run's separator."""
    from privacy_shield import identifiers

    runs = list(identifiers.identifier_runs(f"DE89{filler}3704"))
    assert len(runs) == 1, runs
    assert runs[0][0] == "DE893704"


def test_a_line_break_is_never_an_inline_separator():
    """The bound on all of this: a run still stops at the end of a line."""
    from privacy_shield import identifiers

    for line_break in "\n\r  ":
        runs = list(identifiers.identifier_runs(f"DE89{line_break}3704"))
        assert len(runs) == 2, (line_break.encode("unicode_escape"), runs)
