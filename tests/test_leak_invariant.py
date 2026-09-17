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

# The IBAN country/length registry. IMPORTED, not transcribed a second time.
#
# It used to be copied here byte for byte, 87 entries, on the reasoning that an
# independent oracle should not share the detector's tables. That reasoning was
# wrong twice over: two copies of a transcription drift against each other AND
# against reality, and both copies were in fact missing the same 40 countries,
# so the duplication bought no independence at all - it only doubled the
# maintenance.
#
# Independence that matters is independence of METHOD - how a candidate is
# found - and that is what this oracle has. What an IBAN IS, by ISO 13616, is a
# specification; the guard against it going stale is
# tests/test_iban_registry.py, which checks it against a maintained external
# implementation rather than against another copy of itself.
from privacy_shield.identifiers import IBAN_LENGTHS as _IBAN_LENGTHS

_ORACLE_LINE_BREAKS = "\n\r\v\f\u0085\u2028\u2029"

#: How far the brute-force search may reach for one identifier.
#:
#: This was 136, which is exactly the detector's own MAX_SPAN_MULTIPLE (4)
#: times its MAX_IBAN_LENGTH (34), arrived at by a different-sounding
#: rationalisation in this docstring. A number the detector also uses is not
#: independent however it is described, and it was already wrong: a 33-character
#: IBAN in four-groups with 16-space gaps spans 161, past the window, and the
#: oracle could not see it.
#:
#: There is no layout-free way to derive a window, because how far an
#: identifier reaches IS a fact about layout. So this is not derived from one.
#: It is a SAFETY CAP on a quadratic search, set so the oracle can always see
#: further than the detector can claim, whatever the detector's bounds become.
#: test_the_oracle_outranges_the_detector asserts that relation, so this can
#: never silently shrink into the detector's blind spot.
ORACLE_WINDOW = 600

#: How far either side of an "@" the e-mail search looks.
ORACLE_EMAIL_SPAN = 64


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


# ---------------------------------------------------------------------------
# Brute force. The oracle has NO run rule, so it cannot share one.
# ---------------------------------------------------------------------------
#
# Three rounds running, the check was built from the same materials as the
# thing checked, each time one level further down: `\b` in the regex and `\b`
# in the oracle; a category list in the code and a category list in the oracle;
# then `ahead - position == 1` in both, character for character. Every
# individual fix was right and the method still produced the next hole, because
# an oracle that decides which characters form a candidate can only ever
# disagree with the code about the answer, never about the question.
#
# So this oracle does not decide. It takes every subsequence of alphanumerics
# within ORACLE_WINDOW of each starting position and asks the validator. It is
# quadratic and it is meant to be: this is a release gate, not a hot path, and
# slow is the right trade for a check whose whole job is to fail on something
# nobody thought of. If it ever costs too much, run it over fewer documents -
# never with a smarter rule.
#
# What it still assumes is only the DEFINITION of each identifier: a card
# number is 13-19 decimal digits satisfying Luhn and contains no letters; an
# IBAN is a registered country code, a check pair and a body of the length ISO
# 13616 gives that country; an address has exactly one "@" and matches the RFC
# shape. Nothing about spacing, grouping, boundaries or punctuation.


def _oracle_cards(text: str) -> list[tuple[str, str]]:
    """Every Luhn-valid run of 13-19 digits, whatever lies between them.

    Punctuation of any width is skipped - two spaces, ten spaces, a dot and a
    space, a pipe with spaces either side. A letter ends the search, because a
    letter cannot appear inside a card number; that is the definition of the
    identifier, not a rule about how it is laid out.
    """
    found: list[tuple[str, str]] = []
    length = len(text)
    for start in range(length):
        if not (text[start].isascii() and text[start].isdigit()):
            continue
        digits: list[str] = []
        for index in range(start, min(length, start + ORACLE_WINDOW)):
            char = text[index]
            if char.isascii() and char.isdigit():
                digits.append(char)
                if len(digits) > 19:
                    break
                if len(digits) >= 13:
                    candidate = "".join(digits)
                    if _luhn_ok(candidate):
                        found.append((candidate, text[start:index + 1]))
            elif char.isalnum():
                break
    return found


def _oracle_ibans(text: str) -> list[tuple[str, str]]:
    """Every registered-length, mod-97-valid IBAN, whatever lies between."""
    found: list[tuple[str, str]] = []
    length = len(text)
    for start in range(length):
        if not (text[start].isascii() and text[start].isalpha()):
            continue
        registered = None
        body: list[str] = []
        for index in range(start, min(length, start + ORACLE_WINDOW)):
            char = text[index]
            if char.isascii() and char.isalnum():
                body.append(char)
                if len(body) == 2:
                    registered = _IBAN_LENGTHS.get("".join(body).upper())
                    if registered is None:
                        break
                if registered is not None and len(body) == registered:
                    candidate = "".join(body)
                    if _iban_ok(candidate):
                        found.append((candidate, text[start:index + 1]))
                    break
            elif char.isalnum():
                break
    return found


_ORACLE_EMAIL_SHAPE = re.compile(
    r"\A[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\Z"
)


def _oracle_emails(text: str) -> list[tuple[str, str]]:
    """Every RFC-shaped address, by trying every substring around each "@".

    No expansion over a character class - that would be a run rule. Every
    (start, end) pair within ORACLE_EMAIL_SPAN of the "@" is offered to the
    shape, and the longest that matches is taken.
    """
    found: list[tuple[str, str]] = []
    for at, char in enumerate(text):
        if char != "@":
            continue
        low = max(0, at - ORACLE_EMAIL_SPAN)
        high = min(len(text), at + ORACLE_EMAIL_SPAN)
        best = None
        for begin in range(low, at):
            for finish in range(high, at + 1, -1):
                candidate = text[begin:finish]
                if len(candidate) <= 254 and _ORACLE_EMAIL_SHAPE.match(candidate):
                    if best is None or len(candidate) > len(best):
                        best = candidate
                    break
        if best:
            found.append((best, best))
    return found


def validated_identifiers(text: str) -> list[tuple[str, str, str]]:
    """Every IBAN / card / email in *text* an independent check confirms.

    Returns ``(kind, canonical, as_written)``: the compacted identifier and the
    exact substring of *text* it came from, which differ whenever the input
    groups the number with spaces or anything else.

    NOTHING is excluded. There used to be a filter here that dropped every
    candidate whose written form crossed a line break, on the reasoning that a
    wrapped identifier was a measured and accepted exposure and that dropping
    it at the policy layer kept the exclusion visible.

    It was not visible; it was load-bearing. A word character glued to the
    front of a number AND a line break inside it is the intersection of two
    shapes that are each handled alone, and it leaks all sixteen digits with
    ``pii_detected`` False - and this filter meant the gate reported "oracle
    clean" for it in all three egress modes. The property could never commit
    that counterexample because it could not recognise it as a leak. The bound
    that licensed the filter was measured on the UNPREFIXED wrapped card, the
    benign variant, and authorised blindness to the variant that leaks
    completely.

    A declined claim must show up as a leak rather than as silence. If the
    detector chooses not to claim something across a line break, that is a
    decision the gate has to be able to see and fail on.

    ONE assumption is shared with the detector, and it is named here rather
    than buried: a candidate may contain at most one line break. This is
    definitional, not a layout rule - a value that wraps is continued on the
    NEXT line, whereas a string assembled from five separate lines
    ("CF8 / § 203 StGB / KTO/ / Anna Schmidt / Case C-311/18" compacts to 27
    characters that satisfy mod-97) is not an identifier anybody could read off
    the page. It is the same kind of assumption as "a letter cannot appear
    inside a card number".

    Crucially it does NOT hide the class that motivated removing the old
    exclusion: that leak has exactly one break, and
    test_the_shared_line_break_bound_cannot_hide_the_leak_class proves the
    bound still lets it through to be reported.
    """
    found: list[tuple[str, str, str]] = []
    for canonical, as_written in _oracle_emails(text):
        found.append(("email", canonical, as_written))
    for canonical, as_written in _oracle_ibans(text):
        found.append(("iban", canonical, as_written))
    for canonical, as_written in _oracle_cards(text):
        found.append(("credit_card", canonical, as_written))
    return [
        row for row in found
        if sum(row[2].count(char) for char in _ORACLE_LINE_BREAKS) <= 1
    ]


# ---------------------------------------------------------------------------
# The invariant
# ---------------------------------------------------------------------------

#: Residue shorter than this is coincidence, not a surviving fragment. Eight
#: alphanumerics of a specific identifier colliding with unrelated overlay text
#: is a one-in-a-hundred-million event; eight digits of the identifier itself
#: standing in the payload is a leak of most of the account number.
RESIDUE_RUN = 8


#: Placeholders the redactor and the anonymous-JSON path write.
_PLACEHOLDER = re.compile(r"\[(?:ANON_)?[A-Z][A-Z_0-9]*\]")


def _without_placeholders(overlay: str) -> str:
    """The overlay minus the tokens redaction inserted.

    A placeholder is not surviving PII, and its own letters are not the
    document's. "[ANON_ICD__1]" contains a D, which collided with a
    single-character ICD finding and reported a leak where the value had in
    fact been removed. Counting has to be done against what is left of the
    document, not against the labels standing in for what was taken out.
    """
    return _PLACEHOLDER.sub(" ", overlay)


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
    haystack = _compact(_without_placeholders(overlay))
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
    residual = _without_placeholders(overlay)
    counted: dict[str, int] = {}
    for span in document.spans:
        value = (span.value or "").strip()
        if value:
            counted[value] = counted.get(value, 0) + 1
    for value, claimed in counted.items():
        allowed = max(0, text.count(value) - claimed)
        if residual.count(value) > allowed:
            leaks.append(
                f"a detected span survived: overlay keeps "
                f"{residual.count(value)} copies, at most {allowed} expected"
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
        # RESIDUE is reported only for candidates that sit on one line.
        #
        # A candidate that exists only by joining two lines is already
        # speculative - the oracle can pair any line with the next, and the
        # digits of a retained UUID plus the digits of a redacted phone number
        # satisfy Luhn often enough to report constantly. Partial survival of
        # such a thing is its normal state and says nothing.
        #
        # Whole-value survival is still reported for every candidate, wrapped
        # or not, and that is what the class this bound exists for looks like:
        # the glued-and-wrapped card survives all sixteen digits.
        if any(char in _ORACLE_LINE_BREAKS for char in as_written):
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

#: Characters written BETWEEN the groups of an identifier. The first three
#: were reported leaks: a full card number and a full IBAN, verbatim in the
#: overlay with pii_detected False, because the run never formed. Underscore is
#: Pc and colon is Po - neither was in the Zs/Pd/Cf category set that replaced
#: the original " \t-" list, which is why a category set is still a list.
GROUP_SEPARATORS = [
    pytest.param("_", id="underscore"),
    pytest.param(":", id="colon"),
    pytest.param(".", id="dot"),
    pytest.param("/", id="slash"),
    pytest.param(" ", id="space"),
    pytest.param("-", id="hyphen"),
    pytest.param(",", id="comma"),
    pytest.param("|", id="pipe"),
    pytest.param("\t", id="tab"),
    pytest.param("\u00a0", id="no_break_space"),
]


#: Gaps of more than one character. Every one of these is an ordinary
#: text-extraction artefact, and every one leaked a whole card number: the run
#: rule ended a candidate at the second consecutive joiner, so the validator
#: was never offered it. The rule had been made unfalsifiable in the CHARACTER
#: dimension and left a hard limit of one in the LENGTH dimension.
MULTI_CHARACTER_GAPS = [
    pytest.param("  ", id="two_space_column_gap"),
    pytest.param("   ", id="three_space_fixed_width_padding"),
    pytest.param("    ", id="four_space_column_gap"),
    pytest.param("         ", id="nine_space_wide_column"),
    pytest.param(". ", id="dot_leader"),
    pytest.param(" | ", id="monospaced_table_pipe"),
    pytest.param(" - ", id="spaced_hyphen"),
    pytest.param("\t\t", id="double_tab"),
    pytest.param(" \u00a0 ", id="mixed_space_and_no_break_space"),
    pytest.param(",  ", id="comma_then_padding"),
]


@pytest.mark.parametrize("gap", MULTI_CHARACTER_GAPS)
@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_a_multi_character_gap_does_not_hide_a_card(gap, mode):
    text = "Karte " + gap.join(
        EXAMPLE_CARD[index:index + 4] for index in range(0, 16, 4)
    )
    assert_no_leak(text, mode=mode)
    document = scan(text, mode=mode, force_text=True).documents[0]
    if document.egress_allowed:
        assert document.pii_detected, document.overlay


@pytest.mark.parametrize("gap", MULTI_CHARACTER_GAPS)
@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_a_multi_character_gap_does_not_hide_an_iban(gap, mode):
    body = gap.join(EXAMPLE_IBAN[index:index + 4] for index in range(0, 20, 4))
    text = "Konto " + body + gap + EXAMPLE_IBAN[20:]
    assert_no_leak(text, mode=mode)
    document = scan(text, mode=mode, force_text=True).documents[0]
    if document.egress_allowed:
        assert document.pii_detected, document.overlay


def test_mixed_gap_widths_within_one_identifier():
    """Real extraction is not uniform: a dot leader here, padding there."""
    text = "Pos 4111. 1111   1111 | 1111"
    assert_no_leak(text)
    assert scan(text, force_text=True).documents[0].pii_detected


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            "Nordstern  4111  1111  1111  1111   1.234,56",
            id="pdftotext_column_gap",
        ),
        pytest.param("Pos 4111   1111   1111   1111", id="fixed_width_report"),
        pytest.param("Karte 4111. 1111. 1111. 1111", id="dot_leader_form"),
        pytest.param("| 4111 | 1111 | 1111 | 1111 |", id="monospaced_receipt"),
    ],
)
def test_reported_extraction_artefact_shapes(text):
    """The four shapes reported against the installed artifact."""
    assert_no_leak(text)
    document = scan(text, force_text=True).documents[0]
    assert document.pii_detected, document.overlay
    assert EXAMPLE_CARD not in document.overlay.replace(" ", "")


@pytest.mark.parametrize("separator", GROUP_SEPARATORS)
@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_a_grouped_card_is_found_whatever_separates_the_groups(separator, mode):
    text = "Kartennummer " + separator.join(
        EXAMPLE_CARD[index:index + 4] for index in range(0, 16, 4)
    )
    assert_no_leak(text, mode=mode)
    document = scan(text, mode=mode, force_text=True).documents[0]
    if document.egress_allowed:
        assert document.pii_detected, document.overlay


@pytest.mark.parametrize("separator", GROUP_SEPARATORS)
@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_a_grouped_iban_is_found_whatever_separates_the_groups(separator, mode):
    body = separator.join(EXAMPLE_IBAN[index:index + 4] for index in range(0, 20, 4))
    text = "Konto " + body + separator + EXAMPLE_IBAN[20:]
    assert_no_leak(text, mode=mode)
    document = scan(text, mode=mode, force_text=True).documents[0]
    if document.egress_allowed:
        assert document.pii_detected, document.overlay


@pytest.mark.parametrize("separator", GROUP_SEPARATORS)
def test_a_grouped_identifier_is_typed_as_itself(separator):
    """Not redacted by accident by a detector that thinks it is something else.

    A card written with dots matched the PHONE pattern and one written with
    slashes matched the Unix FILE_PATH pattern, so the overlay read
    "[PHONE].1111" and "4111[PATH]" - fragments of the card left behind, and the
    redaction standing on a pattern that was never about cards. If that pattern
    were ever narrowed these would become leaks, and nothing would have flagged
    it.
    """
    text = "Kartennummer " + separator.join(
        EXAMPLE_CARD[index:index + 4] for index in range(0, 16, 4)
    )
    document = scan(text, force_text=True).documents[0]
    assert document.overlay == "Kartennummer [CREDIT_CARD]", document.overlay
    assert [span.pii_type for span in document.spans] == ["credit_card"], (
        [(s.pii_type, s.start, s.end) for s in document.spans]
    )


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
    document = scan(text, force_text=True).documents[0]
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
    document = scan(text, force_text=True).documents[0]

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

#: What TERMINATES an identifier on the right. This axis had never been
#: generated at all: every prefix above varies the leading side, and the whole
#: of the layout work varied what sits between the groups, but nothing ever
#: put a character after the last one. A `\b`-terminated pattern does not match
#: when a LETTER follows, and "+49 170 1234567Ref " - a letterhead footer where
#: the label runs into the value - egressed a whole phone number.
_SUFFIXES = [
    "", "", "", "Ref", "Fax", "x", "Nr", "EUR", "ff", "GmbH",
    ".", ",", ")", "/", "-", "=20", "\u00a0", "2",
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


#: Characters the battery writes between groups. The underscore and colon
#: shapes were reported leaks, and a generator that only ever emits a space
#: cannot find them.
_BATTERY_SEPARATORS = [" ", " ", "_", "-", ".", ":", "/", ",", "|", "\u00a0", "\t"]

#: A line break INSIDE an identifier, which `pdftotext` produces whenever a
#: value wraps in a narrow column. This was never generated: the gap widths
#: below are horizontal only.
_BATTERY_INTERNAL_BREAKS = ["", "", "", "\n", "\n", "-\n", " \n", "\n "]

#: WIDTHS the battery writes between groups, and GROUP SIZES below. Every
#: generated test once used `joiner.join(...)` - exactly one character per gap,
#: always - so the generator was exhaustive on the axis that was broken one
#: round ago and constant on the axis that was broken the next. Then the widths
#: stopped at 9 and the group sizes at 4 and 5, and the next two leaks were a
#: seventeen-space column gap and a letter-spaced field of single characters.
#:
#: Both axes of the layout bound are now generated across their whole supported
#: range, up to the cliff: gaps to 80 characters, groups from 1 to 6. Where
#: each cliff sits is asserted separately by name, because a bound that has a
#: cliff and no test for it is a bound nobody knows the shape of.
_BATTERY_GAP_WIDTHS = [1, 1, 1, 2, 3, 4, 6, 9, 12, 17, 24, 40, 60, 79]

#: Group sizes. One character per group is what `pdftotext` emits for a
#: letter-spaced form field; six is the middle group of an Amex.
_BATTERY_GROUP_SIZES = [4, 4, 5, 1, 2, 3, 6]


def _gap(rng: random.Random, budget: int = 79) -> str:
    """One gap: a character repeated, or a punctuation mark then padding.

    *budget* keeps the whole identifier inside the documented span bound. A
    generator that strays past the cliff would be generating the known limit
    rather than testing the supported range; the cliff has its own test.
    """
    width = rng.choice([w for w in _BATTERY_GAP_WIDTHS if w <= budget] or [1])
    separator = rng.choice(_BATTERY_SEPARATORS)
    if width > 1 and rng.random() < 0.5:
        # "4111. 1111" - a dot leader, then spaces. Mixed characters in one gap.
        return separator + " " * (width - 1)
    return separator * width


def _spaced(rng: random.Random, digits: str) -> str:
    """Group *digits*, with gap widths varying WITHIN one identifier."""
    if rng.random() < 0.35:
        return digits
    size = rng.choice(_BATTERY_GROUP_SIZES)
    groups = [digits[i:i + size] for i in range(0, len(digits), size)]
    gaps = max(1, len(groups) - 1)
    # 16 x length is the span bound; keep the sum of gaps inside it.
    budget = max(1, (len(digits) * 16 - len(digits)) // gaps)
    uniform = rng.random() < 0.5
    gap = _gap(rng, budget)
    # AT MOST ONE internal line break, which is the documented bound: a value
    # that wraps is continued on the next line, it does not wrap repeatedly.
    # Generating more would be generating the known limit rather than the
    # supported range, and where that limit sits has its own named test.
    break_at = rng.randrange(1, len(groups)) if len(groups) > 1 and rng.random() < 0.4 else None
    out = groups[0]
    for index, group in enumerate(groups[1:], start=1):
        separator = gap if uniform else _gap(rng, budget)
        wrap = rng.choice(["\n", "-\n", " \n"]) if index == break_at else ""
        out += wrap + separator + group
    return out


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
            suffix = rng.choice(_SUFFIXES)
            planted.append((value, written))
            shapes.append(
                f"{kind}/{prefix.strip() or 'bare'}/"
                f"{'spaced' if written != value else 'compact'}/"
                f"{suffix or 'bare'}"
            )
            lines.append(f"{prefix}{written}{suffix}")
        elif kind == "name":
            lines.append(f"{rng.choice(_NAMES)}, Tel. +49 170 {rng.randint(1000000, 9999999)}")
        else:
            lines.append(rng.choice(_NOISE))
    rng.shuffle(lines)
    # A joiner PER FRAGMENT, not one for the whole list. With a single joiner,
    # a glued prefix (which needs "") and an internal line break (which needs
    # "\n" somewhere) were mutually exclusive BY CONSTRUCTION - so the
    # intersection of the two shapes, which leaks every digit, was unreachable
    # for the generator however long it ran.
    out = lines[0] if lines else ""
    for line in lines[1:]:
        out += rng.choice(["\n", " ", ", ", "", "\t"]) + line
    return out, planted, shapes


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
        document = scan(text, mode=mode, force_text=True).documents[0]
        # Ground truth only, deliberately. The brute-force oracle is rule-free
        # and therefore over-inclusive: on generated documents it reports
        # Luhn-valid windows assembled out of a UUID and the first character of
        # the next token, which are not identifiers in the document and which
        # the detector rightly declines. Where this code PLANTED the
        # identifiers it does not need to guess - and the named regressions and
        # the property test, whose inputs are small enough to adjudicate by
        # hand, are where the oracle does its work.
        leaks: list[str] = []
        # Ground truth: the exact identifier this document was BUILT from must
        # not be in the payload, in EITHER the compacted form or the form it
        # was actually written in.
        #
        # Checking only the compacted form was the hole - a card written
        # "4111  1111  1111  1111" never appears compacted anywhere, so the net
        # could not fire on a spaced write and the whole battery fell back on
        # the oracle. Ground truth is stronger than any oracle here, because
        # this code planted the identifiers and knows exactly what they are: no
        # rule, no pattern, no false alarms.
        if document.egress_allowed:
            residual = _without_placeholders(document.overlay)
            for value, written in planted:
                if written in residual:
                    leaks.append("planted identifier survived as written in overlay")
                elif value in _compact(residual):
                    leaks.append("planted identifier survived compacted in overlay")
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
        document = scan(text, mode=mode, force_text=True).documents[0]
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
    # PHONE_1, not PHONE_4. The three phone patterns that used to match digit
    # groups inside the IBAN and the card are dropped now that a validated span
    # outranks a pattern overlapping it, so they no longer burn placeholder
    # numbers on findings that were never separate data.
    # "Kunde" survives now: the name layer claims "Max Mueller" on the evidence
    # of a known given name, where the old capitalisation pattern swallowed the
    # noun in front of it too.
    assert overlay == (
        "Kunde [ANON_NAME_1], IBAN [ANON_IBAN_1], Karte [ANON_CC_1], "
        "Tel. [ANON_PHONE_1]"
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

    document = scan(text, mode=mode, force_text=True).documents[0]
    if document.egress_allowed:
        assert document.pii_detected, document.overlay


@pytest.mark.parametrize("filler", INVISIBLE_CHARACTERS)
def test_an_invisible_character_does_not_split_a_run(filler):
    """Cf characters are not there. They must not use up the run's separator."""
    from privacy_shield import identifiers

    runs = list(identifiers.identifier_runs(f"DE89{filler}3704"))
    assert len(runs) == 1, runs
    assert runs[0][0] == "DE893704"


def test_a_line_break_is_now_an_inline_separator():
    """Reversal, and the reason is written down.

    A line break used to end a run, and that was the seventh leak class: a
    label glued to its value plus a value wrapped in a narrow column - both
    ordinary `pdftotext` artefacts from the extraction path this package
    ships - leaked all sixteen digits of a card with pii_detected False.

    The exclusion was justified as "a run must not span a document". What
    actually bounds a run is the span limit and the interior-group limit, and
    admitting the newline moved neither false-positive budget by a single span:
    eight cards and no IBANs on the realistic corpus, eight on the hostile one,
    zero on the forty-two German documents.
    """
    from privacy_shield import identifiers

    for line_break in "\n\r\u2028\u2029":
        runs = list(identifiers.identifier_runs(f"DE89{line_break}3704"))
        assert len(runs) == 1, (line_break.encode("unicode_escape"), runs)
        assert runs[0][0] == "DE893704"


# ---------------------------------------------------------------------------
# A known gap, pinned rather than hidden
# ---------------------------------------------------------------------------

def test_a_line_wrapped_identifier_is_no_longer_a_gap():
    """This test used to pin the gap. It now pins its absence.

    In its previous form it measured residue on the UNPREFIXED wrapped card -
    the benign variant - found it bounded at six characters, and on that
    basis licensed the oracle to discard every candidate containing a line
    break. That authorised blindness to the prefixed variant, which leaks
    every digit. A bound measured on the harmless case must never license
    silence about the harmful one.
    """
    from privacy_shield import identifiers

    wrapped = EXAMPLE_CARD[:10] + "\n" + EXAMPLE_CARD[10:]
    assert identifiers.find_cards(wrapped), "a wrapped card is not claimed"

    for text in (wrapped, "Kreditkartennummer" + wrapped):
        document = scan(text, force_text=True).documents[0]
        assert document.pii_detected, document.overlay
        assert not leaks_in(text, document)
        surviving = _compact(EXAMPLE_CARD)
        haystack = _compact(_without_placeholders(document.overlay))
        residue = max(
            (
                size
                for size in range(len(surviving), 0, -1)
                for start in range(0, len(surviving) - size + 1)
                if surviving[start:start + size] in haystack
            ),
            default=0,
        )
        assert residue == 0, f"{residue} characters of a wrapped card survived"


# ---------------------------------------------------------------------------
# Extraction artefacts that defeated the layout bound
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_a_letter_spaced_field_does_not_hide_a_card(mode):
    """One character per group - what `pdftotext` emits for a spaced field.

    A bound on the NUMBER of groups refused this. It was there to reject text
    punctuated down to single characters ("4.1.1.1..."), and the two shapes are
    identical: nothing in the text separates a letter-spaced form field from
    dotted prose. The bound is gone and the prose shape is over-redacted along
    with it.
    """
    text = "Karte " + " ".join(EXAMPLE_CARD)
    assert_no_leak(text, mode=mode)
    document = scan(text, mode=mode, force_text=True).documents[0]
    if document.egress_allowed:
        assert document.pii_detected, document.overlay


@pytest.mark.parametrize("gap", [10, 17, 24, 40, 60, 80], ids=lambda g: f"{g}_spaces")
@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_a_wide_column_gap_does_not_hide_a_card(gap, mode):
    """A wide column in a monospaced report. The cliff used to be at 17."""
    text = "Pos " + (" " * gap).join(
        EXAMPLE_CARD[index:index + 4] for index in range(0, 16, 4)
    )
    assert_no_leak(text, mode=mode)
    document = scan(text, mode=mode, force_text=True).documents[0]
    if document.egress_allowed:
        assert document.pii_detected, document.overlay


def test_the_span_bound_has_a_cliff_and_this_is_where_it_is():
    """Pinned, not discovered.

    Any bound on how far a candidate may span has a width past which an
    identifier is no longer found. Sweeping the multiplier from 4 to 1000
    against both precision corpora does not move the false-positive count at
    all - eight cards, no IBANs, at every value - so the bound buys no
    precision and only sets where the cliff is. It is set at sixteen times the
    identifier's length, which puts the cliff far past any real column, and it
    is asserted here so that the next person to change it sees what they are
    moving.
    """
    from privacy_shield import identifiers

    def caught(gap):
        return bool(identifiers.find_cards(
            (" " * gap).join(EXAMPLE_CARD[i:i + 4] for i in range(0, 16, 4))
        ))

    assert caught(80), "a gap inside the documented range is no longer found"
    assert not caught(81), (
        "the cliff moved; re-measure the false-positive corpora and update "
        "docs/limits.md before keeping this"
    )


# ---------------------------------------------------------------------------
# What the oracle shares with the detector, pinned
# ---------------------------------------------------------------------------

def test_the_oracle_outranges_the_detector():
    """The search window must always reach further than the detector claims.

    It was 136, which is exactly the detector's MAX_SPAN_MULTIPLE times its
    MAX_IBAN_LENGTH, reached by a different-sounding rationalisation. That is
    not independence, and it was already too small: a 33-character IBAN in
    four-groups with 16-space gaps spans 161.

    There is no layout-free way to derive a window - how far an identifier
    reaches IS a fact about layout - so the window is a safety cap on a
    quadratic search, and the property that matters is this relation.
    """
    from privacy_shield import identifiers

    furthest = identifiers.MAX_IBAN_LENGTH * identifiers.MAX_SPAN_MULTIPLE
    assert ORACLE_WINDOW > furthest, (
        f"the oracle sees {ORACLE_WINDOW} characters and the detector can "
        f"claim a span of {furthest}; the oracle is blind to what the detector "
        "does at its own limit"
    )


def test_the_oracle_sees_a_widely_spaced_iban_at_the_detectors_limit():
    """The case the old 136-character window could not see."""
    spaced = (" " * 16).join(
        EXAMPLE_IBAN[index:index + 4] for index in range(0, len(EXAMPLE_IBAN), 4)
    )
    assert any(kind == "iban" for kind, _c, _w in validated_identifiers(spaced))
    assert_no_leak("Konto " + spaced)


@pytest.mark.parametrize(
    "digits, label",
    [
        ("٤١١١١١١١١١١١١١١١", "arabic_indic"),
        ("４１１１１１１１１１１１１１１１", "fullwidth"),
    ],
)
def test_non_ascii_digits_are_a_documented_limit_not_a_silent_one(digits, label):
    """ASCII is shared by the detector and this oracle, and it is a FINDING
    rule, not a definition - `luhn_ok` accepts these digits happily while
    neither candidate finder will ever offer them to it.

    Disclosed in docs/limits.md, and pinned here so the disclosure cannot
    quietly stop being true in either direction: if these start being detected,
    this test says so and the documented limit needs removing.
    """
    from privacy_shield import identifiers

    # The validator itself is happy with them...
    normalised = "".join(str(int(char)) for char in digits)
    assert identifiers.luhn_ok(normalised), "test vector is not Luhn-valid"

    # ...and neither finder offers them.
    assert not identifiers.find_cards(digits), label
    assert not validated_identifiers(digits), label


# ---------------------------------------------------------------------------
# Trailing-side termination - the axis nothing had ever varied
# ---------------------------------------------------------------------------

TRAILING = [
    pytest.param("Ref", id="letters"),
    pytest.param("Fax", id="next_field_label"),
    pytest.param("x", id="single_letter"),
    pytest.param("EUR", id="currency"),
    pytest.param("GmbH", id="company_suffix"),
    pytest.param("=20", id="quoted_printable"),
    pytest.param(" ", id="no_break_space"),
]


@pytest.mark.parametrize("suffix", TRAILING)
@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_something_glued_after_an_identifier_does_not_hide_it(suffix, mode):
    for identifier in (EXAMPLE_CARD, EXAMPLE_IBAN):
        assert_no_leak(f"Konto {identifier}{suffix}", mode=mode)


@pytest.mark.parametrize("suffix", TRAILING)
def test_a_phone_number_is_found_with_something_glued_after_it(suffix):
    """The reported case: a letterhead footer where the label runs into the
    value. `\\b` sits between a word character and a non-word character, so a
    number followed by a LETTER has no boundary after it and the pattern did
    not match at all.

    Phones have no checksum, so the run-based pass cannot rescue them the way
    it rescues an IBAN - the pattern boundary is all there is, and it was
    wrong.
    """
    text = f"Tel.+49 170 1234567{suffix}"
    document = scan(text, force_text=True).documents[0]
    assert "1234567" not in document.overlay, document.overlay
    assert document.pii_detected, document.overlay


def test_two_phone_numbers_run_together_with_labels():
    text = "Tel.+49 170 1234567Fax +49 211 9876543"
    document = scan(text, force_text=True).documents[0]
    assert "1234567" not in document.overlay, document.overlay
    assert "9876543" not in document.overlay, document.overlay


# ---------------------------------------------------------------------------
# Every counterexample the property has ever found, committed
# ---------------------------------------------------------------------------
#
# A property test whose evidence lives in `.hypothesis/` is not a gate. That
# directory is generated and gitignored, so a counterexample found on one
# machine is replayed there for ever and never seen anywhere else: CI starts
# with an empty database, searches a different part of the space, and goes
# green on a case that is reproducibly failing on someone's laptop. That is
# exactly what happened - `DE89370400440532013000+49 170 1234567Ref ` failed
# under a stored database and passed 6 runs out of 6 with a fresh one.
#
# So each of these is a committed case with a name, and the property below
# keeps searching beside them rather than instead of them. A counterexample
# that is not written down here has not been fixed; it has been cached.

PROPERTY_COUNTEREXAMPLES = [
    pytest.param(
        "DE89370400440532013000+49 170 1234567Ref ",
        id="iban_then_phone_then_letters",
    ),
    pytest.param(
        "Art. 6 DSGVO4111 1111 1111 1111Ref ",
        id="card_glued_on_both_sides_and_spaced",
    ),
    pytest.param(
        "UUID 550e8400-e29b-41d4-a716-446655440000 7",
        id="uuid_tail_plus_next_token",
    ),
    pytest.param(
        "abcdef1234@example.comabcdef1234@example.com",
        id="two_addresses_run_together",
    ),
    pytest.param(
        "UUID 550e8400-e29b-41d4-a716-446655440000"
        "UUID 550e8400-e29b-41d4-a716-446655440000",
        id="two_identical_uuids",
    ),
    pytest.param(
        "3\te1,e@6CF3D198ee,0_1f-\xa01C-dB\tD08 43\xa04111111111111111Konto=20",
        id="single_letter_finding_and_placeholder_collision",
    ),
]


@pytest.mark.parametrize("text", PROPERTY_COUNTEREXAMPLES)
@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_property_counterexamples_stay_fixed(text, mode):
    assert_no_leak(text, mode=mode)


# ---------------------------------------------------------------------------
# The seventh class: a word character in front AND a line break inside
# ---------------------------------------------------------------------------

GLUED_AND_WRAPPED = [
    pytest.param(
        "Rechnung 2026-0041\nKreditkartennummer4111 1111\n1111 1111\n"
        "Betrag 1.240,00 EUR\n",
        id="label_glued_to_value_then_wrapped_card",
    ),
    pytest.param(
        "Bankverbindung" + EXAMPLE_IBAN[:10] + "\n" + EXAMPLE_IBAN[10:] + "\n",
        id="label_glued_to_value_then_wrapped_iban",
    ),
    pytest.param(
        "Kontonummer4111 1111\n1111 1111 Ende",
        id="glued_and_wrapped_mid_line",
    ),
]


@pytest.mark.parametrize("text", GLUED_AND_WRAPPED)
@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_glued_and_wrapped_is_not_the_intersection_nobody_checks(text, mode):
    """Each shape alone is handled; the intersection was not.

    A label run into its value is the standard `pdftotext` artefact from
    adjacent cells, and a value wrapping in a narrow column is the standard
    artefact from a narrow column. Both come out of the `[extract]` path this
    package ships. Together they leaked all sixteen digits with
    `is_safe_for_external_llm` returning "No PII detected".
    """
    assert_no_leak(text, mode=mode)
    document = scan(text, mode=mode, force_text=True).documents[0]
    if document.egress_allowed:
        assert document.pii_detected, document.overlay


def test_the_line_break_bound_is_one_and_this_is_what_it_costs():
    """Pinned, like the span cliff, rather than left to be discovered.

    A value that wraps in a narrow column is continued on the NEXT line: it is
    interrupted once. A column of separate numbers stacked in a table is
    interrupted between every pair, and without this bound three article
    numbers on three lines were claimed as one card - which is the assembly
    failure the interior-group rule exists to refuse.

    The cost is an identifier wrapped more than once, which needs a column
    narrower than about eight characters. Measured, bounded, and stated.
    """
    from privacy_shield import identifiers

    once = EXAMPLE_CARD[:10] + "\n" + EXAMPLE_CARD[10:]
    twice = EXAMPLE_CARD[:6] + "\n" + EXAMPLE_CARD[6:11] + "\n" + EXAMPLE_CARD[11:]

    assert identifiers.find_cards(once), "one break must be claimed"
    assert not identifiers.find_cards(twice), (
        "two breaks are now claimed; re-measure the stacked-column corpus in "
        "tests/test_identifier_runs.py before keeping this"
    )
    # ...and the assembly case the bound exists for.
    assert not identifiers.find_cards(
        "4029764001807\n4006381333931\n4007817327104"
    )


def test_the_shared_line_break_bound_cannot_hide_the_leak_class():
    """The one assumption the oracle shares, proved harmless for the class.

    The previous exclusion dropped EVERY candidate containing a line break,
    and that hid a leak of all sixteen digits. This one drops only candidates
    with more than one, so the class that exposed the old exclusion is still
    visible to the gate: with the detector's newline support removed, the
    oracle must still report it.
    """
    from privacy_shield import identifiers

    # The reported input, which leaks all sixteen digits when the detector
    # declines. A shorter construction is no good here: with fewer digits the
    # phone pattern masks part of it and the residue falls below the reporting
    # threshold, so the test would pass for the wrong reason.
    text = (
        "Rechnung 2026-0041\nKreditkartennummer4111 1111\n1111 1111\n"
        "Betrag 1.240,00 EUR\n"
    )

    # The oracle sees it...
    assert any(
        kind == "credit_card" for kind, _c, _w in validated_identifiers(text)
    ), "the oracle can no longer see the glued-and-wrapped class"

    # ...and if the detector stops claiming it, leaks_in says so.
    original = identifiers._is_joiner
    try:
        identifiers._is_joiner = lambda char: (
            not char.isalnum() and char not in identifiers._LINE_BREAKS
        )
        document = scan(text, force_text=True).documents[0]
        assert leaks_in(text, document), (
            "the detector declined the claim and the gate stayed silent - "
            "which is the exact failure the old exclusion caused"
        )
    finally:
        identifiers._is_joiner = original
