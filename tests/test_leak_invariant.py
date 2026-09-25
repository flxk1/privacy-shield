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


def _ascii_of(char: str) -> "str | None":
    """What an identifier character IS: a decimal digit of any script, or an
    alphanumeric that is not a modifier letter and is compatibility-equal
    to one ASCII letter. A card in full-width digits is a card; the oracle
    cannot find less than that."""
    if not char.isalnum() or unicodedata.category(char) == "Lm":
        return None
    digit = unicodedata.decimal(char, None)
    if digit is not None:
        return str(digit)
    folded = unicodedata.normalize("NFKC", char)
    if len(folded) == 1 and folded.isascii() and folded.isalpha():
        return folded
    return None

#: One line TERMINATOR, however many characters it is written with.
#:
#: The bound used to count characters, so a single CRLF scored two and a
#: wrapped identifier terminated the normal Windows and MIME way was refused -
#: by the detector AND by this oracle, which applied the identical arithmetic
#: to the identical two characters. Counting the sequence is the fix; adding
#: "\r\n" to a list of characters would not have been, because the next
#: sequence would be missing again.
#:
#: Longest-first alternation, so "\r\n" is never counted as two.
_ORACLE_TERMINATOR = re.compile(
    "|".join(
        [r"\r\n", r"\n\r"] + [re.escape(c) for c in _ORACLE_LINE_BREAKS]
    )
)


def _oracle_terminators(value: str) -> int:
    """How many line terminators *value* contains, counting sequences."""
    return len(_ORACLE_TERMINATOR.findall(value))

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


def _oracle_cards(text: str) -> "list[tuple[str, str, int, int]]":
    """Every Luhn-valid run of 13-19 digits, whatever lies between them.

    NOTHING IS REFUSED, and the argument for refusing is written out here
    because it was persuasive and wrong twice.

    It said: a window overlapping a span already established as some other
    validated identifier cannot be a third identifier, because no character
    belongs to two identifiers at once - an IBAN's digits are the IBAN's, and a
    Luhn-valid window made of an IBAN's tail plus the digits after it is the
    same characters counted twice. True as far as it goes. What it licensed was
    an oracle that could not SEE a genuine card whose first group a coincidental
    IBAN claim happened to cover, and the gate then reported
    "Beleg BE84 6613 1860    4526    0181    5908    3012    Ende" as clean in
    all three egress modes with twelve of the card's sixteen digits standing in
    the overlay.

    Identity and coverage are different questions and only the second one is
    this file's business. Whether those characters are "one identifier or two"
    decides what LABEL a finding carries; whether they are still in the payload
    decides whether the product kept its promise. So the oracle claims every
    Luhn-valid window and asks only whether the overlay still contains it.

    The double-counting this used to prevent is handled where it belongs, by
    the detector covering the remainder of every window it does not label - and
    `RESIDUE_RUN` below is the shared floor that makes the two agree, since a
    fragment shorter than that is not reported by either.

    Punctuation of any width is skipped - two spaces, ten spaces, a dot and a
    space, a pipe with spaces either side. A letter ends the search, because a
    letter cannot appear inside a card number; that is the definition of the
    identifier, not a rule about how it is laid out.
    """
    found: "list[tuple[str, str, int, int]]" = []
    length = len(text)
    for start in range(length):
        if not (_ascii_of(text[start]) or "").isdigit():
            continue
        digits: list[str] = []
        for index in range(start, min(length, start + ORACLE_WINDOW)):
            char = text[index]
            digit = _ascii_of(char)
            if digit is not None and digit.isdigit():
                digits.append(digit)
                if len(digits) > 19:
                    break
                if len(digits) >= 13:
                    candidate = "".join(digits)
                    if _luhn_ok(candidate):
                        found.append(
                            (candidate, text[start:index + 1], start, index + 1)
                        )
            elif char.isalnum() and unicodedata.category(char) != "Lm":
                break
    return found


def _oracle_ibans(text: str) -> "list[tuple[str, str, int, int]]":
    """Every registered-length, mod-97-valid IBAN, whatever lies between."""
    found: "list[tuple[str, str, int, int]]" = []
    length = len(text)
    for start in range(length):
        if not (_ascii_of(text[start]) or "").isalpha():
            continue
        registered = None
        body: list[str] = []
        for index in range(start, min(length, start + ORACLE_WINDOW)):
            char = text[index]
            folded = _ascii_of(char)
            if folded is not None:
                body.append(folded)
                if len(body) == 2:
                    registered = _IBAN_LENGTHS.get("".join(body).upper())
                    if registered is None:
                        break
                if registered is not None and len(body) == registered:
                    candidate = "".join(body)
                    if _iban_ok(candidate):
                        found.append(
                            (candidate, text[start:index + 1], start, index + 1)
                        )
                    break
            elif char.isalnum() and unicodedata.category(char) != "Lm":
                break
    return found


_ORACLE_EMAIL_SHAPE = re.compile(
    r"\A[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\Z"
)


def _read(value: str) -> str:
    """*value* as an address or identifier reads: identifier characters by
    `_ascii_of`, and address punctuation - "＠", "．", "﹫" - by what NFKC
    says it is. Same length, so an offset in one is an offset in the other."""
    out = []
    for char in value:
        folded = _ascii_of(char)
        if folded is None and not char.isascii():
            compat = unicodedata.normalize("NFKC", char)
            if len(compat) == 1 and compat in "@._%+-":
                folded = compat
        out.append(folded or char)
    return "".join(out)


def _oracle_emails(text: str) -> "list[tuple[str, str, int, int]]":
    """Every RFC-shaped address, by trying every substring around each "@".

    No expansion over a character class - that would be a run rule. Every
    (start, end) pair within ORACLE_EMAIL_SPAN of the "@" is offered to the
    shape, and the longest that matches is taken.
    """
    found: "list[tuple[str, str, int, int]]" = []
    original, text = text, _read(text)
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
                    if best is None or len(candidate) > len(best[0]):
                        best = (candidate, begin, finish)
                    break
        if best:
            found.append((best[0], original[best[1]:best[2]], best[1], best[2]))
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
    # The offsets each finder returns are carried rather than looked up again.
    # They were rebuilt with `text.index(written)` - the FIRST occurrence - so a
    # document holding the same IBAN twice registered one span twice and the
    # other not at all. That fed the card pass's overlap rule, which has since
    # been removed altogether; the offsets stay carried because looking a
    # written form up by value is wrong however it is used.
    for canonical, as_written, _start, _end in _oracle_emails(text):
        found.append(("email", canonical, as_written))
    for canonical, as_written, _start, _end in _oracle_ibans(text):
        found.append(("iban", canonical, as_written))
    # Cards are told nothing about what the other layers claimed, on purpose:
    # see _oracle_cards. An overlapping window is still an identifier this file
    # must be able to see the remains of.
    for canonical, as_written, _start, _end in _oracle_cards(text):
        found.append(("credit_card", canonical, as_written))
    return [row for row in found if _oracle_terminators(row[2]) <= 1]


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
    return "".join(_ascii_of(char) or "" for char in value)


def _compact_segments(overlay: str) -> "list[str]":
    """The overlay compacted, but never ACROSS a placeholder.

    Compacting the whole overlay manufactures adjacency. A placeholder stands
    where text was taken out, so the characters either side of it were not
    neighbours in the document; deleting it makes them neighbours, and a
    fragment that never existed anywhere then "survives" in the overlay. The
    occurrence-counting guard below cannot catch it, because the fragment does
    not occur in the source either - `remaining >= source.count(fragment)`
    compares 1 against 0.

    That is one of the two mechanisms that made the release gate red on 3 of
    400 hypothesis seeds: a standalone digit next to a retained UUID, with a
    redaction between them.

    A placeholder is therefore a HARD break. Nothing else is: an identifier
    written across a line break or a column gap must still be counted as
    residue, and those characters are still in the document.
    """
    return [_compact(part) for part in _PLACEHOLDER.split(overlay)]


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
    segments = _compact_segments(overlay)
    source = _compact(text)
    for size in range(len(needle), RESIDUE_RUN - 1, -1):
        for start in range(0, len(needle) - size + 1):
            fragment = needle[start:start + size]
            remaining = sum(segment.count(fragment) for segment in segments)
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
    # Counted per placeholder-delimited segment, for the same reason
    # _compact_segments exists: a value cannot SURVIVE across a redaction.
    residual_segments = _PLACEHOLDER.split(overlay)

    def _residual_count(value: str) -> int:
        return sum(segment.count(value) for segment in residual_segments)

    # A claim is an OCCURRENCE, not a finding. Two phone patterns both matched
    # "001 4111 ..." and both were trimmed back to (0, 4) where the card
    # begins; the one "001 " was claimed twice, so "001" inside "A001" - never
    # detected - read as a survivor. Findings on the same verified occurrence
    # count once; a value that is not the source at its offsets (a layer-5
    # hint) still counts per finding, as before.
    counted: dict[str, int] = {}
    occurrences: set[tuple[str, int]] = set()
    for span in document.spans:
        raw = span.value or ""
        value = raw.strip()
        if not value:
            continue
        at = span.start + len(raw) - len(raw.lstrip())
        if text[at:at + len(value)] == value:
            if (value, at) in occurrences:
                continue
            occurrences.add((value, at))
        counted[value] = counted.get(value, 0) + 1
    for value, claimed in counted.items():
        allowed = max(0, text.count(value) - claimed)
        if _residual_count(value) > allowed:
            leaks.append(
                f"a detected span survived: overlay keeps "
                f"{_residual_count(value)} copies, at most {allowed} expected"
            )

    # Read as the finders read, so a full-width local part is still one.
    read_overlay = _read(overlay)
    for kind, canonical, as_written in validated_identifiers(text):
        if canonical in overlay or as_written in overlay:
            leaks.append(f"validated {kind} survived whole in overlay")
            continue
        if kind == "email":
            local = canonical.split("@", 1)[0]
            if len(local) >= 4 and local in read_overlay:
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
        if _oracle_terminators(as_written):
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


# The input generators come from tests/synth.py, which test_identifier_runs.py
# uses too. Sharing them is not a break with this file's independence: what
# must not be shared is how a candidate is FOUND and what decides that it is
# valid, and neither of those is in there. Two copies of a check-digit
# construction is the duplicated-registry mistake in miniature.
from synth import IBAN_COUNTRIES as _IBAN_COUNTRIES  # noqa: E402
from synth import make_card as _make_card  # noqa: E402
from synth import make_email as _make_email  # noqa: E402
from synth import make_iban as _make_iban  # noqa: E402


#: Characters the battery writes between groups. The underscore and colon
#: shapes were reported leaks, and a generator that only ever emits a space
#: cannot find them.
_BATTERY_SEPARATORS = [" ", " ", "_", "-", ".", ":", "/", ",", "|", "\u00a0", "\t"]

#: A line break INSIDE an identifier, which `pdftotext` produces whenever a
#: value wraps in a narrow column. This was never generated: the gap widths
#: below are horizontal only.
_BATTERY_INTERNAL_BREAKS = [
    "", "", "",
    "\n", "-\n", " \n", "\n ",
    # TERMINATORS, not just "\n". This axis had never been varied: every
    # internal break the generator emitted was a bare newline, so the bound
    # that counted characters instead of terminators - which refuses a single
    # CRLF - was unreachable however long the battery ran. CRLF is the MIME
    # and Windows line terminator.
    "\r\n", "\r\n", "-\r\n", "\r", "\n\r",
]

#: Terminators used BETWEEN fragments, so one document can mix them the way a
#: pasted-together e-mail thread does.
_BATTERY_TERMINATORS = ["\n", "\r\n", "\r", "\n", "\r\n"]

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
        out += rng.choice(_BATTERY_TERMINATORS + [" ", ", ", "", "\t"]) + line
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


if given is not None:  # pragma: no branch
    _SCRIPT_ZEROS = [0xFF10, 0x0660, 0x06F0, 0x0966, 0x0E50]
    _WIDE_JOINERS = ["\u3000", "\uff0d", "\u30fc", "\u30fb", "\u3001", " ", ""]

    def _in_script(value: str, zero: int, wide_letters: bool) -> str:
        out = []
        for char in value:
            if char.isdigit():
                out.append(chr(zero + int(char)))
            elif wide_letters and char.isascii() and char.isalpha():
                out.append(chr(ord(char) + 0xFEE0))
            else:
                out.append(char)
        return "".join(out)

    @settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(
        st.lists(_fragment, min_size=1, max_size=6),
        st.sampled_from(_WIDE_JOINERS),
        st.sampled_from(_SCRIPT_ZEROS),
        st.booleans(),
        st.sampled_from(EGRESS_MODES),
    )
    def test_release_gate_property_in_other_digits(fragments, joiner, zero, wide, mode):
        """The release gate's property, with the digits in another script and
        the joins in the ones a CJK or Arabic document uses."""
        text = joiner.join(_in_script(f, zero, wide) for f in fragments)
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
    bounded a run then was the span limit and the interior-group limit, and
    admitting the newline moved neither false-positive budget by a single span:
    eight cards and no IBANs on the realistic corpus, eight on the hostile one,
    zero on the forty-two German documents. Both limits are gone since; a
    candidate may now contain at most one line terminator.
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


def test_there_is_no_width_at_which_the_detector_stops_claiming():
    """The cliff is GONE, and this is what replaced the test that pinned it.

    There used to be a width - eighty spaces between groups - past which a
    card or an IBAN was no longer claimed. The test above this one asserted
    where it was, which made it deliberate but did not make it safe: the
    brute-force oracle has no width rule, so at eighty-one spaces it claimed
    the identifier, the detector did not, and the gate reported "a validated
    IBAN survived whole in the overlay". That is the gate going red for a
    reason nobody decided, and it is the same mechanism the verifier found at
    an interior group of seventeen.

    Sweeping the multiplier from 4 to 1000 never moved the false-positive
    count, so the bound bought no precision at any setting. It is removed. The
    only bound left is the terminator count, which is definitional and which
    the oracle shares and names.
    """
    from privacy_shield import identifiers

    for gap in (0, 1, 4, 17, 80, 81, 200, 400):
        spaced = (" " * gap).join(EXAMPLE_CARD[i:i + 4] for i in range(0, 16, 4))
        assert identifiers.find_cards(spaced), f"card lost at a gap of {gap}"
        spaced_iban = (" " * gap).join(
            EXAMPLE_IBAN[i:i + 4] for i in range(0, len(EXAMPLE_IBAN), 4)
        )
        assert identifiers.find_ibans(spaced_iban), f"IBAN lost at a gap of {gap}"
        assert_no_leak("Konto " + spaced_iban)


def test_a_long_neighbouring_token_does_not_make_the_detector_decline():
    """The interior-group bound, and the red gate it caused.

    "§ 203 StGB1_66eAD8A77dAA77dA1_66eAD8§ 203 StGB" compacts to a mod-97-valid
    registered-length IBAN whose middle group is seventeen characters. The
    oracle claimed it; the detector refused it at a bound of twelve; the gate
    reported a leak. Reproduced at 3 reds in 400 hypothesis seeds at the
    shipped example count, and 4 in 25 at 4000.

    The candidate is not a plausible IBAN, and that is exactly why it could not
    stay: refusing it here without the oracle being able to agree makes the
    release gate a coin toss. Claiming it costs one over-redaction on a text
    nobody sends.
    """
    from privacy_shield import identifiers

    text = "§ 203 StGB1_66eAD8A77dAA77dA1_66eAD8§ 203 StGB"
    assert any(kind == "iban" for kind, _c, _w in validated_identifiers(text)), (
        "the oracle no longer claims this; the case has drifted"
    )
    assert identifiers.find_ibans(text), "the detector declined what the oracle claims"
    assert_no_leak(text)


# ---------------------------------------------------------------------------
# What the oracle shares with the detector, pinned
# ---------------------------------------------------------------------------

def test_the_detector_declines_on_nothing_the_oracle_cannot_also_see():
    """What replaced "the oracle outranges the detector".

    That relation was `ORACLE_WINDOW > MAX_IBAN_LENGTH * MAX_SPAN_MULTIPLE`,
    and it held only because the detector had a width limit. It no longer has
    one, so the oracle can no longer outrange it and pretending otherwise would
    be the same decorative claim as deriving the terminator set from Unicode.

    The property that actually protects the gate is the one asserted here: the
    detector's ONLY reason to decline a checksum-valid candidate is the
    terminator bound, which the oracle applies too. Anything wider, more
    punctuated or more oddly grouped is claimed by both.

    What the window costs is stated rather than hidden: past ORACLE_WINDOW
    characters the oracle stops looking. That is a blind spot in the CHECK, not
    a hole in the product - the detector has no width limit, so it still claims
    what the oracle can no longer see, and this direction of disagreement
    cannot produce a false green.
    """
    from privacy_shield import identifiers

    rng = random.Random(1904)
    for _ in range(40):
        iban = _make_iban(rng, rng.choice(list(_IBAN_COUNTRIES)))
        gap = " " * rng.randint(0, 40)
        chunk = rng.randint(2, 6)
        written = gap.join(iban[i:i + chunk] for i in range(0, len(iban), chunk))
        text = rng.choice(["Konto ", "acct_", "Ref", ""]) + written
        assert len(text) <= ORACLE_WINDOW, "this case would not be comparable"
        oracle = {kind for kind, _c, _w in validated_identifiers(text)}
        detector = bool(identifiers.find_ibans(text))
        assert ("iban" in oracle) == detector, (
            f"oracle {oracle} vs detector {detector} on a {len(text)}-character "
            "layout: one of them has a rule the other does not"
        )


def test_the_oracle_sees_a_widely_spaced_iban_at_the_detectors_limit():
    """The case the old 136-character window could not see."""
    spaced = (" " * 16).join(
        EXAMPLE_IBAN[index:index + 4] for index in range(0, len(EXAMPLE_IBAN), 4)
    )
    assert any(kind == "iban" for kind, _c, _w in validated_identifiers(spaced))
    assert_no_leak("Konto " + spaced)


def _in_digits(value: str, zero: int) -> str:
    return "".join(chr(zero + int(c)) if c.isdigit() else c for c in value)


def _full_width(value: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if c.isalnum() else c for c in value)


NON_ASCII_DIGITS = [
    pytest.param(0xFF10, id="fullwidth"),
    pytest.param(0x0660, id="arabic_indic"),
    pytest.param(0x06F0, id="extended_arabic_indic"),
    pytest.param(0x0966, id="devanagari"),
]


@pytest.mark.parametrize("zero", NON_ASCII_DIGITS)
@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_a_card_in_non_ascii_digits_is_a_card(zero, mode):
    """ASCII was the finding rule, and "Karte ４１１１ １１１１ １１１１ １１１１"
    went out as "Karte [PHONE] １１１１" - a phone pattern claimed part of it by
    accident and twelve digits stayed, with egress allowed."""
    card = _in_digits(EXAMPLE_CARD_SPACED, zero)
    text = f"Karte {card} bitte"
    assert_no_leak(text, mode=mode)
    document = scan(text, mode=mode, force_text=True).documents[0]
    assert [s.pii_type for s in document.spans] == ["credit_card"], document.overlay
    left = _PLACEHOLDER.sub("", document.overlay)
    assert not any(unicodedata.decimal(c, None) is not None for c in left), left


@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_a_full_width_iban_is_an_iban(mode):
    text = f"IBAN {_full_width(EXAMPLE_IBAN_SPACED)} bitte"
    assert_no_leak(text, mode=mode)
    document = scan(text, mode=mode, force_text=True).documents[0]
    assert [s.pii_type for s in document.spans] == ["iban"], document.overlay


@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_a_card_of_mixed_widths_is_one_card(mode):
    groups = EXAMPLE_CARD_SPACED.split(" ")
    mixed = " ".join(g if i % 2 else _full_width(g) for i, g in enumerate(groups))
    text = f"Karte {mixed}"
    assert_no_leak(text, mode=mode)
    document = scan(text, mode=mode, force_text=True).documents[0]
    assert [s.pii_type for s in document.spans] == ["credit_card"], document.overlay


def test_the_gate_sees_full_width_residue():
    from types import SimpleNamespace

    card = _full_width(EXAMPLE_CARD_SPACED)
    text = f"Karte {card}"
    assert any(kind == "credit_card" for kind, _c, _w in validated_identifiers(text))
    kept = SimpleNamespace(
        egress_allowed=True, overlay="Karte [PHONE]" + card[4:], spans=[]
    )
    assert leaks_in(text, kept)


def test_the_gate_sees_full_width_iban_residue():
    from types import SimpleNamespace

    iban = _full_width(EXAMPLE_IBAN_SPACED)
    text = f"IBAN {iban}"
    assert any(kind == "iban" for kind, _c, _w in validated_identifiers(text))
    kept = SimpleNamespace(
        egress_allowed=True, overlay="IBAN [IBAN]" + iban[9:], spans=[]
    )
    assert leaks_in(text, kept)


@pytest.mark.parametrize(
    "between",
    [
        pytest.param("\u24d0", id="circled_letter"),
        pytest.param("\U0001f130", id="squared_letter"),
        pytest.param("\u30fc", id="prolonged_sound_mark"),
        pytest.param("\u02b0", id="modifier_letter"),
    ],
)
@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_a_symbol_between_groups_joins_them(between, mode):
    """Folding by NFKC alone read a circled "a" as the letter a and ended the
    run mid-card: "4111 1111\u24d01111 1111" went out whole where it had been
    caught. And the katakana prolonged-sound mark is how a Japanese writer
    types the dash in a number."""
    for identifier in (EXAMPLE_CARD_SPACED, EXAMPLE_IBAN_SPACED):
        groups = identifier.split(" ")
        text = "Konto " + between.join(groups) + " danke"
        assert_no_leak(text, mode=mode)
        document = scan(text, mode=mode, force_text=True).documents[0]
        assert _PLACEHOLDER.sub("", document.overlay) == "Konto  danke", (
            document.overlay
        )


#: Letters in the account part, so the card oracle cannot see its digits and
#: only the IBAN side of the gate stands between a detector drift and a leak.
LETTERED_IBAN_GROUPS = ["NL91", "ABNA", "0417", "1643", "00"]


@pytest.mark.parametrize(
    "between, drift",
    [
        pytest.param("\u30fc", "joiner", id="prolonged_sound_mark"),
        pytest.param("\u02b0", "joiner", id="modifier_letter"),
        pytest.param("\u24b6", "fold", id="circled_capital"),
    ],
)
def test_the_gate_sees_a_lettered_iban_the_detector_drops(between, drift, monkeypatch):
    """The gate must hold its own rule on the IBAN side too: weaken the
    detector's joiner or its fold, and the gate reports the IBAN it dropped."""
    from privacy_shield import identifiers

    if drift == "joiner":
        monkeypatch.setattr(identifiers, "_is_joiner", lambda char: not char.isalnum())
    else:
        real = identifiers._identifier_char

        def fold_symbols_too(char):
            folded = unicodedata.normalize("NFKC", char)
            if not char.isascii() and len(folded) == 1 and folded.isascii() and folded.isalpha():
                return folded
            return real(char)

        monkeypatch.setattr(identifiers, "_identifier_char", fold_symbols_too)
    text = "IBAN " + between.join(LETTERED_IBAN_GROUPS) + " danke"
    assert any(kind == "iban" for kind, _c, _w in validated_identifiers(text))
    document = scan(text, force_text=True).documents[0]
    assert leaks_in(text, document), document.overlay


def test_the_gate_sees_a_prolonged_sound_mark_card_the_detector_drops(monkeypatch):
    """The gate must not inherit the detector's joiner rule: if the detector
    stops joining across \u30fc, the gate says so."""
    from privacy_shield import identifiers

    monkeypatch.setattr(identifiers, "_is_joiner", lambda char: not char.isalnum())
    text = "Karte " + "\u30fc".join(_in_digits(EXAMPLE_CARD_SPACED, 0xFF10).split(" "))
    document = scan(text, force_text=True).documents[0]
    assert leaks_in(text, document), document.overlay


@pytest.mark.parametrize(
    "digits",
    [
        pytest.param("\u2463\u2460\u2460\u2460" * 4, id="circled"),
        pytest.param("\u2074\u00b9\u00b9\u00b9" * 4, id="superscript"),
        pytest.param("\u56db\u4e00\u4e00\u4e00" * 4, id="hanzi"),
    ],
)
def test_a_digit_is_a_decimal_digit_on_both_sides(digits):
    """Circled and superscript numerals fold to digits under NFKC but are not
    decimal digits; neither the detector nor the gate treats them as one, so
    the two cannot disagree about them."""
    from privacy_shield import identifiers

    assert identifiers.luhn_ok(EXAMPLE_CARD)
    assert not identifiers.find_cards(digits)
    assert not validated_identifiers(digits)


def test_a_cyrillic_country_code_is_a_documented_limit():
    """docs/limits.md: IBAN country codes are ASCII. "ДЕ" is two Cyrillic
    letters that look like "DE"; if it starts being found, the limit comes
    out."""
    text = "IBAN \u0414\u0415" + EXAMPLE_IBAN[2:]
    assert not any(kind == "iban" for kind, _c, _w in validated_identifiers(text))


FULL_WIDTH_ADDRESSES = [
    pytest.param("erika\uff20example.com", id="full_width_at"),
    pytest.param("\uff45\uff52\uff49\uff4b\uff41\uff20\uff45\uff58\uff41\uff4d"
                 "\uff50\uff4c\uff45\uff0e\uff43\uff4f\uff4d", id="full_width_address"),
    pytest.param("erika@\uff45\uff58\uff41\uff4d\uff50\uff4c\uff45.com", id="full_width_domain"),
    pytest.param("erika@example\uff0ecom", id="full_width_dot"),
    pytest.param("erika\ufe6bexample.com", id="small_commercial_at"),
    pytest.param("m\u00fcller\uff20kanzlei.de", id="umlaut_local_part"),
]


@pytest.mark.parametrize("address", FULL_WIDTH_ADDRESSES)
@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_an_address_written_in_full_width_is_an_address(address, mode):
    """"erika＠example.com" went out whole with pii_detected False: the finder
    only expanded around an ASCII "@"."""
    text = f"Mail {address} bitte"
    assert_no_leak(text, mode=mode)
    document = scan(text, mode=mode, force_text=True).documents[0]
    assert [s.pii_type for s in document.spans] == ["email"], document.overlay
    assert _PLACEHOLDER.sub("", document.overlay) == "Mail  bitte", document.overlay


@pytest.mark.parametrize("address", FULL_WIDTH_ADDRESSES)
def test_the_gate_sees_a_full_width_address(address):
    from types import SimpleNamespace

    text = f"Mail {address} bitte"
    assert any(kind == "email" for kind, _c, _w in validated_identifiers(text))
    untouched = SimpleNamespace(egress_allowed=True, overlay=text, spans=[])
    assert leaks_in(text, untouched)


def test_the_gate_sees_a_full_width_local_part_left_behind():
    from types import SimpleNamespace

    local = "\uff45\uff52\uff49\uff4b\uff41"
    text = f"Mail {local}\uff20example.com"
    kept = SimpleNamespace(egress_allowed=True, overlay=f"Mail {local}[EMAIL]", spans=[])
    assert leaks_in(text, kept)


def test_the_gate_sees_an_identifier_that_changed_width_on_the_way_out():
    """A copy is a copy in any width: an overlay that carries the ASCII form
    of a full-width source - anything that normalises text on the way out
    produces one - still leaks the identifier."""
    from types import SimpleNamespace

    for source, egressed in (
        ("\uff45\uff52\uff49\uff4b\uff41\uff20example.com", "erika@example.com"),
        (_full_width(EXAMPLE_CARD_SPACED), EXAMPLE_CARD_SPACED),
    ):
        kept = SimpleNamespace(
            egress_allowed=True, overlay=f"Daten {egressed}", spans=[]
        )
        assert leaks_in(f"Daten {source}", kept), source


@pytest.mark.parametrize("text", ["Preis 5\uff203.50 EUR", "Mail a\uff20b bitte"])
def test_a_full_width_at_is_not_an_address_by_itself(text):
    document = scan(text, force_text=True).documents[0]
    assert document.overlay == text


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
    """Pinned, with the cost re-measured after round 18.

    The bound is one terminator. Two or more is refused, which is what stops a
    column of stacked numbers being assembled into one identifier; an
    identifier wrapped more than once - needing a column narrower than about
    eight characters - is therefore not found.

    ASSEMBLY ACROSS ONE TERMINATOR IS ACCEPTED, and that is not a choice so
    much as an admission: "4111111111\\n111111" is a card wrapped once and
    "5100004821\\n5100004822" is two document numbers, and nothing in the text
    separates them. Bounding every group rather than only the interior ones was
    tried and refused nothing the baseline accepted, so it was reverted rather
    than kept as decoration. The cost is measured in
    tests/test_identifier_runs.py::test_stacked_numeric_columns_are_over_redacted
    at eleven spans over five documents built for it, and the main corpora do
    not move.

    This test previously asserted that three stacked article numbers were NOT
    claimed. They were not - but only because the merge produced one
    over-terminator interval and then discarded the whole thing, which also
    discarded the valid window that started it. That is what let a real card
    out (see test_a_card_on_its_own_line_is_not_lost_to_a_merge below), so the
    discarding is gone and the over-redaction is the honest consequence.
    """
    from privacy_shield import identifiers

    once = EXAMPLE_CARD[:10] + "\n" + EXAMPLE_CARD[10:]
    twice = EXAMPLE_CARD[:6] + "\n" + EXAMPLE_CARD[6:11] + "\n" + EXAMPLE_CARD[11:]

    assert identifiers.find_cards(once), "one terminator must be claimed"
    assert not identifiers.find_cards(twice), (
        "two terminators are now claimed; re-measure the stacked-column corpus "
        "in tests/test_identifier_runs.py before keeping this"
    )


def test_a_card_on_its_own_line_is_not_lost_to_a_merge():
    """The defect the over-redaction above buys off.

    Card windows are merged so that no validating window is left partly
    uncovered. The merge used to extend an interval without re-checking the
    terminator bound on the UNION, and a post-hoc filter then dropped the whole
    interval for exceeding it - throwing away the valid window that started it.
    A card padded with underscores on a line of its own went out unredacted
    while the same card in isolation was claimed. The bound is enforced when
    intervals are extended instead, and nothing is discarded after the fact.
    """
    text = (
        "Erika Mustermann, Tel. +49 170 2920143\r"
        "Gesch=E4ftskonto=2040______81______21______75______52______68"
        "______18______62/\n74697 \n.   3080.   8547.   1628-"
    )
    document = scan(text, force_text=True).documents[0]
    assert not leaks_in(text, document), document.overlay
    assert document.pii_detected



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


# ---------------------------------------------------------------------------
# The eighth class: a line terminator written with two characters
# ---------------------------------------------------------------------------


def _every_terminator():
    """Every way a line can end, according to something that is not this repo.

    The previous version of this claimed to DERIVE the set "rather than type
    it" and then derived Unicode categories Zl and Zp - which are U+2028 and
    U+2029, the two characters the list beside it already typed. Deriving the
    members of a list from the list is decoration, and decoration in a gate is
    worse than an honest constant because it stops people looking.

    So the authority here is CPython's own notion of a line boundary,
    `str.splitlines`, which is an independent implementation of the Unicode
    rule and knows about three separators this package does not.
    """
    singles = [
        chr(code)
        for code in range(0x3000)
        if len(("a" + chr(code) + "b").splitlines()) > 1
    ]
    return singles + ["\r\n", "\n\r"]


TERMINATORS = _every_terminator()

#: The three CPython calls line boundaries and this package does not: FILE,
#: GROUP and RECORD SEPARATOR. Named rather than silently missing.
#:
#: Both layers treat them as ordinary joiners, so an identifier written across
#: one is CLAIMED rather than refused - the fail-closed direction, and the
#: reason this difference is a disclosure and not a defect. The direction that
#: would matter is the other one: if the ORACLE counted a terminator the
#: detector did not, the oracle's one-break rule would drop candidates and hide
#: whatever was leaking behind them.
JOINED_NOT_TERMINATED = ["\x1c", "\x1d", "\x1e"]


def test_the_terminator_set_is_no_shorter_than_cpythons():
    """Guards the enumeration, so nothing built on it can be vacuous."""
    assert "\r\n" in TERMINATORS and "\n\r" in TERMINATORS
    assert "\n" in TERMINATORS and "\r" in TERMINATORS
    assert "\u2028" in TERMINATORS and "\u2029" in TERMINATORS
    assert len(TERMINATORS) >= 12, TERMINATORS

    from privacy_shield.identifiers import count_terminators

    missing = [
        char for char in TERMINATORS
        if len(char) == 1 and not count_terminators(char)
    ]
    assert missing == JOINED_NOT_TERMINATED, (
        "the set of line boundaries this package does not count has changed: "
        f"{[hex(ord(c)) for c in missing]}"
    )


@pytest.mark.parametrize("separator", JOINED_NOT_TERMINATED, ids=lambda s: hex(ord(s)))
def test_a_separator_cpython_calls_a_line_break_is_claimed_not_refused(separator):
    """The safe direction, asserted rather than assumed."""
    text = "Karte " + EXAMPLE_CARD[:8] + separator + EXAMPLE_CARD[8:]
    assert_no_leak(text)


@pytest.mark.parametrize("terminator", TERMINATORS, ids=lambda s: repr(s))
@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_a_wrapped_identifier_is_found_whatever_ends_the_line(terminator, mode):
    """A line terminator is ONE break however many characters it is written
    with.

    The bound counted characters, so a single CRLF scored two and the wrapped
    identifier was refused: found under a bare LF and under a bare CR, not
    found under CRLF. CRLF is the line terminator of MIME e-mail bodies by
    specification and of Windows text generally, and
    `is_safe_for_external_llm` on an e-mail body is a documented use of this
    package.
    """
    # The reported grouping: four-digit groups either side of the wrap. A
    # different grouping is no good here - with eight digits before the wrap
    # the phone pattern claims part of it and the card is only partly
    # exposed, so the test would pass for the wrong reason.
    text = (
        "Kreditkartennummer " + EXAMPLE_CARD[:4] + " " + EXAMPLE_CARD[4:8]
        + terminator + EXAMPLE_CARD[8:12] + " " + EXAMPLE_CARD[12:]
        + terminator + "Betrag 1.240,00 EUR"
    )
    assert_no_leak(text, mode=mode)
    document = scan(text, mode=mode, force_text=True).documents[0]
    if document.egress_allowed:
        assert document.pii_detected, document.overlay


@pytest.mark.parametrize("terminator", ["\r\n", "\n\r"], ids=["crlf", "lfcr"])
def test_is_safe_for_external_llm_agrees_across_terminators(terminator):
    """The reported asymmetry, on the documented entry point."""
    from privacy_shield.scanner import is_safe_for_external_llm

    body = "Kreditkartennummer 4111 1111{0}1111 1111{0}Betrag 1.240,00 EUR{0}"
    safe_lf = is_safe_for_external_llm(body.format("\n"))[0]
    safe_other = is_safe_for_external_llm(body.format(terminator))[0]
    assert safe_lf is False, "the single-character baseline stopped detecting"
    assert safe_other is False, (
        "a two-character terminator is certified safe while a one-character "
        "terminator is not"
    )


def test_a_mixture_of_terminators_in_one_document():
    """A pasted-together thread does not use one terminator throughout."""
    text = (
        "Von: Buchhaltung\r\n"
        "Kreditkartennummer4111 1111\n1111 1111\r\n"
        "Betrag 1.240,00 EUR\r"
    )
    assert_no_leak(text)
    assert scan(text, force_text=True).documents[0].pii_detected


# ---------------------------------------------------------------------------
# No character belongs to two identifiers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            "UUID 550e8400-e29b-41d4-a716-446655440000 "
            + EXAMPLE_IBAN + " 00 00 7",
            id="uuid_then_iban_then_trailing_digits",
        ),
        pytest.param(
            EXAMPLE_IBAN + " 00 00 7",
            id="iban_then_trailing_digits",
        ),
        pytest.param(
            "Konto " + EXAMPLE_IBAN + " Ref 0000000",
            id="iban_then_reference_digits",
        ),
    ],
)
@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_a_card_is_not_LABELLED_out_of_another_identifiers_digits(text, mode):
    """The residue class that made the gate INTERMITTENT, restated.

    A Luhn-valid window built from an IBAN's tail plus the digits after it is
    not a third identifier; it is the same characters counted twice. This test
    used to assert that the ORACLE does not report such a window, and that was
    the wrong half of the sentence: identity decides a label, coverage decides
    whether the product kept its promise, and an oracle that refuses to look at
    a window cannot tell anybody what remains of it. That refusal hid a genuine
    grouped card whose first four digits a coincidental IBAN claim happened to
    cover - twelve of sixteen digits in a payload the gate called clean.

    So the oracle sees these windows now, and what is asserted here is what
    actually has to hold:

      * the gate is clean in all three egress modes, because every piece of
        the window nobody owns is shorter than MATERIAL_RESIDUE and therefore
        below the floor this file itself calls immaterial;
      * no finding is LABELLED a card out of the IBAN's own characters;
      * and the neighbours keep their digits - the trailing "00 00 7" is not
        redacted, which is the over-redaction this arrangement avoids.

    A UUID beside an account number beside trailing digits is an ordinary
    machine-generated line, not a 130-character concatenation, so this is not
    the artefact it was accepted as two rounds ago.
    """
    assert_no_leak(text, mode=mode)

    from privacy_shield import identifiers

    ibans = identifiers.find_ibans(text)
    assert ibans, "this case is about a window overlapping an IBAN claim"
    owned = set()
    for start, end, _value in ibans:
        owned.update(range(start, end))
    for start, end, _value in identifiers.find_cards(
        text, avoid=[(s, e) for s, e, _v in ibans]
    ):
        assert not (set(range(start, end)) & owned), (
            f"a card span at [{start},{end}) is made of the IBAN's own characters"
        )


@pytest.mark.parametrize(
    "text",
    [
        "Konto " + EXAMPLE_IBAN + " Karte " + EXAMPLE_CARD,
        "Karte " + EXAMPLE_CARD + " Konto " + EXAMPLE_IBAN,
        EXAMPLE_IBAN + "Karte" + EXAMPLE_CARD,
    ],
)
def test_the_rule_does_not_blind_the_gate_to_a_real_card(text):
    """The bound must refuse re-used characters, not adjacent identifiers.

    A card standing next to an IBAN - with or without anything between them -
    is two identifiers, and the oracle must still see both or the fix above
    would have bought determinism with blindness.
    """
    kinds = {kind for kind, _c, _w in validated_identifiers(text)}
    assert kinds == {"iban", "credit_card"}, kinds
    assert_no_leak(text)


def test_two_hundred_further_generated_documents_do_not_leak():
    """The battery's generator, run past the pinned seed.

    This used to be called "the leak gate is deterministic across seeds", and
    it is not that test: the seed it varies is the BATTERY's, and the battery
    is deterministic by construction. The randomness that made `leak-gate`
    intermittently red lives in the hypothesis property, and nothing here
    touched it. Named for what it does - 200 more documents, one more draw.

    The test that does what the old name claimed is
    test_the_property_holds_under_a_varied_hypothesis_seed, below.
    """
    rng = random.Random(18)
    for _ in range(200):
        text, planted, _shapes = generate_document(rng)
        document = scan(text, force_text=True).documents[0]
        assert not leaks_in(text, document), text[:80]
        if document.egress_allowed:
            residual = _without_placeholders(document.overlay)
            for value, written in planted:
                assert written not in residual
                assert value not in _compact(residual)


# ---------------------------------------------------------------------------
# Determinism of the PROPERTY, which is where the randomness actually is
# ---------------------------------------------------------------------------
#
# "Ten fresh-database runs pass" is not determinism. Hypothesis draws from a
# fresh random seed each run, so ten runs sample ten points out of a space
# where the failure rate was 0.75% per run at the shipped example count and
# 4 in 25 at 4000. A test that fixes the seed explicitly, over a spread of
# seeds, is the only way to make an intermittent red reproducible - and the
# only way to notice when it comes back.
#
# The seeds are written down. If one of them ever fails, it fails for
# everybody, on every machine, until it is fixed.

_SEEDS = [1, 2, 3, 5, 8, 13, 21, 34]


@pytest.mark.skipif(given is None, reason="hypothesis is not installed")
@pytest.mark.parametrize("hypothesis_seed", _SEEDS)
def test_the_property_holds_under_a_varied_hypothesis_seed(hypothesis_seed):
    from hypothesis import HealthCheck, given as _given, seed as _seed, settings as _settings

    @_seed(hypothesis_seed)
    @_settings(
        max_examples=250,
        deadline=None,
        database=None,
        derandomize=False,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    @_given(
        st.lists(_fragment, min_size=1, max_size=8),
        st.sampled_from([" ", "\n", ", ", ""]),
        st.sampled_from(EGRESS_MODES),
    )
    def run(fragments, joiner, mode):
        text = joiner.join(fragments)
        if not text.strip():
            return
        document = scan(text, mode=mode, force_text=True).documents[0]
        leaks = leaks_in(text, document)
        assert not leaks, (
            f"hypothesis seed {hypothesis_seed}\nmode={mode.value}\n"
            f"input={text!r}\noverlay={document.overlay!r}\n" + "; ".join(leaks)
        )

    run()


# ---------------------------------------------------------------------------
# The oracle's own two fail-opens
# ---------------------------------------------------------------------------

def test_a_placeholder_is_a_hard_break_when_counting_residue():
    """`_compact` deleted the space a redaction left behind.

    `_without_placeholders` writes a space where a placeholder was and
    `_compact` then removed it, so the characters either side became adjacent -
    though a redaction is precisely what had separated them. A fragment made
    across that join never existed in the source, so the occurrence guard
    (`remaining >= source.count(fragment)`) compared 1 against 0 and reported a
    leak for a value that had been removed.

    One of the two mechanisms behind 3 red runs in 400 hypothesis seeds.
    """
    text = "1111 2222 3333"
    assert _residue_run("11113333", "1111 [PHONE] 3333", text) == "", (
        "a fragment spanning a placeholder was counted as residue"
    )
    # The other direction must not have been softened: real residue is real.
    assert _residue_run("11113333", "Konto 1111 3333 offen", "1111 3333") == "11113333"


def test_the_oracle_sees_both_copies_of_a_repeated_identifier():
    """Offsets are carried, not looked up by value.

    They were rebuilt with `text.index(written)` - the FIRST occurrence - so a
    document holding the same IBAN twice registered one span twice and the
    other not at all. The card pass consumed those spans, and it no longer
    does; what stays true, and is the part that was ever worth asserting, is
    that both copies are SEEN. An oracle that can only find the first
    occurrence of a value is an oracle that cannot report the second one
    leaking.
    """
    text = f"Konto {EXAMPLE_IBAN} und nochmal {EXAMPLE_IBAN} Ende"
    kinds = [kind for kind, _canonical, _written in validated_identifiers(text)]
    assert kinds.count("iban") == 2, kinds
    assert_no_leak(text)


# ---------------------------------------------------------------------------
# The one constant the detector and this file DO share, and why
# ---------------------------------------------------------------------------

def test_the_detector_covers_down_to_this_files_own_materiality_floor():
    """`identifiers.MATERIAL_RESIDUE` is this file's `RESIDUE_RUN`.

    Sharing it is what makes the two agree by construction rather than by
    measurement. The detector covers every unowned piece of a validating window
    that is at least this long, so every piece it leaves is shorter than the
    shortest fragment reported here - and no decision taken in the detector can
    make this gate red.

    It is not the kind of sharing the layout bounds were removed for. Those
    were heuristics about the page, and teaching the oracle one blinds it to
    whatever the detector refuses. This is a materiality POLICY that this file
    owns and the detector obeys. If the detector's floor ever rises above this
    one it goes back to leaking reportable residue, and this fails.
    """
    from privacy_shield import identifiers

    assert identifiers.MATERIAL_RESIDUE == RESIDUE_RUN, (
        f"the detector covers down to {identifiers.MATERIAL_RESIDUE} characters "
        f"and this gate reports from {RESIDUE_RUN}; the gap between them is "
        "residue nobody claims and nobody reports"
    )


@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_a_grouped_card_under_a_coincidental_iban_claim(mode):
    """The reported blocker, verbatim.

        'Beleg BE84 6613 1860    4526    0181    5908    3012    Ende'
          -> 'Beleg [IBAN]    0181    5908    3012    Ende'

    Twelve of sixteen digits of a Luhn-valid card in a payload the gate called
    clean in all three egress modes, and `is_safe_for_external_llm` reported
    "No PII detected" for it. The first eight characters of the reference
    compact to a mod-97-valid Belgian length that reaches into the card's first
    group, and round 19's contiguity precondition then refused the remainder of
    every window covering the rest of it.

    Both halves were blind at once: the detector refused to claim, and the
    oracle refused to look, so nothing could report it.
    """
    assert_no_leak(
        "Beleg BE84 6613 1860    4526    0181    5908    3012    Ende", mode=mode
    )


# ---------------------------------------------------------------------------
# One occurrence claimed by two findings
# ---------------------------------------------------------------------------

DOUBLE_CLAIM_INPUT = "001 4111 1111 1111 1111 A001"


@pytest.mark.parametrize("mode", EGRESS_MODES, ids=lambda m: m.value)
def test_one_occurrence_trimmed_twice_is_one_finding(mode):
    """Found by test_release_gate_property; the redaction was right all along.

    Both phone patterns match from offset 0 into the card and both are trimmed
    back to (0, 4). That used to arrive as two findings, and the oracle,
    counting per finding, claimed both of the input's "001"s and read the
    undetected one in "A001" as a survivor.
    """
    document = scan(DOUBLE_CLAIM_INPUT, mode=mode, force_text=True).documents[0]
    phones = [(s.start, s.end) for s in document.spans if s.pii_type == "phone"]
    assert phones == [(0, 4)], phones
    assert not document.overlay.startswith("001"), document.overlay
    assert not leaks_in(DOUBLE_CLAIM_INPUT, document), document.overlay


def _with_phone_twice(document, overlay):
    from types import SimpleNamespace

    phone = next(s for s in document.spans if s.pii_type == "phone")
    return SimpleNamespace(
        egress_allowed=True, overlay=overlay, spans=[phone, *document.spans]
    )


def test_one_occurrence_claimed_twice_is_one_claim():
    document = scan(DOUBLE_CLAIM_INPUT, force_text=True).documents[0]
    twice = _with_phone_twice(document, document.overlay)
    assert not leaks_in(DOUBLE_CLAIM_INPUT, twice), document.overlay


def test_a_twice_claimed_occurrence_that_survives_is_still_a_leak():
    document = scan(DOUBLE_CLAIM_INPUT, force_text=True).documents[0]
    twice = _with_phone_twice(document, "001 [CREDIT_CARD] A001")
    assert leaks_in(DOUBLE_CLAIM_INPUT, twice)


def test_the_same_value_detected_twice_is_two_claims():
    from types import SimpleNamespace

    text = "Tel 0170 1234567 und 0170 1234567"
    document = scan(text, force_text=True).documents[0]
    assert len({s.start for s in document.spans if s.pii_type == "phone"}) == 2
    kept = SimpleNamespace(
        egress_allowed=True,
        overlay="Tel [PHONE] und 0170 1234567",
        spans=document.spans,
    )
    assert leaks_in(text, kept)


def test_a_hint_that_is_not_the_source_counts_per_finding():
    from types import SimpleNamespace

    text = "Max und Max"
    hint = SimpleNamespace(start=5, end=15, value="Max")
    kept = SimpleNamespace(
        egress_allowed=True,
        overlay="Max und [NAME]",
        spans=[hint, hint],
    )
    assert leaks_in(text, kept)
