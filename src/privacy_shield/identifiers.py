"""Run-based extraction of checksum-validated identifiers.

A regex that starts with ``\\b`` does not find an identifier; it finds a place
where an identifier is allowed to start. Those are not the same thing. A word
boundary sits between a word character and a non-word character, so one word
character glued in front of an IBAN or a card number means no boundary exists
at its first character - and since the rest of the identifier is word
characters too, no boundary exists anywhere inside it either. The pattern never
matches, the validator is never offered the candidate, and the caller is told
no personal data was found while a mod-97-valid account number goes out
verbatim in the payload.

The shapes this happens in are ordinary: an ``acct_`` prefix, a document number
run together with the number, ``id-`` plus hex, and the ``=20`` quoted-printable
writes for a space in any MIME body with a German umlaut in it.

So for the types that have a validator, detection here does not trust a
boundary to find the start. It walks every maximal run of identifier characters
and offers the validator every candidate substring. The span it claims covers
the identifier and nothing else, so a prefixed account reference keeps its
prefix and loses the number.

Precision, measured on a corpus of realistic German business documents that
contain no payment identifiers at all, so every hit is a false positive:

  * IBAN - constrained to the ISO 13616 registered length for the country
    code. This is the specification, not a heuristic: a 23-character string
    beginning "NG20" is not an IBAN because Nigeria has no IBAN, however the
    checksum comes out. Unconstrained, mod-97 fired on ordinary German prose
    ("Wareneingang 20260512 Beleg ...") once in 20 documents and swallowed the
    line. Constrained: no false positives.

  * CREDIT CARD - Luhn over every 13-19 digit window, at every offset, with no
    issuer-prefix table. A Luhn-valid 16-digit window inside a longer digit run
    is therefore redacted: measured at 6 documents in 20, on tracking numbers,
    IMEIs and long internal references. That over-redaction is accepted
    deliberately. An issuer table would cut it to 1 in 20, but issuer ranges go
    stale, and a card whose range the table had not caught up with would be
    invisible to the detector and to the gate at once - which is exactly the
    class of failure this module exists to end. One extra correctly-typed
    placeholder on a reference number is a cost the overlay survives; a card
    number in the payload is not.
"""

from __future__ import annotations

import bisect
import re
import unicodedata
from typing import Dict, Iterator, List, Optional, Tuple

# ISO 13616 registered IBAN length by country code.
#
# A TRANSCRIPTION of a registry that is amended about twice a year, which means
# it can go stale silently and no amount of testing this package against itself
# will notice. It was 87 entries and missing 40, including Honduras and Yemen,
# which are ordinary registrations - an IBAN from either was simply not an IBAN
# as far as this detector was concerned.
#
# tests/test_iban_registry.py now cross-checks every entry against `schwifty`,
# a maintained implementation, and fails on any addition, removal or changed
# length. That test is the only thing that can tell this table it is out of
# date; without it the failure is invisible by construction.
IBAN_LENGTHS: Dict[str, int] = {
    "AD": 24, "AE": 23, "AL": 28, "AO": 25, "AT": 20, "AX": 18, "AZ": 28,
    "BA": 20, "BE": 16, "BF": 28, "BG": 22, "BH": 22, "BI": 27, "BJ": 28,
    "BL": 27, "BR": 29, "BY": 28, "CF": 27, "CG": 27, "CH": 21, "CI": 28,
    "CM": 27, "CR": 22, "CV": 25, "CY": 28, "CZ": 24, "DE": 22, "DJ": 27,
    "DK": 18, "DO": 28, "DZ": 26, "EE": 20, "EG": 29, "ES": 24, "FI": 18,
    "FK": 18, "FO": 18, "FR": 27, "GA": 27, "GB": 22, "GE": 22, "GF": 27,
    "GG": 22, "GI": 23, "GL": 18, "GP": 27, "GQ": 27, "GR": 27, "GT": 28,
    "GW": 25, "HN": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IM": 22,
    "IQ": 23, "IR": 26, "IS": 26, "IT": 27, "JE": 22, "JO": 30, "KM": 27,
    "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20,
    "LV": 21, "LY": 25, "MA": 28, "MC": 27, "MD": 24, "ME": 22, "MF": 27,
    "MG": 27, "MK": 19, "ML": 28, "MN": 20, "MQ": 27, "MR": 27, "MT": 31,
    "MU": 30, "MZ": 25, "NC": 27, "NE": 28, "NI": 28, "NL": 18, "NO": 15,
    "OM": 23, "PF": 27, "PK": 24, "PL": 28, "PM": 27, "PS": 29, "PT": 25,
    "QA": 29, "RE": 27, "RO": 24, "RS": 22, "RU": 33, "SA": 24, "SC": 31,
    "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SN": 28, "SO": 23,
    "ST": 25, "SV": 28, "TD": 27, "TF": 27, "TG": 28, "TL": 23, "TN": 24,
    "TR": 26, "UA": 29, "VA": 22, "VG": 24, "WF": 27, "XK": 20, "YE": 30,
    "YT": 27,
}

MIN_IBAN_LENGTH = 15
MAX_IBAN_LENGTH = 34
MIN_CARD_LENGTH = 13
MAX_CARD_LENGTH = 19

#: The shortest run of an identifier's own characters that counts as SURVIVING.
#:
#: Not this module's own number. It is the release gate's `RESIDUE_RUN`, and
#: tests/test_leak_invariant.py asserts the two are equal, because the gate is
#: what defines materiality here: below eight characters a fragment is
#: coincidence rather than a surviving identifier, and the gate does not report
#: it. Sharing it is what makes the two agree by CONSTRUCTION rather than by
#: measurement - every piece this detector leaves unclaimed is shorter than the
#: shortest thing the gate can report, so the gate cannot go red on a decision
#: taken here.
#:
#: This is not the kind of sharing the layout bounds were removed for. Those
#: were heuristics about the page, and an oracle that learns one goes blind to
#: whatever it refuses. This is a materiality POLICY that the gate owns and
#: this module obeys; if they ever diverge the test fails rather than the
#: coverage silently shrinking.
MATERIAL_RESIDUE = 8

# THE RULE, in one sentence:
#
#   A candidate is any maximal sequence of identifier characters joined by runs
#   of characters that are not alphanumeric at all or are modifier letters,
#   interrupted by at most one line terminator.
#
# Not a list of separators. Twice now a list has been walked around. The first
# version enumerated " \t-", and a no-break space, a soft hyphen and a
# zero-width space went straight through it. The second replaced that with
# Unicode CATEGORIES - Zs space, Pd dash, Cf invisible - which is a better list
# and still a list: underscore is Pc and colon is Po, so
# "4111_1111_1111_1111" and "4111:1111:1111:1111" never formed a run at all,
# the validator was never offered the candidate, and a full card number went
# out with pii_detected=False. Underscore separation is ordinary in log lines,
# machine exports, filenames and code, and `.log` is in the default extension
# set.
#
# So the question is not "which characters separate groups" - which invites a
# fresh enumeration every time - but "what can sit between two identifier
# characters without destroying the identifier". The answer is: anything that
# is not one. A joiner is defined by what it is NOT, so there is no list left
# to be short.
#
# There is no bound on how much punctuation a candidate carries. Text
# punctuated down to single characters ("4.1.1.1...") is claimed if it
# validates, because `pdftotext` writes a letter-spaced form field exactly that
# way and nothing in the text tells the two apart; the over-redaction is in
# docs/limits.md. The only layout bound is the line-terminator count below.
#
# Invisible characters (Unicode Cf - soft hyphen, zero-width space, joiners,
# BOM) are removed before any of this and count for nothing: they are not
# there. A line break joins like any other non-alphanumeric, but a candidate
# may contain at most one (MAX_LINE_BREAKS). An alphanumeric that is not an
# identifier character - an umlaut, a CJK character - is not a joiner either;
# it ends the run, because it is a letter in a word rather than punctuation
# between digits. A modifier letter (Lm) is the exception and joins: the
# katakana prolonged-sound mark is typed as the dash in Japanese numbers.
#
# An identifier character is judged by what it IS, not by its code point: a
# decimal digit of any script, or an alphanumeric that is compatibility-equal
# to one ASCII letter. "４１１１ １１１１ １１１１ １１１１" is a card; ASCII as the
# finding rule let it through with pii_detected set only because a phone
# pattern happened to claim part of it, and twelve digits egressed.
_LINE_BREAKS = "\n\r\v\f\u0085\u2028\u2029"

# THE LAYOUT BOUNDS: there is exactly ONE, and it is definitional.
#
# There used to be three. A span multiple (a candidate may occupy at most 16
# times its own length), an interior-group limit (no whole group strictly
# inside a candidate may exceed 12 characters), and the terminator count. The
# first two are HEURISTICS, and both of them made the release gate red on
# inputs nobody had decided about:
#
#   * interior group - an IBAN written across two article numbers was claimed
#     by the brute-force oracle and refused here at an interior group of 17.
#     The gate reported "a validated IBAN survived whole", intermittently,
#     because the property test draws such a layout only sometimes. Measured
#     at 3 reds in 400 hypothesis seeds.
#
#   * span multiple - the identical mechanism, latent rather than observed:
#     the ECBS specimen IBAN written in groups of four with eighty-space gaps
#     spans 19.2 times its length, so it is refused here, claimed by the
#     oracle, and reported as a leak. The generator has simply never drawn a
#     gap that wide.
#
# A bound the checker cannot see is a bound that turns a release gate into a
# coin toss. A heuristic MUST NOT be shared with the oracle either - that is
# how the line-break filter hid a whole leak class in round 14. So the
# heuristics go, and what remains is the one bound that is a fact about the
# identifier rather than about the page.
#
# WHAT THEY WERE WORTH, measured before removing them:
#
#              93 realistic documents     3000 digit-dense    300 wide columns
#   both        card 27 / iban 0          2999 / 10           300 / 0
#   neither     card 27 / iban 0          2998 / 13           300 / 0
#
# Nothing on realistic text; three extra IBAN false positives per 3000
# documents of deliberate digit soup. The cost of KEEPING them was a gate that
# goes red 0.75% of CI runs for a reason nobody chose.
#
# What stops unbounded assembly now is the terminator bound, which confines
# any candidate to at most two lines. Within those two lines there is no width
# limit, and that is a deliberate fail-closed trade: an over-redacted table row
# is survivable, an unclaimed account number is not. It is stated in
# docs/limits.md as an accepted cost rather than left to be discovered.


#: One line TERMINATOR, however many characters it is written with.
#:
#: The bound below used to count CHARACTERS in _LINE_BREAKS, so a single CRLF
#: scored two and a wrapped identifier terminated the ordinary Windows and MIME
#: way was refused: found under a bare LF and under a bare CR, not found under
#: CRLF. `is_safe_for_external_llm` returned "No PII detected" for an e-mail
#: body with all sixteen digits of a card in it.
#:
#: Counting the sequence is the fix. Adding "\r\n" to a list of characters
#: would not have been - that is the same move as adding a separator to a
#: separator list, and the next sequence would be missing again. Longest-first
#: alternation, so CRLF can never be counted as two.
LINE_TERMINATOR = re.compile(
    "|".join([r"\r\n", r"\n\r"] + [re.escape(c) for c in "\n\r\v\f\u0085\u2028\u2029"])
)


def count_terminators(value: str) -> int:
    """How many line terminators *value* contains, counting sequences."""
    return len(LINE_TERMINATOR.findall(value))


#: How many line terminators a single candidate may contain.
#:
#: One. A value that wraps in a narrow column is continued on the NEXT line -
#: it breaks once. A column of separate numbers stacked in a table breaks
#: between every pair, and admitting the newline as a joiner without this bound
#: let three article numbers on three lines be claimed as one card. The
#: distinction is not how far apart they are, it is how many times the value
#: is interrupted.
MAX_LINE_BREAKS = 1


def _is_transparent(char: str) -> bool:
    """Invisible. Not a separator, because it is not anything."""
    return unicodedata.category(char) == "Cf"


def _is_joiner(char: str) -> bool:
    """May sit between two identifier characters without ending the run.

    Defined by exclusion on purpose: ANYTHING that is not alphanumeric.
    Underscore, colon, dot, slash, comma, pipe, every bracket, every kind of
    space - and a line break.

    The line break used to be excluded, and that exclusion was the seventh leak
    class. A label run into its value ("Kreditkartennummer4111 1111") and a
    value wrapping in a narrow column are both ordinary `pdftotext` artefacts
    from the extraction path this package ships; each was handled alone and
    their intersection leaked all sixteen digits with pii_detected False.
    Keeping it out was justified as "a run must not span a document"; what
    bounds a candidate is that it may contain at most one line terminator
    (MAX_LINE_BREAKS), not that a newline ends it.

    A modifier letter (Lm) joins too. The katakana prolonged-sound mark is
    typed as the dash in Japanese numbers - "４１１１ー１１１１" - and a
    modifier never ends a number the way a word letter does.
    """
    return not char.isalnum() or unicodedata.category(char) == "Lm"

#: Characters a local part may contain. Non-ASCII letters included, because
#: RFC 6531 addresses exist and "mueller" is spelt with an umlaut in Germany.
#:
#: Expanding left from the "@" over ASCII only truncated the local part at the
#: umlaut, so "m\u00fcller@kanzlei.de" was claimed as "ller@kanzlei.de" and the
#: first two characters of the address egressed. The docstring claimed
#: expanding from the "@" handled an umlaut glued in front; it handled an
#: umlaut that is not part of the address, and silently clipped one that is.
#:
#: The two cases are indistinguishable from the characters alone - a letter
#: directly before ASCII local-part characters may be part of the mailbox name
#: or a word run into it - so the address is claimed WHOLE. Where that absorbs
#: a glued word it over-redacts, which is the safe direction.
_LOCAL_PART_CHARS = None  # see _is_local_part_char


def _identifier_char(char: str) -> Optional[str]:
    """The ASCII character *char* stands for in an identifier, else None.

    One character in, one out, so a run's offsets still index the text.
    """
    if char.isascii():
        return char if char.isalnum() else None
    # A symbol is not a letter because NFKC spells it as one: a circled "a" is
    # punctuation between two groups, and folding it ended the run mid-card.
    if not char.isalnum() or unicodedata.category(char) == "Lm":
        return None
    digit = unicodedata.decimal(char, None)
    if digit is not None:
        return str(digit)
    folded = unicodedata.normalize("NFKC", char)
    if len(folded) == 1 and folded.isascii() and folded.isalpha():
        return folded
    return None


#: Address punctuation, which NFKC maps from its full-width and small forms.
_EMAIL_PUNCTUATION = frozenset("@._%+-")

#: Every character NFKC reads as "@". A text with none of them holds no
#: address, and the fold is skipped.
AT_SIGNS = "@\uff20\ufe6b"

#: The ideographic full stops RFC 3490 accepts as label dots alongside the
#: full-width one; NFKC maps neither to ".". They are also how a Japanese or
#: Chinese sentence ends, so they are read as dots only in a domain, and only
#: where the domain has no reading without them: read anywhere, a sentence
#: ending in "。" before an address was claimed as part of its local part, and
#: the paragraph before it went with it.
_IDNA_DOTS = str.maketrans({"\u3002": ".", "\uff61": "."})


def _email_char(char: str) -> str:
    """*char* as the e-mail finder reads it; one character in, one out.

    Digits and letters fold as in a run, and so does address punctuation:
    "ｅｒｉｋａ＠ｅｘａｍｐｌｅ．ｃｏｍ" is an address, and reading "＠" as
    anything but "@" sent it out with pii_detected False. A letter with no
    ASCII form - an umlaut in a local part - stays itself.
    """
    folded = _identifier_char(char)
    if folded is not None:
        return folded
    if not char.isascii():
        compat = unicodedata.normalize("NFKC", char)
        if compat in _EMAIL_PUNCTUATION:
            return compat
    return char


def fold(value: str) -> str:
    """*value* with every character read as the finders read it."""
    return "".join(_email_char(char) for char in value)


def _is_mark(char: str) -> bool:
    """A combining mark: the second half of a decomposed letter."""
    return unicodedata.category(char).startswith("M")


def _address_char(char: str) -> Optional[str]:
    """*char* as an address reads, or None where it is not there at all.

    Invisible characters and combining marks are not there: "jose\u0301" is
    "josé" decomposed, as macOS file names and much copied text are, and
    "erika\u200b@" is "erika@". Each ended the address and it went out
    whole. A Latin letter with a diacritic reads as its base letter, so
    "müller.de" is a domain in either normal form. The rest is `_email_char`.
    """
    if _is_transparent(char) or _is_mark(char):
        return None
    folded = _email_char(char)
    if folded == char and not char.isascii():
        parts = unicodedata.normalize("NFD", char)
        if (
            len(parts) > 1
            and parts[0].isascii()
            and parts[0].isalpha()
            and all(_is_mark(part) for part in parts[1:])
        ):
            return parts[0]
    return folded


def _address_view(value: str) -> Tuple[str, List[int]]:
    """*value* as an address reads, and where each character came from."""
    chars: List[str] = []
    origins: List[int] = []
    for index, char in enumerate(value):
        read = _address_char(char)
        if read is not None:
            chars.append(read)
            origins.append(index)
    return "".join(chars), origins


def _is_local_part_char(char: str) -> bool:
    if char in "._%+-":
        return True
    return char.isalnum() and not char.isspace()
_DOMAIN_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-"
)

_DIGIT_RUN = re.compile(r"\d+")

Span = Tuple[int, int, str]


def luhn_ok(value: str) -> bool:
    digits = re.sub(r"[\s-]", "", value)
    if not digits.isdigit() or not MIN_CARD_LENGTH <= len(digits) <= MAX_CARD_LENGTH:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def iban_ok(value: str) -> bool:
    compact = re.sub(r"\s", "", fold(value)).upper()
    if not MIN_IBAN_LENGTH <= len(compact) <= MAX_IBAN_LENGTH:
        return False
    if not (compact[:2].isalpha() and compact[2:4].isdigit() and compact[4:].isalnum()):
        return False
    rotated = compact[4:] + compact[:4]
    try:
        expanded = "".join(str(int(ch, 36)) if ch.isalpha() else ch for ch in rotated)
        return int(expanded) % 97 == 1
    except ValueError:
        return False


#: The longest valid domain starting immediately after an "@". Greedy, so one
#: match call yields the longest - no per-offset search.
_DOMAIN_AFTER_AT = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}"
)

#: The local part accepts non-ASCII letters (RFC 6531). The domain is ASCII
#: after the fold: an internationalised domain written in its own script
#: ("müller.de" rather than "xn--mller-kva.de") is not found - see
#: docs/limits.md.
RFC_EMAIL = re.compile(
    r"\A[^\W]*[\w._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\Z",
    re.UNICODE,
)


def email_ok(value: str) -> bool:
    if len(value) > 254:
        return False
    read = _address_view(value)[0].strip()
    if RFC_EMAIL.match(read):
        return True
    local, at, domain = read.partition("@")
    return bool(at) and bool(RFC_EMAIL.match(local + at + domain.translate(_IDNA_DOTS)))


def identifier_runs(text: str) -> Iterator[Tuple[str, List[int]]]:
    """Every maximal run of identifier characters, compacted to alphanumerics.

    A run grows over identifier characters and over joiners that are followed
    by one - the way a human writes an IBAN in groups of four. It ends at
    anything else. Yields
    ``(compact, offsets)`` where ``offsets[i]`` is the index in *text* of
    ``compact[i]``, so a claimed span maps back exactly, separators and all.

    Characters are folded by `_identifier_char`: a full-width or
    Arabic-Indic digit continues the run as the digit it is. Other letters end
    it: letting an umlaut continue the run would only glue unrelated words to
    it.
    """
    # Invisible characters are dropped first, so nothing downstream has to know
    # they exist. The offsets still point into the ORIGINAL text, so a claimed
    # span covers them and they are redacted along with the identifier.
    visible = [
        (char, index)
        for index, char in enumerate(text)
        if not _is_transparent(char)
    ]

    compact: List[str] = []
    offsets: List[int] = []
    position = 0
    count = len(visible)
    while position < count:
        char, origin = visible[position]
        folded = _identifier_char(char)
        if folded is not None:
            compact.append(folded)
            offsets.append(origin)
            position += 1
            continue
        if compact and _is_joiner(char):
            ahead = position
            while ahead < count and _is_joiner(visible[ahead][0]):
                ahead += 1
            # ANY number of consecutive joiners, not one. A gap of two or more
            # is the most ordinary text-extraction artefact there is - a
            # `pdftotext` column gap, fixed-width padding, a dot leader, a
            # monospaced table pipe - and requiring exactly one ended the
            # candidate before the validator ever saw it. Nothing bounds the
            # punctuation a candidate carries; at claim time only its line
            # terminators are counted.
            if ahead < count:
                following = visible[ahead][0]
                if _identifier_char(following) is not None:
                    position = ahead
                    continue
        if compact:
            yield "".join(compact), offsets
            compact, offsets = [], []
        position += 1
    if compact:
        yield "".join(compact), offsets


def terminator_offsets(text: str) -> List[int]:
    """Where every line terminator in *text* STARTS, in order.

    Computed once per document so the bound below is O(1) per candidate. It
    used to slice the candidate out of the text and re-scan it, which is linear
    in the span - and with no span limit left to cap it, that is quadratic in
    the length of a line on the egress path. This repo has paid for that
    failure mode three times.
    """
    return [match.start() for match in LINE_TERMINATOR.finditer(text)]


def _within_layout_bounds(
    offsets: List[int], start: int, size: int, breaks: List[int]
) -> bool:
    """Is this candidate ONE value rather than pieces of several lines?

    The only layout question left. A value that wraps in a narrow column is
    continued on the next line, so it is interrupted once; a column of separate
    numbers is interrupted between every pair. Counting interruptions is a fact
    about the identifier. How wide the page is, how many columns the value
    occupies and how long a neighbouring token happens to be are facts about
    the page, and every bound this module ever stated on those turned the
    release gate into a coin toss - see the block above MAX_LINE_BREAKS.

    A claim always begins and ends on an alphanumeric, so a terminator sequence
    is never half inside it: counting the sequences that START inside the span
    is exact, CRLF included.
    """
    first = offsets[start]
    last = offsets[start + size - 1]
    inside = bisect.bisect_right(breaks, last) - bisect.bisect_left(breaks, first)
    return inside <= MAX_LINE_BREAKS


def _claim(
    intervals: List[List[int]],
    offsets: List[int],
    start: int,
    end: int,
    breaks: List[int],
) -> None:
    """Cover ``[start, end)``, merging into the previous claim where they OVERLAP.

    Overlap, not adjacency. Two claims that merely touch in the compact run are
    separated in the text by whatever sat between them, and merging those
    swallowed it: 800 consecutive IBANs separated by single spaces came out as
    one span reaching across all of them, because each started exactly where
    the last ended. A window is already contiguous over its own separators, so
    merging on adjacency buys no coverage at all.

    Claims arrive with non-decreasing starts, so an overlap can only be with
    the last interval. The union is taken rather than the wider of the two,
    which is what makes "no validating window is ever left partially covered"
    hold: picking one of two overlapping windows guesses which digits are the
    identifier, and a wrong guess leaves the rest of it in the payload.

    The one thing that stops a merge is the terminator bound on the UNION. An
    interval that grew past it used to be discarded whole afterwards, throwing
    away the valid window that started it; here the claim simply stands on its
    own instead, and the two overlapping spans are merged downstream by the
    redactor.
    """
    if intervals and start < intervals[-1][1]:
        union_end = max(intervals[-1][1], end)
        first = intervals[-1][0]
        if _within_layout_bounds(offsets, first, union_end - first, breaks):
            intervals[-1][1] = union_end
            return
    intervals.append([start, end])


def _unclaimed_pieces(
    start: int, end: int, claimed: "set[int]"
) -> List[Tuple[int, int]]:
    """``[start, end)`` minus the positions another identifier already owns."""
    pieces: List[Tuple[int, int]] = []
    run: Optional[int] = None
    for position in range(start, end):
        if position in claimed:
            if run is not None:
                pieces.append((run, position))
                run = None
        elif run is None:
            run = position
    if run is not None:
        pieces.append((run, end))
    return pieces


def _iban_spans_in_run(
    compact: str, offsets: List[int], breaks: List[int]
) -> List[Span]:
    """Every registered-length, mod-97-valid window, merged where they overlap.

    Nothing is picked, for the same reason the card pass picks nothing. This
    used to claim the LEFTMOST valid window and then skip its whole length,
    which meant a COINCIDENTAL IBAN suppressed a genuine one and the claiming
    order decided which survived:

        "B.E54.7/<a real DE IBAN>"  ->  "[IBAN]<11 digits of the account>"

    The first eight characters compact to a mod-97-valid Belgian length, the
    genuine IBAN starts five characters in, and advancing past the coincidence
    stepped over it. Measured at about one document in seventy-four on
    realistic German business text, with eight to fourteen characters of a real
    account number left in a payload cleared for egress.

    So every valid window is claimed, the search advances one character at a
    time, and overlapping claims are merged into their union.
    """
    intervals: List[List[int]] = []
    position = 0
    limit = len(compact) - MIN_IBAN_LENGTH + 1
    while position < limit:
        head = compact[position:position + 4]
        if not (head[:2].isalpha() and head[2:].isdigit()):
            position += 1
            continue
        # An unregistered country code is not an IBAN, however the checksum
        # comes out. Accepting any length for one cost a card number its own
        # identity: "ID 4111..." compacts to 18 characters that pass mod-97 by
        # coincidence, and the run claimed it as an Indonesian IBAN - a country
        # with no IBAN - instead of the card it is.
        registered = IBAN_LENGTHS.get(head[:2].upper())
        if registered is None or position + registered > len(compact):
            position += 1
            continue
        candidate = compact[position:position + registered]
        if iban_ok(candidate) and _within_layout_bounds(
            offsets, position, registered, breaks
        ):
            _claim(intervals, offsets, position, position + registered, breaks)
        position += 1
    return [
        (offsets[start], offsets[end - 1] + 1, compact[start:end])
        for start, end in intervals
    ]


def _card_spans_in_run(
    compact: str,
    offsets: List[int],
    claimed: "set[int]",
    breaks: List[int],
) -> List[Span]:
    """Every Luhn-valid window in every digit run, merged where they overlap.

    Where digits run together there is nothing in the text that says which of
    them is the card: "Rechnung2026" in front of a sixteen-digit number makes a
    twenty-digit run, and a nineteen-digit window starting at the invoice year
    can check out by coincidence. Picking the leftmost-longest window guessed,
    and guessed wrong - it covered nineteen of the twenty digits and left the
    card's last digit standing in the payload.

    So nothing is picked. Every valid window is claimed and overlapping claims
    are merged into their union, which cannot leave a validating window
    partially covered. The cost is that adjacent digits go too; that is the
    over-redaction this module's docstring quantifies.

    THE INVARIANT, stated once for both passes: no validating window is ever
    left partially covered. Which identifier gets the LABEL is decided by
    whoever claims first, so no character is reported twice - but what gets
    COVERED is every character of every window that validates. Round 18 stated
    the first half and implemented it as a REFUSAL, which reduced coverage;
    non-reuse may decide a label, never a redaction.
    """
    intervals: List[List[int]] = []
    for run in _DIGIT_RUN.finditer(compact):
        run_start, run_end = run.start(), run.end()
        if run_end - run_start < MIN_CARD_LENGTH:
            continue
        for position in range(run_start, run_end - MIN_CARD_LENGTH + 1):
            for size in range(MAX_CARD_LENGTH, MIN_CARD_LENGTH - 1, -1):
                if position + size > run_end:
                    continue
                if not luhn_ok(compact[position:position + size]):
                    continue
                if not _within_layout_bounds(offsets, position, size, breaks):
                    continue
                overlaps = any(
                    index in claimed for index in range(position, position + size)
                )
                if not overlaps:
                    _claim(intervals, offsets, position, position + size, breaks)
                    break
                # A window that reuses characters another validated identifier
                # owns does not get to be a second identifier - but it is not
                # discarded either, because discarding it loses whatever part
                # of it nobody owns, and that part is usually the rest of a
                # genuine card.
                #
                # EVERY unowned piece of MATERIAL_RESIDUE characters or more is
                # claimed. No condition on the window's shape: the previous
                # version required it to sit inside one unbroken group, which
                # sounded like a discriminator and was a refusal wearing one -
                # a card written in four groups of four is not contiguous, so
                # its remainder was never claimed and
                # "Beleg <coincidental IBAN><card in 4x4>" egressed twelve of
                # the card's sixteen digits with the gate reporting no PII.
                # That is the ordinary pdftotext and hand-written shape.
                #
                # Measured on 400 documents of each shape, generated from
                # layouts rather than from this rule:
                #
                #                grouped leak  contiguous leak  over-redaction
                #   refuse         200/200        200/200        70 sp / 1045 ch
                #   contiguous     200/200          0/200        70 sp / 1045 ch
                #   piece >= 13    200/200        200/200       131 sp / 2500 ch
                #   piece >= 8       0/200          0/200       137 sp / 2622 ch
                #   any piece        0/200          0/200       199 sp / 3046 ch
                #
                # A floor of thirteen - the length of the shortest card - fails
                # the grouped case, because the remainder there is twelve.
                # Claiming every piece however short costs more and buys
                # nothing: a piece below the floor is one the gate itself calls
                # immaterial, so claiming it cannot change any verdict.
                for piece_start, piece_end in _unclaimed_pieces(
                    position, position + size, claimed
                ):
                    if piece_end - piece_start < MATERIAL_RESIDUE:
                        continue
                    _claim(intervals, offsets, piece_start, piece_end, breaks)
                break

    # No post-hoc filter. The bound is enforced when intervals are extended,
    # above, so an interval can never exceed it - and discarding a whole
    # interval after the fact threw away the valid window that started it.
    return [
        (offsets[start], offsets[end - 1] + 1, compact[start:end])
        for start, end in intervals
    ]


def find_ibans(text: str) -> List[Span]:
    """Every checksum-valid IBAN in *text*, found without a word boundary."""
    spans: List[Span] = []
    breaks = terminator_offsets(text)
    for compact, offsets in identifier_runs(text):
        spans.extend(_iban_spans_in_run(compact, offsets, breaks))
    return spans


def find_cards(text: str, avoid: Optional[List[Tuple[int, int]]] = None) -> List[Span]:
    """Every Luhn-valid card number in *text*, found without a word boundary.

    *avoid* holds spans already claimed as something else - in practice the
    IBANs, whose 18-digit national body would otherwise throw off Luhn-valid
    windows of its own and bury a real finding under a duplicate.
    """
    # One pass over the offsets per run, with a binary search into the avoid
    # list. It used to loop every offset for every avoid span, which is
    # quadratic in the number of validated IBANs on the page: 200 IBANs took
    # 0.32s and 800 took 4.5s, on the egress path.
    merged: List[Tuple[int, int]] = []
    for start, end in sorted(avoid or []):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    starts = [start for start, _end in merged]

    spans: List[Span] = []
    breaks = terminator_offsets(text)
    for compact, offsets in identifier_runs(text):
        if not offsets:
            continue
        blocked = set()
        if merged:
            for position, origin in enumerate(offsets):
                index = bisect.bisect_right(starts, origin) - 1
                if index >= 0 and origin < merged[index][1]:
                    blocked.add(position)
        spans.extend(_card_spans_in_run(compact, offsets, blocked, breaks))
    return spans


def find_emails(text: str) -> List[Span]:
    """Every RFC-shaped address, found by expanding outwards from each '@'.

    Expanding from the '@' is what makes this anchor-free. A word character the
    local-part class does not cover - a German umlaut, say - glued in front of
    an address leaves a boundary-anchored pattern with nowhere legal to start,
    and it matches nothing at all.

    The longest valid address is claimed, not the shortest: a longer local part
    is still the same mailbox, and "acct_erika@example.com" IS the address
    rather than a prefix plus an address.

    Two addresses written with nothing between them share characters: the
    first domain runs on into the second local part. Each is claimed whole
    and the claims overlap, so the redactor's union covers both. Clipping the
    second claim at the end of the first left its local part empty, so it was
    not claimed at all and its domain went out.
    """
    if not any(sign in text for sign in AT_SIGNS):
        return []
    # Searched on the folded text, which has the same length, so every offset
    # found there is an offset into *text*.
    # Searched on the address view; `kept` maps it back to *text*, so a claim
    # still covers the invisibles and marks it read through.
    original = text
    text, kept = _address_view(text)
    dotted = text.translate(_IDNA_DOTS)
    spans: List[Span] = []
    for at in (index for index, char in enumerate(text) if char == "@"):
        left = at
        while left > 0 and _is_local_part_char(text[left - 1]):
            left -= 1
        right = at + 1
        while right < len(text) and text[right] in _DOMAIN_CHARS:
            right += 1
        # The local part and the domain are independent given the "@", so each
        # is found in ONE pass instead of trying every (start, end) pair. The
        # nested search was cubic: 1.6 KB of one long line took 8 seconds and
        # 2.4 KB took 27, on the egress path, which is a gate nobody can
        # afford to run and therefore a gate that gets bypassed.
        #
        # SHAPE, not `email_ok`: the validator also caps the whole address at
        # RFC 5321's 254 characters, and using it to choose where the address
        # ENDS made the search shorten the DOMAIN to get under the cap, leaving
        # the last letter of the TLD in the overlay. Length is a property of an
        # address, not a way to decide where one ends.
        domain = _DOMAIN_AFTER_AT.match(text, at + 1, right)
        if domain is None:
            right = at + 1
            while right < len(dotted) and dotted[right] in _DOMAIN_CHARS:
                right += 1
            domain = _DOMAIN_AFTER_AT.match(dotted, at + 1, right)
        if domain is None:
            continue
        candidate = text[left:at + 1] + dotted[at + 1:domain.end()]
        if not RFC_EMAIL.match(candidate):
            continue
        start, end = kept[left], kept[domain.end() - 1] + 1
        spans.append((start, end, original[start:end]))
    return spans
