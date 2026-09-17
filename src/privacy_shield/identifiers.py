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

# THE RULE, in one sentence:
#
#   A candidate is any maximal sequence of ASCII alphanumerics joined by single
#   characters that are not alphanumeric at all and not a line break, carrying
#   at most one such joiner for every two identifier characters.
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
# The bound is what stops prose being assembled into a false positive. Real
# grouping is sparse - sixteen digits in fours is three joiners, an IBAN in
# fours is five - while text punctuated down to single characters ("4.1.1.1")
# is fifteen joiners for sixteen characters. Requiring an identifier's own
# characters to outnumber its punctuation two to one admits every real grouping
# and rejects assembled prose.
#
# Invisible characters (Unicode Cf - soft hyphen, zero-width space, joiners,
# BOM) are removed before any of this and count for nothing: they are not
# there. A line break is never a joiner. A NON-ASCII alphanumeric - an umlaut,
# a CJK character - is not a joiner either; it ends the run, because it is a
# letter in a word rather than punctuation between digits.
_LINE_BREAKS = "\n\r\v\f\u0085\u2028\u2029"

#: A candidate may span at most this many times its own length, so a
#: sixteen-digit card may occupy 256 columns and tolerate gaps of up to eighty
#: characters.
#:
#: The number is high because measurement said the bound buys nothing. Swept
#: from 4 to 1000 against both corpora, the false-positive count does not move
#: at all - eight cards and no IBANs at every value. All the bound does is
#: create a cliff, and at 4 the cliff was at exactly seventeen spaces:
#: sixteen-space column gaps were claimed and seventeen-space ones egressed the
#: card whole. A wide column in a monospaced report is an ordinary shape.
#:
#: It is not removed altogether because without any span limit two numbers at
#: opposite ends of a long line could be assembled into one candidate. It is
#: set where no real layout reaches. THE CLIFF STILL EXISTS - it is now at
#: about eighty characters of gap - and it is pinned by
#: test_the_span_bound_has_a_cliff_and_this_is_where_it_is rather than left to
#: be discovered.
#:
#: This replaced "at most one joiner per two identifier characters", which was
#: a bound on the TOTAL and still implied a hard limit of one per gap once the
#: run rule required single joiners. Three-space padding is nine joiners for
#: sixteen digits and was refused by it.
MAX_SPAN_MULTIPLE = 16

#: The longest INTERIOR group a multi-group candidate may contain.
#:
#: This is what separates GROUPING from ASSEMBLY, and the word "interior" is
#: doing all the work. Whatever a candidate's first and last groups look like,
#: the groups strictly between them are whole, and in a real layout a whole
#: group is small: four for a card or an IBAN, six for the middle of an Amex,
#: two on a densely spaced form. When a Luhn window instead falls across a list
#: of separate numbers, the group in the middle is a whole other number -
#: thirteen digits of an article code, seven of a phone number.
#:
#: Bounding the longest group ANYWHERE was tried first and cannot work: "DE89
#: 370400440532013000" is an ordinary way to write an IBAN and its second group
#: is eighteen characters, longer than the thirteen-character groups that have
#: to be refused. Requiring whole-group ALIGNMENT was tried next and cannot
#: work either: a glued prefix on a spaced number ("7" run together with
#: "4111 1111 1111 1111") starts in the middle of its first group, which is the
#: entire case this detector exists to catch. Only the interior is reliable,
#: because only the interior is never clipped by the candidate's own edges.
#:
#: A candidate with fewer than three groups has no interior and is unbounded.
MAX_INTERIOR_GROUP = 12

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
    Keeping it out was justified as "a run must not span a document", but what
    actually bounds a run is the span and interior-group limits, not the
    newline - measured below.
    """
    return not char.isalnum()

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
    compact = re.sub(r"\s", "", value).upper()
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

#: The local part accepts non-ASCII letters (RFC 6531); the domain stays
#: ASCII, since an internationalised domain reaches this code already
#: punycoded.
RFC_EMAIL = re.compile(
    r"\A[^\W]*[\w._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\Z",
    re.UNICODE,
)


def email_ok(value: str) -> bool:
    return bool(RFC_EMAIL.match(value.strip())) and len(value) <= 254


def identifier_runs(text: str) -> Iterator[Tuple[str, List[int]]]:
    """Every maximal run of identifier characters, compacted to alphanumerics.

    A run grows over ASCII alphanumerics and over a SINGLE space, tab or hyphen
    that is itself followed by an alphanumeric - the way a human writes an IBAN
    in groups of four. It ends at anything else, a newline included. Yields
    ``(compact, offsets)`` where ``offsets[i]`` is the index in *text* of
    ``compact[i]``, so a claimed span maps back exactly, separators and all.

    Non-ASCII letters end a run: an IBAN is ASCII, and letting an umlaut
    continue the run would only glue unrelated words to it.
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
        if char.isascii() and char.isalnum():
            compact.append(char)
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
            # candidate before the validator ever saw it. How much punctuation
            # a candidate may carry in total is decided at claim time by the
            # span budget, which is a bound on the whole identifier rather than
            # a hard limit of one on each gap.
            if ahead < count:
                following = visible[ahead][0]
                if following.isascii() and following.isalnum():
                    position = ahead
                    continue
        if compact:
            yield "".join(compact), offsets
            compact, offsets = [], []
        position += 1
    if compact:
        yield "".join(compact), offsets


def _within_layout_bounds(
    text: str, offsets: List[int], start: int, size: int
) -> bool:
    """Is this candidate compact enough to be one identifier?

    The bound is what keeps "anything that is not an identifier character,
    however many of them" from assembling prose into a checksum. It is stated
    on the SPAN - how many columns the candidate occupies - rather than on the
    number of gaps or their width, because layout varies both and neither is a
    property of the identifier.

    Counted from the ORIGINAL offsets, which is where the punctuation actually
    is; invisible characters were dropped before the run was built and are
    correctly invisible here too.
    """
    span = offsets[start + size - 1] + 1 - offsets[start]
    if span > size * MAX_SPAN_MULTIPLE:
        return False

    claimed = text[offsets[start]:offsets[start + size - 1] + 1]
    if count_terminators(claimed) > MAX_LINE_BREAKS:
        return False

    groups: List[int] = []
    current = 0
    for position in range(offsets[start], offsets[start + size - 1] + 1):
        if text[position].isascii() and text[position].isalnum():
            current += 1
        elif not _is_transparent(text[position]):
            if current:
                groups.append(current)
            current = 0
    if current:
        groups.append(current)
    longest = max(groups) if groups else 0

    # "Single group" means ONE unbroken group, not "span equals size". A soft
    # hyphen inside an otherwise solid account number makes the span one longer
    # than the identifier while splitting nothing.
    if longest == size:
        return True

    # There is deliberately NO bound on the number of groups. One was tried -
    # "the average group must hold at least two characters", to reject text
    # punctuated down to singles like "4.1.1.1.1..." - and it refused
    # "4 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1", which is what `pdftotext` emits for a
    # letter-spaced field on a form. The two shapes are identical; nothing in
    # the text separates them. So single-character groups are accepted and the
    # dotted-prose shape is over-redacted with them.

    # No condition on the EDGES. Requiring at least one of them to sit on a
    # group boundary was tried and is wrong: text glued to BOTH ends of a
    # spaced number clips both edges, and
    # "Art. 6 DSGVO4111 1111 1111 1111Ref " then egressed the card whole. The
    # brute-force oracle caught it, which is the whole reason it has no run
    # rule of its own. The cost of dropping the condition is one more
    # false positive on the realistic corpus, a window assembled across a
    # single separator out of two adjacent numbers in a list - a trade that
    # goes the safe way.
    return all(group <= MAX_INTERIOR_GROUP for group in groups[1:-1])


def _iban_spans_in_run(text: str, compact: str, offsets: List[int]) -> List[Span]:
    spans: List[Span] = []
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
        if iban_ok(candidate) and _within_layout_bounds(text, offsets, position, registered):
            spans.append(
                (offsets[position], offsets[position + registered - 1] + 1, candidate)
            )
            position += registered
            continue
        position += 1
    return spans


def _card_spans_in_run(
    text: str,
    compact: str,
    offsets: List[int],
    claimed: "set[int]",
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
    """
    intervals: List[List[int]] = []
    for run in _DIGIT_RUN.finditer(compact):
        run_start, run_end = run.start(), run.end()
        if run_end - run_start < MIN_CARD_LENGTH:
            continue
        for position in range(run_start, run_end - MIN_CARD_LENGTH + 1):
            if position in claimed:
                continue
            for size in range(MAX_CARD_LENGTH, MIN_CARD_LENGTH - 1, -1):
                if position + size > run_end:
                    continue
                # No character may belong to two identifiers. Skipping only a
                # window that STARTS inside a claimed span let a window start
                # before an IBAN and run across it, reusing the IBAN's own
                # digits as part of a "card".
                if any(index in claimed for index in range(position, position + size)):
                    continue
                if luhn_ok(compact[position:position + size]) and _within_layout_bounds(
                    text, offsets, position, size
                ):
                    # Extend the previous interval only if the UNION still
                    # respects the terminator bound. Merging without that
                    # check produced a union spanning two terminators, which
                    # the re-check below then discarded WHOLE - throwing away
                    # the valid window that started it. A card padded with
                    # underscores on a line of its own went out that way,
                    # while the same card in isolation was claimed.
                    if intervals and position <= intervals[-1][1]:
                        union_end = max(intervals[-1][1], position + size)
                        union = text[
                            offsets[intervals[-1][0]]:offsets[union_end - 1] + 1
                        ]
                        if count_terminators(union) <= MAX_LINE_BREAKS:
                            intervals[-1][1] = union_end
                            break
                    intervals.append([position, position + size])
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
    for compact, offsets in identifier_runs(text):
        spans.extend(_iban_spans_in_run(text, compact, offsets))
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
    import bisect

    merged: List[Tuple[int, int]] = []
    for start, end in sorted(avoid or []):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    starts = [start for start, _end in merged]

    spans: List[Span] = []
    for compact, offsets in identifier_runs(text):
        if not offsets:
            continue
        blocked = set()
        if merged:
            for position, origin in enumerate(offsets):
                index = bisect.bisect_right(starts, origin) - 1
                if index >= 0 and origin < merged[index][1]:
                    blocked.add(position)
        spans.extend(_card_spans_in_run(text, compact, offsets, blocked))
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

    Addresses are claimed left to right and an address may not reach back into
    one already claimed. Without that, two addresses written with nothing
    between them defeated this: expanding left from the SECOND "@" ran back
    through the first address's domain, and the longest thing that validated
    from there started halfway through address one - so the claim covered the
    join and left "abcdef1234@" standing in the overlay. The mailbox name of a
    real address, which is usually the person's name.
    """
    spans: List[Span] = []
    claimed_to = 0
    for at in (index for index, char in enumerate(text) if char == "@"):
        left = at
        while left > 0 and _is_local_part_char(text[left - 1]):
            left -= 1
        left = max(left, claimed_to)
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
            continue
        candidate = text[left:domain.end()]
        if not RFC_EMAIL.match(candidate):
            continue
        spans.append((left, domain.end(), candidate))
        claimed_to = domain.end()
    return spans
