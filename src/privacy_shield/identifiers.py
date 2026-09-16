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
IBAN_LENGTHS: Dict[str, int] = {
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

MIN_IBAN_LENGTH = 15
MAX_IBAN_LENGTH = 34
MIN_CARD_LENGTH = 13
MAX_CARD_LENGTH = 19

# What may sit inside an identifier, by CHARACTER PROPERTY rather than by a
# list someone remembered. The first version of this module enumerated
# " \t-", and an adversarial pass walked straight through it: a no-break space
# between the groups of an IBAN, a soft hyphen from a justified paragraph, a
# zero-width space from an HTML paste. All three ended the run early, and the
# identifier behind a glued prefix went out again. Enumerating separators from
# memory is the same mistake as enumerating leak inputs from memory.
#
# Cf is the invisible class - soft hyphen, zero-width space and joiners, BOM.
# These are not separators at all: they are not there, so they are skipped
# without interrupting the run and without using up its one separator.
#
# Zs is every horizontal space, which is what a PDF or DOCX extractor actually
# emits between the groups of a printed account number - no-break, thin, narrow
# and figure spaces included. Pd is every hyphen, including the non-breaking
# one. A line break is never either.
_LINE_BREAKS = "\n\r\v\f  "


def _is_transparent(char: str) -> bool:
    return unicodedata.category(char) == "Cf"


def _is_inline_separator(char: str) -> bool:
    if char in _LINE_BREAKS:
        return False
    return char == "\t" or unicodedata.category(char) in ("Zs", "Pd")

_LOCAL_PART_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-"
)
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


RFC_EMAIL = re.compile(
    r"\A[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\Z"
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
        if compact and _is_inline_separator(char):
            ahead = position
            while ahead < count and _is_inline_separator(visible[ahead][0]):
                ahead += 1
            if ahead - position == 1 and ahead < count:
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


def _iban_spans_in_run(compact: str, offsets: List[int]) -> List[Span]:
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
        if iban_ok(candidate):
            spans.append(
                (offsets[position], offsets[position + registered - 1] + 1, candidate)
            )
            position += registered
            continue
        position += 1
    return spans


def _card_spans_in_run(
    compact: str,
    offsets: List[int],
    claimed: List[Tuple[int, int]],
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
            if any(start <= position < end for start, end in claimed):
                continue
            for size in range(MAX_CARD_LENGTH, MIN_CARD_LENGTH - 1, -1):
                if position + size > run_end:
                    continue
                if luhn_ok(compact[position:position + size]):
                    if intervals and position <= intervals[-1][1]:
                        intervals[-1][1] = max(intervals[-1][1], position + size)
                    else:
                        intervals.append([position, position + size])
                    break

    return [
        (offsets[start], offsets[end - 1] + 1, compact[start:end])
        for start, end in intervals
    ]


def find_ibans(text: str) -> List[Span]:
    """Every checksum-valid IBAN in *text*, found without a word boundary."""
    spans: List[Span] = []
    for compact, offsets in identifier_runs(text):
        spans.extend(_iban_spans_in_run(compact, offsets))
    return spans


def find_cards(text: str, avoid: Optional[List[Tuple[int, int]]] = None) -> List[Span]:
    """Every Luhn-valid card number in *text*, found without a word boundary.

    *avoid* holds spans already claimed as something else - in practice the
    IBANs, whose 18-digit national body would otherwise throw off Luhn-valid
    windows of its own and bury a real finding under a duplicate.
    """
    avoid = avoid or []
    spans: List[Span] = []
    for compact, offsets in identifier_runs(text):
        if not offsets:
            continue
        blocked: List[Tuple[int, int]] = []
        for start, end in avoid:
            for position, origin in enumerate(offsets):
                if start <= origin < end:
                    blocked.append((position, position + 1))
        spans.extend(_card_spans_in_run(compact, offsets, blocked))
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
    """
    spans: List[Span] = []
    for at in (index for index, char in enumerate(text) if char == "@"):
        left = at
        while left > 0 and text[left - 1] in _LOCAL_PART_CHARS:
            left -= 1
        right = at + 1
        while right < len(text) and text[right] in _DOMAIN_CHARS:
            right += 1
        claimed = False
        for start in range(left, at):
            for end in range(right, at + 1, -1):
                candidate = text[start:end]
                if email_ok(candidate):
                    spans.append((start, end, candidate))
                    claimed = True
                    break
            if claimed:
                break
    return spans
