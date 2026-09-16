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
"""

from __future__ import annotations

import random
import re

import pytest

from privacy_shield import scan
from privacy_shield.shield import PrivacyMode

# ---------------------------------------------------------------------------
# Independent oracle - no privacy_shield imports below this line
# ---------------------------------------------------------------------------

_ORACLE_EMAIL = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
)
_ORACLE_IBAN = re.compile(r"\b[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]{2,4}){2,8}\b")
_ORACLE_CARD = re.compile(r"\b(?:[0-9]{4}[ -]?){3}[0-9]{1,4}\b")


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


def _validated_identifiers(text: str) -> list[tuple[str, str]]:
    """Every IBAN / card / email in *text* that an independent check confirms."""
    found: list[tuple[str, str]] = []
    for match in _ORACLE_EMAIL.finditer(text):
        found.append(("email", match.group()))
    for match in _ORACLE_IBAN.finditer(text):
        if _iban_ok(match.group()):
            found.append(("iban", match.group()))
    for match in _ORACLE_CARD.finditer(text):
        raw = match.group()
        if _luhn_ok(re.sub(r"[ -]", "", raw)):
            found.append(("credit_card", raw))
    return found


# ---------------------------------------------------------------------------
# The invariant
# ---------------------------------------------------------------------------


def leaks_in(text: str, document) -> list[str]:
    """Every way *document* breaks the leak invariant for input *text*."""
    if not document.egress_allowed:
        return []

    overlay = document.overlay
    leaks: list[str] = []

    for span in document.spans:
        value = (span.value or "").strip()
        if value and value in overlay:
            leaks.append(f"detected {span.pii_type} value {value!r} survived in overlay")

    for kind, value in _validated_identifiers(text):
        if value in overlay:
            leaks.append(f"validated {kind} {value!r} survived in overlay")

    return leaks


def assert_no_leak(text: str, mode: PrivacyMode = PrivacyMode.STANDARD) -> None:
    report = scan(text, mode=mode)
    for document in report.documents:
        leaks = leaks_in(text, document)
        assert not leaks, (
            "LEAK INVARIANT VIOLATED\n"
            f"  mode      : {mode.value}\n"
            f"  input     : {text!r}\n"
            f"  overlay   : {document.overlay!r}\n"
            f"  pii       : {document.pii_detected}\n"
            f"  egress    : {document.egress_allowed}\n"
            "  leaks     : " + "\n              ".join(leaks)
        )


# ---------------------------------------------------------------------------
# Named regressions - the five reproductions that rejected 2.0.0
# ---------------------------------------------------------------------------

REJECTION_REPRODUCTIONS = [
    pytest.param("DE89370400440532013000", id="bare_iban"),
    pytest.param("Ref DE89370400440532013000", id="iban_behind_ref_prefix"),
    pytest.param("4111111111111111", id="bare_card"),
    pytest.param("ID 4111111111111111", id="card_behind_id_prefix"),
    pytest.param("Kontakt: ref abcdef1234@example.com", id="email_behind_ref_hex_local_part"),
]


@pytest.mark.parametrize("text", REJECTION_REPRODUCTIONS)
def test_release_gate_rejection_reproductions(text):
    assert_no_leak(text)


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
    text = "Ref DE89370400440532013000\nID 4111111111111111\n"
    document = scan(text).documents[0]

    assert not leaks_in(text, document)
    assert document.overlay == "Ref [IBAN]\nID [CREDIT_CARD]\n", document.overlay


# ---------------------------------------------------------------------------
# Generated documents
# ---------------------------------------------------------------------------

_NAMES = ["Erika Mustermann", "Max Mueller", "Anna Schmidt", "Klaus Weber"]
_PREFIXES = ["", "Ref ", "REF: ", "ID ", "id-", "UUID ", "Referenz: ", "Nr. "]
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


def _make_iban(rng: random.Random, country: str = "DE") -> str:
    bban = "".join(rng.choice("0123456789") for _ in range(18))
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


def generate_document(rng: random.Random) -> str:
    """A short realistic document carrying at least one validated identifier."""
    lines: list[str] = []
    for _ in range(rng.randint(1, 4)):
        kind = rng.choice(["iban", "card", "email", "name", "noise"])
        prefix = rng.choice(_PREFIXES)
        if kind == "iban":
            lines.append(f"{prefix}{_spaced(rng, _make_iban(rng))}")
        elif kind == "card":
            lines.append(f"{prefix}{_spaced(rng, _make_card(rng))}")
        elif kind == "email":
            lines.append(f"{prefix}{_make_email(rng)}")
        elif kind == "name":
            lines.append(f"{rng.choice(_NAMES)}, Tel. +49 170 {rng.randint(1000000, 9999999)}")
        else:
            lines.append(rng.choice(_NOISE))
    rng.shuffle(lines)
    joiner = rng.choice(["\n", " ", ", "])
    return joiner.join(lines)


GENERATED_DOCUMENT_COUNT = 300


@pytest.mark.parametrize("mode", [PrivacyMode.STANDARD, PrivacyMode.REGEX_ONLY])
def test_release_gate_generated_battery(mode):
    """No generated document may egress carrying its own PII."""
    rng = random.Random(20260916)
    failures: list[str] = []
    for index in range(GENERATED_DOCUMENT_COUNT):
        text = generate_document(rng)
        document = scan(text, mode=mode).documents[0]
        leaks = leaks_in(text, document)
        if leaks:
            failures.append(
                f"[{index}] input={text!r}\n      overlay={document.overlay!r}\n"
                f"      {'; '.join(leaks)}"
            )
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
                "DE89370400440532013000",
                "DE89 3704 0044 0532 0130 00",
                "4111111111111111",
                "4012 8888 8888 1881",
                "abcdef1234@example.com",
                "erika.mustermann@example.com",
                "+49 170 1234567",
            ]
        ),
        st.text(alphabet="abcdefABCDEF0123456789 .:,-/", max_size=24),
    )

    @settings(max_examples=250, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(st.lists(_fragment, min_size=1, max_size=8), st.sampled_from([" ", "\n", ", "]))
    def test_release_gate_property(fragments, joiner):
        text = joiner.join(fragments)
        if not text.strip():
            return
        document = scan(text).documents[0]
        leaks = leaks_in(text, document)
        assert not leaks, (
            f"input={text!r}\noverlay={document.overlay!r}\n" + "; ".join(leaks)
        )
