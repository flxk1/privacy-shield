"""Three norms from the skill's governance block, each held by a test.

A compiled norm is a promise in machine form. If nothing fails when it stops
being true, formalising it only makes a false zero look more convincing. These
three had no test at all, and two of them could not have had one as they were
worded:

`present_cleared_as_a_zero_residual_guarantee` named a claim with no artefact.
Replacing both disclaimers in SKILL.md with the exact guarantee it forbids left
the suite byte-identically green. It is now two falsifiable norms - the
prohibition on claiming zero residual anywhere we ship, and the obligation to
carry the disclaimer in the three documents a reader actually consults.

`gate_on_source_classification_not_overlay_residual` asked for proof that a
function never reads something, which is close to untestable. It is now its two
observable consequences: a blocked source class stays blocked however well it
was redacted, and a cleared source class stays cleared whatever residual its
overlay carries. Both are checked by moving the overlay and holding the source
class fixed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_MD = REPO_ROOT / "skills" / "privacy-shield" / "SKILL.md"

#: The documents a reader consults to find out what "cleared" means. SKILL.md is
#: what an agent loads, README.md is the front door, docs/limits.md is where the
#: gaps are stated. A disclaimer in only one of them is a disclaimer most
#: readers never see.
DISCLAIMING_DOCUMENTS = ("skills/privacy-shield/SKILL.md", "README.md", "docs/limits.md")


def _governance() -> dict:
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(SKILL_MD.read_text(encoding="utf-8").split("---\n", 2)[1])[
        "governance"
    ]


def _text(relative: str) -> str:
    return (REPO_ROOT / relative).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# claim_zero_residual_in_any_shipped_document
# disclaim_cleared_as_source_class_in_skill_readme_and_limits
# ---------------------------------------------------------------------------

#: What the disclaimer has to SAY, not how it has to be phrased. Each entry is a
#: pair of patterns that must co-occur in one document: the word being qualified
#: and the qualification. Matching on meaning-bearing pairs rather than on an
#: exact sentence means the prose can be rewritten without silently retiring the
#: test, and cannot be satisfied by the word "cleared" appearing on its own.
_DISCLAIMER_PATTERNS = (
    re.compile(r"not\s+a\s+zero-?residual\s+certificate", re.IGNORECASE),
    re.compile(r"not\s+a\s+certificate\s+of\s+zero\s+residual", re.IGNORECASE),
    re.compile(r"short\s+of\s+a\s+zero-?residual", re.IGNORECASE),
    re.compile(r"source\s+class(?:ification)?\s+(?:is\s+allowed\s+to|may)\s+egress",
               re.IGNORECASE),
)

#: Every mention of zero residual in a shipped document, negated or not. The
#: check cannot be a list of forbidden phrasings - "Cleared guarantees zero
#: residual PII" and "cleared certifies zero residual" are the same act - so it
#: finds every mention and requires each one to be NEGATED.
_ZERO_RESIDUAL = re.compile(r"zero[-\s]?residual", re.IGNORECASE)

#: What makes a mention a disclaimer rather than a claim, looked for in the
#: window before it. `not`, `never`, `short of`, `rather than`, `stops short`.
_NEGATOR = re.compile(
    r"\b(?:not|never|no|short\s+of|rather\s+than|stops?\s+short|without|"
    r"cannot|is\s+n[o']t)\b",
    re.IGNORECASE,
)

#: Where a sentence ends. The negator has to live in the SAME sentence as the
#: mention it is claimed to negate: a fixed character lookback let a negator in
#: the PREVIOUS sentence excuse the claim, and "There is no charge for this
#: feature. Cleared guarantees zero residual PII." passed a 90-character
#: window. Measured on the shipped function before this was scoped.
_SENTENCE_END = re.compile(r"[.!?:;]\s|\n\s*\n")


def _containing_sentence_before(text: str, position: int) -> str:
    """The text from the start of the mention's own sentence up to *position*."""
    start = 0
    for end in _SENTENCE_END.finditer(text, 0, position):
        start = end.end()
    return text[start:position]


def _mention_is_inside_an_identifier(text: str, start: int, end: int) -> bool:
    """True when the mention itself sits in a norm slug or an inline code span.

    Not "a backtick appears nearby": `` "Cleared certifies zero residual in the
    `overlay` we ship." `` has a backtick twelve characters along and is a
    claim, not a name. An odd number of backticks before the mention means it
    is inside a code span; an adjacent word character or underscore means it is
    part of a slug like `claim_zero_residual_in_any_shipped_document`.
    """
    if text.count("`", 0, start) % 2 == 1:
        return True
    before = text[start - 1] if start else " "
    after = text[end] if end < len(text) else " "
    return before in "_`" or after in "_`" or before.isalnum() or after.isalnum()


def _affirmative_zero_residual_claims(text: str) -> list[str]:
    """Every mention of zero residual that is NOT negated and not a slug."""
    claims = []
    for match in _ZERO_RESIDUAL.finditer(text):
        sentence = _containing_sentence_before(text, match.start())
        if _NEGATOR.search(sentence):
            continue
        if _mention_is_inside_an_identifier(text, match.start(), match.end()):
            continue
        claims.append(sentence + text[match.start():match.end() + 30])
    return claims


def test_the_two_reworded_norms_are_declared():
    """The rewording is itself a claim; this is what makes it checkable.

    If someone restores the old unfalsifiable wording, the tests below would
    still pass while no longer holding what the block says.
    """
    governance = _governance()
    assert "claim_zero_residual_in_any_shipped_document" in governance["prohibited"]
    assert (
        "disclaim_cleared_as_source_class_in_skill_readme_and_limits"
        in governance["obligations"]
    )
    assert "block_a_blocked_source_class_however_redacted" in governance["obligations"]
    assert (
        "clear_a_cleared_source_class_whatever_the_overlay_residual"
        in governance["obligations"]
    )
    # The wordings that could not be tested must not come back.
    assert "present_cleared_as_a_zero_residual_guarantee" not in governance["prohibited"]
    assert (
        "gate_on_source_classification_not_overlay_residual"
        not in governance["obligations"]
    )


@pytest.mark.parametrize("document", DISCLAIMING_DOCUMENTS)
def test_the_disclaimer_is_in_every_document_a_reader_consults(document):
    """`disclaim_cleared_as_source_class_in_skill_readme_and_limits`.

    Fails on the mutation that found this gap: replacing the disclaimers with
    "Cleared guarantees zero residual PII" left 1160 tests green.
    """
    text = _text(document)
    assert any(pattern.search(text) for pattern in _DISCLAIMER_PATTERNS), (
        f"{document} no longer says that 'cleared' is a verdict on the source "
        f"class rather than a certificate of zero residual. That sentence is "
        f"the difference between a scoped claim and a false promise; it does "
        f"not come out."
    )


@pytest.mark.parametrize(
    "document",
    DISCLAIMING_DOCUMENTS + ("CHANGELOG.md", "llms.txt", "docs/pipeline.md"),
)
def test_no_shipped_document_claims_zero_residual(document):
    """`claim_zero_residual_in_any_shipped_document`, the other direction.

    Carrying the disclaimer somewhere and the opposite claim somewhere else is
    still making the claim.
    """
    path = REPO_ROOT / document
    if not path.is_file():
        pytest.skip(f"{document} is not in this tree")

    claims = _affirmative_zero_residual_claims(path.read_text(encoding="utf-8"))
    assert not claims, (
        f"{document} mentions zero residual without negating it, which is the "
        f"claim the block forbids:\n  "
        + "\n  ".join(repr(c) for c in claims)
    )


# ---------------------------------------------------------------------------
# block_a_blocked_source_class_however_redacted
# clear_a_cleared_source_class_whatever_the_overlay_residual
# ---------------------------------------------------------------------------
#
# The norm this replaces asked for proof that the gate never consults the
# overlay's residual. You cannot assert that a function does not read something.
# What you can assert is the pair of consequences: hold the source class fixed,
# move the overlay from "perfectly redacted" to "carrying a live identifier",
# and require the verdict not to move. If the gate ever started consulting
# residual, one of these two would break.

_BLOCKED_SOURCE = "Streng vertraulich - Mandantengeheimnis."
_CLEARED_SOURCE = "Projektnotiz zum Sprint."

#: A live, checksum-valid identifier. The point is that its presence in the
#: payload must NOT change a verdict that is about the source class.
_LIVE_RESIDUAL = "IBAN DE89370400440532013000 Karte 4111 1111 1111 1111"


def _verdict(text: str, destination: str = "openai"):
    from privacy_shield.gate import PrivacyGate

    return PrivacyGate()._decide_local({"text": text}, destination)


def test_a_blocked_source_class_stays_blocked_however_well_it_was_redacted():
    """`block_a_blocked_source_class_however_redacted`.

    A privileged document that redaction emptied is still privileged. Gating on
    residual would clear it, which is the failure the original norm was written
    against.
    """
    with_residual = _verdict(f"{_BLOCKED_SOURCE} {_LIVE_RESIDUAL}")
    perfectly_redacted = _verdict(f"{_BLOCKED_SOURCE} [IBAN] [CREDIT_CARD]")

    assert not with_residual.allowed
    assert not perfectly_redacted.allowed, (
        "an over-redacted privileged document was cleared for egress; the "
        "verdict moved with the overlay's residual instead of with the source "
        f"class ({perfectly_redacted.classification})"
    )
    assert with_residual.classification == perfectly_redacted.classification


def test_a_cleared_source_class_stays_cleared_whatever_residual_it_carries():
    """`clear_a_cleared_source_class_whatever_the_overlay_residual`.

    The other direction, and the one that would catch the gate quietly growing
    a residual check: an ordinary document does not become blocked because its
    overlay still holds something that looks like an identifier.
    """
    clean = _verdict(_CLEARED_SOURCE)
    assert clean.allowed, "an ordinary document was blocked before residual entered it"

    with_residual = _verdict(f"{_CLEARED_SOURCE} {_LIVE_RESIDUAL}")
    assert with_residual.allowed == clean.allowed, (
        "the egress verdict moved when residual was added to an ordinary "
        "document, so the gate is deciding on overlay residual rather than on "
        f"source classification (was {clean.classification}, now "
        f"{with_residual.classification})"
    )


def test_the_verdict_tracks_the_source_class_and_nothing_else():
    """Both directions in one statement, across the tiers that matter.

    Holds the residual constant and moves only the source class: the verdict
    must follow the class. Together with the two tests above this pins the
    verdict to one variable.
    """
    residual = _LIVE_RESIDUAL
    for source, expected_allowed in (
        ("Projektnotiz zum Sprint.", True),
        ("Streng vertraulich.", False),
        ("Mandantengeheimnis, anwaltlich.", False),
    ):
        result = _verdict(f"{source} {residual}")
        assert result.allowed is expected_allowed, (
            f"{source!r} with residual present: allowed={result.allowed}, "
            f"expected {expected_allowed} (classification "
            f"{result.classification!r})"
        )


# ---------------------------------------------------------------------------
# The guard over the prohibition, guarded
# ---------------------------------------------------------------------------
#
# `_affirmative_zero_residual_claims` is the only thing standing between the
# documents and `prohibited: claim_zero_residual_in_any_shipped_document`. A
# porous guard over a prohibition is worse than none: it reads as enforcement.
# Each case below defeated the shipped guard and is pinned so it cannot return.

_BYPASSES = [
    # A negator in the PREVIOUS sentence, excused by a fixed 90-char lookback.
    "The overlay is not a transcript of the source document. "
    "Cleared certifies zero residual PII in every case.",
    "There is no charge for this feature. Cleared guarantees zero residual PII.",
    # A negator in the same sentence but belonging to a different clause.
    "No operator should be in doubt: cleared guarantees zero residual PII.",
    # A backtick twelve characters along made the mention look like a slug.
    "Cleared certifies zero residual in the `overlay` we ship.",
]

#: Naming the norm, disclaiming it, or quoting the slug is not making the claim.
_LEGITIMATE = [
    '"Cleared" means the source class is allowed to egress, not a '
    "zero-residual certificate.",
    "The block prohibits claim_zero_residual_in_any_shipped_document.",
    "See `claim_zero_residual_in_any_shipped_document` in the manifest.",
    "This is never a zero-residual guarantee.",
]


@pytest.mark.parametrize("text", _BYPASSES)
def test_a_known_bypass_of_the_zero_residual_guard_is_caught(text):
    assert _affirmative_zero_residual_claims(text), (
        f"the guard over the prohibition let this through: {text!r}"
    )


@pytest.mark.parametrize("text", _LEGITIMATE)
def test_naming_or_disclaiming_the_norm_is_not_the_claim(text):
    assert not _affirmative_zero_residual_claims(text), (
        f"the guard flagged text that names or disclaims the norm: {text!r}"
    )


# ---------------------------------------------------------------------------
# every_decision_written_to_the_audit_trail
# ---------------------------------------------------------------------------
#
# PO decision (2026-09-26): kept, made true of what THIS SKILL does rather
# than of the library's own default, which is opt-in (gate.py) and writes
# nothing on its own. SKILL.md documents one fixed invocation; this pins it
# by extracting and RUNNING that exact line, so editing the doc to drop
# --audit/--audit-log breaks the test instead of silently untruthing the
# obligation.

_INVOCATION_BLOCK = re.compile(r"```\nprivacy-shield scan <path\|-\|text> (.+)\n```")


def _documented_invocation_flags() -> list[str]:
    match = _INVOCATION_BLOCK.search(_text("skills/privacy-shield/SKILL.md"))
    assert match, (
        "SKILL.md no longer documents a fixed `privacy-shield scan "
        "<path|-|text> ...` invocation for this test to hold"
    )
    return match.group(1).split()


def _skill_md_body() -> str:
    """SKILL.md's body, past the frontmatter: the allowed-tools line names
    `privacy_scan` without describing a call and must not count as one."""
    return SKILL_MD.read_text(encoding="utf-8").split("---\n", 2)[2]


_FENCE = re.compile(r"```\n(.*?)\n```", re.DOTALL)

#: The ONLY prose paragraph (outside a fenced block) allowed to mention
#: `privacy_scan` at all. A substring check ("mentions audit_log_path
#: somewhere nearby") passed an inverted instruction ("Never pass
#: audit_log_path; leave it unset") that also happens to mention the name;
#: pinning the exact paragraph, rather than searching for a keyword, is what
#: catches that class of mutation.
_ALLOWED_PRIVACY_SCAN_PROSE = (
    "Enriched path, when `loomground-mcp` is installed and running: call the\n"
    "`privacy_scan` tool as:",
)


def _fenced_blocks(text: str) -> list[str]:
    return _FENCE.findall(text)


def _prose_outside_fences(text: str) -> str:
    return _FENCE.sub("", text)


def test_every_documented_privacy_scan_call_is_a_pinned_fenced_call_with_audit_log_path():
    """F4: the MCP tool's own default is `audit_log_path=None` (silent, same
    as the library) - loomground_mcp/tools/applied.py:61-84, read read-only
    from the installed package, not edited here.

    Three ways this obligation can go quietly false again, each closed here:

    1. The fenced `privacy_scan(...)` call itself drops `audit_log_path=`, or
       keeps the keyword but stops pointing it at `privacy-shield audit-path`
       (e.g. reverting to the unreachable `python -c` form, or a bare
       placeholder nobody can act on).
    2. A prose paragraph OUTSIDE any fence tells the agent something
       different - up to and including the inverted instruction "Never pass
       audit_log_path; leave it unset" - which a substring/keyword check
       cannot distinguish from a paragraph that correctly requires it,
       because both mention both words. Every non-fenced paragraph
       mentioning `privacy_scan` must match the pinned allow-list exactly;
       anything else fails, inverted or not.
    3. The `privacy-shield audit-path` command named in the doc does not
       actually print `audit_log_path()` - checked by running it for real.
    """
    body = _skill_md_body()

    # (1) Every fenced privacy_scan(...) call passes audit_log_path=
    # pointing at `privacy-shield audit-path`.
    calls = [b for b in _fenced_blocks(body) if "privacy_scan(" in b]
    assert calls, "SKILL.md no longer documents a fenced privacy_scan(...) call"
    for call in calls:
        assert "audit_log_path=" in call, (
            f"a documented privacy_scan call does not pass audit_log_path=:\n{call}"
        )
        match = re.search(r"audit_log_path=(\S.*?)(?:,\s*\w+=|\)\s*$)", call, re.DOTALL)
        assert match, f"could not isolate the audit_log_path= value in:\n{call}"
        assert "privacy-shield audit-path" in match.group(1), (
            f"audit_log_path= is not sourced from `privacy-shield audit-path`:\n{call}"
        )

    # (2) Every OUTSIDE-fence paragraph mentioning privacy_scan is one of the
    # pinned, allow-listed ones - not a keyword search.
    prose = _prose_outside_fences(body)
    paragraphs = [p.strip() for p in prose.split("\n\n") if "privacy_scan" in p]
    unpinned = [p for p in paragraphs if p not in _ALLOWED_PRIVACY_SCAN_PROSE]
    assert not unpinned, (
        "a prose paragraph mentioning privacy_scan outside a fenced block is "
        "not on the pinned allow-list (this catches an inverted instruction "
        "a substring check would miss):\n  " + "\n  ---\n  ".join(unpinned)
    )

    # (3) `privacy-shield audit-path`, run for real, prints audit_log_path().
    assert "privacy-shield audit-path" in body, (
        "SKILL.md no longer names the `privacy-shield audit-path` command at all"
    )
    from privacy_shield import cli
    from privacy_shield.audit_log import audit_log_path
    import io
    import contextlib

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(["audit-path"])
    assert code == 0
    assert out.getvalue().strip() == str(audit_log_path())

    # (4) The command SKILL.md tells the agent to run is actually permitted
    # by its own allowed-tools grant.
    allowed_tools = SKILL_MD.read_text(encoding="utf-8").split("---\n", 2)[1]
    assert re.search(r"Bash\(privacy-shield:\*\)", allowed_tools), (
        "SKILL.md documents running `privacy-shield audit-path` but its "
        "allowed-tools grant no longer permits a Bash(privacy-shield:*) call"
    )


def test_skill_md_documents_an_audit_opt_in_invocation():
    flags = _documented_invocation_flags()
    assert "--audit" in flags or "--audit-log" in flags, (
        f"the documented invocation flags {flags!r} opt into neither --audit "
        f"nor --audit-log, so every_decision_written_to_the_audit_trail is "
        f"false of what this skill actually runs"
    )


def test_the_documented_invocation_actually_writes_the_audit_trail(tmp_path, caplog):
    """F3: shield.py's own write used to fail silently into a logged error on
    a fresh HOME (no parent dir yet) - is_file() alone did not catch that the
    shield's own entry was lost while the gate's still landed. Pinned here on
    the exact invocation SKILL.md documents, not just any scan().
    """
    import json as json_mod

    from privacy_shield import cli
    from privacy_shield.audit_log import AuditEvent, audit_log_path

    flags = _documented_invocation_flags()
    code = cli.main(["scan", "hello there", "--text", *flags])
    assert code == 0

    if "--audit-log" in flags:
        path = Path(flags[flags.index("--audit-log") + 1])
    else:
        path = audit_log_path()
    assert path.is_file(), (
        f"the skill's documented invocation ({['scan', 'hello there', '--text', *flags]}) "
        f"did not write an audit record at {path}"
    )
    events = [
        json_mod.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    gate_events = [e for e in events if e.get("event") == AuditEvent.AI_PRIVACY_SHIELD_DECISION.value]
    shield_events = [e for e in events if "event" not in e]
    assert len(gate_events) == 1, f"expected 1 gate entry, got {len(gate_events)}: {events}"
    assert len(shield_events) == 1, f"expected 1 shield entry, got {len(shield_events)}: {events}"
    assert not any("Audit logging failed" in r.message for r in caplog.records)
