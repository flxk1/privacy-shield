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

#: The paragraph that tells the agent how to get audit_log_path and what
#: destination means - pinned verbatim because it does not mention
#: `privacy_scan` by name (it says "this tool"/"this call") and so would
#: never be caught by the allow-list above if reworded or replaced.
_RUN_AUDIT_PATH_PARAGRAPH = (
    "Run `privacy-shield audit-path` first — permitted by `Bash(privacy-shield:*)`,\n"
    "prints the standard user-state audit path (honouring\n"
    "`PRIVACY_SHIELD_AUDIT_LOG`) and writes nothing — for the `audit_log_path`\n"
    "value above. `text` is the only input this tool accepts, forced to raw text:\n"
    "a file or folder goes through the CLI instead\n"
    "(`privacy-shield scan <path> --audit`), never through this call. `destination`\n"
    "is the EGRESS TARGET (`external_llm`, `openai`, `datev`, ...), never a\n"
    "classification: the gate computes the source classification from `text`\n"
    "itself and blocks or allows on it, so a non-external value there — passing a\n"
    "classification word instead of a real destination — skips every block rule\n"
    "and clears data that should have been refused. The result includes the clean\n"
    "overlay, span findings and egress verdict; only the overlay may be used for a\n"
    "subsequent external call. Without `loomground-mcp`, fall back to the primary\n"
    "path above — see `degrade_gracefully_without_optional_extras` below."
)

#: The installed loomground_mcp privacy_scan signature, verified read-only
#: via AST against the installed package (not edited by this repo):
#: text, mode, destination, redaction_mode, min_confidence, audit_log_path,
#: tenant_id, user_id, hash_salt. `text` has no default (required); the rest
#: do. Any keyword the fenced call passes must be one of these.
_PRIVACY_SCAN_PARAMS = frozenset({
    "text", "mode", "destination", "redaction_mode", "min_confidence",
    "audit_log_path", "tenant_id", "user_id", "hash_salt",
})

_AUDIT_LOG_PATH_PLACEHOLDER = "<output of `privacy-shield audit-path`>"


def _fenced_blocks(text: str) -> list[str]:
    return _FENCE.findall(text)


def _prose_outside_fences(text: str) -> str:
    return _FENCE.sub("", text)


def _split_top_level_commas(s: str) -> list[str]:
    """Split on commas at <...> placeholder depth 0. A real ast.parse chokes
    on a placeholder like `<egress target, e.g. external_llm>`, whose own
    comma is not an argument separator; a plain split(",") would cut it in
    half."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in s:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current))
    return parts


def _parse_call(call_source: str) -> tuple[str, dict[str, str]]:
    """Parse `name(kw=value, kw=value, ...)`, tolerating the <...>
    placeholders above. Returns (name, {keyword: raw_value_text})."""
    open_paren = call_source.index("(")
    name = call_source[:open_paren].strip()
    inner = call_source[open_paren + 1:call_source.rindex(")")]
    kwargs: dict[str, str] = {}
    for part in _split_top_level_commas(inner):
        part = part.strip()
        if not part:
            continue
        key, sep, value = part.partition("=")
        assert sep, f"positional argument {part!r} in a keyword-only call: {call_source!r}"
        kwargs[key.strip()] = value.strip()
    return name, kwargs


def test_every_documented_privacy_scan_call_is_a_pinned_fenced_call_with_audit_log_path():
    """F4: the MCP tool's own default is `audit_log_path=None` (silent, same
    as the library) - loomground_mcp/tools/applied.py:61-84, read read-only
    from the installed package, not edited here.

    What this test checks, exactly - and no more:

    1. Each fence contains exactly one `privacy_scan(` call and no `#`
       comment lines - a second call, or a commented-out alternative,
       inside the one fence a reader is shown would be ambiguous about
       which is documented.
    2. That call is parsed (a hand-written parser, not `ast.parse` - the
       `<...>` placeholders are not valid Python literals) and every
       keyword it passes is one of the installed function's own parameter
       names (`_PRIVACY_SCAN_PARAMS`, verified by AST above); `text` is
       present (the tool's only required parameter; there is no `target`);
       `audit_log_path`'s value is EXACTLY the pinned placeholder text (not
       merely containing the phrase, so `None` or a bare unexplained
       placeholder both fail); `destination`'s example value (after
       "e.g.") is a real external destination
       (`privacy_shield.gate._EXTERNAL_DESTINATIONS`) - a classification
       word there silently disables every block rule (verified against the
       gate below).
    3. If `loomground_mcp` is importable, the same keywords are additionally
       bound against the REAL function's signature with
       `inspect.signature(...).bind_partial` - a second, independent check
       that does not depend on this test's own pinned parameter set being
       current. Skipped, not failed, when the package is absent (the CLI
       and this test both work standalone).
    4. Two paragraphs are pinned VERBATIM: the one prose sentence outside
       any fence allowed to mention `privacy_scan` at all
       (`_ALLOWED_PRIVACY_SCAN_PROSE` - any other paragraph mentioning it,
       inverted or not, fails), and the paragraph that explains
       `audit_log_path`/`destination` and does not itself say
       "privacy_scan" (`_RUN_AUDIT_PATH_PARAGRAPH` - it would not be caught
       by the allow-list above if reworded, since it never names the tool).
    5. `privacy-shield audit-path` is run for real (not just named in the
       text) and its stdout is compared to `audit_log_path()`.
    6. The `allowed-tools` VALUE, parsed from the YAML frontmatter with
       `yaml.safe_load` (not a text search over the raw frontmatter, which
       a commented-out copy of the real grant would also satisfy), contains
       an entry starting `Bash(privacy-shield`.

    Out of reach of this test: free-text prose ANYWHERE else in the
    document that tells the agent something wrong about `privacy_scan`
    without naming the pinned paragraphs above or using the word
    `privacy_scan` outside a fence - inversion in unconstrained prose is
    not provable by a fixed regex or allow-list; the pins above hold the
    specific paragraphs this obligation is grounded in.
    """
    body = _skill_md_body()

    # (1) Exactly one privacy_scan( call per fence, no comment lines.
    fences_with_call = [b for b in _fenced_blocks(body) if "privacy_scan(" in b]
    assert fences_with_call, "SKILL.md no longer documents a fenced privacy_scan(...) call"
    for fence in fences_with_call:
        assert fence.count("privacy_scan(") == 1, (
            f"more than one privacy_scan( call in one fence:\n{fence}"
        )
        assert "#" not in fence, f"a comment line in the fenced call:\n{fence}"

    # (2) Parse each call; check keywords, text, audit_log_path, destination.
    from privacy_shield.gate import _EXTERNAL_DESTINATIONS

    for fence in fences_with_call:
        name, kwargs = _parse_call(fence.strip())
        assert name == "privacy_scan", f"unexpected call name {name!r} in:\n{fence}"

        unknown = set(kwargs) - _PRIVACY_SCAN_PARAMS
        assert not unknown, (
            f"keyword(s) {unknown} are not real privacy_scan parameters "
            f"({sorted(_PRIVACY_SCAN_PARAMS)}):\n{fence}"
        )
        assert "text" in kwargs, (
            f"privacy_scan's only required parameter is `text` (there is no "
            f"`target`), missing from:\n{fence}"
        )

        assert kwargs.get("audit_log_path") == _AUDIT_LOG_PATH_PLACEHOLDER, (
            f"audit_log_path= is not exactly {_AUDIT_LOG_PATH_PLACEHOLDER!r} "
            f"(got {kwargs.get('audit_log_path')!r}) in:\n{fence}"
        )

        destination_value = kwargs.get("destination", "")
        example = re.search(r"e\.g\.\s*([A-Za-z0-9_]+)", destination_value)
        assert example, (
            f"destination= gives no `e.g. <value>` example to check against "
            f"the gate's real external destinations:\n{fence}"
        )
        assert example.group(1) in _EXTERNAL_DESTINATIONS, (
            f"destination='s example value {example.group(1)!r} is not a real "
            f"external destination ({sorted(_EXTERNAL_DESTINATIONS)}) - a "
            f"classification word there disables every block rule:\n{fence}"
        )

        # (3) Bind against the REAL installed signature too, when available.
        try:
            import loomground_mcp.tools.applied as applied
        except ImportError:
            applied = None
        if applied is not None:
            import inspect

            sig = inspect.signature(applied.privacy_scan)
            sig.bind_partial(**{k: v for k, v in kwargs.items()})

    # (4a) The one allowed prose sentence outside any fence.
    prose = _prose_outside_fences(body)
    paragraphs = [p.strip() for p in prose.split("\n\n")]
    mentioning = [p for p in paragraphs if "privacy_scan" in p]
    unpinned = [p for p in mentioning if p not in _ALLOWED_PRIVACY_SCAN_PROSE]
    assert not unpinned, (
        "a prose paragraph mentioning privacy_scan outside a fenced block is "
        "not on the pinned allow-list (this catches an inverted instruction "
        "a substring check would miss):\n  " + "\n  ---\n  ".join(unpinned)
    )

    # (4b) The audit-path/destination explainer paragraph, pinned verbatim.
    assert _RUN_AUDIT_PATH_PARAGRAPH in paragraphs, (
        "the paragraph explaining audit_log_path/destination no longer "
        "matches the pinned text (it never says \"privacy_scan\" itself, so "
        "the allow-list above cannot catch a rewording of it)"
    )

    # (5) `privacy-shield audit-path`, run for real, prints audit_log_path().
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

    # (6) allowed-tools, parsed structurally (yaml.safe_load), not by text
    # search over the raw frontmatter - a commented-out copy of the real
    # grant elsewhere in the frontmatter must not satisfy a text search.
    yaml = pytest.importorskip("yaml")
    frontmatter = yaml.safe_load(SKILL_MD.read_text(encoding="utf-8").split("---\n", 2)[1])
    allowed_tools = frontmatter["allowed-tools"]
    entries = [e.strip() for e in allowed_tools.split(",")]
    assert any(e.startswith("Bash(privacy-shield") for e in entries), (
        f"allowed-tools ({allowed_tools!r}) has no entry starting "
        f"Bash(privacy-shield, so `privacy-shield audit-path` is not permitted"
    )


def test_scan_blocks_a_berufsgeheimnis_text_bound_for_an_external_destination():
    """Grounds the doc's own claim: passing a real external `destination`
    (not a classification word) still gets a privileged document blocked.
    If this regresses, the doc's example destination stops meaning what the
    doc says it means.
    """
    from privacy_shield.runner import scan
    from privacy_shield.shield import PrivacyMode

    report = scan(
        "Streng vertraulich: Mandantengeheimnis, patient diabetes",
        mode=PrivacyMode.STANDARD,
        destination="external_llm",
        force_text=True,
    )
    assert report.documents[0].egress_allowed is False


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
