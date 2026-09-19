"""Tests for the governed-folder runner (``scan()``) and the CLI.

All fixtures are SYNTHETIC — fake PII generated here, never real data. The tests
prove:

- the runner walks a folder span by span and produces a clean overlay with the
  injected PII redacted (no injected value survives into the overlay);
- the egress verdict is correct (LOCAL_ONLY / berufsgeheimnis / Art. 9 block;
  a non-confidential PII doc passes);
- every decision is recorded to the standalone ``audit_log``;
- the runner attaches no external enforcement adapter;
- the CLI writes overlays and reports the right exit code.
"""

import json
from pathlib import Path

import pytest

from privacy_shield.audit_log import AuditEvent
from privacy_shield import cli
from privacy_shield.runner import (
    EXTENSION_FILTERED_CHOSEN,
    EXTENSION_FILTERED_DEFAULT,
    DocumentScan,
    ScanReport,
    scan,
)
from privacy_shield.shield import PrivacyMode

# Synthetic (fake) PII tokens used across the fixtures.
FAKE_EMAIL = "jane.roe@example.org"
FAKE_IBAN = "DE89370400440532013000"
FAKE_PHONE = "+49 30 12345678"
FAKE_CC = "4111 1111 1111 1111"


@pytest.fixture()
def temp_audit(tmp_path, monkeypatch):
    """Redirect the standalone audit trail (and breach log) to temp files.

    Keeps the tests hermetic: no writes to the tracked working tree, even on the
    blocking paths that notify the breach detector.
    """
    audit_file = tmp_path / "audit.jsonl"
    monkeypatch.setattr("privacy_shield.audit_log.AUDIT_LOG_PATH", audit_file)

    # The gate's block path lazily notifies the breach detector, which otherwise
    # writes under src/privacy_shield/data/. Redirect that singleton's log dir to temp.
    import privacy_shield.breach as breach_mod

    monkeypatch.setattr(
        breach_mod.breach_detector, "_BREACH_LOG_DIR", tmp_path / "breach", raising=False
    )

    def _read():
        if not audit_file.exists():
            return []
        return [
            json.loads(line)
            for line in audit_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    return _read


@pytest.fixture()
def pii_folder(tmp_path):
    """A folder of synthetic documents: two with fake PII, one plain."""
    root = tmp_path / "governed"
    root.mkdir()
    (root / "contact.txt").write_text(
        f"Email: {FAKE_EMAIL}\nPhone: {FAKE_PHONE}\n", encoding="utf-8"
    )
    (root / "payment.txt").write_text(
        f"IBAN: {FAKE_IBAN}\nCard: {FAKE_CC}\n", encoding="utf-8"
    )
    (root / "notes.md").write_text(
        "quarterly roadmap review scheduled for next week\n", encoding="utf-8"
    )
    # A nested file to prove recursion.
    sub = root / "sub"
    sub.mkdir()
    (sub / "more.txt").write_text(f"reach me at {FAKE_EMAIL}\n", encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# scan() — folder walk, clean overlay, span by span
# ---------------------------------------------------------------------------
def test_scan_folder_redacts_pii_span_by_span(pii_folder, temp_audit):
    report = scan(pii_folder, mode=PrivacyMode.STANDARD)

    assert isinstance(report, ScanReport)
    # Four files walked (incl. the nested one).
    assert report.document_count == 4
    assert all(isinstance(d, DocumentScan) for d in report.documents)

    by_source = {d.source: d for d in report.documents}
    contact = next(d for s, d in by_source.items() if s.endswith("contact.txt"))
    payment = next(d for s, d in by_source.items() if s.endswith("payment.txt"))

    # PII was found (spans) and the overlay carries NONE of the injected values.
    assert contact.span_count > 0
    for value in (FAKE_EMAIL, FAKE_PHONE):
        assert value not in contact.overlay
    for value in (FAKE_IBAN, FAKE_CC):
        assert value not in payment.overlay

    # Non-confidential PII docs are cleared for egress; the CLEAN overlay leaves.
    assert contact.egress_allowed is True
    assert payment.egress_allowed is True
    assert report.all_allowed is True

    # The gate recorded a decision per document to the standalone audit trail.
    events = temp_audit()
    decisions = [e for e in events if e["event"] == AuditEvent.AI_PRIVACY_SHIELD_DECISION.value]
    assert len(decisions) == report.document_count


def test_scan_raw_text_produces_overlay(temp_audit):
    report = scan(f"contact {FAKE_EMAIL} for details", mode=PrivacyMode.STANDARD)
    assert report.document_count == 1
    doc = report.documents[0]
    assert doc.source == "text_input"
    assert doc.pii_detected is True
    assert FAKE_EMAIL not in doc.overlay
    assert doc.egress_allowed is True


def test_scan_single_file(pii_folder, temp_audit):
    report = scan(pii_folder / "payment.txt", mode=PrivacyMode.STANDARD)
    assert report.document_count == 1
    assert FAKE_IBAN not in report.documents[0].overlay


# ---------------------------------------------------------------------------
# Egress verdict — unsafe blocks / safe passes
# ---------------------------------------------------------------------------
def test_local_only_blocks_all_external_egress(pii_folder, temp_audit):
    report = scan(pii_folder, mode=PrivacyMode.LOCAL_ONLY)
    assert report.all_allowed is False
    assert all(d.egress_allowed is False for d in report.documents)
    assert all("LOCAL_ONLY" in d.blocked_reason for d in report.documents)


def test_confidential_source_blocks_egress(temp_audit):
    report = scan(
        "this record is subject to steuergeheimnis and stays internal",
        mode=PrivacyMode.STANDARD,
    )
    doc = report.documents[0]
    assert doc.egress_allowed is False
    assert doc.classification == "berufsgeheimnis"


def test_art9_special_category_blocks_egress(temp_audit):
    report = scan(
        "patient diagnosis: diabetes; medication prescribed by the doctor",
        mode=PrivacyMode.STANDARD,
    )
    doc = report.documents[0]
    assert doc.egress_allowed is False
    assert doc.classification == "confidential"


def test_anonymous_json_mode_builds_placeholder_overlay(temp_audit):
    report = scan(f"send to {FAKE_EMAIL} and {FAKE_IBAN}", mode=PrivacyMode.ANONYMOUS_JSON)
    doc = report.documents[0]
    assert doc.placeholder_count >= 1
    assert FAKE_EMAIL not in doc.overlay
    assert FAKE_IBAN not in doc.overlay
    assert "ANON_" in doc.overlay


# ---------------------------------------------------------------------------
# No host adapter on the runner path
# ---------------------------------------------------------------------------
def test_runner_sources_attach_no_external_adapter():
    import pathlib

    from privacy_shield import runner as runner_mod

    for mod_file in ("runner.py", "cli.py"):
        text = (pathlib.Path(runner_mod.__file__).parent / mod_file).read_text()
        assert "ExternalEnforcementAdapter" not in text
        assert "attach_enforcement_sink" not in text


# ---------------------------------------------------------------------------
# Global privacy mode is restored after a scan
# ---------------------------------------------------------------------------
def test_global_privacy_mode_restored(temp_audit):
    from privacy_shield.shield import get_global_privacy_mode

    before = get_global_privacy_mode()
    scan("hello", mode=PrivacyMode.LOCAL_ONLY)
    assert get_global_privacy_mode() == before


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def test_cli_scan_writes_overlays_and_exits_zero(pii_folder, tmp_path, temp_audit, capsys):
    out_dir = tmp_path / "overlays"
    code = cli.main(["scan", str(pii_folder), "--out", str(out_dir)])
    assert code == 0  # every overlay cleared for egress
    written = list(out_dir.glob("*.overlay.txt"))
    assert len(written) == 4
    for path in written:
        assert FAKE_EMAIL not in path.read_text()
        assert FAKE_IBAN not in path.read_text()


def test_cli_local_only_exits_two(pii_folder, temp_audit):
    code = cli.main(["scan", str(pii_folder), "--mode", "LOCAL_ONLY"])
    assert code == 2  # blocked egress -> non-zero


def test_cli_human_output_names_the_cause_of_a_non_document_block(tmp_path, capsys):
    """Reproduced: one ordinary `.txt` file, one `.png` - no flags.

    Every listed document was `[ALLOW]`, `BLOCKED: 0 document(s)` read as
    "nothing is wrong", and `logo.png` - the only reason the exit code was 2
    - was named nowhere in the human output. That trains an operator to
    ignore exit 2; the file, or walk-level cause, that tripped it has to be
    on the screen.
    """
    root = tmp_path / "folder"
    root.mkdir()
    (root / "ok.txt").write_text("hello world\n", encoding="utf-8")
    (root / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n")

    code = cli.main(["scan", str(root)])
    out = capsys.readouterr().out

    assert code == 2
    assert "all_allowed: False" in out
    # The per-document section still shows nothing blocked - that is correct,
    # not the defect. The defect was that nothing ELSE named the cause.
    assert "[ALLOW] " in out
    assert "logo.png" in out, "the file that caused exit 2 is not named anywhere"
    assert "skipped by the default extension scope" in out


def test_cli_human_output_names_a_chosen_filter_that_matched_nothing(tmp_path, capsys):
    """Reproduced: `--extensions .txtt` (a typo) on a folder with two real,
    PII-bearing `.txt` documents.

    `documents: 0  all_allowed: True  EXIT=0` is the CORRECT verdict - the
    caller chose that scope, on purpose, and a chosen filter must not move
    `all_allowed` (tested elsewhere). What was missing is that NEITHER file
    was named anywhere in the output: `chosen_filtered_files` held both the
    whole time, but the entire cause block only printed when `all_allowed`
    was False, and a chosen filter is exactly the case where it stays True.
    A folder that matched nothing because of a typo was indistinguishable
    from an empty, fully-read folder. The same gap, `--extensions ,` (an
    empty frozenset) reproduces identically.
    """
    root = tmp_path / "folder"
    root.mkdir()
    (root / "contact.txt").write_text(
        f"mail me at {FAKE_EMAIL}\n", encoding="utf-8"
    )
    (root / "payment.txt").write_text(f"IBAN {FAKE_IBAN}\n", encoding="utf-8")

    for extensions in (".txtt", ","):
        code = cli.main(["scan", str(root), "--extensions", extensions])
        out = capsys.readouterr().out

        assert code == 0, f"a caller-chosen scope moved the exit code ({extensions!r})"
        assert "documents: 0" in out
        assert "all_allowed: True" in out
        assert "contact.txt" in out, (
            f"a real file skipped by extensions={extensions!r} is named nowhere"
        )
        assert "payment.txt" in out
        assert "extensions scope you chose" in out


def test_cli_json_output(pii_folder, temp_audit, capsys):
    code = cli.main(["scan", str(pii_folder), "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["document_count"] == 4
    assert payload["all_allowed"] is True
    assert "documents" in payload


def test_json_walk_errors_keep_kind_a_consumer_must_not_reconstruct(tmp_path):
    """`WalkError`'s own docstring: `message` carries an OS-reported filename
    and MUST NOT be parsed to recover `kind` - that parsing IS the defect
    commit 5b6c4b5 closed. `to_dict()` used to flatten `walk_errors` to bare
    strings with `[str(e) for e in self.walk_errors]`, throwing `kind` away
    at exactly the boundary an agent or a shell script consumes and would
    otherwise be tempted to re-derive it the same unsafe way.
    """
    import os

    root_name = "extension_filtered_chosen_docs"
    root = tmp_path / root_name
    root.mkdir()
    (root / "readable.txt").write_text("nichts\n", encoding="utf-8")
    locked = root / "locked"
    locked.mkdir()
    (locked / "hidden.txt").write_text("nichts", encoding="utf-8")
    os.chmod(locked, 0o000)
    try:
        report = scan(str(root), extensions=frozenset({".txt"}))
        payload = report.to_dict()

        assert payload["walk_errors"], "no walk_errors surfaced at all"
        for entry in payload["walk_errors"]:
            assert set(entry) == {"kind", "message"}, entry
        kinds = {entry["kind"] for entry in payload["walk_errors"]}
        assert "unreadable" in kinds, (
            "the permission error's kind did not survive into the JSON payload"
        )
        assert "unreadable_errors" in payload
        assert payload["unreadable_errors"] == report.unreadable_errors
        # And it must NOT be recoverable by re-parsing message text, the
        # exact thing the docstring warns against and the reproduced defect
        # was doing.
        assert not any(
            entry["message"].startswith("extension_filtered_chosen")
            and entry["kind"] != "unreadable"
            for entry in payload["walk_errors"]
        )
    finally:
        os.chmod(locked, 0o755)


def test_cli_reads_text_from_stdin(temp_audit, monkeypatch, capsys):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO(f"mail {FAKE_EMAIL}"))
    code = cli.main(["scan", "-", "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["documents"][0]["source"] == "text_input"
    assert FAKE_EMAIL not in payload["documents"][0]["overlay"]

from privacy_shield import scan


# ---------------------------------------------------------------------------
# A folder scan that could not read everything is not a clean result
# ---------------------------------------------------------------------------

def test_an_unreadable_directory_does_not_silently_truncate_the_scan(tmp_path):
    """A generator that raises is finished.

    The walk caught OSError around `next()`, which cannot work: the following
    `next()` raises StopIteration and the loop exits. On 3.14 `rglob` swallows
    the error internally so the handler never fired; on 3.10, where
    PermissionError propagates, it turned a loud crash into a silent partial
    scan certified `all_allowed=True`. For an egress gate that is worse than
    the crash it replaced.
    """
    import os

    readable = tmp_path / "readable.txt"
    readable.write_text("Karte 4111 1111 1111 1111\n", encoding="utf-8")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "hidden.txt").write_text("nichts", encoding="utf-8")
    os.chmod(locked, 0o000)
    try:
        report = scan(str(tmp_path))
        # The readable document is still scanned...
        assert report.document_count >= 1
        # ...and the gap is REPORTED, not swallowed.
        assert report.walk_errors, "an unreadable directory was not reported"
        assert report.scan_complete is False
        # ...and nothing about the folder is certified.
        assert report.all_allowed is False, (
            "a folder scan that skipped an unreadable directory was certified "
            "as cleared for egress"
        )
        assert report.to_dict()["walk_errors"], "not surfaced in the report dict"
    finally:
        os.chmod(locked, 0o755)


def test_an_unreadable_directory_named_like_a_filter_tag_is_not_misclassified(
    tmp_path, monkeypatch
):
    """Reproduced: a RELATIVE root whose name begins with the filter tag.

    `_record` used to write `f"{error.filename}: {error.strerror}"` into the
    same list `str.startswith` then sorted into imposed / chosen / unreadable.
    `error.filename` is the OS-reported path - filesystem-controlled text,
    not this package's - and for a relative root it is exactly what `os.walk`
    was given plus what it found: a directory named
    `extension_filtered_chosen_docs`, containing an unreadable `locked`
    subdirectory, produces the message
    `"extension_filtered_chosen_docs/locked: Permission denied"`, which
    starts with the CHOSEN-filter tag though nothing was filtered and no
    extension was ever consulted. It was sorted into `chosen_filtered_files`
    - which does not move `all_allowed` - and vanished from
    `unreadable_errors`, which does. The scan reported `all_allowed = True`
    over a directory it never read.
    """
    import os

    root_name = "extension_filtered_chosen_docs"
    monkeypatch.chdir(tmp_path)
    root = Path(root_name)
    root.mkdir()
    (root / "readable.txt").write_text("Karte 4111 1111 1111 1111\n", encoding="utf-8")
    locked = root / "locked"
    locked.mkdir()
    (locked / "hidden.txt").write_text("nichts", encoding="utf-8")
    os.chmod(locked, 0o000)
    try:
        # A CHOSEN extensions filter, exactly as reproduced - the shape that
        # must not, on its own, clear `all_allowed`.
        report = scan(root_name, extensions=frozenset({".txt"}))

        assert report.document_count >= 1, "the readable file was not scanned"
        assert any(root_name in str(e) for e in report.walk_errors), (
            "the locked directory left no trace in walk_errors"
        )

        # The permission error is genuinely UNREADABLE, whatever its message
        # happens to start with.
        assert any(root_name in e for e in report.unreadable_errors), (
            "an unreadable directory was classified away by a message that "
            "happens to start with a filter tag"
        )
        assert not any(root_name in e for e in report.chosen_filtered_files), (
            "a permission error was reported as a chosen extension skip"
        )

        assert report.scan_complete is False
        assert report.all_allowed is False, (
            "all_allowed was certified True over a directory the walk could "
            "not read, because its OS-reported path happened to start with "
            "the chosen-filter tag"
        )
    finally:
        os.chmod(locked, 0o755)


def test_walk_error_kind_is_set_by_the_branch_not_read_from_the_message():
    """The structural guarantee: `kind` is a field of its own.

    A `WalkError` constructed with an UNREADABLE kind and a message that
    textually looks like every filter tag stays UNREADABLE - there is no
    parse step left that could disagree with the constructor.
    """
    from privacy_shield.runner import WalkError, WalkErrorKind

    error = WalkError(
        WalkErrorKind.UNREADABLE,
        f"{EXTENSION_FILTERED_CHOSEN}: {EXTENSION_FILTERED_DEFAULT}: whatever text",
    )
    report = ScanReport(mode="STANDARD", destination="x", root="r", walk_errors=[error])

    assert report.unreadable_errors == [str(error)]
    assert report.chosen_filtered_files == []
    assert report.imposed_filtered_files == []
    assert report.all_allowed is False


def test_a_complete_folder_scan_is_still_certifiable(tmp_path):
    """The incompleteness rule must not make every folder uncertifiable."""
    (tmp_path / "a.txt").write_text("Nur Text ohne Daten.\n", encoding="utf-8")
    report = scan(str(tmp_path))
    assert report.walk_errors == []
    assert report.scan_complete is True


# ---------------------------------------------------------------------------
# A file the walk saw and did not open because of `extensions` is a third way
# a document goes unread - it must be recorded and it must not certify clean,
# the same way an unreadable directory already does not.
#
# The line that decides `all_allowed` is not "was a filter applied" but "did
# the caller choose it": a default the caller never named (`extensions` not
# passed at all -> `DEFAULT_EXTENSIONS` IMPOSED) hides a file from someone
# with no way to know it fell out, and that is not different in kind from an
# unreadable directory. A filter the caller passed explicitly - including
# `DEFAULT_EXTENSIONS` by hand - is CHOSEN: recorded, and it still clears
# `scan_complete`, but it does not move `all_allowed`.
#
# These extensions are chosen independently of `runner.DEFAULT_EXTENSIONS` and
# hardcoded: the point is observable behaviour (exit code, `all_allowed`,
# `scan_complete`, the report entry), not agreement with the table the code
# under test consults.
# ---------------------------------------------------------------------------
def test_imposed_default_extension_filter_breaks_all_allowed(tmp_path):
    """The reproduced case: no `extensions` argument at all."""
    root = tmp_path / "governed"
    root.mkdir()
    (root / "bank.xlsx").write_text(f"IBAN: {FAKE_IBAN}\n", encoding="utf-8")
    (root / "contact.eml").write_text(f"From: {FAKE_EMAIL}\n", encoding="utf-8")

    report = scan(root)  # extensions not passed - DEFAULT_EXTENSIONS imposed

    # Neither file was opened - a scan that never read them cannot report on
    # what they contain.
    assert report.document_count == 0

    # The skip is RECORDED, distinguishably from an unreadable directory and
    # from a CHOSEN filter.
    assert report.walk_errors, "a filtered-out file was not reported at all"
    assert report.filtered_files, "filtered_files did not surface the skip"
    assert report.imposed_filtered_files, "the imposed skip was not tagged as imposed"
    assert report.chosen_filtered_files == []
    assert any("bank.xlsx" in e for e in report.imposed_filtered_files)
    assert any("contact.eml" in e for e in report.imposed_filtered_files)
    from privacy_shield.runner import EXTENSION_FILTERED_DEFAULT

    assert all(e.startswith(EXTENSION_FILTERED_DEFAULT) for e in report.imposed_filtered_files)

    # A scan that skipped files never reports itself complete.
    assert report.scan_complete is False
    # An imposed filter the caller had no way to know about DOES break
    # `all_allowed` - the caller asked for "the folder" and got less back,
    # silently, the same shape as an unreadable directory.
    assert report.unreadable_errors == []
    assert report.all_allowed is False

    payload = report.to_dict()
    assert payload["walk_errors"]
    assert payload["imposed_filtered_files"]
    assert payload["chosen_filtered_files"] == []
    assert payload["scan_complete"] is False
    assert payload["all_allowed"] is False


def test_imposed_default_extension_filter_is_reported_by_the_cli_with_exit_2(tmp_path, temp_audit):
    """The exact defect this closes, run through the real entry point:
    `privacy-shield scan <folder> --json` on such a folder used to print
    `all_allowed = True | scan_complete = True | documents = 0` and exit 0,
    with nothing anywhere in the report distinguishing it from an empty,
    fully-read folder. Reproduced and verified by the coordinator directly.
    """
    root = tmp_path / "governed"
    root.mkdir()
    (root / "bank.xlsx").write_text(f"IBAN: {FAKE_IBAN}\n", encoding="utf-8")
    (root / "contact.eml").write_text(f"From: {FAKE_EMAIL}\n", encoding="utf-8")

    import io
    import contextlib

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(["scan", str(root), "--json"])

    assert code == 2, "an imposed filter that skipped files exited 0"
    payload = json.loads(out.getvalue())
    assert payload["document_count"] == 0
    assert payload["all_allowed"] is False
    assert payload["scan_complete"] is False, (
        "the folder was reported complete though two files were never read"
    )
    assert payload["imposed_filtered_files"], "the skip left no trace in the report"


def test_chosen_extension_filter_is_recorded_but_does_not_break_all_allowed(tmp_path):
    """The counterpart: the caller names a scope on purpose."""
    root = tmp_path / "governed"
    root.mkdir()
    (root / "bank.xlsx").write_text(f"IBAN: {FAKE_IBAN}\n", encoding="utf-8")
    (root / "contact.eml").write_text(f"From: {FAKE_EMAIL}\n", encoding="utf-8")

    report = scan(root, extensions=frozenset({".txt"}))

    assert report.document_count == 0
    assert report.chosen_filtered_files, "the chosen skip was not recorded"
    assert report.imposed_filtered_files == []
    from privacy_shield.runner import EXTENSION_FILTERED_CHOSEN

    assert all(e.startswith(EXTENSION_FILTERED_CHOSEN) for e in report.chosen_filtered_files)

    # Still incomplete - a scope decision is still a decision about what got
    # looked at, not a claim the rest was read.
    assert report.scan_complete is False
    # But NOT less trustworthy about what it DID read: the caller knew the
    # scope and excluded these files on purpose.
    assert report.unreadable_errors == []
    assert report.all_allowed is True


def test_chosen_extension_filter_via_the_cli_exits_0(tmp_path, temp_audit):
    root = tmp_path / "governed"
    root.mkdir()
    (root / "bank.xlsx").write_text(f"IBAN: {FAKE_IBAN}\n", encoding="utf-8")
    (root / "contact.eml").write_text(f"From: {FAKE_EMAIL}\n", encoding="utf-8")
    (root / "notes.txt").write_text("kein Fund", encoding="utf-8")

    import io
    import contextlib

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(["scan", str(root), "--extensions", ".txt", "--json"])

    assert code == 0
    payload = json.loads(out.getvalue())
    assert payload["document_count"] == 1
    assert payload["all_allowed"] is True
    assert payload["scan_complete"] is False
    assert payload["chosen_filtered_files"]
    assert payload["imposed_filtered_files"] == []


def test_naming_default_extensions_explicitly_is_still_a_choice(tmp_path):
    """The trap: an identity check (`extensions is DEFAULT_EXTENSIONS`) would
    misclassify a caller who names the default set by hand as "did not
    choose". A caller who writes the words `extensions=DEFAULT_EXTENSIONS`
    knows exactly what that excludes."""
    from privacy_shield.runner import DEFAULT_EXTENSIONS

    root = tmp_path / "governed"
    root.mkdir()
    (root / "bank.xlsx").write_text(f"IBAN: {FAKE_IBAN}\n", encoding="utf-8")

    report = scan(root, extensions=DEFAULT_EXTENSIONS)  # same value, explicit

    assert report.chosen_filtered_files, "an explicit DEFAULT_EXTENSIONS was treated as imposed"
    assert report.imposed_filtered_files == []
    assert report.all_allowed is True


def test_all_files_disables_filtering_entirely(tmp_path):
    """`extensions=None` (`--all-files`) is also a caller CHOICE - it just
    happens to choose "everything", so nothing is ever skipped by it."""
    root = tmp_path / "governed"
    root.mkdir()
    (root / "bank.xlsx").write_text(f"IBAN: {FAKE_IBAN}\n", encoding="utf-8")

    report = scan(root, extensions=None)

    assert report.document_count == 1
    assert report.filtered_files == []
    assert report.walk_errors == []
    assert report.all_allowed is True


# ---------------------------------------------------------------------------
# The two entry points into `extensions` filtering do not behave the same way
# - a directory walk filters, a directly-passed single file never does. That
# is documented (`"A single file passed directly — no extension filter."`),
# but it means the SAME file produces two different verdicts depending only
# on how it is named to `scan()`. Recorded here as observed behaviour, not
# smoothed into one or the other; that divergence is a finding, not a defect
# this repair closes.
# ---------------------------------------------------------------------------
def test_folder_walk_and_direct_single_file_disagree_on_the_same_extension(tmp_path):
    root = tmp_path / "governed"
    root.mkdir()
    target = root / "bank.xlsx"
    target.write_text(f"IBAN: {FAKE_IBAN}\n", encoding="utf-8")

    walked = scan(root, extensions=frozenset({".txt"}))
    assert walked.document_count == 0
    assert walked.filtered_files

    direct = scan(target, extensions=frozenset({".txt"}))
    assert direct.document_count == 1
    assert direct.walk_errors == []
    assert direct.filtered_files == []


def test_an_unreadable_directory_still_breaks_all_allowed_alongside_a_filtered_file(tmp_path):
    """The three `walk_errors` reasons stay independently effective when they
    co-occur: the involuntary one (`unreadable_errors`) and the imposed one
    (`imposed_filtered_files`) both kill `all_allowed`; a chosen filter still
    does not, on its own."""
    import os

    root = tmp_path / "governed"
    root.mkdir()
    (root / "bank.xlsx").write_text(f"IBAN: {FAKE_IBAN}\n", encoding="utf-8")
    locked = root / "locked"
    locked.mkdir()
    (locked / "hidden.xlsx").write_text("nichts", encoding="utf-8")
    os.chmod(locked, 0o000)
    try:
        report = scan(root, extensions=frozenset({".txt"}))
        assert report.chosen_filtered_files, "the extension skip was not recorded"
        assert report.unreadable_errors, "the locked directory was not recorded"
        assert report.scan_complete is False
        assert report.all_allowed is False, (
            "an unreadable directory stopped flipping all_allowed"
        )
    finally:
        os.chmod(locked, 0o755)
