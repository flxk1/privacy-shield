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
import pytest

from privacy_shield.audit_log import AuditEvent
from privacy_shield import cli
from privacy_shield.runner import DocumentScan, ScanReport, scan
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


def test_cli_json_output(pii_folder, temp_audit, capsys):
    code = cli.main(["scan", str(pii_folder), "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["document_count"] == 4
    assert payload["all_allowed"] is True
    assert "documents" in payload


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
# These extensions are chosen independently of `runner.DEFAULT_EXTENSIONS` and
# hardcoded: the point is observable behaviour (exit code, `all_allowed`,
# `scan_complete`, the report entry), not agreement with the table the code
# under test consults.
# ---------------------------------------------------------------------------
def test_extension_filtered_documents_are_recorded_and_break_completeness(tmp_path):
    root = tmp_path / "governed"
    root.mkdir()
    (root / "bank.xlsx").write_text(f"IBAN: {FAKE_IBAN}\n", encoding="utf-8")
    (root / "contact.eml").write_text(f"From: {FAKE_EMAIL}\n", encoding="utf-8")

    report = scan(root, extensions=frozenset({".txt"}))

    # Neither file was opened - a scan that never read them cannot report on
    # what they contain.
    assert report.document_count == 0

    # The skip is RECORDED, distinguishably from an unreadable directory.
    assert report.walk_errors, "a filtered-out file was not reported at all"
    assert report.filtered_files, "filtered_files did not surface the skip"
    assert any("bank.xlsx" in e for e in report.filtered_files)
    assert any("contact.eml" in e for e in report.filtered_files)
    # And distinguishably TAGGED, so a caller can tell "skipped by filter"
    # apart from "could not be read" within the same list.
    from privacy_shield.runner import EXTENSION_FILTERED

    assert all(e.startswith(EXTENSION_FILTERED) for e in report.filtered_files)

    # A scan that skipped files never reports itself complete - unconditionally,
    # regardless of which way `all_allowed` decides below.
    assert report.scan_complete is False
    # `all_allowed` takes the MILDER of the two variants this defect leaves
    # open: `extensions` is a parameter, and a file skipped by it is not
    # folded into "cleared for egress" the way an unreadable directory is.
    # `unreadable_errors` (the OSError family) is empty here, so `all_allowed`
    # is unaffected by the filter alone.
    assert report.unreadable_errors == []
    assert report.all_allowed is True

    payload = report.to_dict()
    assert payload["walk_errors"]
    assert payload["filtered_files"]
    assert payload["scan_complete"] is False
    assert payload["all_allowed"] is True


def test_extension_filtered_folder_is_reported_by_the_cli(tmp_path, temp_audit):
    """The exact defect this closes: `scan --json` on such a folder used to
    print `all_allowed = True | scan_complete = True | documents = 0` and
    exit 0, with nothing anywhere in the report distinguishing it from an
    empty, fully-read folder.

    Under the milder `all_allowed` variant (see `ScanReport.all_allowed`) the
    CLI exit code does not change here - it folds only `all_allowed`, not
    `scan_complete`, and that fold is outside this fix's territory. What
    closes the case is that the report is no longer silent: `scan_complete`
    and `filtered_files` now say exactly what did not happen, where before
    both were absent and `scan_complete` read True.
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

    assert code == 0  # unchanged by this fix - see docstring
    payload = json.loads(out.getvalue())
    assert payload["document_count"] == 0
    assert payload["all_allowed"] is True
    assert payload["scan_complete"] is False, (
        "the folder was reported complete though two files were never read"
    )
    assert payload["filtered_files"], "the skip left no trace in the report"


def test_default_extensions_also_record_what_they_skip(tmp_path):
    """The everyday case, not just an explicit `--extensions`: the default
    filter (whatever it currently names) still leaves a record when it skips
    a file, rather than a scan going quiet about it."""
    root = tmp_path / "governed"
    root.mkdir()
    (root / "bank.xlsx").write_text(f"IBAN: {FAKE_IBAN}\n", encoding="utf-8")

    report = scan(root)  # extensions defaults to DEFAULT_EXTENSIONS

    assert report.document_count == 0
    assert report.filtered_files
    assert report.scan_complete is False


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
    """The two `walk_errors` reasons stay independently effective when they
    co-occur: the involuntary one (`unreadable_errors`) still kills
    `all_allowed`; the voluntary one (`filtered_files`) still does not, on its
    own."""
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
        assert report.filtered_files, "the extension skip was not recorded"
        assert report.unreadable_errors, "the locked directory was not recorded"
        assert report.scan_complete is False
        assert report.all_allowed is False, (
            "an unreadable directory stopped flipping all_allowed"
        )
    finally:
        os.chmod(locked, 0o755)
