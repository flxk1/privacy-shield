"""Tests for the governed-folder runner (``scan()``) and the CLI.

All fixtures are SYNTHETIC — fake PII generated here, never real data. The tests
prove:

- the runner walks a folder span by span and produces a clean overlay with the
  injected PII redacted (no injected value survives into the overlay);
- the egress verdict is correct (LOCAL_ONLY / berufsgeheimnis / Art. 9 block;
  a non-confidential PII doc passes);
- every decision is recorded to the standalone ``audit_log``;
- the whole path runs with ZERO RVND present (no ``rvnd`` import anywhere);
- the CLI writes overlays and reports the right exit code.
"""

import json
import sys

import pytest

from brain.audit_log import AuditEvent
from brain.privacy_shield import cli
from brain.privacy_shield.runner import DocumentScan, ScanReport, scan
from brain.privacy_shield.shield import PrivacyMode

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
    monkeypatch.setattr("brain.audit_log.AUDIT_LOG_PATH", audit_file)

    # The gate's block path lazily notifies the breach detector, which otherwise
    # writes under src/brain/data/. Redirect that singleton's log dir to temp.
    import brain.privacy_shield.breach as breach_mod

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
# Zero RVND on the path
# ---------------------------------------------------------------------------
def test_runner_runs_with_zero_rvnd(pii_folder, temp_audit):
    # Nothing named rvnd may be imported by exercising the runner.
    scan(pii_folder, mode=PrivacyMode.STANDARD)
    rvnd_modules = [m for m in sys.modules if m == "rvnd" or m.startswith("rvnd.")]
    assert rvnd_modules == []


def test_runner_sources_have_no_rvnd_import():
    import pathlib

    from brain.privacy_shield import runner as runner_mod

    for mod_file in ("runner.py", "cli.py"):
        text = (pathlib.Path(runner_mod.__file__).parent / mod_file).read_text()
        assert "import rvnd" not in text
        assert "from rvnd" not in text


# ---------------------------------------------------------------------------
# Global privacy mode is restored after a scan
# ---------------------------------------------------------------------------
def test_global_privacy_mode_restored(temp_audit):
    from brain.privacy_shield.shield import get_global_privacy_mode

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
