import json

import pytest

from privacy_shield import release as release_mod
from privacy_shield.gate import PrivacyGate
from privacy_shield.release import Release
from privacy_shield.runner import scan

HEALTH = "Herr Albrecht hat Diabetes und kommt am Montag."
CONSENT = Release(basis="a", reference="Einwilligung 2026-114", granted_by="Dr. Weber")


@pytest.fixture
def approved(monkeypatch, tmp_path):
    monkeypatch.setenv(release_mod.DESTINATIONS_ENV, "openai, Praxis-LLM")
    return tmp_path / "audit.jsonl"


def _doc(text, audit, destination="openai", release=CONSENT):
    return scan(text, destination=destination, audit_log_path=str(audit) if audit else None,
                release=release).documents[0]


def _events(audit):
    return [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]


def test_without_a_release_health_data_is_blocked(approved):
    assert _doc(HEALTH, approved, release=None).egress_allowed is False


def test_a_recorded_release_lets_the_overlay_leave(approved):
    doc = _doc(HEALTH, approved)
    assert doc.egress_allowed is True
    assert doc.released["basis"] == "Art. 9(2)(a) GDPR"
    assert "Albrecht" not in doc.overlay
    released = [e for e in _events(approved) if e.get("event") == release_mod.EVENT]
    assert len(released) == 1
    assert released[0]["details"]["release"]["reference"] == "Einwilligung 2026-114"
    assert released[0]["details"]["destination"] == "openai"


def test_the_destination_list_matches_normalised_names(approved):
    assert _doc(HEALTH, approved, destination="praxis llm").egress_allowed is True


@pytest.mark.parametrize("why, kwargs", [
    ("destination", {"destination": "gemini"}),
    ("basis", {"release": Release("z", "Einwilligung 1", "Dr. Weber")}),
    ("reference", {"release": Release("a", "  ", "Dr. Weber")}),
    ("granting", {"release": Release("a", "Einwilligung 1", "")}),
])
def test_an_incomplete_release_is_refused(approved, why, kwargs):
    doc = _doc(HEALTH, approved, **kwargs)
    assert doc.egress_allowed is False
    assert "release refused" in doc.blocked_reason
    assert not doc.released


def test_no_audit_log_means_no_release(approved):
    doc = _doc(HEALTH, None)
    assert doc.egress_allowed is False
    assert "no audit log" in doc.blocked_reason


def test_an_unwritable_audit_log_means_no_release(approved, tmp_path):
    (tmp_path / "is_a_dir").mkdir()
    doc = _doc(HEALTH, tmp_path / "is_a_dir")
    assert doc.egress_allowed is False
    assert "release refused" in doc.blocked_reason


@pytest.mark.parametrize("text", [
    HEALTH + " Zugang: ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "Arztgeheimnis: " + HEALTH,
    "Streng vertraulich: " + HEALTH,
])
def test_a_release_never_lifts_secrets_or_secrecy_markers(approved, text):
    doc = _doc(text, approved)
    assert doc.egress_allowed is False
    assert "not an Art. 9 block" in doc.blocked_reason


def test_local_only_mode_is_not_lifted(approved, monkeypatch):
    monkeypatch.setattr(PrivacyGate, "_get_privacy_mode", staticmethod(lambda tenant_id: "local_only"))
    doc = _doc(HEALTH, approved)
    assert doc.egress_allowed is False


def test_a_release_covers_one_document_not_a_folder(approved, tmp_path):
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "a.txt").write_text(HEALTH, encoding="utf-8")
    with pytest.raises(ValueError, match="one document"):
        scan(str(folder), destination="openai", audit_log_path=str(approved), release=CONSENT)


def test_an_unneeded_release_changes_and_records_nothing(approved):
    doc = _doc("Die Lieferung kommt am Montag.", approved)
    assert doc.egress_allowed is True and not doc.released
    assert not [e for e in _events(approved) if e.get("event") == release_mod.EVENT]


def test_the_cli_needs_all_three_release_flags(capsys):
    from privacy_shield.cli import main
    assert main(["scan", HEALTH, "--text", "--release-basis", "a"]) == 1
    assert "needs --release-basis, --release-ref and --released-by" in capsys.readouterr().err


def test_a_device_as_audit_log_means_no_release(approved):
    doc = _doc(HEALTH, __import__("pathlib").Path("/dev/null"))
    assert doc.egress_allowed is False
    assert "release refused" in doc.blocked_reason


def test_medical_secrecy_is_never_lifted(approved):
    doc = _doc("Unterliegt der ärztlichen Schweigepflicht. " + HEALTH, approved)
    assert doc.egress_allowed is False
    assert "duty of professional secrecy" in doc.blocked_reason


def test_a_secrecy_clause_alone_does_not_block(approved):
    assert _doc("Der Auftragnehmer unterliegt der Schweigepflicht nach Ziffer 9.", approved,
                release=None).egress_allowed is True


def test_a_fifo_audit_path_never_hangs_and_refuses_the_release(approved, tmp_path):
    import os
    import threading
    fifo = tmp_path / "audit.fifo"
    os.mkfifo(fifo)
    out = {}
    worker = threading.Thread(target=lambda: out.setdefault("doc", _doc(HEALTH, fifo)), daemon=True)
    worker.start()
    worker.join(30)
    assert not worker.is_alive(), "scan hung on a FIFO audit path"
    assert out["doc"].egress_allowed is False
