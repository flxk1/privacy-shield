"""Runtime state lands outside the installed package.

Both surfaces — the standalone audit trail (``privacy_shield.audit_log``) and the privacy
skill KG (``privacy_shield.privacy_skill_kg``) — resolve their paths at call
time, default to the platform user-state directory, honour an environment override
verbatim, and create the directory on demand. Every path here is under ``tmp_path``;
nothing is written into the repository tree.
"""

import json
from pathlib import Path

import pytest

import privacy_shield.audit_log as audit_log
from privacy_shield.audit_log import AuditEvent, audit_log_path, log_audit_event
from privacy_shield import privacy_skill_kg as kg

PKG_ROOT = Path(audit_log.__file__).resolve().parent
AUDIT_ENV = "PRIVACY_SHIELD_AUDIT_LOG"
KG_ENV = "PRIVACY_SHIELD_KG_DIR"
_MISSING = object()


@pytest.fixture(autouse=True)
def _unpinned():
    # An earlier test module monkeypatches privacy_shield.audit_log.AUDIT_LOG_PATH; pytest's
    # undo writes the resolved value back into the module dict. Drop it for the
    # duration of this module so lazy resolution is what is under test.
    pinned = audit_log.__dict__.pop("AUDIT_LOG_PATH", _MISSING)
    yield
    audit_log.__dict__.pop("AUDIT_LOG_PATH", None)
    if pinned is not _MISSING:
        audit_log.__dict__["AUDIT_LOG_PATH"] = pinned


@pytest.fixture()
def fake_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / ".local" / "state"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "AppData" / "Local"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    return tmp_path


def _outside_package(path: Path) -> bool:
    resolved = Path(path).resolve()
    return PKG_ROOT not in resolved.parents and "site-packages" not in resolved.parts


# --------------------------------------------------------------------------- audit


def test_audit_default_resolves_outside_the_installed_package(monkeypatch, fake_home):
    monkeypatch.delenv(AUDIT_ENV, raising=False)
    resolved = audit_log_path()
    assert _outside_package(resolved)
    assert _outside_package(Path(audit_log.AUDIT_LOG_PATH))
    assert fake_home in resolved.parents
    assert resolved.name == "audit.jsonl"
    assert not resolved.parent.exists()


def test_audit_env_override_wins_verbatim(tmp_path, monkeypatch):
    target = tmp_path / "override" / "custom-audit.jsonl"
    monkeypatch.setenv(AUDIT_ENV, str(target))

    assert audit_log_path() == target
    assert str(audit_log_path()) == str(target)

    log_audit_event(AuditEvent.AI_PRIVACY_SHIELD_DECISION, user="probe", details={"k": "v"})
    rows = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert rows[-1]["user"] == "probe"


def test_audit_state_dir_is_created_on_demand(tmp_path, monkeypatch):
    target = tmp_path / "absent" / "logs" / "audit.jsonl"
    monkeypatch.setenv(AUDIT_ENV, str(target))
    assert not target.parent.exists()

    log_audit_event(AuditEvent.LOGIN_SUCCESS, user="probe", ip="127.0.0.1", details={})

    assert target.parent.is_dir()
    assert target.read_text(encoding="utf-8").strip()


def test_audit_log_path_import_stays_compatible(tmp_path, monkeypatch):
    target = tmp_path / "imported.jsonl"
    monkeypatch.setenv(AUDIT_ENV, str(target))

    from privacy_shield.audit_log import AUDIT_LOG_PATH

    assert AUDIT_LOG_PATH == target


def test_audit_writer_follows_the_environment_set_after_import(tmp_path, monkeypatch):
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(audit_log, "AUDIT_LOG_PATH", tmp_path / "patched.jsonl")
        log_audit_event(AuditEvent.LOGOUT, user="patched", ip="127.0.0.1")
    assert (tmp_path / "patched.jsonl").exists()

    target = tmp_path / "late" / "audit.jsonl"
    monkeypatch.setenv(AUDIT_ENV, str(target))

    log_audit_event(AuditEvent.LOGOUT, user="late", ip="127.0.0.1")

    assert audit_log_path() == target
    assert json.loads(target.read_text(encoding="utf-8").splitlines()[-1])["user"] == "late"


# ------------------------------------------------------------------------------ kg


def test_kg_default_resolves_outside_the_installed_package(monkeypatch, fake_home):
    monkeypatch.delenv(KG_ENV, raising=False)
    resolved = kg._kg_dir()
    assert _outside_package(resolved)
    assert fake_home in resolved.parents
    assert resolved.name == "privacy_skill_kg"
    assert kg.privacy_kg_path("acme").name == "acme.jsonl"
    assert not resolved.exists()


def test_kg_env_override_wins_verbatim(tmp_path, monkeypatch):
    target = tmp_path / "override" / "kg"
    monkeypatch.setenv(KG_ENV, str(target))

    assert kg._kg_dir() == target
    assert str(kg._kg_dir()) == str(target)
    assert kg.privacy_kg_path("acme") == target / "acme.jsonl"


def test_kg_blank_override_falls_back_to_the_default(monkeypatch, fake_home):
    for blank in ("", "   ", "\t\n"):
        monkeypatch.setenv(KG_ENV, blank)
        resolved = kg._kg_dir()
        assert _outside_package(resolved)
        assert fake_home in resolved.parents


def test_kg_state_dir_is_created_on_demand(tmp_path, monkeypatch):
    target = tmp_path / "absent" / "kg"
    monkeypatch.setenv(KG_ENV, str(target))
    assert not target.exists()

    kg.record_privacy_kg_fact(
        tenant_id="acme",
        issue_key="pii_in_payload",
        issue_label="PII in payload",
        solution_key="overlay",
        solution_label="clean overlay",
        status="applied",
        confidence_value=0.9,
        confidence_threshold=0.75,
        scope="docs",
        run_id="run-1",
        approval_event_id="evt-1",
    )

    assert target.is_dir()
    rows = kg.list_privacy_kg_facts(tenant_id="acme")
    assert rows[-1]["issue_key"] == "pii_in_payload"
    assert (target / "acme.jsonl").exists()
