"""Runtime state lands outside the installed package.

Both surfaces — the standalone audit trail (``privacy_shield.audit_log``) and the privacy
skill KG (``privacy_shield.privacy_skill_kg``) — resolve their paths at call time, default
to the platform user-state directory, honour an environment override verbatim, and create
the directory on demand. ``tests/conftest.py`` points the user-state home at ``tmp_path``.
"""

import json
from pathlib import Path

import pytest

import privacy_shield.audit_log as audit_log
from privacy_shield import privacy_skill_kg as kg
from privacy_shield.audit_log import AuditEvent, audit_log_path, get_recent_audit_events, log_audit_event

PKG_ROOT = Path(audit_log.__file__).resolve().parent
AUDIT_ENV = "PRIVACY_SHIELD_AUDIT_LOG"
KG_ENV = "PRIVACY_SHIELD_KG_DIR"
_MISSING = object()


def _outside_package(path: Path) -> bool:
    resolved = Path(path).resolve()
    return PKG_ROOT not in resolved.parents and "site-packages" not in resolved.parts


def _rows(path: Path) -> list:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# --------------------------------------------------------------------------- audit


def test_audit_default_resolves_outside_the_installed_package(tmp_path):
    resolved = audit_log_path()
    assert _outside_package(resolved)
    assert tmp_path in resolved.parents
    assert resolved.name == "audit.jsonl"
    assert not resolved.parent.exists()


def test_audit_env_override_wins_verbatim(tmp_path, monkeypatch):
    target = tmp_path / "override" / "custom-audit.jsonl"
    monkeypatch.setenv(AUDIT_ENV, str(target))

    assert audit_log_path() == target
    assert str(audit_log_path()) == str(target)

    log_audit_event(AuditEvent.AI_PRIVACY_SHIELD_DECISION, user="probe", details={"k": "v"})
    assert _rows(target)[-1]["user"] == "probe"


def test_audit_state_dir_is_created_on_demand(tmp_path, monkeypatch):
    target = tmp_path / "absent" / "logs" / "audit.jsonl"
    monkeypatch.setenv(AUDIT_ENV, str(target))
    assert not target.parent.exists()

    log_audit_event(AuditEvent.LOGIN_SUCCESS, user="probe", ip="127.0.0.1", details={})

    assert target.parent.is_dir()
    assert target.read_text(encoding="utf-8").strip()


def test_audit_log_path_import_is_none_unless_pinned(tmp_path, monkeypatch):
    target = tmp_path / "env.jsonl"
    monkeypatch.setenv(AUDIT_ENV, str(target))

    from privacy_shield.audit_log import AUDIT_LOG_PATH

    assert AUDIT_LOG_PATH is None
    log_audit_event(AuditEvent.LOGOUT, user="env", ip="127.0.0.1")
    assert _rows(target)[-1]["user"] == "env"


def test_a_pin_wins_for_writer_and_reader_until_it_is_undone(tmp_path, monkeypatch):
    env_target = tmp_path / "env" / "audit.jsonl"
    pinned = tmp_path / "pinned.jsonl"
    monkeypatch.setenv(AUDIT_ENV, str(env_target))

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(audit_log, "AUDIT_LOG_PATH", pinned)
        log_audit_event(AuditEvent.LOGOUT, user="pinned", ip="127.0.0.1")
        assert get_recent_audit_events(limit=1)[0]["user"] == "pinned"

    assert audit_log.AUDIT_LOG_PATH is None
    assert not env_target.exists()
    log_audit_event(AuditEvent.LOGOUT, user="env", ip="127.0.0.1")
    assert _rows(env_target)[-1]["user"] == "env"
    assert get_recent_audit_events(limit=1)[0]["user"] == "env"
    assert [row["user"] for row in _rows(pinned)] == ["pinned"]


def test_stale_pin_replay_follows_a_later_override(tmp_path, monkeypatch):
    # f8a163d: monkeypatch undo wrote the handed-out path back, a fixture popped it, the
    # attribute was read again, the fixture restored the old object, and that object
    # then pinned the log against every later override.
    monkeypatch.setattr(audit_log, "AUDIT_LOG_PATH", None)
    early = tmp_path / "early.jsonl"
    monkeypatch.setenv(AUDIT_ENV, str(early))

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(audit_log, "AUDIT_LOG_PATH", tmp_path / "patched.jsonl")
    popped = audit_log.__dict__.pop("AUDIT_LOG_PATH", _MISSING)
    getattr(audit_log, "AUDIT_LOG_PATH", None)
    if popped is not _MISSING:
        audit_log.__dict__["AUDIT_LOG_PATH"] = popped

    later = tmp_path / "later" / "audit.jsonl"
    monkeypatch.setenv(AUDIT_ENV, str(later))
    log_audit_event(AuditEvent.LOGOUT, user="later", ip="127.0.0.1")

    assert not early.exists()
    assert _rows(later)[-1]["user"] == "later"
    assert get_recent_audit_events(limit=1)[0]["user"] == "later"


# ------------------------------------------------------------------------------ kg


def test_kg_and_audit_share_one_user_state_home():
    assert kg._user_state_home is audit_log._user_state_home


def test_kg_default_resolves_outside_the_installed_package(tmp_path):
    resolved = kg._kg_dir()
    assert _outside_package(resolved)
    assert tmp_path in resolved.parents
    assert resolved.name == "privacy_skill_kg"
    assert kg.privacy_kg_path("acme").name == "acme.jsonl"
    assert not resolved.exists()


def test_kg_env_override_wins_verbatim(tmp_path, monkeypatch):
    target = tmp_path / "override" / "kg"
    monkeypatch.setenv(KG_ENV, str(target))

    assert kg._kg_dir() == target
    assert str(kg._kg_dir()) == str(target)
    assert kg.privacy_kg_path("acme") == target / "acme.jsonl"


def test_kg_blank_override_falls_back_to_the_default(tmp_path, monkeypatch):
    for blank in ("", "   ", "\t\n"):
        monkeypatch.setenv(KG_ENV, blank)
        resolved = kg._kg_dir()
        assert _outside_package(resolved)
        assert tmp_path in resolved.parents


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
