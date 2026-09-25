"""Runtime state lands outside the installed package.

Five surfaces — the standalone audit trail (``privacy_shield.audit_log``), the privacy
skill KG (``privacy_shield.privacy_skill_kg``), the GDPR Art. 33(2) breach log
(``privacy_shield.breach``), the pseudonymisation session store
(``privacy_shield.anonymisation_skill``) and the context-embeddings cache
(``privacy_shield.privacy_shield_embeddings``) — resolve their paths at call time, default
to the platform user-state directory, honour an environment override verbatim, and create
the directory on demand. ``tests/conftest.py`` points the user-state home at ``tmp_path``.

The last two used to write into ``os.path.dirname(__file__)``: the breach log into
``src/privacy_shield/data/breach_log``, and the session store — which holds the full
re-identification map, pseudonym back to the real email address — into
``src/privacy_shield/user/pseudonymisation_sessions``, inside site-packages.
"""

import json
import os
import shutil
import sqlite3
import stat
from pathlib import Path

import pytest

import privacy_shield.audit_log as audit_log
from privacy_shield import breach as breach_mod
from privacy_shield import privacy_skill_kg as kg
from privacy_shield.anonymisation_skill import SESSION_STORE_ENV, PseudonymisationSession
from privacy_shield.audit_log import AuditEvent, audit_log_path, get_recent_audit_events, log_audit_event
from privacy_shield.breach import BREACH_LOG_DIR_ENV, BreachDetector, breach_log_dir
from privacy_shield.scanner import PIIType
from privacy_shield.privacy_shield_embeddings import (
    CONTEXT_EMBEDDINGS_ENV,
    PIIContextMatcher,
    context_embeddings_path,
)

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


# -------------------------------------------------------------------------- breach


def test_breach_log_default_resolves_outside_the_installed_package(tmp_path):
    resolved = breach_log_dir()
    assert _outside_package(resolved)
    assert tmp_path in resolved.parents
    assert resolved.name == "breach_log"
    assert not resolved.exists()


def test_breach_log_never_lands_in_the_package_tree():
    assert PKG_ROOT / "data" / "breach_log" != breach_log_dir()
    assert PKG_ROOT not in breach_log_dir().parents


def test_breach_log_env_override_wins_verbatim(tmp_path, monkeypatch):
    target = tmp_path / "override" / "breaches"
    monkeypatch.setenv(BREACH_LOG_DIR_ENV, str(target))
    assert breach_log_dir() == target
    assert BreachDetector()._log_dir() == target


def test_breach_log_writes_to_the_user_state_home(tmp_path):
    detector = BreachDetector()
    detector._log_breach(
        breach_mod.BreachEvent(
            event_id="breach_probe",
            severity="high",
            description="probe",
            affected_data_categories=["email"],
            detected_by="test",
        )
    )
    written = list(breach_log_dir().glob("breaches_*.jsonl"))
    assert written, breach_log_dir()
    assert _outside_package(written[0])
    assert tmp_path in written[0].parents
    assert _rows(written[0])[-1]["event_id"] == "breach_probe"


def test_breach_log_dir_stays_pinnable_for_callers(tmp_path):
    detector = BreachDetector()
    pinned = tmp_path / "pinned-breach"
    detector._BREACH_LOG_DIR = pinned
    assert detector._log_dir() == pinned


# ------------------------------------------------------------------- session store


def test_session_store_default_resolves_outside_the_installed_package(tmp_path):
    resolved = PseudonymisationSession().store_path()
    assert _outside_package(resolved)
    assert tmp_path in resolved.parents
    assert resolved.name == "pseudonymisation_sessions"
    assert not resolved.exists()


def test_session_store_never_lands_in_the_package_tree():
    resolved = PseudonymisationSession().store_path()
    assert PKG_ROOT / "user" / "pseudonymisation_sessions" != resolved
    assert PKG_ROOT not in resolved.parents


def test_session_store_env_override_wins_verbatim(tmp_path, monkeypatch):
    target = tmp_path / "override" / "sessions"
    monkeypatch.setenv(SESSION_STORE_ENV, str(target))
    assert PseudonymisationSession().store_path() == target


def test_session_store_explicit_path_beats_the_override(tmp_path, monkeypatch):
    monkeypatch.setenv(SESSION_STORE_ENV, str(tmp_path / "env"))
    explicit = tmp_path / "explicit"
    assert PseudonymisationSession(store_path=str(explicit)).store_path() == explicit


def test_saved_session_is_written_to_user_state_with_0600(tmp_path):
    session = PseudonymisationSession()
    session.get_or_create_pseudonym("erika.mustermann@example.com", PIIType.EMAIL)
    session.save()

    session_file = session._session_file()
    assert _outside_package(session_file)
    assert tmp_path in session_file.parents
    assert stat.S_IMODE(session_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(session_file.parent.stat().st_mode) == 0o700


def test_saved_session_round_trips_the_reverse_map(tmp_path):
    original = PseudonymisationSession()
    pseudo = original.get_or_create_pseudonym("erika.mustermann@example.com", PIIType.EMAIL)
    original.save()

    resumed = PseudonymisationSession(session_id=original.session_id)
    assert resumed._reverse_mappings[pseudo] == "erika.mustermann@example.com"


def test_the_docstring_does_not_claim_encryption_it_does_not_do(tmp_path):
    """Item 5's second half: no false security statement left in the code.

    The class docstring used to say "Mappings are stored encrypted on disk".
    Nothing encrypts them. If encryption is ever added, this test is the thing
    that has to change with it.
    """
    doc = PseudonymisationSession.__doc__ or ""
    assert "encrypted" not in doc.lower()
    assert "PLAINTEXT" in doc

    session = PseudonymisationSession()
    session.get_or_create_pseudonym("erika.mustermann@example.com", PIIType.EMAIL)
    session.save()
    on_disk = session._session_file().read_text(encoding="utf-8")
    assert "erika.mustermann@example.com" in on_disk, (
        "the file is plaintext; if that changed, the docstring must change too"
    )


# ---------------------------------------------------------------- context embeddings


def test_context_embeddings_default_resolves_outside_the_installed_package(tmp_path):
    resolved = context_embeddings_path()
    assert _outside_package(resolved)
    assert tmp_path in resolved.parents
    assert PKG_ROOT not in PIIContextMatcher().embeddings_path.parents


def test_context_embeddings_env_override_wins_verbatim(tmp_path, monkeypatch):
    target = tmp_path / "override" / "ctx.json"
    monkeypatch.setenv(CONTEXT_EMBEDDINGS_ENV, str(target))
    assert context_embeddings_path() == target
    assert PIIContextMatcher().embeddings_path == target


def test_context_embeddings_explicit_path_beats_the_override(tmp_path, monkeypatch):
    monkeypatch.setenv(CONTEXT_EMBEDDINGS_ENV, str(tmp_path / "env.json"))
    explicit = tmp_path / "explicit.json"
    assert PIIContextMatcher(embeddings_path=explicit).embeddings_path == explicit


def test_context_embeddings_setup_writes_to_the_user_state_home(tmp_path):
    matcher = PIIContextMatcher()
    matcher._embed = lambda text: [0.1, 0.2, 0.3]
    assert matcher.embed_pii_contexts({"name": ["employee named"]}) == 1
    written = context_embeddings_path()
    assert written.exists() and _outside_package(written)
    assert tmp_path in written.parents
    assert PIIContextMatcher().is_ready


@pytest.mark.parametrize("write", [
    lambda p: p.write_text("{}", encoding="utf-8"),
    lambda p: os.close(os.open(p, os.O_CREAT | os.O_WRONLY)),
    lambda p: os.link(__file__, p),
    lambda p: os.symlink(__file__, p),
    lambda p: sqlite3.connect(p),
    lambda p: (p.parent / "__pycache__" / p.name).write_text("{}", encoding="utf-8"),
    lambda p: (p.parent / "__pycache__" / "leak.pyc.json").write_text("{}", encoding="utf-8"),
    lambda p: shutil.copyfile(__file__, p),
], ids=["open", "os.open", "link", "symlink", "sqlite", "pycache-non-pyc", "pycache-pyc-prefix",
        "shutil-copy"])
def test_a_write_into_the_package_tree_is_refused_and_recorded(write):
    import conftest

    probe = PKG_ROOT / "guard_probe"
    with pytest.raises(PermissionError):
        write(probe)
    assert conftest.GUARD_HITS
    conftest.GUARD_HITS.clear()
    assert not probe.exists() and not probe.is_symlink()
    assert not (PKG_ROOT / "__pycache__" / probe.name).exists()
    assert not (PKG_ROOT / "__pycache__" / "leak.pyc.json").exists()


def test_reading_or_copying_out_of_the_package_tree_is_not_flagged(tmp_path):
    import conftest

    shutil.copy(PKG_ROOT / "__init__.py", tmp_path / "init_copy.py")
    shutil.copytree(PKG_ROOT / "utils", tmp_path / "utils")
    os.link(PKG_ROOT / "__init__.py", tmp_path / "init_link.py")
    assert not conftest.GUARD_HITS


def test_a_cache_left_in_the_package_is_named_not_read(tmp_path, monkeypatch, caplog):
    import privacy_shield.privacy_shield_embeddings as emb

    legacy = tmp_path / "pkg" / "pii_context_embeddings.json"
    legacy.parent.mkdir()
    legacy.write_text(json.dumps({"name": [{"phrase": "x", "embedding": [1.0]}]}))
    monkeypatch.setattr(emb, "_LEGACY_PACKAGE_FILE", legacy)
    with caplog.at_level("WARNING", logger=emb.__name__):
        matcher = PIIContextMatcher()
    assert not matcher.is_ready
    assert str(legacy) in caplog.text and str(matcher.embeddings_path) in caplog.text
