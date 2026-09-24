"""`scan --redaction-mode hash` needs a salt, from `--hash-salt` or
`PRIVACY_SHIELD_HASH_SALT`. The salt is a secret: a known salt lets anyone test
guessed values against the hashes, so it must not reach any output either.
"""

import json
import logging
import re

import pytest

from privacy_shield.cli import HASH_SALT_ENV, main

_EMAIL = "erika.mustermann@example.com"
_IBAN = "DE89370400440532013000"
_DOC = f"Kontakt {_EMAIL} Konto {_IBAN}"
_SALT_A = "saltA-" + "1" * 58
_SALT_B = "saltB-" + "2" * 58
_SHA = re.compile(r"\[SHA:[0-9a-f]{16}\]")


@pytest.fixture(autouse=True)
def _no_ambient_salt(monkeypatch):
    monkeypatch.delenv(HASH_SALT_ENV, raising=False)


def _run(capsys, *extra):
    code = main(["scan", _DOC, "--text", "--json", "--redaction-mode", "hash", *extra])
    captured = capsys.readouterr()
    payload = json.loads(captured.out) if captured.out.strip() else None
    return code, payload, captured


def _overlay(payload):
    return payload["documents"][0]["overlay"]


def test_the_flag_reaches_the_redactor(capsys):
    code, payload, _ = _run(capsys, "--hash-salt", _SALT_A)
    overlay = _overlay(payload)
    assert code == 0
    assert len(_SHA.findall(overlay)) == 2
    assert _EMAIL not in overlay and _IBAN not in overlay


def test_the_environment_variable_reaches_the_redactor(capsys, monkeypatch):
    _, by_flag, _ = _run(capsys, "--hash-salt", _SALT_A)
    monkeypatch.setenv(HASH_SALT_ENV, _SALT_A)
    code, by_env, _ = _run(capsys)
    assert code == 0
    assert _SHA.search(_overlay(by_env))
    assert _overlay(by_env) == _overlay(by_flag)


def test_the_salt_changes_the_hash(capsys):
    _, a, _ = _run(capsys, "--hash-salt", _SALT_A)
    _, b, _ = _run(capsys, "--hash-salt", _SALT_B)
    assert _overlay(a) != _overlay(b), "the salt does not reach the hash"


def test_the_flag_wins_over_the_environment(capsys, monkeypatch):
    _, flag_only, _ = _run(capsys, "--hash-salt", _SALT_A)
    monkeypatch.setenv(HASH_SALT_ENV, _SALT_B)
    _, both, _ = _run(capsys, "--hash-salt", _SALT_A)
    assert _overlay(both) == _overlay(flag_only)


@pytest.mark.parametrize("env", [None, ""], ids=["unset", "empty"])
def test_no_salt_fails_closed_and_names_both_sources(capsys, monkeypatch, env):
    if env is not None:
        monkeypatch.setenv(HASH_SALT_ENV, env)
    code, payload, captured = _run(capsys)
    assert code == 1
    assert payload is None, "a report was printed although nothing was hashed"
    assert "--hash-salt" in captured.err and HASH_SALT_ENV in captured.err
    assert _EMAIL not in captured.err and _IBAN not in captured.err


@pytest.mark.parametrize("source", ["flag", "env"])
@pytest.mark.parametrize("output", [["--json"], []], ids=["json", "human"])
def test_the_salt_reaches_no_output(capsys, monkeypatch, tmp_path, source, output):
    args = ["scan", _DOC, "--text", "--redaction-mode", "hash", *output,
            "--out", str(tmp_path / "out"), "--audit-log", str(tmp_path / "audit.jsonl")]
    if source == "flag":
        args += ["--hash-salt", _SALT_A]
    else:
        monkeypatch.setenv(HASH_SALT_ENV, _SALT_A)

    assert main(args) == 0
    captured = capsys.readouterr()
    written = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert any(p.suffix == ".txt" for p in written), "no overlay written; this run proved nothing"
    surfaces = {"stdout": captured.out, "stderr": captured.err}
    surfaces.update({str(p): p.read_text(encoding="utf-8") for p in written})
    for name, text in surfaces.items():
        assert _SALT_A not in text, f"the salt reached {name}"


def test_a_short_salt_is_accepted_with_a_warning_that_does_not_carry_it(capsys, caplog):
    short = "tiny-salt-9f"
    with caplog.at_level(logging.WARNING, logger="privacy_shield.redactor"):
        code, payload, captured = _run(capsys, "--hash-salt", short)
    assert code == 0 and _SHA.search(_overlay(payload))
    warnings = [r.getMessage() for r in caplog.records if r.name == "privacy_shield.redactor"]
    assert any("shorter than 32" in w for w in warnings)
    assert all(short not in text for text in [*warnings, captured.out, captured.err])


def test_an_empty_flag_counts_as_unset(capsys, monkeypatch):
    _, by_env_only, _ = _run(capsys, "--hash-salt", _SALT_B)
    monkeypatch.setenv(HASH_SALT_ENV, _SALT_B)
    code, payload, _ = _run(capsys, "--hash-salt", "")
    assert code == 0 and _overlay(payload) == _overlay(by_env_only)
