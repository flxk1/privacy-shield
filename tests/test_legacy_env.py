import os
import subprocess
import sys
from pathlib import Path

import pytest

import privacy_shield
from privacy_shield import LegacyEnvironmentError, PrivacyGate, cli, scan
from privacy_shield import is_safe_for_external_llm, privacy_skill_kg as kg
from privacy_shield._legacy_env import LEGACY_ENV
from privacy_shield.audit_log import audit_log_path
from privacy_shield.shield import PrivacyMode

PKG = Path(privacy_shield.__file__).resolve().parent

ENTRY_POINTS = {
    "scan": lambda: scan("hello", mode=PrivacyMode.REGEX_ONLY),
    "cli.main": lambda: cli.main(["scan", "hello", "--text", "--mode", "REGEX_ONLY"]),
    "PrivacyGate.check": lambda: PrivacyGate().check({"text": "hello"}, "external_llm"),
    # a second egress-safety judgment call, parallel to PrivacyGate.check; it must
    # not silently downgrade to pattern-only checking on a legacy name.
    "is_safe_for_external_llm": lambda: is_safe_for_external_llm("hello", use_local_llm_check=False),
}

# cli.main is a process boundary: it converts LegacyEnvironmentError into the
# documented "error: <msg>" + exit 1 contract instead of raising, so it is
# exercised separately below (test_cli_main_reports_legacy_name_as_error).
_RAISING_ENTRY_POINTS = {k: v for k, v in ENTRY_POINTS.items() if k != "cli.main"}


def _sources():
    return [p for p in PKG.rglob("*.py") if p.name != "_legacy_env.py"]


def test_table_is_an_injective_rename():
    assert len(LEGACY_ENV) == 25
    assert len(set(LEGACY_ENV.values())) == len(LEGACY_ENV)
    assert all(old.startswith("BRAIN_") for old in LEGACY_ENV)
    assert all(new.startswith("PRIVACY_SHIELD_") for new in LEGACY_ENV.values())
    assert not set(LEGACY_ENV) & set(LEGACY_ENV.values())


def test_the_package_reads_only_the_replacements():
    text = "\n".join(p.read_text(encoding="utf-8") for p in _sources())
    assert [old for old in LEGACY_ENV if old in text] == []
    assert [new for new in LEGACY_ENV.values() if f'"{new}"' not in text] == []


@pytest.mark.parametrize("entry", sorted(_RAISING_ENTRY_POINTS))
@pytest.mark.parametrize("legacy", sorted(LEGACY_ENV))
def test_a_legacy_name_raises_naming_its_replacement(entry, legacy, monkeypatch):
    monkeypatch.setenv(legacy, "1")
    with pytest.raises(LegacyEnvironmentError, match=LEGACY_ENV[legacy]):
        _RAISING_ENTRY_POINTS[entry]()


@pytest.mark.parametrize("legacy", sorted(LEGACY_ENV))
def test_cli_main_reports_legacy_name_as_error_exit_1(legacy, monkeypatch, capsys):
    monkeypatch.setenv(legacy, "1")
    code = cli.main(["scan", "hello", "--text", "--mode", "REGEX_ONLY"])
    assert code == 1
    err = capsys.readouterr().err
    assert err.startswith("error: ")
    assert LEGACY_ENV[legacy] in err


def test_cli_help_with_a_legacy_name_set_still_prints_help(monkeypatch, capsys):
    monkeypatch.setenv("BRAIN_PRIVACY_AUDIT_LOG", "1")
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "usage:" in out


def test_replacement_names_are_honoured(tmp_path, monkeypatch):
    audit = tmp_path / "set" / "audit.jsonl"
    kg_dir = tmp_path / "set" / "kg"
    monkeypatch.setenv("PRIVACY_SHIELD_AUDIT_LOG", str(audit))
    monkeypatch.setenv("PRIVACY_SHIELD_KG_DIR", str(kg_dir))
    for call in ENTRY_POINTS.values():
        call()
    assert audit.is_file()
    assert kg._kg_dir() == kg_dir


def test_neither_name_set_uses_the_default(tmp_path):
    for call in ENTRY_POINTS.values():
        call()
    assert tmp_path in audit_log_path().parents
    assert audit_log_path().is_file()


def test_unrelated_brain_prefixed_names_are_ignored(monkeypatch):
    for name in ("BRAIN_FOO", "BRAIN_", "BRAIN_PRIVACY_AUDIT_LOG_EXTRA"):
        monkeypatch.setenv(name, "1")
    for call in ENTRY_POINTS.values():
        call()


def test_importing_with_a_legacy_name_set_does_not_raise(tmp_path):
    env = {
        **os.environ,
        "BRAIN_PRIVACY_AUDIT_LOG": str(tmp_path / "legacy.jsonl"),
        "PYTHONPATH": str(PKG.parent),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    code = (
        "import pathlib, pkgutil, importlib\n"
        "made = []\n"
        "real = pathlib.Path.mkdir\n"
        "pathlib.Path.mkdir = lambda self, *a, **k: (made.append(str(self)), real(self, *a, **k))[1]\n"
        "import privacy_shield\n"
        "for info in pkgutil.walk_packages(privacy_shield.__path__, privacy_shield.__name__ + '.'):\n"
        "    importlib.import_module(info.name)\n"
        "assert made == [], made\n"
    )
    done = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert not (tmp_path / "legacy.jsonl").exists()


# The CHANGELOG says reject_legacy_env() tests "presence, not value" — an
# empty-valued legacy variable still raises. Nothing set "" until these.
EMPTY_VALUES = ("", " ", "\t")


@pytest.mark.parametrize("value", EMPTY_VALUES)
@pytest.mark.parametrize("entry", sorted(_RAISING_ENTRY_POINTS))
def test_an_empty_valued_legacy_name_still_raises(entry, value, monkeypatch):
    monkeypatch.setenv("BRAIN_PRIVACY_AUDIT_LOG", value)
    with pytest.raises(LegacyEnvironmentError, match="PRIVACY_SHIELD_AUDIT_LOG"):
        _RAISING_ENTRY_POINTS[entry]()


@pytest.mark.parametrize("value", EMPTY_VALUES)
@pytest.mark.parametrize("legacy", sorted(LEGACY_ENV))
def test_every_empty_valued_legacy_name_still_raises(legacy, value, monkeypatch):
    monkeypatch.setenv(legacy, value)
    with pytest.raises(LegacyEnvironmentError, match=LEGACY_ENV[legacy]):
        scan("hello", mode=PrivacyMode.REGEX_ONLY)


@pytest.mark.parametrize("value", EMPTY_VALUES)
def test_cli_main_reports_an_empty_valued_legacy_name_too(value, monkeypatch, capsys):
    monkeypatch.setenv("BRAIN_PRIVACY_AUDIT_LOG", value)
    assert cli.main(["scan", "hello", "--text", "--mode", "REGEX_ONLY"]) == 1
    assert "PRIVACY_SHIELD_AUDIT_LOG" in capsys.readouterr().err


# The two entries dropped with user_credentials.py. 2.0.0 promises legacy names
# are refused with an error naming the replacement; these two get silence
# instead, because they are no longer in the table to be recognised. That is a
# deliberate consequence, disclosed in the CHANGELOG — and asserted here so it
# cannot quietly become something else.
DROPPED_LEGACY_NAMES = ("BRAIN_CREDENTIALS_MASTER_KEY", "BRAIN_SKILL_INTAKE_MASTER_KEY")


@pytest.mark.parametrize("dropped", DROPPED_LEGACY_NAMES)
def test_dropped_legacy_names_are_not_in_the_rename_table(dropped):
    assert dropped not in LEGACY_ENV
    assert dropped not in LEGACY_ENV.values()


@pytest.mark.parametrize("dropped", DROPPED_LEGACY_NAMES)
@pytest.mark.parametrize("entry", sorted(_RAISING_ENTRY_POINTS))
def test_dropped_legacy_names_yield_silence_not_the_promised_error(
    entry, dropped, monkeypatch
):
    monkeypatch.setenv(dropped, "secret")
    _RAISING_ENTRY_POINTS[entry]()  # no LegacyEnvironmentError: silence, by design


def test_the_silence_of_the_dropped_names_is_disclosed():
    """The consequence, not just the removal, has to be findable in the CHANGELOG.

    Asserted on the paragraph that names them, so a generic "silently"
    elsewhere in the file cannot satisfy it.
    """
    changelog = (PKG.parents[1] / "CHANGELOG.md").read_text(encoding="utf-8")
    paragraphs = [
        block
        for block in changelog.split("\n\n")
        if all(name in block for name in DROPPED_LEGACY_NAMES)
    ]
    assert paragraphs, "the two dropped legacy names are not disclosed together"
    assert any(
        "silence" in block.lower() or "silently" in block.lower()
        for block in paragraphs
    ), "the dropped names are disclosed, but not the silence they now produce"
