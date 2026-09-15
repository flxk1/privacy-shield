import os
import subprocess
import sys
from pathlib import Path

import pytest

import privacy_shield
from privacy_shield import LegacyEnvironmentError, PrivacyGate, cli, scan
from privacy_shield import privacy_skill_kg as kg
from privacy_shield._legacy_env import LEGACY_ENV
from privacy_shield.audit_log import audit_log_path
from privacy_shield.shield import PrivacyMode

PKG = Path(privacy_shield.__file__).resolve().parent

ENTRY_POINTS = {
    "scan": lambda: scan("hello", mode=PrivacyMode.REGEX_ONLY),
    "cli.main": lambda: cli.main(["scan", "hello", "--text", "--mode", "REGEX_ONLY"]),
    "PrivacyGate.check": lambda: PrivacyGate().check({"text": "hello"}, "external_llm"),
}


def _sources():
    return [p for p in PKG.rglob("*.py") if p.name != "_legacy_env.py"]


def test_table_is_an_injective_rename():
    assert len(LEGACY_ENV) == 27
    assert len(set(LEGACY_ENV.values())) == len(LEGACY_ENV)
    assert all(old.startswith("BRAIN_") for old in LEGACY_ENV)
    assert all(new.startswith("PRIVACY_SHIELD_") for new in LEGACY_ENV.values())
    assert not set(LEGACY_ENV) & set(LEGACY_ENV.values())


def test_the_package_reads_only_the_replacements():
    text = "\n".join(p.read_text(encoding="utf-8") for p in _sources())
    assert [old for old in LEGACY_ENV if old in text] == []
    assert [new for new in LEGACY_ENV.values() if f'"{new}"' not in text] == []


@pytest.mark.parametrize("entry", sorted(ENTRY_POINTS))
@pytest.mark.parametrize("legacy", sorted(LEGACY_ENV))
def test_a_legacy_name_raises_naming_its_replacement(entry, legacy, monkeypatch):
    monkeypatch.setenv(legacy, "1")
    with pytest.raises(LegacyEnvironmentError, match=LEGACY_ENV[legacy]):
        ENTRY_POINTS[entry]()


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
        "import pathlib\n"
        "made = []\n"
        "real = pathlib.Path.mkdir\n"
        "pathlib.Path.mkdir = lambda self, *a, **k: (made.append(str(self)), real(self, *a, **k))[1]\n"
        "import privacy_shield, privacy_shield.cli, privacy_shield.gate, privacy_shield.runner\n"
        "import privacy_shield.audit_log, privacy_shield.privacy_shield_embeddings\n"
        "assert made == [], made\n"
    )
    done = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert not (tmp_path / "legacy.jsonl").exists()
