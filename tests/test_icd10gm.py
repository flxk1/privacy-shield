import zipfile

import pytest

from privacy_shield import icd10gm, pii_model
from privacy_shield.gate import PrivacyGate

# synthetic rows in the BfArM EDV layout; the real index never enters the repo
_ROWS = [
    "1|1|1|E11.9||||Diabetes mellitus, Typ 2",
    "1|2|1|G35.9||||Multiple Sklerose",
    "1|3|1|G43.9||||Migräne",
    "1|4|1|F32.9||||Depression",
    "1|5|1|R50.9||||Fieber",
    "1|6|1|Z73.0||||Ausgebranntsein",
    "0|7|1|||||Zucker - s.a. Diabetes",
    "1|8|1|J45.9||||Asthma bronchiale",
    "1|9|1|K40.9||||Hernie",
]


def _write(folder, name="icd10gm2026alpha_edvtxt_20250926.txt"):
    path = folder / name
    path.write_text("\r\n".join(_ROWS) + "\r\n", encoding="utf-8")
    return path


@pytest.fixture
def index(tmp_path, monkeypatch):
    monkeypatch.delenv(pii_model.ENV, raising=False)
    monkeypatch.setenv(icd10gm.ENV, str(_write(tmp_path)))
    icd10gm._cache.clear()
    return tmp_path


def _terms(text):
    return [t for _s, _e, t in icd10gm.find_terms(text)]


def test_absent_index_finds_nothing_and_says_where_it_looked(tmp_path, monkeypatch):
    monkeypatch.setenv(icd10gm.ENV, str(tmp_path / "missing"))
    assert icd10gm.find_terms("Er hat Migräne.") == []
    status = icd10gm.status()
    assert status["found"] is False and status["download"].startswith("https://www.bfarm.de/")


def test_found_in_a_folder_and_in_a_zip(tmp_path, monkeypatch):
    txt = _write(tmp_path)
    monkeypatch.setenv(icd10gm.ENV, str(tmp_path))
    assert icd10gm.locate() == txt
    archive = tmp_path / "zipped" / "icd10gm2026alpha-txt.zip"
    archive.parent.mkdir()
    with zipfile.ZipFile(archive, "w") as z:
        z.write(txt, txt.name)
    monkeypatch.setenv(icd10gm.ENV, str(archive.parent))
    icd10gm._cache.clear()
    assert icd10gm.locate() == archive
    assert _terms("Er hat Migräne.") == ["Migräne"]


def test_the_default_folder_is_the_user_state_folder(tmp_path, monkeypatch):
    monkeypatch.delenv(icd10gm.ENV, raising=False)
    monkeypatch.setattr(icd10gm, "_user_state_home", lambda: tmp_path)
    monkeypatch.setattr(icd10gm.Path, "home", lambda: tmp_path / "nohome")
    folder = tmp_path / "privacy-shield" / "icd10gm"
    folder.mkdir(parents=True)
    assert icd10gm.locate() is None
    _write(folder)
    assert icd10gm.locate().parent == folder


def test_terms_phrases_endings_and_heads(index):
    assert _terms("Er hat Migräne.") == ["Migräne"]
    assert _terms("Sie ist an Multipler Sklerose erkrankt.") == ["Multipler Sklerose"]
    assert _terms("Er hat Diabetes mellitus Typ 2.") == ["Diabetes mellitus Typ"]
    assert _terms("Er hat Diabetes.") == ["Diabetes"]


def test_everyday_words_reference_rows_and_z_chapter_are_left_out(index):
    assert _terms("Die Depression der Märkte hält an.") == []
    assert _terms("Er hat ein Ausgebranntsein.") == []
    assert _terms("Zucker kostet mehr.") == []


def _art9(text):
    return PrivacyGate().check_art9(text)


@pytest.mark.parametrize("text", [
    "Herr Albrecht ist wegen Migräne krankgeschrieben.",
    "Sie hat Asthma bronchiale.",
    "Der Mitarbeiter leidet an Multipler Sklerose.",
    "Name: Jonas Albrecht\nBefund: Hernie",
])
def test_a_diagnosis_about_a_person_is_health_data(index, text):
    assert "health" in _art9(text)


@pytest.mark.parametrize("text", [
    "Migräne ist eine häufige Erkrankung.",
    "Fieber kann viele Ursachen haben. Herr Albrecht kommt morgen.",
    "Das Gutachten muss geprüft sein, Asthma bronchiale ist dort nicht erwähnt.",
])
def test_a_diagnosis_about_nobody_is_not(index, text):
    assert "health" not in _art9(text)


@pytest.mark.parametrize("text", ["Sie haben Migräne erwähnt.", "Sie sind über Asthma bronchiale informiert."])
def test_the_formal_you_is_not_a_person_in_the_text(index, text):
    assert "health" not in _art9(text)


def test_without_the_index_the_gate_is_unchanged(tmp_path, monkeypatch):
    monkeypatch.delenv(pii_model.ENV, raising=False)
    monkeypatch.setenv(icd10gm.ENV, str(tmp_path / "missing"))
    assert _art9("Herr Albrecht ist wegen Migräne krankgeschrieben.") == []


# conftest moves the user-state folder, so the real index comes in by path
_REAL = icd10gm.locate()


@pytest.mark.skipif(_REAL is None, reason="no ICD-10-GM index on this machine")
def test_the_real_index_loads(monkeypatch):
    monkeypatch.setenv(icd10gm.ENV, str(_REAL))
    status = icd10gm.status()
    assert status["found"] and status["single_terms"] > 10000


def test_icd_status_reports_and_exits_3_when_absent(tmp_path, monkeypatch, capsys):
    from privacy_shield.cli import main
    monkeypatch.setenv(icd10gm.ENV, str(tmp_path / "missing"))
    assert main(["icd-status"]) == 3
    assert '"found": false' in capsys.readouterr().out
    monkeypatch.setenv(icd10gm.ENV, str(_write(tmp_path)))
    icd10gm._cache.clear()
    assert main(["icd-status"]) == 0
