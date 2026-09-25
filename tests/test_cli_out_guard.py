"""`--out` must never replace a file it was not asked to replace.

Overlays are named after their source, flattened, and were written with a plain
`write_text`: `scan . --out .` replaced a user's own `a.txt.overlay.txt` with
`a.txt`'s overlay, and `sub/b.md` and `sub__b.md` wrote one file between them
while the CLI reported both. Every target is now checked before anything is
written, and a scanned file is refused even under `--overwrite`.
"""

import errno
import hashlib
import os
from pathlib import Path

import pytest

import privacy_shield.cli as cli
from privacy_shield.cli import _safe_name, main

_EMAIL = "erika.mustermann@example.com"


def _digest(folder: Path) -> dict:
    return {
        str(p.relative_to(folder)): (
            "link->" + os.readlink(p) if p.is_symlink()
            else hashlib.sha256(p.read_bytes()).hexdigest()
        )
        for p in sorted(folder.rglob("*")) if p.is_file() or p.is_symlink()
    }


def _overlay_of(out: Path, source: Path) -> Path:
    return out / f"{_safe_name(str(source))}.overlay.txt"


def _scan(*args):
    return main(["scan", *map(str, args)])


def _refused(capsys, *names):
    captured = capsys.readouterr()
    assert captured.out == "", "a report was printed although nothing was written"
    assert "nothing was written" in captured.err
    for name in names:
        assert name in captured.err, f"{name!r} is not named in the refusal"
    return captured.err


@pytest.mark.parametrize("overwrite", [[], ["--overwrite"]], ids=["plain", "overwrite"])
def test_a_scanned_file_is_never_replaced(tmp_path, capsys, monkeypatch, overwrite):
    """The reproduced loss: out is the scanned folder, and a user's own file has
    the name an overlay would take."""
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "a.txt").write_text("x erika@example.org\n", encoding="utf-8")
    (folder / "a.txt.overlay.txt").write_text(f"mine, PII {_EMAIL}\n", encoding="utf-8")
    before = _digest(folder)
    monkeypatch.chdir(folder)

    assert _scan(".", "--out", ".", *overwrite) == 1

    assert _digest(folder) == before, "the scanned folder changed"
    assert "is one of the scanned files" in _refused(capsys, "a.txt.overlay.txt")


def test_two_documents_never_share_one_overlay(tmp_path, capsys):
    folder = tmp_path / "docs"
    (folder / "sub").mkdir(parents=True)
    (folder / "sub" / "b.md").write_text("one erika@example.org\n", encoding="utf-8")
    (folder / "sub__b.md").write_text("two hans@example.org\n", encoding="utf-8")
    out = tmp_path / "out"

    assert _scan(folder, "--out", out, "--overwrite") == 1

    assert not out.exists(), "a refused run still created --out"
    _refused(capsys, "sub__b.md", "would both write")


def test_names_differing_only_in_case_are_one_file(tmp_path, capsys):
    folder = tmp_path / "docs"
    (folder / "sub").mkdir(parents=True)
    (folder / "sub" / "B.md").write_text("one erika@example.org\n", encoding="utf-8")
    (folder / "sub__b.md").write_text("two hans@example.org\n", encoding="utf-8")

    assert _scan(folder, "--out", tmp_path / "out") == 1
    _refused(capsys, "would both write")


def test_an_existing_overlay_needs_overwrite(tmp_path, capsys):
    source = tmp_path / "note.txt"
    source.write_text(f"Kontakt {_EMAIL}\n", encoding="utf-8")
    out = tmp_path / "out"
    assert _scan(source, "--out", out) == 0
    capsys.readouterr()
    (overlay,) = out.iterdir()
    overlay.write_text("an earlier run, edited by hand\n", encoding="utf-8")

    assert _scan(source, "--out", out) == 1
    assert overlay.read_text(encoding="utf-8") == "an earlier run, edited by hand\n"
    _refused(capsys, "already exists")

    assert _scan(source, "--out", out, "--overwrite") == 0
    assert "[EMAIL]" in overlay.read_text(encoding="utf-8")
    assert [p.name for p in out.iterdir()] == [overlay.name], "a temporary file was left behind"


def test_a_refusal_writes_no_overlay_at_all(tmp_path, capsys):
    """One conflict stops every write, not just the conflicting one."""
    folder = tmp_path / "docs"
    folder.mkdir()
    for name in ("a.txt", "b.txt", "c.txt"):
        (folder / name).write_text(f"{name} erika@example.org\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    blocker = _overlay_of(out, folder / "b.txt")
    blocker.write_text("keep\n", encoding="utf-8")

    assert _scan(folder, "--out", out) == 1
    assert [p.name for p in out.iterdir()] == [blocker.name]
    assert blocker.read_text(encoding="utf-8") == "keep\n"
    _refused(capsys, "already exists")


@pytest.mark.parametrize("overwrite", [[], ["--overwrite"]], ids=["plain", "overwrite"])
def test_a_symbolic_link_is_never_written_through(tmp_path, capsys, overwrite):
    source = tmp_path / "note.txt"
    source.write_text(f"Kontakt {_EMAIL}\n", encoding="utf-8")
    precious = tmp_path / "precious.txt"
    precious.write_text("not to be touched\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    link = _overlay_of(out, source)
    link.symlink_to(precious)

    assert _scan(source, "--out", out, *overwrite) == 1
    assert precious.read_text(encoding="utf-8") == "not to be touched\n"
    assert link.is_symlink()
    _refused(capsys, "symbolic link")


def test_a_hard_link_to_a_scanned_file_is_refused(tmp_path, capsys):
    source = tmp_path / "note.txt"
    source.write_text(f"Kontakt {_EMAIL}\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    os.link(source, _overlay_of(out, source))

    assert _scan(source, "--out", out, "--overwrite") == 1
    assert source.read_text(encoding="utf-8") == f"Kontakt {_EMAIL}\n"
    _refused(capsys, "is one of the scanned files")


def test_overwrite_replaces_the_entry_not_a_file_linked_to_it(tmp_path, capsys):
    """A hard link to an unscanned file is not a source, so --overwrite may
    replace the entry - and must leave the other file as it was."""
    source = tmp_path / "note.txt"
    source.write_text(f"Kontakt {_EMAIL}\n", encoding="utf-8")
    precious = tmp_path / "precious.txt"
    precious.write_text("not to be touched\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    dest = _overlay_of(out, source)
    os.link(precious, dest)

    assert _scan(source, "--out", out, "--overwrite") == 0
    assert precious.read_text(encoding="utf-8") == "not to be touched\n"
    assert "[EMAIL]" in dest.read_text(encoding="utf-8")


def test_a_directory_in_the_way_is_refused(tmp_path, capsys):
    source = tmp_path / "note.txt"
    source.write_text(f"Kontakt {_EMAIL}\n", encoding="utf-8")
    out = tmp_path / "out"
    _overlay_of(out, source).mkdir(parents=True)

    assert _scan(source, "--out", out, "--overwrite") == 1
    _refused(capsys, "is a directory")


def test_a_clean_run_reports_what_it_wrote(tmp_path, capsys):
    folder = tmp_path / "docs"
    (folder / "sub").mkdir(parents=True)
    (folder / "sub" / "b.md").write_text("one erika@example.org\n", encoding="utf-8")
    (folder / "c.md").write_text("two hans@example.org\n", encoding="utf-8")
    out = tmp_path / "out"

    assert _scan(folder, "--out", out) == 0
    assert "overlays written: 2" in capsys.readouterr().out
    assert len(list(out.iterdir())) == 2


def test_names_differing_only_in_unicode_normalisation_are_one_file(tmp_path, capsys):
    """APFS and HFS+ store NFC and NFD spellings as one name."""
    folder = tmp_path / "docs"
    (folder / "\u00e9").mkdir(parents=True)
    (folder / "\u00e9" / "x.txt").write_text("one erika@example.org\n", encoding="utf-8")
    (folder / "e\u0301__x.txt").write_text("two hans@example.org\n", encoding="utf-8")
    out = tmp_path / "out"

    for extra in ([], ["--overwrite"]):
        assert _scan(folder, "--out", out, *extra) == 1
        assert not out.exists()
        _refused(capsys, "would both write")


def test_a_name_the_filesystem_rejects_leaves_nothing(tmp_path, capsys):
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "a.txt").write_text("a erika@example.org\n", encoding="utf-8")
    long = folder / ("n" * 230 + ".txt")
    long.write_text("b hans@example.org\n", encoding="utf-8")
    assert len(_overlay_of(tmp_path, long).name) > 255
    out = tmp_path / "out"

    assert _scan(folder, "--out", out) == 1
    assert list(out.iterdir()) == []
    assert "Nothing was written" in _write_failed(capsys)


def test_a_long_non_ascii_name_the_filesystem_accepts_is_written(tmp_path, capsys):
    """APFS limits characters, not bytes: this name is under 255 characters and
    well over 255 bytes."""
    folder = tmp_path / "jp"
    folder.mkdir()
    source = folder / ("日本語の長いファイル名" * 8 + ".txt")
    source.write_text("Kontakt erika@example.org\n", encoding="utf-8")
    name = _overlay_of(tmp_path, source).name
    assert len(name) < 255 < len(os.fsencode(name))
    out = tmp_path / "out"

    assert _scan(folder, "--out", out) == 0
    (written,) = out.iterdir()
    assert "[EMAIL]" in written.read_text(encoding="utf-8")


def _late_intruder(monkeypatch, make):
    """Something appears at the second target after the plan was made."""
    real = cli._plan_overlays

    def plan(*args, **kwargs):
        result = real(*args, **kwargs)
        make(result[1][0])
        return result

    monkeypatch.setattr(cli, "_plan_overlays", plan)


def _three_documents(tmp_path):
    folder = tmp_path / "docs"
    folder.mkdir()
    for name in ("a.txt", "b.txt", "c.txt"):
        (folder / name).write_text(f"{name} erika@example.org\n", encoding="utf-8")
    return folder


def _write_failed(capsys):
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "writing overlays failed" in captured.err
    return captured.err


@pytest.mark.parametrize("hard_links", [True, False], ids=["link", "no-link-fs"])
def test_a_file_appearing_after_the_plan_is_kept_and_nothing_is_left(tmp_path, capsys, monkeypatch, hard_links):
    folder = _three_documents(tmp_path)
    out = tmp_path / "out"
    _late_intruder(monkeypatch, lambda dest: (out.mkdir(exist_ok=True), dest.write_text("intruder\n")))
    if not hard_links:
        def no_link(*args, **kwargs):
            raise OSError(errno.ENOTSUP, "no hard links here")
        monkeypatch.setattr(cli.os, "link", no_link)

    assert _scan(folder, "--out", out) == 1

    (left,) = out.iterdir()
    assert left.read_text() == "intruder\n", "the file that appeared was replaced"
    assert "Nothing was written" in _write_failed(capsys)


def test_a_failure_under_overwrite_names_what_it_already_replaced(tmp_path, capsys, monkeypatch):
    folder = _three_documents(tmp_path)
    out = tmp_path / "out"
    assert _scan(folder, "--out", out) == 0
    capsys.readouterr()
    first = _overlay_of(out, folder / "a.txt")
    first.write_text("earlier\n", encoding="utf-8")
    _overlay_of(out, folder / "c.txt").unlink()
    _late_intruder(monkeypatch, lambda dest: (dest.unlink(), dest.mkdir()))

    assert _scan(folder, "--out", out, "--overwrite") == 1

    err = _write_failed(capsys)
    assert "already replaced" in err and first.name in err
    assert "[EMAIL]" in first.read_text(encoding="utf-8")
    assert not _overlay_of(out, folder / "c.txt").exists(), "an overlay created in the failed run was left"
    assert not list(out.glob(".overlay-*.tmp")), "a temporary file was left behind"


def test_a_failure_while_staging_leaves_nothing(tmp_path, capsys, monkeypatch):
    folder = _three_documents(tmp_path)
    out = tmp_path / "out"
    real = cli.tempfile.mkstemp
    calls = []

    def flaky(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real(*args, **kwargs)

    monkeypatch.setattr(cli.tempfile, "mkstemp", flaky)

    assert _scan(folder, "--out", out) == 1
    assert list(out.iterdir()) == []
    err = _write_failed(capsys)
    assert "No space left" in err and "Nothing was written" in err


def test_the_no_hard_link_fallback_still_writes(tmp_path, capsys, monkeypatch):
    def no_link(*args, **kwargs):
        raise OSError(errno.EPERM, "no hard links here")

    monkeypatch.setattr(cli.os, "link", no_link)
    folder = _three_documents(tmp_path)
    out = tmp_path / "out"

    assert _scan(folder, "--out", out) == 0
    written = sorted(out.iterdir())
    assert len(written) == 3 and all("[EMAIL]" in p.read_text() for p in written)
