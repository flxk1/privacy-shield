import os
import re
import sys
from pathlib import Path

import pytest

import privacy_shield
from privacy_shield._legacy_env import LEGACY_ENV

USER_STATE_VARS = ("HOME", "XDG_STATE_HOME", "LOCALAPPDATA", "USERPROFILE")

# The package tree must never receive runtime state (v2.0.0 rule). Both the
# imported package and the checkout's src/ are covered, whichever differs.
# In-process only: child processes and dir_fd-relative opens are not seen.
PROTECTED_ROOTS = sorted({
    os.path.realpath(Path(privacy_shield.__file__).parent),
    os.path.realpath(Path(__file__).resolve().parent.parent / "src"),
})

GUARD_HITS: list = []

# importlib writes "<name>.pyc.<id>" and renames it into place.
_BYTECODE = re.compile(r".+\.pyc(\.\d+)?")
# Which argument of each shutil audit event is the path written to.
_SHUTIL_TARGET = {
    "shutil.copyfile": 1, "shutil.copymode": 1, "shutil.copystat": 1,
    "shutil.copytree": 1, "shutil.move": 1, "shutil.unpack_archive": 1,
    "shutil.rmtree": 0, "shutil.chown": 0, "shutil.make_archive": 0,
}

_WRITE_FLAGS = (
    os.O_WRONLY | os.O_RDWR | os.O_CREAT
    | getattr(os, "O_APPEND", 0) | getattr(os, "O_TRUNC", 0)
)


def _is_protected(path) -> bool:
    try:
        resolved = os.path.realpath(os.fsdecode(os.fspath(path)))
    except TypeError:
        return False
    parts = resolved.split(os.sep)
    if parts[-1] == "__pycache__" or (
        parts[-2:-1] == ["__pycache__"] and _BYTECODE.fullmatch(parts[-1])
    ):
        return False
    return any(resolved == root or resolved.startswith(root + os.sep) for root in PROTECTED_ROOTS)


def _audit_hook(event: str, args: tuple) -> None:
    hit_path = None
    if event == "open":
        path, mode, flags = args
        is_write = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
            isinstance(flags, int) and bool(flags & _WRITE_FLAGS)
        )
        if is_write and path is not None and not isinstance(path, int) and _is_protected(path):
            hit_path = path
    elif event in ("os.mkdir", "os.rmdir", "os.remove", "os.truncate"):
        if not isinstance(args[0], int) and _is_protected(args[0]):
            hit_path = args[0]
    elif event in ("os.rename", "os.replace"):
        hit_path = next((p for p in args[:2] if p is not None and _is_protected(p)), None)
    elif event in ("os.link", "os.symlink"):
        if _is_protected(args[1]):
            hit_path = args[1]
    elif event == "sqlite3.connect":
        if isinstance(args[0], (str, bytes, os.PathLike)) and _is_protected(args[0]):
            hit_path = args[0]
    elif event in _SHUTIL_TARGET:
        target = args[_SHUTIL_TARGET[event]]
        if isinstance(target, (str, bytes, os.PathLike)) and _is_protected(target):
            hit_path = target
    if hit_path is not None:
        GUARD_HITS.append((event, str(hit_path)))
        raise PermissionError(f"blocked write into the package tree: event={event} path={hit_path}")


sys.addaudithook(_audit_hook)


@pytest.fixture(autouse=True)
def _isolated_user_state(tmp_path, monkeypatch):
    for var in USER_STATE_VARS:
        monkeypatch.setenv(var, str(tmp_path))
    for name in list(os.environ):
        if name.startswith("PRIVACY_SHIELD_") or name in LEGACY_ENV:
            monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _fail_on_package_writes():
    # Code under test may swallow the hook's PermissionError; fail on the record.
    GUARD_HITS.clear()
    yield
    if GUARD_HITS:
        hits = list(GUARD_HITS)
        GUARD_HITS.clear()
        pytest.fail(f"blocked write(s) into the package tree during this test: {hits}")
