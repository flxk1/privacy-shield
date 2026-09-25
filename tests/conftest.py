import os
import pwd
import sys
from pathlib import Path

import pytest

from privacy_shield._legacy_env import LEGACY_ENV

USER_STATE_VARS = ("HOME", "XDG_STATE_HOME", "LOCALAPPDATA", "USERPROFILE")

# Real user home, from the OS account, never from $HOME (which the autouse
# fixture below monkeypatches to tmp_path for every test).
_REAL_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)
_REAL_STATE_ROOTS = [
    str(_REAL_HOME / "Library" / "Application Support" / "privacy-shield"),
    str(_REAL_HOME / ".local" / "state" / "privacy-shield"),
]
_orig_xdg_state_home = os.environ.get("XDG_STATE_HOME", "").strip()
if _orig_xdg_state_home:
    _REAL_STATE_ROOTS.append(str(Path(_orig_xdg_state_home) / "privacy-shield"))

# Hits the hook refused; drained and asserted per-test by _fail_on_real_state_writes.
GUARD_HITS: list = []

_WRITE_FLAGS = (
    os.O_WRONLY | os.O_RDWR | os.O_CREAT
    | getattr(os, "O_APPEND", 0) | getattr(os, "O_TRUNC", 0)
)


def _under_real_root(path) -> bool:
    try:
        resolved = os.path.abspath(os.fspath(path))
    except TypeError:
        return False
    for root in _REAL_STATE_ROOTS:
        if resolved == root or resolved.startswith(root + os.sep):
            return True
    return False


def _audit_hook(event: str, args: tuple) -> None:
    hit_path = None

    if event == "open":
        path, mode, flags = args
        is_write = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
            isinstance(flags, int) and bool(flags & _WRITE_FLAGS)
        )
        if is_write and not isinstance(path, int) and _under_real_root(path):
            hit_path = path
    elif event in ("os.mkdir", "os.rmdir", "os.remove"):
        if _under_real_root(args[0]):
            hit_path = args[0]
    elif event in ("os.rename", "os.replace"):
        for p in args[:2]:
            if p is not None and _under_real_root(p):
                hit_path = p
                break
    elif event.startswith("shutil."):
        for a in args:
            if isinstance(a, (str, bytes, os.PathLike)) and _under_real_root(a):
                hit_path = a
                break

    if hit_path is not None:
        GUARD_HITS.append((event, str(hit_path)))
        # Raising refuses the operation itself — the guard never writes.
        raise PermissionError(
            f"blocked write to real privacy-shield user state: "
            f"event={event} path={hit_path}"
        )


sys.addaudithook(_audit_hook)


@pytest.fixture(autouse=True)
def _isolated_user_state(tmp_path, monkeypatch):
    for var in USER_STATE_VARS:
        monkeypatch.setenv(var, str(tmp_path))
    for name in list(os.environ):
        if name.startswith("PRIVACY_SHIELD_") or name in LEGACY_ENV:
            monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _fail_on_real_state_writes():
    """Code under test may swallow the guard's PermissionError (e.g.
    _record_audit's own except Exception); surface it as a test failure
    regardless by checking the recorded hits after each test."""
    GUARD_HITS.clear()
    yield
    if GUARD_HITS:
        hits = list(GUARD_HITS)
        GUARD_HITS.clear()
        pytest.fail(f"blocked write(s) to real user state during this test: {hits}")
