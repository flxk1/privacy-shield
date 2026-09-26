import os
import pwd
import sys
from pathlib import Path

import pytest

from privacy_shield._legacy_env import LEGACY_ENV

pytest_plugins = ["pytester"]

USER_STATE_VARS = ("HOME", "XDG_STATE_HOME", "LOCALAPPDATA", "USERPROFILE")

# Real user home, from the OS account, never from $HOME (which the autouse
# fixture below monkeypatches to tmp_path for every test).
_REAL_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)

# Mutable: tests register additional (fake) roots via guarded_fake_root below.
# The guard's own tests must never probe the real entries here — see
# test_hermetic_write_guard.py.
_REAL_STATE_ROOTS: list = [
    str(_REAL_HOME / "Library" / "Application Support" / "privacy-shield"),
    str(_REAL_HOME / ".local" / "state" / "privacy-shield"),
]
_orig_xdg_state_home = os.environ.get("XDG_STATE_HOME", "").strip()
if _orig_xdg_state_home:
    _REAL_STATE_ROOTS.append(str(Path(_orig_xdg_state_home) / "privacy-shield"))

# Hits the hook refused; drained and asserted per-test by _fail_on_real_state_writes,
# and once more at session end for anything outside a test body (collection-time
# imports, fixture teardown after the last test).
GUARD_HITS: list = []

_WRITE_FLAGS = (
    os.O_WRONLY | os.O_RDWR | os.O_CREAT
    | getattr(os, "O_APPEND", 0) | getattr(os, "O_TRUNC", 0)
)

_CASE_INSENSITIVE = sys.platform == "darwin" or os.name == "nt"


def _normalize(path_str: str) -> str:
    # realpath resolves symlinks in the existing prefix (e.g. macOS /tmp ->
    # /private/tmp) and leaves a nonexistent tail as-is.
    resolved = os.path.realpath(path_str)
    return resolved.lower() if _CASE_INSENSITIVE else resolved


def _under_real_root(path) -> bool:
    if isinstance(path, int):  # fd-only open/truncate: no path to check
        return False
    try:
        raw = os.fsdecode(path)
    except TypeError:
        return False
    candidate = _normalize(raw)
    for root in _REAL_STATE_ROOTS:
        r = _normalize(root)
        if candidate == r or candidate.startswith(r + os.sep):
            return True
    return False


def _target_paths(event: str, args: tuple) -> list:
    # Out of scope: dir_fd-relative opens (the audited path can be relative
    # and unresolvable without the fd) and writes performed by a subprocess
    # (this hook runs only in this interpreter).
    if event == "open":
        path, mode, flags = args
        is_write = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
            isinstance(flags, int) and bool(flags & _WRITE_FLAGS)
        )
        return [path] if is_write else []
    if event in ("os.mkdir", "os.rmdir", "os.remove"):
        return [args[0]]
    if event in ("os.rename", "os.replace"):
        return [p for p in args[:2] if p is not None]
    if event in ("os.link", "os.symlink"):
        # The new directory entry is the second arg (dst / link_name); the
        # first (src / link target) is not itself written.
        return [args[1]] if len(args) > 1 else []
    if event == "os.truncate":
        return [args[0]] if args else []
    if event == "sqlite3.connect":
        return [args[0]] if args else []
    if event.startswith("shutil."):
        return [a for a in args if isinstance(a, (str, bytes, os.PathLike))]
    return []


def _audit_hook(event: str, args: tuple) -> None:
    for target in _target_paths(event, args):
        if _under_real_root(target):
            GUARD_HITS.append((event, str(target)))
            # Raising refuses the operation itself — the guard never writes.
            raise PermissionError(
                f"blocked write to a guarded user-state root: "
                f"event={event} path={target}"
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
    regardless by checking the recorded hits before and after each test —
    before, so a hit from collection/import time (before any test's setup
    ran) is not silently discarded by this fixture's own bookkeeping.
    """
    if GUARD_HITS:
        stale = list(GUARD_HITS)
        GUARD_HITS.clear()
        pytest.fail(f"blocked write(s) to guarded user state before this test ran: {stale}")
    yield
    if GUARD_HITS:
        hits = list(GUARD_HITS)
        GUARD_HITS.clear()
        pytest.fail(f"blocked write(s) to guarded user state during this test: {hits}")


@pytest.fixture()
def guarded_fake_root(tmp_path_factory):
    """Register a FAKE root the guard treats exactly like a real one, so the
    guard's own tests can prove it fires without ever probing the real
    ~/Library/Application Support/privacy-shield or ~/.local/state trees.
    """
    fake_root = tmp_path_factory.mktemp("guarded_fake_root") / "privacy-shield"
    fake_root.mkdir()  # mirrors the real root, which always pre-exists; done
    # BEFORE registration below, or this mkdir would itself be refused.
    _REAL_STATE_ROOTS.append(str(fake_root))
    try:
        yield fake_root
    finally:
        _REAL_STATE_ROOTS.remove(str(fake_root))


def pytest_sessionfinish(session, exitstatus):
    if GUARD_HITS:
        hits = list(GUARD_HITS)
        GUARD_HITS.clear()
        session.exitstatus = 1
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_line(
                f"HERMETIC WRITE GUARD: outstanding blocked write(s) at session "
                f"end (not attributed to any test): {hits}",
                red=True,
            )
