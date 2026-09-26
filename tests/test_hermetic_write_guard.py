"""Proves the conftest.py write guard actually fires — against a FAKE root
registered via the guarded_fake_root fixture, never against the real
~/Library/Application Support/privacy-shield or ~/.local/state trees: a
regression in the guard must not be provable by writing into the user's
real state (it already happened once, from an earlier version of this file).
"""
import os
import shutil
from pathlib import Path

from conftest import GUARD_HITS


def test_guard_refuses_a_write_under_a_fake_root(guarded_fake_root):
    probe = guarded_fake_root / "__hermetic_probe__" / "x.jsonl"
    assert not GUARD_HITS

    raised = False
    try:
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("should never land\n")
    except PermissionError:
        raised = True
    assert raised, "the write guard did not refuse a write under a guarded root"
    assert not probe.exists()
    assert not probe.parent.exists()

    # This is the deliberate probe hit the guard was supposed to record —
    # clear it so the per-test check does not fail on it.
    assert GUARD_HITS
    GUARD_HITS.clear()


def test_guard_refuses_mkdir_under_a_fake_root(guarded_fake_root):
    probe_dir = guarded_fake_root / "__hermetic_probe_dir__"
    assert not GUARD_HITS

    raised = False
    try:
        os.mkdir(probe_dir)
    except PermissionError:
        raised = True
    assert raised
    assert not probe_dir.exists()

    assert GUARD_HITS
    GUARD_HITS.clear()


def test_guard_refuses_rename_and_replace_under_a_fake_root(guarded_fake_root, tmp_path):
    outside = tmp_path / "source.txt"
    outside.write_text("x", encoding="utf-8")
    dest = guarded_fake_root / "renamed.txt"

    for op in (os.rename, os.replace):
        assert not GUARD_HITS
        raised = False
        try:
            op(outside, dest)
        except PermissionError:
            raised = True
        assert raised, f"{op.__name__} was not refused"
        assert not dest.exists()
        assert outside.exists()  # the source was never touched either
        assert GUARD_HITS
        GUARD_HITS.clear()


def test_guard_refuses_remove_under_a_fake_root(guarded_fake_root):
    victim = guarded_fake_root / "victim.txt"
    # The guard would refuse creating this file too (it's under the root);
    # unregister just long enough to seed the fixture, then re-register so
    # the removal itself is what this test proves is refused.
    from conftest import _REAL_STATE_ROOTS

    _REAL_STATE_ROOTS.remove(str(guarded_fake_root))
    try:
        victim.write_text("do not remove me", encoding="utf-8")
    finally:
        _REAL_STATE_ROOTS.append(str(guarded_fake_root))

    assert not GUARD_HITS
    raised = False
    try:
        os.remove(victim)
    except PermissionError:
        raised = True
    assert raised
    assert victim.exists()

    assert GUARD_HITS
    GUARD_HITS.clear()


def test_guard_refuses_shutil_operations_under_a_fake_root(guarded_fake_root, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    dest = guarded_fake_root / "copied.txt"

    assert not GUARD_HITS
    raised = False
    try:
        shutil.copyfile(outside, dest)
    except PermissionError:
        raised = True
    assert raised
    assert not dest.exists()
    assert GUARD_HITS
    GUARD_HITS.clear()


def test_guard_refuses_link_and_symlink_into_a_fake_root(guarded_fake_root, tmp_path):
    outside = tmp_path / "source.txt"
    outside.write_text("x", encoding="utf-8")

    for op, name in ((os.link, "hardlink.txt"), (os.symlink, "softlink.txt")):
        dest = guarded_fake_root / name
        assert not GUARD_HITS
        raised = False
        try:
            op(outside, dest)
        except PermissionError:
            raised = True
        assert raised, f"{op.__name__} was not refused"
        assert not dest.exists() and not os.path.islink(dest)
        assert GUARD_HITS
        GUARD_HITS.clear()


def test_guard_refuses_truncate_under_a_fake_root(guarded_fake_root):
    from conftest import _REAL_STATE_ROOTS

    victim = guarded_fake_root / "truncate-me.txt"
    _REAL_STATE_ROOTS.remove(str(guarded_fake_root))
    try:
        victim.write_text("some content here", encoding="utf-8")
    finally:
        _REAL_STATE_ROOTS.append(str(guarded_fake_root))

    assert not GUARD_HITS
    raised = False
    try:
        os.truncate(victim, 0)
    except PermissionError:
        raised = True
    assert raised
    assert victim.read_text(encoding="utf-8") == "some content here"
    assert GUARD_HITS
    GUARD_HITS.clear()


def test_guard_refuses_sqlite3_connect_under_a_fake_root(guarded_fake_root):
    import sqlite3

    db_path = guarded_fake_root / "state.sqlite3"
    assert not GUARD_HITS
    raised = False
    try:
        sqlite3.connect(str(db_path))
    except PermissionError:
        raised = True
    assert raised
    assert not db_path.exists()
    assert GUARD_HITS
    GUARD_HITS.clear()


def test_pytester_a_stale_hit_from_before_any_test_fails_the_first_test(pytester):
    """D4: a hit recorded before any test's fixture setup ran (collection or
    import time) must not be silently discarded by the first test's own
    ``GUARD_HITS.clear()`` bookkeeping — the fixture checks BEFORE it clears.
    """
    real_conftest_path = str(Path(__file__).resolve().parent / "conftest.py")

    pytester.makeconftest(f"""
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "_real_outer_conftest_for_pytester_test2", {real_conftest_path!r}
)
_real = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_real)

# Simulate a write refused during collection/import, before any test ran.
_real.GUARD_HITS.append(("open", "/simulated/collection-time/hit.jsonl"))

GUARD_HITS = _real.GUARD_HITS
_REAL_STATE_ROOTS = _real._REAL_STATE_ROOTS
_fail_on_real_state_writes = _real._fail_on_real_state_writes
_isolated_user_state = _real._isolated_user_state
guarded_fake_root = _real.guarded_fake_root
""")
    pytester.makepyfile(
        test_inner_stale="""
def test_a_clean_test_that_never_writes_anything():
    assert 1 == 1
"""
    )
    result = pytester.runpytest_inprocess("-p", "no:cacheprovider")
    # pytest.fail() raised during fixture SETUP (before yield) reports as an
    # error, not a failure — either way the run is not a clean pass.
    result.assert_outcomes(errors=1)
    result.stdout.fnmatch_lines(["*before this test ran*"])
    assert result.ret != 0


def test_pytester_swallowed_write_exception_still_fails_the_inner_test(pytester):
    """D1/M7: a PermissionError from the guard, caught and swallowed exactly
    the way gate.py's _record_audit does (``except Exception: ...``), must
    still fail the test — via the autouse fixture's post-test check, not via
    the exception propagating. Run as a real, separate pytest session
    (pytester) so nothing here can special-case "this is the outer test".
    """
    # Load the real conftest.py under a distinct module name (not "conftest")
    # so it does not collide with the inner run's own conftest.py of the same
    # basename — a plain `from conftest import ...` here would re-enter the
    # module currently being imported and fail with a circular import.
    real_conftest_path = str(Path(__file__).resolve().parent / "conftest.py")

    pytester.makeconftest(f"""
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "_real_outer_conftest_for_pytester_test", {real_conftest_path!r}
)
_real = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_real)

GUARD_HITS = _real.GUARD_HITS
_REAL_STATE_ROOTS = _real._REAL_STATE_ROOTS
_fail_on_real_state_writes = _real._fail_on_real_state_writes
_isolated_user_state = _real._isolated_user_state
guarded_fake_root = _real.guarded_fake_root
""")
    pytester.makepyfile(
        test_inner_swallow="""
def test_inner_swallows_the_permission_error(guarded_fake_root):
    probe = guarded_fake_root / "x.jsonl"
    try:
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("never lands\\n")
    except Exception:
        pass  # the exact swallow shape gate.py._record_audit uses
    # No assertion here at all — if the fixture's own check did not run,
    # this inner test would report PASSED.
"""
    )
    result = pytester.runpytest_inprocess("-p", "no:cacheprovider")
    # The inner test BODY completes without raising (the write's
    # PermissionError was swallowed) — pytest reports that as passed with a
    # teardown error, not a failure, but either way the run is NOT a clean
    # pass: the fixture's post-test check still surfaces the blocked write.
    result.assert_outcomes(passed=1, errors=1)
    result.stdout.fnmatch_lines(["*blocked write(s)*during this test*"])
    assert result.ret != 0
