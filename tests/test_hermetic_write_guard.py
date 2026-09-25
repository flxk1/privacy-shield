"""Proves the conftest.py write guard actually fires: a write attempted at a
real (non-existent) probe path under the real user-state roots is refused,
and nothing is created there.
"""
from conftest import GUARD_HITS, _REAL_STATE_ROOTS


def test_guard_refuses_a_write_under_the_real_root():
    root = _REAL_STATE_ROOTS[0]
    probe = f"{root}/__hermetic_probe__/x.jsonl"
    assert not GUARD_HITS

    raised = False
    try:
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("should never land\n")
    except PermissionError:
        raised = True
    assert raised, "the write guard did not refuse a write under the real root"

    import os
    assert not os.path.exists(probe)
    assert not os.path.exists(f"{root}/__hermetic_probe__")

    # This is the deliberate probe hit the guard was supposed to record —
    # clear it so the per-test session-end check does not fail on it.
    assert GUARD_HITS
    GUARD_HITS.clear()


def test_guard_refuses_mkdir_under_the_real_root():
    root = _REAL_STATE_ROOTS[0]
    probe_dir = f"{root}/__hermetic_probe_dir__"
    assert not GUARD_HITS

    import os
    raised = False
    try:
        os.mkdir(probe_dir)
    except PermissionError:
        raised = True
    assert raised
    assert not os.path.exists(probe_dir)

    assert GUARD_HITS
    GUARD_HITS.clear()
