"""A broken breach-log directory must not break the egress decision
PrivacyGate.check() exists to make, but it must be visible: debug-level is
invisible at most deployments' log level, so gate.py's swallow logs at error.
"""
import logging
import os

import pytest

from privacy_shield.breach import BreachDetector
from privacy_shield.gate import PrivacyGate


@pytest.fixture()
def unwritable_breach_log_dir(tmp_path, monkeypatch):
    detector = BreachDetector()
    monkeypatch.setattr(detector, "_BREACH_LOG_DIR", tmp_path / "data" / "breach_log")
    # _on_blocked does `from privacy_shield.breach import breach_detector` locally on
    # every call, so patching the module attribute here is what it will pick up.
    monkeypatch.setattr("privacy_shield.breach.breach_detector", detector)
    (tmp_path / "data").mkdir()
    os.chmod(tmp_path / "data", 0o555)
    try:
        yield detector
    finally:
        os.chmod(tmp_path / "data", 0o755)


def test_broken_breach_log_dir_does_not_break_the_gate_decision(unwritable_breach_log_dir):
    gate = PrivacyGate()
    for _ in range(5):  # BreachDetector's escalation threshold
        gate._on_blocked("local_only_external_blocked", "external_llm", "t1", "u1", {})
    # no exception means the egress-check isolation held


def test_broken_breach_log_dir_logs_at_error_not_debug(unwritable_breach_log_dir, caplog):
    gate = PrivacyGate()
    with caplog.at_level(logging.DEBUG, logger="privacy_shield.gate"):
        for _ in range(5):
            gate._on_blocked("local_only_external_blocked", "external_llm", "t1", "u1", {})
    error_records = [r for r in caplog.records if r.levelno == logging.ERROR
                      and "Breach detector notification failed" in r.message]
    assert error_records, "expected an error-level record for the swallowed breach-log failure"
