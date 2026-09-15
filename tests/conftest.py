import os

import pytest

from privacy_shield._legacy_env import LEGACY_ENV

USER_STATE_VARS = ("HOME", "XDG_STATE_HOME", "LOCALAPPDATA", "USERPROFILE")


@pytest.fixture(autouse=True)
def _isolated_user_state(tmp_path, monkeypatch):
    for var in USER_STATE_VARS:
        monkeypatch.setenv(var, str(tmp_path))
    for name in list(os.environ):
        if name.startswith("PRIVACY_SHIELD_") or name in LEGACY_ENV:
            monkeypatch.delenv(name, raising=False)
