"""Every module `national.PERSON_NUMBER_MODULES` names has to exist at the
FLOOR `pyproject.toml`'s `national` extra declares (`python-stdnum>=1.19`),
not merely at whatever `python-stdnum` happens to be installed here.

`freshness.observe()`'s dead-path check resolves import existence with
`importlib.import_module` against the INSTALLED library - the same
resolution `national._validators` makes at runtime. It cannot ever disagree
with the code it is checking, because it uses the code's own oracle. And
`freshness.STDNUM_PIN = "2.2"` (with `test_the_pin_matches_the_installed_
release`) turns that whole suite red everywhere except the one pinned
version, so the only environment its OTHER checks can speak in is the one
where a floor defect is invisible by construction: `stdnum.be.ssn` was
declared in `PERSON_NUMBER_MODULES` and does not exist below `python-stdnum`
2.0, and nothing running at the installed 2.2 could ever have said so.

Outside what the code depends on being true here means: `pyproject.toml`'s
version string, not `sys.modules['stdnum'].__version__`. This file installs
that exact floor into an isolated directory and imports every declared path
against it - a real, `pip`-driven measurement, not introspection of
whatever this machine happens to have.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PYPROJECT = _REPO_ROOT / "pyproject.toml"
_SRC = _REPO_ROOT / "src"


def _declared_stdnum_floor() -> str:
    """Parsed from `pyproject.toml`'s `national` extra, not written here
    twice - if the pin changes, this reads the new one."""
    text = _PYPROJECT.read_text(encoding="utf-8")
    match = re.search(r'national\s*=\s*\[\s*"python-stdnum>=([0-9.]+)"', text)
    assert match, (
        "pyproject.toml's `national` extra no longer pins python-stdnum with "
        "a `>=X.Y` floor the way this test expects to parse; update the regex "
        "or the floor declaration together."
    )
    return match.group(1)


@pytest.fixture(scope="session")
def stdnum_at_the_declared_floor(tmp_path_factory):
    """An isolated install of EXACTLY the declared floor, nothing else on
    the path it is imported from."""
    floor = _declared_stdnum_floor()
    target = tmp_path_factory.mktemp("stdnum_floor")
    result = subprocess.run(
        [
            sys.executable, "-m", "pip", "install",
            "--target", str(target), "--no-deps", f"python-stdnum=={floor}",
        ],
        capture_output=True, text=True, timeout=180,
    )
    if result.returncode != 0:
        pytest.fail(
            f"could not install the declared floor python-stdnum=={floor} to "
            "measure against it - this is not a skip, `national`'s floor "
            "promise in pyproject.toml is unverifiable without it:\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return floor, target


def test_every_declared_module_exists_at_the_declared_floor(
    stdnum_at_the_declared_floor,
):
    """`freshness.observe()`'s `dead_paths`, run against the floor instead
    of whatever is installed. `stdnum.be.ssn` was `dead_paths` at 1.19 and
    `()` at 2.2, and only the first of those is the environment `national`'s
    declared floor promises to work in.
    """
    floor, target = stdnum_at_the_declared_floor
    script = (
        "import sys, importlib, json\n"
        f"sys.path.insert(0, {str(target)!r})\n"
        f"sys.path.insert(0, {str(_SRC)!r})\n"
        "from privacy_shield.national import PERSON_NUMBER_MODULES\n"
        "dead = []\n"
        "for country, entries in PERSON_NUMBER_MODULES.items():\n"
        "    for path, _minimum in entries:\n"
        "        try:\n"
        "            importlib.import_module(path)\n"
        "        except ImportError:\n"
        "            dead.append(path)\n"
        "print(json.dumps(sorted(dead)))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, (
        f"the floor-version probe crashed rather than reporting dead paths:\n"
        f"{result.stdout}\n{result.stderr}"
    )
    dead = json.loads(result.stdout.strip().splitlines()[-1])
    assert dead == [], (
        f"PERSON_NUMBER_MODULES names {dead}, which does not exist at "
        f"python-stdnum=={floor} - the floor pyproject.toml's `national` "
        f"extra declares (`pip install \".[national]\"` at that floor "
        f"crashes every scan, not just the one country's, because "
        f"`national.MissingValidator` propagates out of `find_national_ids`"
        f"). Either adopt a module (or module pair) that exists at the "
        f"floor, or raise the floor in pyproject.toml and say why in the "
        f"commit."
    )


def test_scanning_at_the_declared_floor_does_not_crash(stdnum_at_the_declared_floor):
    """The end-to-end version of the same measurement: a folder with a
    `be`-configured, entirely non-Belgian document, scanned at the declared
    floor. Reproduced by the coordinator as `EXIT 1` on `HEAD`: not the
    Belgian document dying, every document, because `MissingValidator` is
    never caught between `_validators` and `scan()`.
    """
    floor, target = stdnum_at_the_declared_floor
    script = (
        "import sys\n"
        f"sys.path.insert(0, {str(target)!r})\n"
        f"sys.path.insert(0, {str(_SRC)!r})\n"
        "import os\n"
        "os.environ['PRIVACY_SHIELD_NATIONAL_COUNTRIES'] = 'be'\n"
        "from privacy_shield import scan\n"
        "result = scan('contact erika.mustermann@example.com', force_text=True)\n"
        "assert result.documents[0].pii_detected, 'the floor lost email detection'\n"
        "print('ok')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, (
        f"a scan crashed at the declared floor python-stdnum=={floor} with "
        f"`be` configured, on a document with no Belgian content at all:\n"
        f"{result.stdout}\n{result.stderr}"
    )
    assert result.stdout.strip().splitlines()[-1] == "ok"
