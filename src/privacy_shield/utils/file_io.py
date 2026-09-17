"""Shared file I/O utilities.

Extracted from the upstream application module to reduce the monolith and provide
reusable JSON/JSONL/text read-write helpers.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, List

logger = logging.getLogger(__name__)


def read_text(path: Path) -> str:
    """Read a text file, replacing encoding errors."""
    return path.read_text(encoding="utf-8", errors="replace")


def write_text(path: Path, content: str) -> None:
    """Write a text file with automatic timestamped backup."""
    backup = path.with_suffix(
        path.suffix + f".bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    if path.exists():
        backup.write_text(read_text(path), encoding="utf-8")
    path.write_text(content, encoding="utf-8")


def read_json(path: Path) -> Any:
    """Read a JSON file, returning None on missing or invalid file."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def write_json(path: Path, payload: Any) -> None:
    """Write pretty-printed JSON to a file."""
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def load_jsonl(path: Path, limit: int = 0) -> List[dict]:
    """Load a JSONL file, returning a list of dicts.

    If *limit* > 0, only the last *limit* records are returned.
    """
    if not path.exists():
        return []
    rows: List[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    if limit > 0:
        return rows[-limit:]
    return rows


def append_jsonl(path: Path, payload: dict) -> None:
    """Append a single JSON object as a new line to a JSONL file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

def path_exists(target: object) -> bool:
    """Is *target* a path that exists? False for anything that cannot be one.

    `Path(...).exists()` raises OSError rather than returning False when the
    string is too long to be a filename - ENAMETOOLONG - and whether it does
    depends on the Python version: 3.13 started swallowing it, 3.10 and 3.12
    do not. So on CI's 3.10 leg any text input longer than the filesystem's
    name limit crashed the scan on the main entry point, while the same input
    scanned cleanly on 3.14. A privacy scanner must not decide whether to look
    at your document based on how long it is.

    Shared by every caller that has to tell raw text from a path: runner.scan,
    shield.pre_flight and the CLI. Three copies of `Path(x).exists()` is three
    copies of the same crash.
    """
    from pathlib import Path

    if not isinstance(target, (str, Path)):
        return False
    try:
        return Path(target).exists()
    except (OSError, ValueError):
        return False
