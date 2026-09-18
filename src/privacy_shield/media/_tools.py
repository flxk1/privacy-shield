"""Shared seam for the external media tools (ffmpeg, ffprobe, exiftool).

``audio.py``, ``video.py`` and ``metadata.py`` each shell out to a third-party
binary over a file that is, in this package, attacker-controlled input by
definition. Each had its own availability probe and its own argument
construction; three copies of that is three copies of the same mistake, so both
live here once.

Two rules are enforced here rather than at each of the fourteen call sites:

- **Every file operand is resolved to an absolute path.** A relative operand
  that begins with ``-`` is parsed as an *option* by every one of these tools:
  ``ffprobe`` takes its input file positionally, ``ffmpeg`` takes its output
  file positionally, and ``exiftool`` reads ``-tag=value`` as a write
  instruction. ``scan()`` hands a single file straight through, so
  ``scan("-delete_original!")`` on an existing file of that name reached
  ``exiftool`` as an argument vector it would act on. ``Path.resolve()`` always
  yields a leading ``/``, which none of them can read as an option. None of
  these tools accepts the ``--`` end-of-options convention, so this is the
  portable fix.
- **Every call has a timeout.** A malformed container can make ffprobe or
  ffmpeg block indefinitely; without a bound, one crafted file in a scanned
  folder stops the scan rather than failing it.
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Sequence, Union

logger = logging.getLogger(__name__)

# Long enough to transcode a real recording, short enough that one malformed
# container cannot park a folder scan forever.
TOOL_TIMEOUT_SECONDS = 300.0
PROBE_TIMEOUT_SECONDS = 15.0


def operand(path: Union[str, Path]) -> str:
    """A file operand no media tool can mistake for an option."""
    return os.fspath(Path(path).resolve())


def tool_available(tool: str) -> bool:
    """Is *tool* on PATH and runnable?"""
    try:
        subprocess.run(
            [tool, "-version"],
            capture_output=True,
            check=True,
            timeout=PROBE_TIMEOUT_SECONDS,
        )
        return True
    except Exception as exc:
        logger.debug("media tool %s unavailable: %s", tool, exc)
        return False


def run_tool(
    argv: Sequence[str],
    *,
    text: bool = False,
    timeout: float = TOOL_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess:
    """Run a media tool. List-form argv, no shell, bounded, raises on failure."""
    return subprocess.run(
        list(argv),
        capture_output=True,
        text=text,
        check=True,
        timeout=timeout,
    )


# Every media PII channel (EXIF, OCR, face detection, container tags, STT,
# frame extraction) depends on a backend this package does not declare and
# cannot install. When one is missing the channel reports nothing found, which
# is indistinguishable from "looked and found nothing" unless it says so. This
# is the prefix that says so, and it is one string because a caller has to be
# able to grep for it: `any(e.startswith(CHANNEL_UNAVAILABLE) for e in errors)`
# is how a consumer learns that `egress_allowed` is a verdict about a file that
# was only partly read. Same mechanism the text side uses for an undecodable
# binary (docs/limits.md, "Folder walk") - a per-document error, not a fatal.
CHANNEL_UNAVAILABLE = "media_channel_unavailable"


def channel_unavailable(channel: str, reason: object) -> str:
    """The error string for a media PII channel that could not run at all."""
    return f"{CHANNEL_UNAVAILABLE}: {channel}: {reason}"


__all__ = [
    "CHANNEL_UNAVAILABLE",
    "PROBE_TIMEOUT_SECONDS",
    "TOOL_TIMEOUT_SECONDS",
    "channel_unavailable",
    "operand",
    "run_tool",
    "tool_available",
]
