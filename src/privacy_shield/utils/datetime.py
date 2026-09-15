"""
DateTime Utilities
==================
ISO timestamp generation for consistent datetime formatting across the platform.
"""

from datetime import datetime, timezone


def now_iso() -> str:
    """
    Get current UTC timestamp in ISO 8601 format with Z suffix.

    Returns:
        ISO formatted timestamp like "2026-03-01T12:30:45Z"

    Example:
        >>> now_iso()
        '2026-03-01T12:30:45Z'
    """
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def now_iso_full() -> str:
    """
    Get current UTC timestamp in ISO 8601 format with microseconds.

    Returns:
        ISO formatted timestamp with microseconds

    Example:
        >>> now_iso_full()
        '2026-03-01T12:30:45.123456+00:00'
    """
    return datetime.now(timezone.utc).isoformat()
