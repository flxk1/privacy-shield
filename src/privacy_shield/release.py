"""A recorded release of special-category data for one egress.

The gate blocks Art. 9 data from external destinations. A controller with a
legal basis (a patient's explicit consent, Art. 9(2)(a); health care,
Art. 9(2)(h); …) can release one document for one destination. The release
names the basis, a reference to the consent or record that carries it, and
who granted it; the destination must be on the owner's list in
``PRIVACY_SHIELD_RELEASE_DESTINATIONS`` (for example a provider with an
Art. 28 contract). It lifts only an Art. 9 block: never professional-secrecy
markers, a confidentiality marker, a credential or LOCAL_ONLY mode, and never
the redaction - only the overlay leaves.

A release is granted only once its audit record is written; with no audit log
or a failed write it is refused.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, FrozenSet, List

DESTINATIONS_ENV = "PRIVACY_SHIELD_RELEASE_DESTINATIONS"
EVENT = "ai.privacy_shield.art9_release"

# Art. 9(2) GDPR, points (a) to (j)
BASES = frozenset("abcdefghij")


def _norm(destination: object) -> str:
    return str(destination or "").strip().lower().replace("-", "_").replace(" ", "_")


def approved_destinations() -> FrozenSet[str]:
    return frozenset(_norm(d) for d in os.environ.get(DESTINATIONS_ENV, "").split(",") if d.strip())


@dataclass(frozen=True)
class Release:
    basis: str
    reference: str
    granted_by: str

    def problems(self, destination: object) -> List[str]:
        out = []
        if str(self.basis).strip().lower() not in BASES:
            out.append("basis must be the Art. 9(2) point, a to j")
        if not re.search(r"\w", self.reference or ""):
            out.append("no reference to the consent or record")
        if not re.search(r"\w", self.granted_by or ""):
            out.append("no one named as granting it")
        if _norm(destination) not in approved_destinations():
            out.append(f"destination not in {DESTINATIONS_ENV}")
        return out

    def to_dict(self) -> Dict[str, str]:
        d = asdict(self)
        d["basis"] = f"Art. 9(2)({str(self.basis).strip().lower()}) GDPR"
        return d


def record(path: Path, details: Dict[str, object], tenant_id: str = "") -> None:
    """Append the release to the audit log, synced to disk; raises on any failure."""
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": EVENT,
        "success": True,
        "tenant_id": tenant_id or None,
        "details": details,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    # /dev/null or a pipe accepts the write and keeps nothing
    if path.exists() and not path.is_file():
        raise OSError(f"{path} is not a regular file")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    if not path.is_file():
        raise OSError(f"{path} is not a regular file")
