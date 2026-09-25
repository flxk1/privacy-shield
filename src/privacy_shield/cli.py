"""``privacy-shield`` command-line entry point.

A thin CLI over :func:`privacy_shield.runner.scan`. It prints the egress
verdict, optionally writes the clean overlays, and exits non-zero when any
document is blocked — so an agent or a human can gate on the result.

    privacy-shield scan <path|-|text> [--mode STANDARD|LOCAL_ONLY|ANONYMOUS_JSON|REGEX_ONLY]
                                      [--destination external_llm]
                                      [--redaction-mode redact|pseudonymize|hash|detect_only|block]
                                      [--min-confidence low|medium|high]
                                      [--out DIR] [--json] [--audit-log PATH]
                                      [--no-recursive] [--all-files]
                                      [--extensions .txt,.csv] [--text]

Exit codes: 0 = every overlay cleared for egress; 2 = at least one blocked;
1 = usage / runtime error.

``--all-files`` and ``--extensions`` are both a caller CHOICE at this
boundary, the same as in :func:`~privacy_shield.runner.scan`: naming neither
imposes ``DEFAULT_EXTENSIONS`` (a skip then counts against exit code 0, via
``all_allowed``); naming either is a chosen scope (a skip is recorded but
does not move the exit code). See ``ScanReport.all_allowed``.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import sys
import tempfile
import unicodedata
from pathlib import Path
from typing import List, Optional, Tuple

from ._legacy_env import reject_legacy_env
from .redactor import RedactionMode
from .utils.file_io import path_exists
from .runner import ScanReport, scan
from .scanner import Confidence
from .shield import PrivacyMode

HASH_SALT_ENV = "PRIVACY_SHIELD_HASH_SALT"

_MODES = {
    "STANDARD": PrivacyMode.STANDARD,
    "LOCAL_ONLY": PrivacyMode.LOCAL_ONLY,
    "ANONYMOUS_JSON": PrivacyMode.ANONYMOUS_JSON,
    "REGEX_ONLY": PrivacyMode.REGEX_ONLY,
}
_REDACTION_MODES = {m.value: m for m in RedactionMode}
_CONFIDENCE = {c.value: c for c in Confidence}


def _safe_name(source: str) -> str:
    """Turn a document source into a safe overlay filename."""
    if source == "text_input":
        return "text_input"
    return source.strip("/").replace("/", "__").replace("\\", "__").lstrip(".") or "document"


def _parse_extensions(value: str) -> frozenset:
    """Turn a comma-separated ``--extensions`` value into a suffix frozenset.

    A caller of the CLI who reaches this parses `.txt,csv` or `.TXT, .Csv`
    into ``{".txt", ".csv"}`` - the leading dot is optional per entry, case
    is folded to match ``path.suffix.lower()`` in the runner.
    """
    result = set()
    for raw in value.split(","):
        raw = raw.strip().lower()
        if not raw:
            continue
        result.add(raw if raw.startswith(".") else f".{raw}")
    return frozenset(result)


class OverlayConflict(Exception):
    """An overlay would replace a file it must not; nothing was written."""

    def __init__(self, problems: List[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


class OverlayWriteError(Exception):
    """Writing failed part-way; `replaced` lists overlays already replaced
    under --overwrite, which cannot be rolled back. Nothing else is left."""

    def __init__(self, cause: OSError, replaced: List[Path]):
        super().__init__(str(cause))
        self.replaced = replaced


def _file_id(path: Path) -> Tuple[int, int]:
    st = path.stat()
    return st.st_dev, st.st_ino


def _name_key(name: str) -> str:
    # APFS and HFS+ are case- and normalisation-insensitive: one file, two spellings
    return unicodedata.normalize("NFD", unicodedata.normalize("NFD", name).casefold())


def _plan_overlays(report: ScanReport, out_dir: Path, overwrite: bool) -> List[Tuple[Path, str]]:
    # Every target is checked before anything is written. A scanned source is
    # matched by device and inode, so a hard link or a path spelled another way
    # is still the source; `--overwrite` never extends to it.
    sources = set()
    for doc in report.documents:
        path = Path(doc.source)
        if doc.source != "text_input" and path.is_file():
            sources.add(_file_id(path))

    plan: List[Tuple[Path, str]] = []
    claimed: dict = {}
    problems: List[str] = []
    for doc in report.documents:
        # a file named .overlay.txt is read as cleaned; one a detected value is
        # still in (detect_only, block) is not written, as to_dict withholds it.
        if doc.overlay_residual:
            continue
        dest = out_dir / f"{_safe_name(doc.source)}.overlay.txt"
        key = _name_key(dest.name)
        if key in claimed:
            problems.append(f"{claimed[key]} and {doc.source} would both write {dest}")
        claimed[key] = doc.source
        if dest.is_symlink():
            problems.append(f"{dest} is a symbolic link")
        elif dest.is_dir():
            problems.append(f"{dest} is a directory")
        elif dest.exists():
            if _file_id(dest) in sources:
                problems.append(f"{dest} is one of the scanned files")
            elif not overwrite:
                problems.append(f"{dest} already exists")
        plan.append((dest, doc.overlay))
    if problems:
        raise OverlayConflict(problems)
    return plan


#: a filesystem without hard links (exFAT, some network shares) reports these
_NO_HARD_LINKS = {
    code for code in (
        getattr(errno, "EPERM", None), getattr(errno, "ENOTSUP", None),
        getattr(errno, "EOPNOTSUPP", None), getattr(errno, "ENOSYS", None),
    ) if code is not None
}


def _write_overlays(report: ScanReport, out_dir: Path, overwrite: bool = False) -> List[Path]:
    plan = _plan_overlays(report, out_dir, overwrite)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Stage every overlay first, so a failure there leaves nothing behind.
    staged: List[Tuple[Path, str, str]] = []
    try:
        for dest, overlay in plan:
            fd, tmp = tempfile.mkstemp(dir=out_dir, prefix=".overlay-", suffix=".tmp")
            staged.append((dest, tmp, overlay))
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(overlay)
    except BaseException as exc:
        for _, tmp, _ in staged:
            Path(tmp).unlink(missing_ok=True)
        if isinstance(exc, OSError):
            raise OverlayWriteError(exc, []) from exc
        raise

    created: List[Path] = []
    replaced: List[Path] = []
    try:
        for dest, tmp, overlay in staged:
            if overwrite and os.path.lexists(dest):
                # a rename replaces the directory entry, never writes through it
                os.replace(tmp, dest)
                replaced.append(dest)
                continue
            try:
                # a hard link fails if anything appeared at dest since the plan
                os.link(tmp, dest, follow_symlinks=False)
                created.append(dest)
            except OSError as exc:
                if exc.errno not in _NO_HARD_LINKS:
                    raise
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0))
                created.append(dest)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(overlay)
            os.unlink(tmp)
    except OSError as exc:
        for dest in created:
            dest.unlink(missing_ok=True)
        for _, tmp, _ in staged:
            Path(tmp).unlink(missing_ok=True)
        raise OverlayWriteError(exc, replaced) from exc
    return [dest for dest, _, _ in staged]


def _print_human(report: ScanReport, written: Optional[List[Path]]) -> None:
    out = sys.stdout
    out.write(f"Privacy Shield scan — mode={report.mode} destination={report.destination}\n")
    out.write(f"root: {report.root}\n")
    out.write(
        f"documents: {report.document_count}  spans: {report.total_spans}  "
        f"all_allowed: {report.all_allowed}\n"
    )
    out.write("-" * 72 + "\n")
    for doc in report.documents:
        verdict = "ALLOW" if doc.egress_allowed else "BLOCK"
        out.write(f"[{verdict}] {doc.source}\n")
        out.write(
            f"    type={doc.input_type} classification={doc.classification} "
            f"spans={doc.span_count} pii={doc.pii_detected} "
            f"placeholders={doc.placeholder_count}\n"
        )
        if doc.findings_by_type:
            summary = ", ".join(f"{k}:{v}" for k, v in sorted(doc.findings_by_type.items()))
            out.write(f"    findings: {summary}\n")
        if not doc.egress_allowed:
            out.write(f"    blocked_reason: {doc.blocked_reason}\n")
        if doc.redaction_blocked:
            out.write(f"    redaction_blocked: {doc.redaction_block_reason}\n")
        if doc.errors:
            out.write(f"    errors: {'; '.join(doc.errors)}\n")
        if doc.audit_id:
            out.write(f"    audit_id: {doc.audit_id}\n")
    out.write("-" * 72 + "\n")
    # UNCONDITIONAL - not gated on `all_allowed`. A CHOSEN `--extensions`
    # scope that excludes real files is not a defect in `all_allowed` (the
    # caller asked for that scope, on purpose, and the contract that a
    # chosen filter does not move `all_allowed` is correct and tested
    # elsewhere) - but it was invisible in this printer's OTHER output too:
    # `--extensions .txtt` (a typo) or `--extensions ,` (an empty scope)
    # matched nothing, printed `documents: 0  all_allowed: True`, and named
    # neither file anywhere, indistinguishable from an empty, fully-read
    # folder. `chosen_filtered_files` held both the whole time; nothing
    # printed it because the entire cause block below only runs when
    # `all_allowed` is False, and a chosen filter is exactly the case where
    # it stays True. This is the ALLOWING-side counterpart to the block
    # below, not a duplicate of it - `imposed_filtered_files` and
    # `unreadable_errors` still only appear under "not all_allowed".
    if report.chosen_filtered_files:
        out.write(
            f"skipped by the extensions scope you chose "
            f"({len(report.chosen_filtered_files)} file(s); this does NOT "
            f"count against all_allowed - check the scope if that's not "
            f"what you meant):\n"
        )
        for entry in report.chosen_filtered_files:
            out.write(f"    - {entry}\n")
    if written:
        out.write(f"overlays written: {len(written)} -> {written[0].parent}\n")
    for doc in report.documents:
        if doc.overlay_residual:
            out.write(f"overlay withheld: {doc.source}: {doc.overlay_residual} detected "
                      f"value(s) still present; not a cleaned overlay\n")
    if not report.all_allowed:
        # `all_allowed` is a conjunction of FOUR terms (see its docstring):
        # every document cleared the gate, every document was fully read, the
        # walk could read everything, and no file was silently dropped by a
        # scope the caller never chose. Printing only `blocked_documents`
        # answered the first term and went silent on the other three - a
        # folder with zero blocked documents and one unreadable directory, or
        # one file dropped by the imposed default extension list, still
        # printed every document as `[ALLOW]`, a blocked count of `0`, and
        # nothing naming `logo.png` or the locked directory anywhere in the
        # output, while exiting 2. An operator reading that output has no way
        # to find what tripped the exit code, which is what trains operators
        # to stop reading it.
        blocked = report.blocked_documents
        incomplete = report.incomplete_documents
        unreadable = report.unreadable_errors
        imposed = report.imposed_filtered_files
        out.write(
            f"BLOCKED: not every document is cleared for egress "
            f"({len(blocked)} blocked by the gate, {len(incomplete)} "
            f"incompletely read, {len(unreadable)} unreadable, "
            f"{len(imposed)} skipped by the default extension scope).\n"
        )
        if blocked:
            out.write("  blocked by the gate:\n")
            for doc in blocked:
                out.write(f"    - {doc.source}: {doc.blocked_reason}\n")
        if incomplete:
            out.write("  not fully read (some PII channel never ran):\n")
            for doc in incomplete:
                out.write(
                    f"    - {doc.source}: {'; '.join(doc.incomplete_channels)}\n"
                )
        if unreadable:
            out.write("  the walk could not read:\n")
            for entry in unreadable:
                out.write(f"    - {entry}\n")
        if imposed:
            out.write(
                "  skipped by the default extension scope (no --extensions "
                "or --all-files given; pass one to include them, or accept "
                "the exclusion by naming it):\n"
            )
            for entry in imposed:
                out.write(f"    - {entry}\n")
    out.flush()


def _cmd_scan(args: argparse.Namespace) -> int:
    mode = _MODES[args.mode]
    redaction_mode = _REDACTION_MODES[args.redaction_mode]
    min_confidence = _CONFIDENCE[args.min_confidence]

    # `extensions` is only passed to `scan()` when the caller named a scope
    # (`--all-files` or `--extensions`) - a CHOICE, at this boundary exactly
    # as at the API's. Passing nothing at all leaves `scan()`'s own default
    # unresolved, which is what makes it an IMPOSED filter, not a chosen one
    # (see `runner.scan`'s docstring and `ScanReport.all_allowed`). Hardcoding
    # `DEFAULT_EXTENSIONS` here for the no-flags case, as this used to, would
    # forward it as an explicit choice and silently defeat that distinction.
    scan_kwargs: dict = {}
    if args.all_files:
        scan_kwargs["extensions"] = None
    elif args.extensions:
        scan_kwargs["extensions"] = _parse_extensions(args.extensions)

    target = args.target
    force_text = args.text
    # ``-`` reads text from stdin; ``--text`` forces raw-text interpretation.
    if target == "-":
        target = sys.stdin.read()
        force_text = True
    elif not force_text and not path_exists(target):
        sys.stderr.write(
            f"note: '{target}' is not an existing path; treating as raw text.\n"
        )
        force_text = True

    hash_salt = args.hash_salt or os.environ.get(HASH_SALT_ENV, "") or None
    if redaction_mode is RedactionMode.HASH and not hash_salt:
        sys.stderr.write(
            f"error: --redaction-mode hash needs a salt: set {HASH_SALT_ENV} "
            "or pass --hash-salt.\n"
        )
        return 1

    report = scan(
        target,
        mode=mode,
        destination=args.destination,
        redaction_mode=redaction_mode,
        min_confidence=min_confidence,
        recursive=not args.no_recursive,
        audit_log_path=args.audit_log,
        tenant_id=args.tenant_id,
        user_id=args.user_id,
        force_text=force_text,
        hash_salt=hash_salt,
        **scan_kwargs,
    )

    try:
        written = _write_overlays(report, Path(args.out), args.overwrite) if args.out else None
    except OverlayConflict as exc:
        sys.stderr.write("error: --out would replace files it must not; nothing was written:\n")
        for problem in exc.problems:
            sys.stderr.write(f"  - {problem}\n")
        sys.stderr.write(
            "Write --out to an empty folder outside the one being scanned, or pass "
            "--overwrite to replace earlier overlays (never a scanned file).\n"
        )
        return 1
    except OverlayWriteError as exc:
        sys.stderr.write(f"error: writing overlays failed: {exc}\n")
        if exc.replaced:
            sys.stderr.write("These existing files were already replaced (--overwrite):\n")
            for dest in exc.replaced:
                sys.stderr.write(f"  - {dest}\n")
            sys.stderr.write("No other overlay was left behind.\n")
        else:
            sys.stderr.write("Nothing was written.\n")
        return 1

    if args.json:
        payload = report.to_dict(include_original=args.include_original_values)
        if written:
            payload["overlays_written"] = [str(p) for p in written]
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        _print_human(report, written)

    return 0 if report.all_allowed else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="privacy-shield",
        description=(
            "Local-first PII scan + clean-overlay runner. Only the cleaned "
            "overlay is meant to leave the machine; enforcement hosts are optional."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser(
        "scan",
        help="Scan a folder, file, or raw text span by span and gate egress.",
    )
    scan_p.add_argument(
        "target",
        help="Folder path, file path, raw text, or '-' to read text from stdin.",
    )
    scan_p.add_argument(
        "--mode",
        choices=sorted(_MODES),
        default="STANDARD",
        help="Privacy mode (default: STANDARD).",
    )
    scan_p.add_argument(
        "--destination",
        default="external_llm",
        help="Egress destination identifier (default: external_llm).",
    )
    scan_p.add_argument(
        "--redaction-mode",
        choices=sorted(_REDACTION_MODES),
        default=RedactionMode.REDACT.value,
        help="How PII spans are rewritten in the overlay (default: redact).",
    )
    scan_p.add_argument(
        "--min-confidence",
        choices=sorted(_CONFIDENCE),
        default=Confidence.MEDIUM.value,
        help="Minimum detection confidence to act on (default: medium).",
    )
    scan_p.add_argument(
        "--hash-salt",
        help=f"Salt for --redaction-mode hash, required there; use 32+ characters. "
             f"Prefer {HASH_SALT_ENV}: an argument is visible in the process "
             f"list and shell history, and a known salt lets anyone test "
             f"guessed values against the hashes. The flag wins if both are set.",
    )
    scan_p.add_argument(
        "--out",
        help="Directory to write the clean overlays into. Nothing is written if "
             "an overlay would replace an existing file, a scanned file, or "
             "another overlay of this run.",
    )
    scan_p.add_argument(
        "--overwrite", action="store_true",
        help="Let --out replace an existing file at an overlay's name, even one "
             "that is not an overlay. A scanned file, a symbolic link, a "
             "directory or a clash between two overlays is still refused.",
    )
    scan_p.add_argument("--json", action="store_true", help="Emit the full report as JSON.")
    scan_p.add_argument(
        "--include-original-values", action="store_true",
        help="Include each finding's original value and surrounding context in "
             "--json. OFF by default: stdout is the model's context when this "
             "CLI runs under the skill's Bash grant.",
    )
    scan_p.add_argument("--audit-log", help="Path for the shield's per-document audit log.")
    scan_p.add_argument(
        "--no-recursive",
        action="store_true",
        help="Do not descend into subfolders when scanning a directory.",
    )
    scan_p.add_argument(
        "--all-files",
        action="store_true",
        help="Consider every file, not just known text/document extensions.",
    )
    scan_p.add_argument(
        "--extensions",
        help=(
            "Comma-separated file extensions to consider when walking a folder "
            "(e.g. '.txt,.csv'), instead of the default text/document list. A "
            "CHOSEN scope: a skipped file is recorded but does not affect the "
            "exit code, unlike the imposed default. Mutually exclusive in "
            "effect with --all-files (which wins if both are given)."
        ),
    )
    scan_p.add_argument(
        "--text",
        action="store_true",
        help="Force the target to be treated as raw text, never a path.",
    )
    scan_p.add_argument("--tenant-id", default="", help="Tenant id for the audit trail.")
    scan_p.add_argument("--user-id", default="", help="Acting user id for the audit trail.")
    scan_p.set_defaults(func=_cmd_scan)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        reject_legacy_env()
        return args.func(args)
    except FileNotFoundError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    except Exception as exc:  # noqa: BLE001 — CLI boundary
        sys.stderr.write(f"error: {exc}\n")
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
