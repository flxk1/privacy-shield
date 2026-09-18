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
import json
import sys
from pathlib import Path
from typing import List, Optional

from ._legacy_env import reject_legacy_env
from .redactor import RedactionMode
from .utils.file_io import path_exists
from .runner import ScanReport, scan
from .scanner import Confidence
from .shield import PrivacyMode

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


def _write_overlays(report: ScanReport, out_dir: Path) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    for doc in report.documents:
        dest = out_dir / f"{_safe_name(doc.source)}.overlay.txt"
        dest.write_text(doc.overlay, encoding="utf-8")
        written.append(dest)
    return written


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
    if written:
        out.write(f"overlays written: {len(written)} -> {written[0].parent}\n")
    if not report.all_allowed:
        blocked = report.blocked_documents
        out.write(f"BLOCKED: {len(blocked)} document(s) may NOT egress.\n")
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
        **scan_kwargs,
    )

    written = _write_overlays(report, Path(args.out)) if args.out else None

    if args.json:
        payload = report.to_dict()
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
    scan_p.add_argument("--out", help="Directory to write the clean overlays into.")
    scan_p.add_argument("--json", action="store_true", help="Emit the full report as JSON.")
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
