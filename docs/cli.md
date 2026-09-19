# `scan()` and the `privacy-shield` CLI

Moved out of the README (README canon, `repo-standards/STANDARDS.md` § README canon).

## `scan()`

`privacy_shield.runner.scan` (re-exported as `privacy_shield.scan`)
walks a **folder**, a **single file**, or **raw text**, runs the pipeline per
document (extract → regex → semantic → local-LLM → redact → overlay), then the
**egress guard** decides — on the source classification (privacy mode +
confidential / berufsgeheimnis tiers + Art. 9) — whether the payload may leave.
Only when it may does the clean overlay go out. Every decision is recorded to
the standalone `audit_log`. No external enforcement sink is attached.

Keyword-only signature:

```
scan(target, *, mode=PrivacyMode.STANDARD, destination="external_llm",
     redaction_mode=RedactionMode.REDACT, min_confidence=Confidence.MEDIUM,
     recursive=True, extensions=<not passed>, audit_log_path=None,
     tenant_id="", user_id="", force_text=False) -> ScanReport
```

`Confidence` comes from `privacy_shield.scanner`; `DEFAULT_EXTENSIONS`
from `privacy_shield.runner`.

`extensions` is written `<not passed>` above on purpose, not
`=DEFAULT_EXTENSIONS`: those are different calls. Leaving `extensions` out
entirely — the ordinary no-flags scan — resolves internally to
`DEFAULT_EXTENSIONS` as an **imposed** scope the caller did not choose, and a
file it skips (a `.xlsx`, an `.eml`, …) counts against `report.all_allowed`
and the CLI's exit code. Passing `extensions=DEFAULT_EXTENSIONS` **by name**
is a **chosen** scope — same set of suffixes, same files skipped — and a skip
is recorded but does not move `all_allowed`. See
`ScanReport.all_allowed`, `ScanReport.imposed_filtered_files` and
`ScanReport.chosen_filtered_files`.

```python
from privacy_shield import scan
from privacy_shield.shield import PrivacyMode

report = scan("/path/to/governed/folder", mode=PrivacyMode.STANDARD)
report.all_allowed                 # aggregate egress verdict (bool)
for doc in report.documents:
    doc.overlay                    # the cleaned overlay — the only thing that egresses
    doc.spans                      # per-span findings (pii_type/start/end/confidence/layer)
    doc.egress_allowed             # this document's egress verdict
    doc.classification             # public | internal | confidential | berufsgeheimnis
report.to_dict()                   # JSON-ready structured result
```

## CLI

Installed as the `privacy-shield` console script by `pip install .`:

```
privacy-shield scan <path|-|text> [--mode STANDARD|LOCAL_ONLY|ANONYMOUS_JSON|REGEX_ONLY]
                                  [--destination external_llm] [--out DIR] [--json]
                                  [--redaction-mode redact|pseudonymize|hash|detect_only|block]
                                  [--min-confidence low|medium|high]
                                  [--audit-log PATH] [--no-recursive]
                                  [--all-files | --extensions .txt,.csv] [--text]
```

`--all-files` and `--extensions` are both a caller CHOICE, at the CLI
boundary exactly as at `scan()`'s: naming neither imposes `DEFAULT_EXTENSIONS`
(a skip then counts against exit `0`); naming either — including
`--extensions` with the same suffixes `DEFAULT_EXTENSIONS` covers — is a
chosen scope, and a skip is recorded but does not move the exit code. A
CHOSEN filter that ends up excluding every file in scope (a typo'd suffix, an
empty `--extensions ,`) still exits `0` — that is correct, the caller asked
for that scope — but every excluded file is named in the human output under
"skipped by the extensions scope you chose", not silently absorbed into
`documents: 0`.

It prints the verdict, writes the clean overlays with `--out`, and **exits `0`
only when `report.all_allowed` is True: every document is fully read AND
cleared for egress. It exits `2` when any of that is not so** — a document
blocked by the gate, a document only partly read (a media channel with no
backend installed), a path the walk could not read at all, or a file the
default extension scope silently dropped because neither `--extensions` nor
`--all-files` was given — (so an agent or a shell can gate on it). The human
output names which of these tripped the exit code, per file; `--json` carries
the same facts in `documents[].egress_allowed` / `incomplete_documents` /
`walk_errors` (a list of `{"kind", "message"}` objects, `kind` one of
`unreadable` / `filtered_default` / `filtered_chosen` — never re-derive
`kind` by matching on `message`, which can carry an OS-reported filename) /
`unreadable_errors` / `imposed_filtered_files` / `chosen_filtered_files`.
`-` reads text from stdin. Without an install, run it as
`python -m privacy_shield.cli scan ...`.

The CLI prints a per-document `audit_id` (`ps-<UTC timestamp>-<random>`), which
differs on every run.
