# `scan()` and the `privacy-shield` CLI

Moved out of the README (README canon, `repo-standards/STANDARDS.md` § README canon).

## `scan()`

`brain.privacy_shield.runner.scan` (re-exported as `brain.privacy_shield.scan`)
walks a **folder**, a **single file**, or **raw text**, runs the pipeline per
document (extract → regex → semantic → local-LLM → redact → overlay), then the
**egress guard** decides — on the source classification (privacy mode +
confidential / berufsgeheimnis tiers + Art. 9) — whether the payload may leave.
Only when it may does the clean overlay go out. Every decision is recorded to
the standalone `audit_log`. RVND is left unimported and no enforcement sink is
attached.

Keyword-only signature:

```
scan(target, *, mode=PrivacyMode.STANDARD, destination="external_llm",
     redaction_mode=RedactionMode.REDACT, min_confidence=Confidence.MEDIUM,
     recursive=True, extensions=DEFAULT_EXTENSIONS, audit_log_path=None,
     tenant_id="", user_id="", force_text=False) -> ScanReport
```

`Confidence` comes from `brain.privacy_shield.scanner`; `DEFAULT_EXTENSIONS`
from `brain.privacy_shield.runner`.

```python
from brain.privacy_shield import scan
from brain.privacy_shield.shield import PrivacyMode

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
                                  [--audit-log PATH] [--no-recursive] [--all-files] [--text]
```

It prints the verdict, writes the clean overlays with `--out`, and **exits `0`
when every overlay is cleared for egress, `2` when any document is blocked** (so
an agent or a shell can gate on it). `-` reads text from stdin. Without an
install, run it as `python -m brain.privacy_shield.cli scan ...`.

The CLI prints a per-document `audit_id` (`ps-<UTC timestamp>-<random>`), which
differs on every run.
