---
name: privacy-shield
description: >-
  Local-first PII/PHI detection and clean-overlay pipeline for governed folders.
  Scan a folder, file, or text span by span, produce the PII-cleaned overlay —
  the only thing meant to leave the machine — then decide whether egress to an
  external service is allowed, by source classification. Personal data is found
  with a regex/lexicon floor plus an optional local embedding/LLM layer; the
  value<->placeholder map stays local; this skill always passes `--audit` (or
  `--audit-log PATH`), so every decision is written to a local audit trail
  (the library alone writes none). Works standalone with every Loomground plane optional. An external
  enforcement host can attach behind the neutral sink interface
  that no-ops when absent. "Cleared" means the source class is allowed to egress,
  NOT a zero-residual certificate. Use when the user says "redact this", "clean
  this before I send it to the cloud", "is this safe for an external LLM", "scan
  this folder for personal data", "make a privacy overlay", "lock this folder's
  egress".
allowed-tools: privacy_scan, Bash(privacy-shield:*), Read
governance:
  grade: L1
  actions:
    - { kind: scan, risk: low }
    - { kind: produce_overlay, risk: low }
    - { kind: egress_decision, risk: medium }
  reserved:
    - { kind: allow_egress_of_a_blocked_source, by: workspace_owner }
  prohibited:
    - egress_original_unredacted_text
    - claim_zero_residual_in_any_shipped_document
    - leak_the_value_placeholder_map
    - require_external_enforcement_on_default_path
  obligations:
    - only_the_overlay_egresses
    - value_placeholder_map_stays_local
    - every_decision_written_to_the_audit_trail
    - disclaim_cleared_as_source_class_in_skill_readme_and_limits
    - block_a_blocked_source_class_however_redacted
    - clear_a_cleared_source_class_whatever_the_overlay_residual
    - degrade_gracefully_without_optional_extras
  redress:
    - { kind: recorded_override, by: workspace_owner, overturn: true }
  budget: { usd: 1, iters: 20 }
  on-boundary: report-not-repair
---

# privacy-shield

Primary path, works standalone with nothing else installed: the
`privacy_shield` package's scan / overlay / egress engine (`scanner`,
`redactor`, `anonymous_json`, `gate`, `audit_log`). Call it as
`privacy_shield.scan(target) -> ScanReport`, or via the `privacy-shield` CLI
over a file or folder. This skill's documented invocation always carries
`--audit` (record to the standard user-state audit path) or `--audit-log
PATH` (a specific one) — never neither:

```
privacy-shield scan <path|-|text> --audit
```

That opt-in is what makes `every_decision_written_to_the_audit_trail` below
true of what this skill does; the library's own default, called with
neither flag, writes nothing (see `PrivacyGate` in the package docs).

The shell grant is scoped to `Bash(privacy-shield:*)` — the console script this
package installs, and nothing else. An unrestricted `Bash` would hand a skill
whose governance block prohibits `egress_original_unredacted_text` the ability
to `curl` the original file anywhere, which is the exact act the block forbids.
`Read` stays unscoped so the overlays the CLI writes to `--out` can be consumed;
it cannot egress anything by itself. The four modes (STANDARD /
LOCAL_ONLY / ANONYMOUS_JSON / REGEX_ONLY) are listed in the README, which
links the repository's pipeline and external-enforcement notes.

Enriched path, when `loomground-mcp` is installed and running: call the
`privacy_scan` tool as:

```
privacy_scan(text=<text>, destination=<egress target, e.g. external_llm>, audit_log_path=<output of `privacy-shield audit-path`>, mode=<privacy mode>, redaction_mode=<redaction mode>, min_confidence=<confidence floor>)
```

Run `privacy-shield audit-path` first — permitted by `Bash(privacy-shield:*)`,
prints the standard user-state audit path (honouring
`PRIVACY_SHIELD_AUDIT_LOG`) and writes nothing — for the `audit_log_path`
value above. `text` is the only input this tool accepts, forced to raw text:
a file or folder goes through the CLI instead
(`privacy-shield scan <path> --audit`), never through this call. `destination`
is the EGRESS TARGET (`external_llm`, `openai`, `datev`, ...), never a
classification: the gate computes the source classification from `text`
itself and blocks or allows on it, so a non-external value there — passing a
classification word instead of a real destination — skips every block rule
and clears data that should have been refused. The result includes the clean
overlay, span findings and egress verdict; only the overlay may be used for a
subsequent external call. Without `loomground-mcp`, fall back to the primary
path above — see `degrade_gracefully_without_optional_extras` below.

## Order of work

1. Scan before anything reads the original. For a file, run
   `privacy-shield scan <file> --out <empty folder> --audit` and `Read` only
   the overlay it writes; never `Read` the original file first. Text that is
   already in the conversation has already been seen: scanning it afterwards
   lists what is in it, it protects nothing. Say so instead of presenting the
   scan as protection.
2. Scan the whole document, not an excerpt you chose. Personal data outside
   the excerpt is not found.
3. Continue only from the overlay. If the scan result carries
   `overlay_withheld`, detected values are still in it: do not use it.

## Health data and the ICD-10-GM list

Health data (GDPR Art. 9) is found far better with BfArM's ICD-10-GM
alphabetical index, about 89,000 diagnosis terms and synonyms. The index is
not part of this package: BfArM's download conditions forbid changing it and
require citing it, so each user keeps their own copy and the scanner reads it
unchanged.

1. Before a scan of anything that may hold health data, run
   `privacy-shield icd-status`. It prints where the index was found, or every
   place it looked, and exits `3` when it is missing. It writes nothing.
2. Where it is looked for, in order: the file or folder in
   `PRIVACY_SHIELD_ICD10GM`; `<user state>/privacy-shield/icd10gm/` (on macOS
   `~/Library/Application Support/privacy-shield/icd10gm/`); a BfArM ZIP in
   `~/Downloads`. The ZIP works as downloaded; unpacking is not needed.
3. When it is missing, tell the user before the scan that health terms will
   be found only by the short built-in keyword list, and how to get the index:
   bfarm.de > Kodiersysteme > Services > Downloads > ICD-10-GM >
   "Alphabet EDV-Fassung TXT (CSV)", which forms a usage contract with BfArM.
   The user accepts those terms and downloads it; this skill does not.
4. Index terms and the optional model's own hits do not decide the verdict.
   They are redacted in the overlay, and the document lists them under
   `art9_suspected`. Report that list as "special-category data suspected"
   and name the evidence. The verdict comes from the keyword list, which
   counts only in a sentence about a person. Drug names are not in the index
   and are not found. Say in the report whether the index was used.

## Releasing special-category data (consent)

A controller with a legal basis may send one document's special-category
data to an approved destination. Examples of a basis: the patient's explicit
consent, Art. 9(2)(a); health care, Art. 9(2)(h). The release is reserved
for the workspace owner (`allow_egress_of_a_blocked_source`), so:

- Pass `--release-basis <a-j> --release-ref <reference> --released-by <name>`
  only when the user has given all three in this conversation for this
  document. Never infer a basis, never reuse an earlier release, and never
  suggest one to get past a block.
- The destination must be on the owner's list in
  `PRIVACY_SHIELD_RELEASE_DESTINATIONS`. Do not set or change that variable.
- The scan must carry `--audit` or `--audit-log`; an unrecorded release is
  refused.
- A release lifts only an Art. 9 block. A professional-secrecy marker, a
  confidentiality marker, a credential or LOCAL_ONLY mode stays blocked. For
  a doctor, consent under the GDPR does not by itself release medical
  secrecy (§ 203 StGB). Say so when a doctor asks.
- Only the overlay leaves, and names stay redacted. Report `released` with
  its basis and reference.


## Reporting a scan

- Report what was found, by type, and say that the scan can miss values. It
  never certifies that none remain.
- `egress_allowed: true` means the source class may leave for that
  destination. It does not mean the overlay contains no personal data. Never
  report it as "no personal data" or "safe".
- Third parties' data (tenants, sellers, patients) needs the overlay, not the
  verdict.
- When you can see a value the scan missed, or a finding that is wrong (a file
  number marked as a diagnosis, a direction marked as a political opinion),
  name it in your answer as a detection defect and give the user the snippet
  shape (not the value) so it can become a test case.

## Notes
- The egress verdict is on SOURCE CLASSIFICATION (privacy mode + confidential /
  professional-secrecy / special-category tiers), not on residual overlay PII:
  redaction has already removed original values, and gating the overlay could let
  an over-redacted privileged document pass. "Cleared" = the source class may
  egress, not a certificate of zero residual.
- Three of the norms above were reworded to be falsifiable, because a norm no
  test can fail on is a promise in machine form and nothing else.
  `gate_on_source_classification_not_overlay_residual` asked for proof that a
  function never reads something, which cannot be tested; it is now the two
  observable consequences — `block_a_blocked_source_class_however_redacted` and
  `clear_a_cleared_source_class_whatever_the_overlay_residual`.
  `present_cleared_as_a_zero_residual_guarantee` named a claim with no artefact;
  it is now `claim_zero_residual_in_any_shipped_document` plus the positive
  `disclaim_cleared_as_source_class_in_skill_readme_and_limits`. Each is held by
  a test in `tests/test_governance_block_norms.py`.
- The optional semantic (embeddings / local model) and document/media extraction
  layers require extras and degrade gracefully when absent.
- `--redaction-mode hash` takes its salt from `PRIVACY_SHIELD_HASH_SALT`, which
  the user sets before the session starts. Never pass `--hash-salt`, never put
  the salt or `$PRIVACY_SHIELD_HASH_SALT` in any argument, and never read or
  print the variable: whoever knows the salt can test guessed values against
  the hashes. If the variable is unset the CLI exits `1`; ask the user to set
  it rather than inventing a salt.
- Write `--out` to an empty folder outside the one being scanned. If the CLI
  refuses with "nothing was written", report the named files to the user; do
  not add `--overwrite` unless the user asks to replace earlier overlays.
