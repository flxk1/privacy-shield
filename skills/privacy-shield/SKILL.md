---
name: privacy-shield
description: >-
  Scan a folder, file, or text span-by-span and produce a PII-cleaned overlay —
  the only thing meant to leave the machine — then decide whether egress to an
  external service is allowed, by source classification. Personal data is found
  with a regex/lexicon floor plus an optional local embedding/LLM layer; the
  value<->placeholder map stays local; every decision is written to a local audit
  trail. Works fully standalone with ZERO loomground and ZERO RVND; RVND is an
  OPTIONAL enforcement skin (permit/hold/deny + signed chain) behind an adapter
  that no-ops when absent. "Cleared" means the source class is allowed to egress,
  NOT a zero-residual certificate. Triggers on "redact this", "clean this before
  I send it to the cloud", "is this safe for an external LLM", "scan this folder
  for personal data", "make a privacy overlay", "lock this folder's egress".
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
    - present_cleared_as_a_zero_residual_guarantee
    - leak_the_value_placeholder_map
    - require_rvnd_on_default_path
  obligations:
    - only_the_overlay_egresses
    - value_placeholder_map_stays_local
    - every_decision_written_to_the_audit_trail
    - gate_on_source_classification_not_overlay_residual
    - degrade_gracefully_without_optional_extras
  redress:
    - { kind: recorded_override, by: workspace_owner, overturn: true }
  budget: { usd: 1, iters: 20 }
  on-boundary: report-not-repair
---

# privacy-shield

The scan / overlay / egress engine lives in the `brain.privacy_shield` package
(`scanner`, `redactor`, `anonymous_json`, `gate`, `audit_log`). The agent-facing
entry is `brain.privacy_shield.scan(target) -> ScanReport` and the
`privacy-shield` CLI. The four modes (STANDARD / LOCAL_ONLY / ANONYMOUS_JSON /
REGEX_ONLY) and the RVND-optional enforcement seam are described in the README.

## Notes
- The egress verdict is on SOURCE CLASSIFICATION (privacy mode + confidential /
  professional-secrecy / special-category tiers), not on residual overlay PII:
  redaction has already removed original values, and gating the overlay could let
  an over-redacted privileged document pass. "Cleared" = the source class may
  egress, not a certificate of zero residual.
- The optional semantic (embeddings / local model) and document/media extraction
  layers require extras and degrade gracefully when absent.
