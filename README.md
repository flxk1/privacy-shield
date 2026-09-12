<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# privacy-shield

**What in this folder may reach a cloud model?**

Local-first PII/PHI detection and clean-overlay pipeline for governed folders.

## Problem

Sending a document to a cloud model sends every personal value in it. Detection and the egress verdict belong on the machine holding the file.

## Install

```
pip install "git+https://github.com/flxk1/privacy-shield.git@v1.0.0"
```

Zero required dependencies. Extras: `[semantic]` numpy>=1.24 +
onnxruntime>=1.16 (embedding and shadow-ONNX layer), `[extract]` PyMuPDF>=1.23 +
opencv-python-headless>=4.8 (PDF, image extraction; PyMuPDF is AGPL), `[dev]` pyyaml>=6 +
pytest>=7 (config layer, tests).

## Usage

```python
from brain.privacy_shield import scan

doc = scan("/path/to/governed/folder").documents[0]
doc.overlay            # the cleaned overlay — the one payload cleared to leave
doc.classification     # public | internal | confidential | berufsgeheimnis
doc.egress_allowed     # the guard's verdict for this document
```

`privacy-shield scan <path|-|text>` is the same capability as a console script;
it exits `0` when every overlay clears and `2` when a document is blocked. Full
signature, flags and stdin handling: [docs/cli.md](docs/cli.md).

## Example

```
in : Ticket 12: Erika Mustermann. Mail: erika@example.invalid. Diagnosis: migraine.
out: Ticket 12: [NAME]. Mail: [EMAIL]. [HEALTH]: migraine.
     confidential False {'name': 1, 'email': 1, 'health_data': 1}
```

The health marker classifies the source `confidential`, so the guard blocks
egress. Input is invented placeholder data.

## Interface

- `scan(target, *, mode, destination, redaction_mode, min_confidence, recursive, extensions, audit_log_path, tenant_id, user_id, force_text) -> ScanReport`
- `ScanReport(mode, destination, root, documents)` · `DocumentScan(overlay, spans, findings_by_type, egress_allowed, classification, blocked_reason, audit_id, errors)` · `SpanFinding(pii_type, start, end, confidence, layer, value, context)`
- `PrivacyMode`: `STANDARD` · `LOCAL_ONLY` · `ANONYMOUS_JSON` · `REGEX_ONLY`. `RedactionMode`: `DETECT_ONLY` · `REDACT` · `PSEUDONYMIZE` · `HASH` · `BLOCK`.
- egress guard: `PrivacyGate.check(data, destination) -> PrivacyGateResult` · `require_privacy_check` · `PrivacyGate.attach_enforcement_sink(sink)`
- overlay: `anonymize_for_cloud` · `rehydrate_response` · `AnonymousEnvelope` — the value↔placeholder map stays local.
- enforcement seam: `EnforcementSink` · `EnforcementDecision` · `EnforcementVerdict` · `NoOpEnforcementSink` · `RvndEnforcementAdapter`
- Stages, module map, layout: [docs/pipeline.md](docs/pipeline.md).

## Family

Runtime controls: the span-by-span PII-cleaned overlay and egress guard; only
the overlay leaves the machine. `pyproject.toml` declares an empty
`dependencies` list, so every loomground plane and RVND stay optional here and
downstream. Absent the `[semantic]` and `[extract]` extras, detection degrades
to the deterministic regex/lexicon floor. Absent an enforcement sink, the guard
decides locally and writes the standalone audit trail; RVND attaches through
`EnforcementSink` as an additive skin —
[docs/adr/0001-rvnd-optional.md](docs/adr/0001-rvnd-optional.md). The
`privacy-shield` skill wraps the same capability for agents.

## Status

1.0.0 · 122 tests, 114 passing · Python >=3.10 · zero required dependencies ·
limits, gaps and the test split: [docs/limits.md](docs/limits.md).

## License

Apache-2.0 — `LICENSES/Apache-2.0.txt`, `LICENSE`, attribution in `NOTICE`.
