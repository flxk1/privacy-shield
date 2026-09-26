<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# privacy-shield

Detect PII and PHI locally, produce a clean overlay, and block unsafe egress before content reaches an external model.

## Problem

Sending a document to a cloud model sends every personal value in it. Detection and the egress verdict belong on the machine holding the file.

## Install

```
pip install "git+https://github.com/flxk1/privacy-shield.git@v2.0.0"
```

Zero required dependencies. Extras: `[national]` python-stdnum>=1.19 (23
check-digit validator modules across 21 EU countries for national person
numbers; off unless a country is configured, and about one spurious finding
per three documents with every country enabled — scope it to your own and
measure, see [docs/limits.md](docs/limits.md)), `[freshness]` norm-freshness
(a staleness verdict for the `[national]` table against whatever
`python-stdnum` is installed; off unless both are present — see
`privacy_shield/freshness.py`; not on PyPI as of this writing, only
`[national]` is installable from PyPI today), `[semantic]` numpy>=1.24 +
onnxruntime>=1.16 (embeddings/shadow ONNX), `[extract]` PyMuPDF>=1.23 +
opencv-python-headless>=4.8 (PDF/image, PyMuPDF AGPL), `[openai]` openai>=1
(local-model client), `[dev]` pyyaml>=6 + pytest>=7 + hypothesis>=6 +
schwifty>=2024 + python-stdnum>=1.19.

State lands outside the package in `<user-state>/privacy-shield/`:
`logs/audit.jsonl` and `privacy_skill_kg/`, lazy-made. User-state is
`$XDG_STATE_HOME` (default `~/.local/state`), macOS `~/Library/Application
Support`, Windows `%LOCALAPPDATA%`. `PRIVACY_SHIELD_AUDIT_LOG` and
`PRIVACY_SHIELD_KG_DIR` override them.
`PRIVACY_SHIELD_{NATIVE,EMBEDDED}_LOCAL_MODEL_ENDPOINT` is loopback/unix;
`PRIVACY_SHIELD_MODEL_ENDPOINT_ALLOW_REMOTE=1` permits remote, logged.

## Usage

```python
from privacy_shield import scan

doc = scan("/path/to/governed/folder").documents[0]
doc.overlay            # the one payload cleared to leave
doc.classification     # public | internal | confidential | berufsgeheimnis
doc.egress_allowed     # the guard's verdict
```

`privacy-shield scan <path|-|text>` is the same capability as a console script;
it exits `0` only when every document is fully read AND cleared for egress,
`2` when any of that is not so — a document blocked by the gate, a document
only partly read, a path the walk could not read at all, or a file silently
dropped by the default extension scope the caller never named. The human
output names which of those it was, per file. Full signature, flags and stdin
handling: [docs/cli.md](docs/cli.md).

`egress_allowed` is a verdict on the source CLASS — privacy mode plus the
confidential / professional-secrecy / special-category tiers — and not a
certificate of zero residual. Gating on what survives in the overlay would clear
an over-redacted privileged document, so the gate does not look there. What
"cleared" does and does not cover: [docs/limits.md](docs/limits.md).

## Example

```
in : Ticket 12: Erika Mustermann. Mail: erika@example.invalid. Diagnosis: migraine.
out: Ticket 12: [NAME]. Mail: [EMAIL]. [HEALTH]: migraine.
     confidential False {'name': 1, 'email': 1, 'health_data': 1}
```

The health marker classifies the source `confidential`, so the guard blocks
egress. Placeholder data.

## Interface

- `scan(target, *, mode, destination, redaction_mode, min_confidence, recursive, extensions, audit_log_path, tenant_id, user_id, force_text) -> ScanReport`
- `ScanReport(mode, destination, root, documents)` · `DocumentScan(overlay, spans, findings_by_type, egress_allowed, classification, blocked_reason, audit_id, errors)` · `SpanFinding(pii_type, start, end, confidence, layer, value, context)`
- `PrivacyMode`: `STANDARD` · `LOCAL_ONLY` · `ANONYMOUS_JSON` · `REGEX_ONLY`. `RedactionMode`: `DETECT_ONLY` · `REDACT` · `PSEUDONYMIZE` · `HASH` · `BLOCK`.
- egress guard: `PrivacyGate.check(data, destination) -> PrivacyGateResult` · `require_privacy_check` · `PrivacyGate.attach_enforcement_sink(sink)`
- overlay: `anonymize_for_cloud` · `rehydrate_response` · `AnonymousEnvelope` — the value↔placeholder map stays local.
- enforcement seam: `EnforcementSink` · `EnforcementDecision` · `EnforcementVerdict` · `NoOpEnforcementSink` · `ExternalEnforcementAdapter`
- Stages, module map, layout: [docs/pipeline.md](docs/pipeline.md).

## Family

Runtime controls: the PII-cleaned overlay and egress guard; only the overlay
leaves. An empty `dependencies` list keeps every Loomground plane and external
enforcement host optional. Absent `[semantic]`/`[extract]`, detection
degrades to the deterministic regex/lexicon floor. Without a sink,
the guard decides locally and writes nothing to disk unless configured
(`audit_log=`/`PRIVACY_SHIELD_AUDIT_LOG`) to record to the standalone audit
trail. A host
attaches via the neutral `EnforcementSink` contract; see
[ADR 0001](docs/adr/0001-external-enforcement.md). The `privacy-shield` skill
wraps this for agents: package/CLI needs nothing else; MCP requires
`loomground-mcp`.

## Status

2.0.0 · 984 tests, 974 passing (CI extras; 2 skip without httpx) · Python >=3.10 · limits and gaps:
[docs/limits.md](docs/limits.md).

## License

Apache-2.0 — `LICENSES/Apache-2.0.txt`, `LICENSE`, attribution in `NOTICE`.
