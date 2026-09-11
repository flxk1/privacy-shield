# Privacy Shield

Local-first PII/PHI detection and **clean-overlay** pipeline for governed folders.

Documents are scanned span-by-span and a cleaned *overlay* is produced, guarded by
two layers — a deterministic **regex/lexicon filter** (the floor) and a **local
model / embeddings semantic PII detector** (novel phrasing) — so that **only the
cleaned overlay ever leaves the machine** to a cloud LLM. Original values stay
local; a local step rehydrates the cloud response. Every action is written to an
audit trail.

100% local execution on the detection path — zero external API calls to detect or
redact. The cloud LLM only ever sees anonymised placeholders.

> Extracted and consolidated from the internal **Brain** platform. This repo is
> the standalone privacy-shield subset plus its direct dependencies; the wider
> Brain application is intentionally not included.

## Pipeline (end to end)

```
document / draft text
   │
   ▼  extract (optional)      extractor.py + media/{image,audio,video,metadata}.py
span text
   │
   ▼  1. regex/lexicon floor  scanner.py  (PrivacyScanner.scan_text — deterministic)
   ▼  2. semantic 2nd pass    privacy_shield_embeddings.py (PIIContextMatcher, cosine ≥0.75)
   ▼     shadow contextual    onnx_contextual_pii.py / onnx_shadow.py (16-feature ONNX, shadow)
   ▼     local-LLM check      scanner.scan_text_with_local_llm → services/local_model_runtime.py
   │
   ▼  redact / walk spans     redactor.py (placeholders, preserve analytical value)
   │
   ▼  build clean overlay     anonymous_json.py (AnonymousEnvelope: PII→placeholders,
   │                          value↔placeholder map kept LOCAL only)
   │
   ▼  EGRESS GUARD            gate.py (PrivacyGate / require_privacy_check),
   │                          scanner.is_safe_for_external_llm  → only overlay leaves
   ▼
cloud LLM  ──►  response
   │
   ▼  rehydrate locally       anonymous_json.rehydrate_response
   ▼  audit every action      audit_log.py + privacy_skill_kg.py (+ compliance_evidence_export.py*)
```

`shield.py` (`PrivacyShield`) is the orchestrator, with four modes:
**STANDARD · LOCAL_ONLY · ANONYMOUS_JSON · REGEX_ONLY**.

## Run it — `scan()` + CLI

The pipeline above is driven by one thin, agent-invokable entry point,
`brain.privacy_shield.runner.scan` (also re-exported as
`brain.privacy_shield.scan`). It walks a **folder**, a **single file**, or **raw
text**, runs the real pipeline per document (extract → regex → semantic →
local-LLM → redact → overlay), then the **egress guard** decides — on the source
classification (privacy mode + confidential/berufsgeheimnis tiers + Art. 9) —
whether the payload may leave. Only when it may does the **clean overlay** (the
only thing meant to leave the machine) go out. Every decision is recorded to the
standalone `audit_log`. No RVND is imported and no enforcement sink is attached.

```python
from brain.privacy_shield import scan
from brain.privacy_shield.shield import PrivacyMode

report = scan("/path/to/governed/folder", mode=PrivacyMode.STANDARD)
report.all_allowed                 # aggregate egress verdict (bool)
for doc in report.documents:
    doc.overlay                    # the cleaned overlay — the ONLY thing that egresses
    doc.spans                      # per-span findings (type/start/end/confidence/layer)
    doc.egress_allowed             # this document's egress verdict
    doc.classification             # public | internal | confidential | berufsgeheimnis
report.to_dict()                   # JSON-ready structured result
```

`scan()` signature (keyword-only options):
`scan(target, *, mode=PrivacyMode.STANDARD, destination="external_llm",
redaction_mode=RedactionMode.REDACT, min_confidence=Confidence.MEDIUM,
recursive=True, extensions=DEFAULT_EXTENSIONS, audit_log_path=None,
tenant_id="", user_id="", force_text=False) -> ScanReport`.

CLI (installed as the `privacy-shield` console script by `pip install -e .`):

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

**Honest limits (runner/CLI):**
- **Egress verdict is source-classification, not proof of anonymity.** The gate
  blocks LOCAL_ONLY / confidential / berufsgeheimnis / Art. 9 sources; a
  non-confidential PII document passes and its redacted overlay leaves. It does
  not re-scan the overlay to certify zero residual PII.
- **Overlay cosmetics.** Redaction reuses the engine's `redactor.py`. When the
  regex layers produce *overlapping* findings (e.g. a name pattern overlapping an
  email), the placeholder splicing can leave placeholder-text fragments (never
  original PII — the tests assert injected values never survive). The engine is
  reused unchanged; this is a known redactor artefact, not introduced here.
- **Folder walk** defaults to known text/document extensions (`DEFAULT_EXTENSIONS`);
  use `--all-files` to consider every file. Binary/undecodable files are recorded
  as per-document `errors`, not fatal.
- **Semantic + local-LLM passes are optional.** With neither the `[semantic]`
  extras nor a local model present, detection is the deterministic regex/lexicon
  floor only (the modules degrade gracefully). `[extract]` extras (PyMuPDF/opencv)
  are needed for PDF/image extraction; without them those documents surface an
  extraction error.
- **MCP wrapper** is intentionally out of scope here — `scan()` is the callable
  capability; wrap it in a tool server when needed.

## RVND-optional

The core is **RVND-optional**: it runs as a complete standalone artifact with
**zero RVND present** — no `import rvnd`, no RVND call, no MCP `workspace_*`
call on any core path. RVND governance is an **optional enrichment** behind a
flag-gated adapter that no-ops when absent. (See `docs/adr/0001-rvnd-optional.md`.)

The seam lives at the **egress guard** (`gate.py`). Every guard entry point
behaves in both modes:

- **Default (zero RVND):** the guard decides **locally** (privacy mode +
  classification tiers + Art. 9, over the scanner's regex/embeddings/local-LLM
  verdict) and records the decision to the standalone `audit_log`
  (`AI_PRIVACY_SHIELD_DECISION`); `require_privacy_check` raises
  `PermissionError` on an unsafe egress. Fully functional alone.
- **Enriched (adapter attached):** the **same** decision is additionally
  surfaced to an optional `EnforcementSink` (e.g. an RVND adapter → verdict +
  signed-chain receipt). Enrichment is strictly additive and never overrides
  the local decision.

The seam (`brain.privacy_shield.enforcement`) is interface-only —
`EnforcementSink` (Protocol), `EnforcementDecision` / `EnforcementVerdict`, the
inert default `NoOpEnforcementSink`, and `RvndEnforcementAdapter`, an
**interface-only stub** that documents the intended RVND bindings without
importing or calling `rvnd.*`. Attach a real adapter (built outside this core)
via `PrivacyGate.attach_enforcement_sink(...)`.

```python
from brain.privacy_shield.gate import PrivacyGate

gate = PrivacyGate()                       # zero RVND — decides locally + audits
# gate.attach_enforcement_sink(rvnd_sink)  # optional: add verdict + signed chain
result = gate.check({"text": doc}, destination="external_llm")
```

**Advisory vs enforce (design note):** RVND's `decide_action` *appends to the
signed chain* — gating is itself a mutating act — so an adapter distinguishes an
advisory preview (pure `action_gate.gate`, no chain write) from an enforce call
(`decide_action`, which writes the chain and yields an `audit_id`). The
`enforce` flag on `EnforcementSink.gate` carries that distinction;
`record_decision` is always advisory. The standalone `audit_log` is the default
audit trail; the RVND signed-chain is the optional enrichment via the same seam.
`compliance_evidence_export.py` (Brain-coupled) is an optional/enterprise export,
not a core dependency.

## Module inventory

| Stage | Module | Status |
|---|---|---|
| Agent entry point (`scan()` + CLI) | `privacy_shield/runner.py`, `privacy_shield/cli.py` | complete |
| Orchestrator + 4 modes | `privacy_shield/shield.py` | complete |
| Regex/lexicon filter (floor) | `privacy_shield/scanner.py` | complete |
| Semantic PII (embeddings) | `privacy_shield_embeddings.py` (`PIIContextMatcher`) | complete |
| Contextual PII (shadow ONNX) | `privacy_shield/onnx_contextual_pii.py`, `onnx_shadow.py` | complete (shadow-only) |
| Local-LLM detector runtime | `services/local_model_runtime.py` (+ `llm_client.py`, `user_credentials.py`) | complete |
| Span redaction | `privacy_shield/redactor.py` | complete |
| Document/media extraction | `privacy_shield/extractor.py`, `privacy_shield/media/*` | complete (PDF/img need optional extras) |
| Clean overlay builder | `privacy_shield/anonymous_json.py` (`AnonymousEnvelope`, `anonymize_for_cloud`, `rehydrate_response`) | complete |
| Egress guard | `privacy_shield/gate.py` (`PrivacyGate`, `require_privacy_check`), `scanner.is_safe_for_external_llm` | complete |
| Optional enforcement/audit seam | `privacy_shield/enforcement.py` (`EnforcementSink`, `NoOpEnforcementSink`, `RvndEnforcementAdapter` stub) | complete (interface-only; RVND-optional) |
| Anonymisation / pseudonymisation | `privacy_shield/anonymisation_skill.py` | complete |
| Breach handling | `privacy_shield/breach.py` | complete |
| Prompt-injection / threat scan | `privacy_shield/security_scanner.py` | complete |
| Audit trail | `audit_log.py`, `privacy_shield/privacy_skill_kg.py` | complete |
| JSON-template overlay helper | `helpers/json_template_overlay.py` | complete |
| Compliance evidence export | `compliance_evidence_export.py` | **coupled to Brain app — see Gaps** |
| Text simplifier | `simplifier.py` | core complete; LLM path needs Brain LLM gateway |
| Declarative config | `configs/privacy_shield/*` (taxonomy, patterns, lexica ×7, onnx policy, review profiles) | complete |

## Layout

```
privacy-shield/
├── src/brain/                 # import namespace preserved from Brain (unmodified code)
│   ├── privacy_shield/         # the pipeline package
│   ├── privacy_shield_embeddings.py
│   ├── simplifier.py
│   ├── audit_log.py  llm_client.py  user_credentials.py
│   ├── compliance_evidence_export.py
│   ├── helpers/  (json_template_overlay, documents)
│   ├── services/ (local_model_runtime)
│   └── utils/    (file_io, datetime)
├── configs/privacy_shield/     # declarative taxonomy / patterns / lexica / onnx policy
├── tests/                      # extracted test subset
├── conftest.py  pyproject.toml
└── LICENSE  LICENSES/  REUSE.toml  NOTICE
```

The `brain.*` import namespace is kept deliberately so the original code and its
tests run unmodified (no reimplementation). Distribution renaming is a later step.

## Tests

```
python3 -m pytest tests/ -q
```

114 passed, 8 failed. Every privacy-shield **core** test file passes 100%
(regex-only, embeddings, semantic wiring, overlay, local-model runtime, config,
onnx contextual PII, media inputs, review profiles, the RVND-optional egress
guard — `test_privacy_gate_rvnd_optional.py` — and the runner + CLI on synthetic
PII fixtures — `test_privacy_shield_runner.py`, 14 tests). The 8 failures are all
in `test_simplifier.py`'s LLM path, which patches `brain.services.llm_runtime` —
the Brain LLM gateway chain that is intentionally out of scope here.

## Install

From the `loomground-plugins` marketplace (publication pending):

```
/plugin marketplace add flxk1/loomground-plugins
/plugin install privacy-shield@loomground
```

Directly from GitHub, with pip:

```
pip install "git+https://github.com/flxk1/privacy-shield.git"
```

Base install has zero hard dependencies. Optional extras:

- `pip install -e .[semantic]` — numpy + onnxruntime (embeddings + shadow model)
- `pip install -e .[extract]` — PyMuPDF + opencv (document/image extraction; PyMuPDF is AGPL, optional)
- `pip install -e .[dev]` — pyyaml + pytest

## Known gaps

The compliance evidence export is still woven into the Brain service layer;
the CLI entry point ships (`privacy-shield scan`) but there is no MCP-tool
wrapper in this subset; the ONNX contextual model is shadow-only (no
promotion); there is no bundled pre-embedded PII-context file.
