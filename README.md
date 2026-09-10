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

> Extracted and consolidated from the internal **Brain** platform (Privacy Shield =
> "Heart 4"). This repo is the standalone privacy-shield subset plus its direct
> dependencies; the wider Brain application is intentionally not included.

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

100 passed, 8 failed. Every privacy-shield **core** test file passes 100%
(regex-only, embeddings, semantic wiring, overlay, local-model runtime, config,
onnx contextual PII, media inputs, review profiles, and the RVND-optional egress
guard — `test_privacy_gate_rvnd_optional.py`). The 8 failures are all in
`test_simplifier.py`'s LLM path, which patches `brain.services.llm_runtime` — the
Brain LLM gateway chain that is intentionally out of scope here. Not weakened.

## Install extras

- `pip install -e .[semantic]` — numpy + onnxruntime (embeddings + shadow model)
- `pip install -e .[extract]` — PyMuPDF + opencv (document/image extraction; PyMuPDF is AGPL, optional)
- `pip install -e .[dev]` — pyyaml + pytest

## Gaps (to be a product)

See `GAPS` section below and the assembly report. Headlines: the compliance
evidence export is still woven into the Brain service layer; there is no packaged
CLI / MCP entry point in this subset; ONNX contextual model is shadow-only (no
promotion); no bundled pre-embedded PII-context file.
