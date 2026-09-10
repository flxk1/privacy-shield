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

91 passed, 8 failed. Every privacy-shield **core** test file passes 100%
(regex-only, embeddings, semantic wiring, overlay, local-model runtime, config,
onnx contextual PII, media inputs, review profiles). The 8 failures are all in
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
