# Pipeline, module map and layout

Moved out of the README (README canon, `repo-standards/STANDARDS.md` § README canon).

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

The egress guard decides on the source classification (privacy mode +
confidential / berufsgeheimnis tiers + Art. 9) — see
[adr/0001-external-enforcement.md](adr/0001-external-enforcement.md) for the guard's two modes
and the optional enforcement seam.

## Module inventory

| Stage | Module | Status |
|---|---|---|
| Agent entry point (`scan()` + CLI) | `runner.py`, `cli.py` | complete |
| Orchestrator + 4 modes | `shield.py` | complete |
| Regex/lexicon filter (floor) | `scanner.py` | complete |
| Semantic PII (embeddings) | `privacy_shield_embeddings.py` (`PIIContextMatcher`) | complete |
| Contextual PII (shadow ONNX) | `onnx_contextual_pii.py`, `onnx_shadow.py` | complete (shadow-only) |
| Local-LLM detector runtime | `services/local_model_runtime.py` (+ `llm_client.py`, `user_credentials.py`) | complete |
| Span redaction | `redactor.py` | complete |
| Document/media extraction | `extractor.py`, `media/*` | complete (PDF/img need optional extras) |
| Clean overlay builder | `anonymous_json.py` (`AnonymousEnvelope`, `anonymize_for_cloud`, `rehydrate_response`) | complete |
| Egress guard | `gate.py` (`PrivacyGate`, `require_privacy_check`), `scanner.is_safe_for_external_llm` | complete |
| Optional enforcement/audit seam | `enforcement.py` (`EnforcementSink`, `NoOpEnforcementSink`, `ExternalEnforcementAdapter` stub) | complete; interface-only |
| Anonymisation / pseudonymisation | `anonymisation_skill.py` | complete |
| Breach handling | `breach.py` | complete |
| Prompt-injection / threat scan | `security_scanner.py` | complete |
| Audit trail | `audit_log.py`, `privacy_skill_kg.py` | complete |
| JSON-template overlay helper | `helpers/json_template_overlay.py` | complete |
| Compliance evidence export | `compliance_evidence_export.py` | coupled to the upstream app — see [limits.md](limits.md) |
| Text simplifier | `simplifier.py` | core complete; LLM path needs the upstream LLM gateway |
| Declarative config | `configs/privacy_shield/*` (taxonomy, patterns, lexica ×7, onnx policy, review profiles) | complete |

## Layout

```
privacy-shield/
├── src/privacy_shield/         # the package and its only import root
│   ├── __init__.py             # public API: scan, PrivacyGate, overlay, enforcement seam
│   ├── runner.py  cli.py  shield.py  scanner.py  redactor.py  gate.py
│   ├── anonymous_json.py  enforcement.py  extractor.py  breach.py
│   ├── anonymisation_skill.py  security_scanner.py  onnx_contextual_pii.py  onnx_shadow.py
│   ├── media/    (image, audio, video, metadata)
│   ├── privacy_shield_embeddings.py  simplifier.py
│   ├── audit_log.py  privacy_skill_kg.py  llm_client.py  user_credentials.py
│   ├── compliance_evidence_export.py  _legacy_env.py
│   ├── helpers/  (json_template_overlay, documents)
│   ├── services/ (local_model_runtime)
│   └── utils/    (file_io, datetime)
├── configs/privacy_shield/     # declarative taxonomy / patterns / lexica / onnx policy
├── tests/                      # extracted test subset; conftest.py isolates user state
├── pyproject.toml
└── LICENSE  LICENSES/  REUSE.toml  NOTICE
```

`privacy_shield` is the only import root. The pre-rename module paths and environment
variable names map to their replacements in the CHANGELOG migration table.
