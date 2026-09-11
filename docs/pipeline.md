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
[adr/0001-rvnd-optional.md](adr/0001-rvnd-optional.md) for the guard's two modes
and the optional enforcement seam.

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
| Compliance evidence export | `compliance_evidence_export.py` | coupled to the upstream app — see [limits.md](limits.md) |
| Text simplifier | `simplifier.py` | core complete; LLM path needs the upstream LLM gateway |
| Declarative config | `configs/privacy_shield/*` (taxonomy, patterns, lexica ×7, onnx policy, review profiles) | complete |

## Layout

```
privacy-shield/
├── src/brain/                  # import namespace preserved upstream (unmodified code)
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
tests run unmodified. Distribution renaming is a later step.
