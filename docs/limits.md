# Limits, gaps and test split

Moved out of the README (README canon, `repo-standards/STANDARDS.md` § README canon).

## Limits of the runner and CLI

- **The egress verdict is a source classification, not proof of anonymity.** The
  gate blocks LOCAL_ONLY / confidential / berufsgeheimnis / Art. 9 sources; a
  non-confidential PII document passes and its redacted overlay leaves. The gate
  leaves the overlay unscanned, so "cleared" stays short of a zero-residual
  certificate.
- **Overlay cosmetics.** Redaction reuses the engine's `redactor.py`. When the
  regex layers produce *overlapping* findings (e.g. a name pattern overlapping an
  email), the placeholder splicing can leave placeholder-text fragments (the
  tests assert injected original values stay out of the overlay). The engine is
  reused unchanged; this is a known redactor artefact.
- **Folder walk** defaults to known text/document extensions
  (`runner.DEFAULT_EXTENSIONS`); use `--all-files` to consider every file.
  Binary/undecodable files are recorded as per-document `errors`, not fatal.
- **Semantic and local-LLM passes are optional.** With neither the `[semantic]`
  extras nor a local model present, detection is the deterministic regex/lexicon
  floor only (the modules degrade gracefully). `[extract]` extras
  (PyMuPDF, which is AGPL, and opencv) are needed for PDF/image extraction; without them those
  documents surface an extraction error.
- **The local-LLM layer talks to local HTTP endpoints.**
  `services/local_model_runtime.py` discovers providers on
  `http://localhost:11434` (Ollama), `:1234` (LM Studio), `:1337` (Jan) and
  `:4891` (GPT4All). Detection stays on the machine; it is local HTTP rather
  than an in-process model.
- **The MCP tool is the enriched path, not the only path.** `scan()` and the
  `privacy-shield` CLI are the callable capability with nothing else
  installed; the `privacy-shield` skill's `privacy_scan` tool requires
  `loomground-mcp`.

## Known gaps

The ONNX contextual model is shadow-only (no promotion); there is no bundled
pre-embedded PII-context file.

## Test split

```
python3 -m pytest -q
253 passed, 8 failed
```

261 tests collected (`pip install ".[dev,semantic,extract,openai]"`). The 8
failures are all in `tests/test_simplifier.py`'s LLM path, which patches
`privacy_shield.services.llm_runtime` — an upstream gateway this package does
not ship. `openai` is installed here (and by CI's `tests` job) so
`tests/test_local_model_endpoint_guard.py`'s send-path assertions run rather
than skip.
`.github/workflows/ci.yml` deselects the 8 llm_runtime tests by name, so the
`tests` job runs 253 passed, 8 deselected.

Every privacy-shield core test file passes: regex-only, embeddings, semantic
wiring, overlay, local-model runtime, config, onnx contextual PII, media inputs,
review profiles, the optional external-enforcement seam
(`tests/test_privacy_gate_external_enforcement.py`), and the runner + CLI on synthetic
PII fixtures (`tests/test_privacy_shield_runner.py`, 13 tests).
