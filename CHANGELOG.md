<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Changelog

## 2.0.0

Breaking release: the import root, the console script and every environment
variable are renamed, `AUDIT_LOG_PATH` changes semantics, and two modules
leave the distribution. Installs of `1.0.0` and `2.0.0` are incompatible
trees — pin the major version.

### Breaking changes

- Import root renamed `brain.privacy_shield` -> `privacy_shield`; every
  submodule moves with it (`brain.<module>` -> `privacy_shield.<module>`).
  Tested: `tests/test_2_0_0_surface.py::test_the_import_root_is_privacy_shield_not_brain`.
- Console script renamed `brain.privacy_shield.cli:main` -> `privacy_shield.cli:main`.
  Tested: `tests/test_2_0_0_surface.py::test_the_console_script_is_privacy_shield_cli_main`.
- All `BRAIN_*` environment variables are renamed to the `PRIVACY_SHIELD_*`
  prefix (full table below). `reject_legacy_env()` tests **presence, not
  value** — an empty-valued legacy variable still raises, naming its
  replacement, at five entry points: `scan`, the CLI `main`,
  `PrivacyGate.check`, `is_safe_for_external_llm`, and package import (which
  does not raise, but every other public function silently treats a legacy
  name as unset rather than raising). Tested:
  `tests/test_legacy_env.py::test_an_empty_valued_legacy_name_still_raises`,
  `::test_every_empty_valued_legacy_name_still_raises`,
  `::test_cli_main_reports_an_empty_valued_legacy_name_too` — each sets the
  variable to `""`, `" "` and `"\t"`, which nothing did before.
- **The two dropped legacy names are not refused — they are ignored.**
  `BRAIN_CREDENTIALS_MASTER_KEY` and `BRAIN_SKILL_INTAKE_MASTER_KEY` left the
  rename table with `user_credentials.py`, so they are no longer recognised as
  legacy names at all. Every other `BRAIN_*` name raises
  `LegacyEnvironmentError` naming its replacement; these two produce **silence**
  — no error, no warning, no replacement — and an operator who still has one
  exported gets no signal that 2.0.0 stopped reading it. There is no
  replacement to name, because the feature they configured is gone. Tested:
  `tests/test_legacy_env.py::test_dropped_legacy_names_yield_silence_not_the_promised_error`,
  `::test_dropped_legacy_names_are_not_in_the_rename_table`.
- `AUDIT_LOG_PATH` semantics changed: `from privacy_shield.audit_log import
  AUDIT_LOG_PATH` yields `None` unless a caller pinned it. The audit writer
  and reader resolve `AUDIT_LOG_PATH or audit_log_path()` at call time, so a
  stale pin handed back by a test harness no longer redirects the trail.
  Tested: `tests/test_state_paths.py::test_audit_log_path_import_is_none_unless_pinned`,
  `test_a_pin_wins_for_writer_and_reader_until_it_is_undone`.
- **The on-disk state root moved**: *all four* runtime stores — the audit
  trail, the privacy skill KG, the GDPR Art. 33(2) breach log and the
  pseudonymisation session store — now resolve outside the installed package,
  under the platform user-state directory (`$XDG_STATE_HOME`, macOS
  `~/Library/Application Support`, Windows `%LOCALAPPDATA%`), not under
  `<site-packages>/brain/...`. The last two moved late: until then the breach
  log wrote to `<package>/data/breach_log` and the session store wrote the full
  re-identification map — pseudonym back to the real name, email or IBAN — as
  mode-0644 plaintext JSON into `<package>/user/pseudonymisation_sessions`,
  which is why the migration row below was not true when it was first written.
  `PRIVACY_SHIELD_AUDIT_LOG` / `PRIVACY_SHIELD_KG_DIR` /
  `PRIVACY_SHIELD_BREACH_LOG_DIR` / `PRIVACY_SHIELD_SESSION_STORE_DIR` override
  the paths verbatim. Session files are written 0600 inside a 0700 directory.
  Tested: `tests/test_state_paths.py::test_audit_default_resolves_outside_the_installed_package`,
  `test_kg_default_resolves_outside_the_installed_package`,
  `test_breach_log_never_lands_in_the_package_tree`,
  `test_session_store_never_lands_in_the_package_tree`,
  `test_saved_session_is_written_to_user_state_with_0600`.
- `PseudonymisationSession`'s docstring said mappings were "stored encrypted on
  disk". They are not, and nothing in this package encrypts them. The claim is
  gone and the docstring now says plainly that a saved session is plaintext and
  as sensitive as the source document. Tested:
  `tests/test_state_paths.py::test_the_docstring_does_not_claim_encryption_it_does_not_do`.
- **`PRIVACY_SHIELD_{NATIVE,EMBEDDED}_LOCAL_MODEL_ENDPOINT` must resolve to a
  loopback address (`127.0.0.1`/`::1`/`localhost`, http or https) or a unix
  socket.** A non-loopback value is refused — the scan degrades to the
  regex/lexicon floor rather than sending raw text to it, and logs a
  `logger.error` naming the host and the variable. Set
  `PRIVACY_SHIELD_MODEL_ENDPOINT_ALLOW_REMOTE=1` to opt back in deliberately;
  every send then logs a `logger.warning` naming the destination. The check
  lives at one choke point, `privacy_shield.utils.network.is_loopback_or_unix_endpoint`,
  shared by `llm_client.get_local_client` and
  `services/local_model_runtime.resolve_embedded_endpoint`. A malformed
  endpoint (one `urlsplit`/`.hostname` itself raises `ValueError` on, e.g. a
  bracketed-IPv6-looking netloc followed by `@host`) is refused the same way
  rather than raising out of `scan()`. The `..._COMMAND` subprocess path is
  unaffected — it never leaves the machine by construction. Tested:
  `tests/test_local_model_endpoint_guard.py`.
- **`user_credentials.py` and `compliance_evidence_export.py` leave the
  distribution.** Neither was reachable from `scan`/`redact`/the egress
  gate/the audit trail, neither was described in the README or the skill,
  and both were sources of recurring defects. The code is not gone — it is
  recoverable from the `v1.0.0` tag and from this repository's history; a
  host that needs BYOK credential storage or the compliance evidence
  exporter should vendor it from there rather than expect it in `2.0.0`.
  `llm_client.get_local_client` no longer reads a credential's
  `endpoint_url` override — with the credential store gone, its only
  non-default-endpoint source is the `endpoint_url` parameter itself, still
  behind the loopback guard above. The `credentials` extra
  (`cryptography`), the two `BRAIN_CREDENTIALS_MASTER_KEY` /
  `BRAIN_SKILL_INTAKE_MASTER_KEY` legacy-name entries (see the silence note
  above), and `utils/datetime.py` (used only by the exporter) go with them.
- **Nine public names went with the split and are removed from 2.0.0.** They
  were not previously disclosed. From `privacy_shield.llm_client`:
  `get_openai_client`, `get_anthropic_client`, `get_google_client`,
  `get_llm_client`, `check_byok_available`, `list_available_providers`,
  `get_openai_client_simple`, `get_anthropic_client_simple` — the BYOK/cloud
  provider factories, which existed to serve the removed credential store.
  From `privacy_shield.enforcement`: `RvndEnforcementAdapter` — superseded by
  the vendor-neutral `ExternalEnforcementAdapter`, which is still exported.
  Importing any of them raises `AttributeError` in 2.0.0. Tested:
  `tests/test_2_0_0_surface.py::test_the_split_removed_modules_stay_removed`
  (now covering all three removed modules, not two),
  `::test_the_split_removed_public_names_stay_removed` (all nine names), and
  `::test_the_removed_public_names_are_disclosed_in_the_changelog`, which fails
  if a name is removed from the code without being named here.

### Fixed

- **The core emitted raw PII in the payload it certified as safe to send.** A
  candidate false-positive suppressor ran *instead of* the validated Layer-1
  detectors and could discard them, so `Ref DE89370400440532013000` scanned
  clean — `pii_detected=False`, `egress_allowed=True`, the IBAN verbatim in the
  overlay — while the same IBAN without the prefix was redacted. The same held
  for `ID <card number>` and for an email address behind a hex-looking local
  part, and any allowlisted token merely *near* a finding (an `Art. 6 DSGVO`
  citation, a `CEO Meyer` title) switched detection off for it. Suppression now
  masks allowlisted text before any detector runs, and the unmasked text is
  rescanned so that anything a validating detector claims — IBAN mod-97, Luhn,
  RFC-shaped email — is reinstated over the allowlist. The over-broad
  generic-ID pattern was narrowed as depth, not as the fix. Tested:
  `tests/test_leak_invariant.py`.
- **Overlapping findings corrupted the overlay and let PII survive.** The
  redactor computed replacements on original offsets and applied overlapping
  ones to an already-mutated string, producing output like `[NAME]L]ME]
  +[PHONE]` — corrupt text with un-redacted PII beside it. Overlapping spans are
  merged into disjoint ones covering the union before being applied
  right-to-left. Tested:
  `tests/test_leak_invariant.py::test_overlay_is_not_corrupted_by_overlapping_spans`.
- **The local-endpoint guard checked the address but not the transport.**
  `httpx` and the `openai` client built on it default to `trust_env=True`, so
  with `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` set, an endpoint that passed the
  loopback check still built a proxy transport and sent raw un-redacted text to
  the configured proxy. Both send paths now build their client with
  `trust_env=False`, and both local-provider probes (`httpx` and the `urllib`
  fallback) run without the environment's proxy. Tested:
  `tests/test_proxy_transport_guard.py`.
- The `privacy-shield` skill's `allowed-tools` granted unrestricted `Bash` to a
  skill whose governance block prohibits `egress_original_unredacted_text`.
  Scoped to `Bash(privacy-shield:*)`. Tested: `tests/test_skill_manifest.py`.

### Other changes

- `tests/conftest.py` points `HOME`, `XDG_STATE_HOME`, `LOCALAPPDATA` and `USERPROFILE`
  at each test's `tmp_path` and clears every `PRIVACY_SHIELD_*` and legacy variable.
- The `privacy-shield` skill's MCP tool (`privacy_scan`) is the enriched
  path and requires `loomground-mcp`; the package/CLI path (`scan()`,
  `privacy-shield` on the command line) needs nothing else installed and is
  what the skill falls back to without it.
- Governance key renamed in the skill's manifest: `require_rvnd_on_default_path`
  -> `require_external_enforcement_on_default_path`.

### Migration

| 1.0.0 | 2.0.0 |
|---|---|
| `import brain.privacy_shield` | `import privacy_shield` |
| `brain.<module>`, e.g. `brain.audit_log` | `privacy_shield.<module>` |
| console script `brain.privacy_shield.cli:main` | `privacy_shield.cli:main` |
| `<site-packages>/brain/...` runtime state (audit log, skill KG, breach log, pseudonymisation sessions) | platform user-state directory, all four (see `docs/limits.md`) |
| skill governance key `require_rvnd_on_default_path` | `require_external_enforcement_on_default_path` |
| `privacy_shield.user_credentials`, `privacy_shield.compliance_evidence_export`, `privacy_shield.utils.datetime` | removed; vendor from the `v1.0.0` tag if needed |
| `llm_client.get_openai_client`, `get_anthropic_client`, `get_google_client`, `get_llm_client`, `check_byok_available`, `list_available_providers`, `get_openai_client_simple`, `get_anthropic_client_simple` | removed with the credential store; no replacement |
| `enforcement.RvndEnforcementAdapter` | `enforcement.ExternalEnforcementAdapter` |
| `BRAIN_CREDENTIALS_MASTER_KEY`, `BRAIN_SKILL_INTAKE_MASTER_KEY` | removed with `user_credentials.py`; no replacement, and **no error either** — unlike every other legacy name these are ignored silently |
| skill `allowed-tools: Bash` | `Bash(privacy-shield:*)` |
| `BRAIN_DEVICE_CLASS` | `PRIVACY_SHIELD_DEVICE_CLASS` |
| `BRAIN_EMBEDDED_LOCAL_MODEL_API_KEY` | `PRIVACY_SHIELD_EMBEDDED_LOCAL_MODEL_API_KEY` |
| `BRAIN_EMBEDDED_LOCAL_MODEL_AVAILABLE` | `PRIVACY_SHIELD_EMBEDDED_LOCAL_MODEL_AVAILABLE` |
| `BRAIN_EMBEDDED_LOCAL_MODEL_COMMAND` | `PRIVACY_SHIELD_EMBEDDED_LOCAL_MODEL_COMMAND` |
| `BRAIN_EMBEDDED_LOCAL_MODEL_ENDPOINT` | `PRIVACY_SHIELD_EMBEDDED_LOCAL_MODEL_ENDPOINT` |
| `BRAIN_EMBEDDED_LOCAL_MODEL_ID` | `PRIVACY_SHIELD_EMBEDDED_LOCAL_MODEL_ID` |
| `BRAIN_EMBEDDED_LOCAL_MODEL_NAME` | `PRIVACY_SHIELD_EMBEDDED_LOCAL_MODEL_NAME` |
| `BRAIN_EMBEDDED_LOCAL_MODEL_OPENAI_COMPAT` | `PRIVACY_SHIELD_EMBEDDED_LOCAL_MODEL_OPENAI_COMPAT` |
| `BRAIN_ENABLE_PYMUPDF` | `PRIVACY_SHIELD_ENABLE_PYMUPDF` |
| `BRAIN_NATIVE_LOCAL_MODEL_API_KEY` | `PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_API_KEY` |
| `BRAIN_NATIVE_LOCAL_MODEL_AVAILABLE` | `PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_AVAILABLE` |
| `BRAIN_NATIVE_LOCAL_MODEL_COMMAND` | `PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_COMMAND` |
| `BRAIN_NATIVE_LOCAL_MODEL_ENDPOINT` | `PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_ENDPOINT` |
| `BRAIN_NATIVE_LOCAL_MODEL_ID` | `PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_ID` |
| `BRAIN_NATIVE_LOCAL_MODEL_NAME` | `PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_NAME` |
| `BRAIN_NATIVE_LOCAL_MODEL_OPENAI_COMPAT` | `PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_OPENAI_COMPAT` |
| `BRAIN_PRIVACY_AUDIT_LOG` | `PRIVACY_SHIELD_AUDIT_LOG` |
| `BRAIN_PRIVACY_KG_DIR` | `PRIVACY_SHIELD_KG_DIR` |
| `BRAIN_PRIVACY_SHIELD_ONNX_AVAILABLE` | `PRIVACY_SHIELD_ONNX_AVAILABLE` |
| `BRAIN_PRIVACY_SHIELD_ONNX_MODE` | `PRIVACY_SHIELD_ONNX_MODE` |
| `BRAIN_PRIVACY_SHIELD_ONNX_MODEL_ID` | `PRIVACY_SHIELD_ONNX_MODEL_ID` |
| `BRAIN_PRIVACY_SHIELD_ONNX_MODEL_PATH` | `PRIVACY_SHIELD_ONNX_MODEL_PATH` |
| `BRAIN_PRIVACY_SHIELD_SEMANTIC_CHUNK_SIZE` | `PRIVACY_SHIELD_SEMANTIC_CHUNK_SIZE` |
| `BRAIN_PRIVACY_SHIELD_SEMANTIC_ENABLED` | `PRIVACY_SHIELD_SEMANTIC_ENABLED` |
| `BRAIN_PRIVACY_SHIELD_SEMANTIC_THRESHOLD` | `PRIVACY_SHIELD_SEMANTIC_THRESHOLD` |

## 1.0.0

First release. Local-first PII/PHI detection and clean-overlay pipeline for governed folders.
