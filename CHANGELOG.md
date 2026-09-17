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
- **That fix addressed five inputs, not the class they belong to.** Every
  Layer-1 pattern begins with `\b`, which does not find an identifier — it
  finds a place one is allowed to start. A single word character glued in front
  means no boundary exists at the identifier's first character, and because the
  rest of it is word characters too, none exists inside it either: the pattern
  matches nothing, the validator is never offered the candidate, and the caller
  gets `pii_detected=False` with the account number verbatim in the payload.
  `Ref ` was one instance; `acct_`, a document number run together with the
  number, `id-` plus hex, a CSV field with no delimiter and the `=20`
  quoted-printable writes for a space were all still open, in every
  egress-capable mode at every confidence floor. For the three types that have
  a validator, detection now walks every maximal run of identifier characters
  and tests every candidate substring, consulting no word boundary
  (`privacy_shield/identifiers.py`). Tested:
  `tests/test_leak_invariant.py::test_release_gate_glued_prefix_class`,
  `::test_glued_prefix_is_reported_not_merely_removed`,
  `::test_umlaut_glued_to_an_email_does_not_hide_it`,
  `tests/test_identifier_runs.py`.
  - **Precision cost, measured**: on twenty realistic German business documents
    containing no payment identifier, IBAN detection produces **no** false
    positives (candidates are held to the ISO 13616 registered length for their
    country code) and card detection produces **six** — always a Luhn-valid
    window inside a longer digit run, on tracking numbers, an IMEI and long
    internal references. That over-redaction is deliberate: an issuer-prefix
    table would cut it to one, at the price of putting a stale BIN range
    between a real card and the gate. A false positive can only consume digits
    and the separators written inside a number, never prose. Tested:
    `tests/test_identifier_runs.py::test_iban_precision_on_clean_business_text`,
    `::test_card_precision_on_clean_business_text`,
    `::test_over_redaction_never_eats_a_word`.
  - What may sit *inside* an identifier is decided by exclusion, not by a list.
    Two lists were walked around first: the literal `" \t-"` (defeated by a
    no-break space, a soft hyphen and a zero-width space) and then the Unicode
    categories `Zs`/`Pd`/`Cf`, which miss `Pc` and `Po` — so
    `4111_1111_1111_1111` and `4111:1111:1111:1111` were never offered to Luhn
    at all, and a full card number egressed with `pii_detected` False.
    **The rule:** *a candidate is any maximal sequence of ASCII alphanumerics
    joined by single characters that are not alphanumeric at all and not a line
    break, carrying at most one such joiner for every two identifier
    characters.* The bound is what stops punctuated prose being assembled into
    a checksum. Tested:
    `tests/test_identifier_runs.py::test_every_joiner_category_groups_an_identifier`
    and `::test_a_glued_prefix_plus_any_joiner_still_finds_the_identifier`,
    which generate joiners from `unicodedata` across every category rather than
    from a list, `::test_the_layout_bounds_reject_assembled_prose`,
    `tests/test_leak_invariant.py::test_a_separator_inside_an_identifier_does_not_hide_it`,
    `::test_a_grouped_card_is_found_whatever_separates_the_groups`,
    `::test_a_grouped_iban_is_found_whatever_separates_the_groups`,
    `::test_an_invisible_character_does_not_split_a_run`,
    `::test_a_line_break_is_never_an_inline_separator`.
  - A line break is never a joiner, so an identifier wrapped across two lines
    is a known gap, pinned rather than hidden by
    `tests/test_leak_invariant.py::test_a_line_wrapped_identifier_is_a_known_gap`.
- **Identifiers were being redacted by accident, by the wrong detector.** A
  card written with dots matched the phone pattern and one written with slashes
  matched the Unix path pattern, so the overlay read `[PHONE].1111` and
  `4111[PATH]` — fragments of the card left standing, and the redaction resting
  on a pattern that was never about cards. A validated span now outranks a
  pattern that merely overlaps it: contained pattern findings are dropped and
  overlapping ones trimmed, so a card is redacted as a card and nothing of it
  remains. Tested:
  `tests/test_leak_invariant.py::test_a_grouped_identifier_is_typed_as_itself`.
- **Overlapping findings corrupted the overlay and let PII survive.** The
  redactor computed replacements on original offsets and applied overlapping
  ones to an already-mutated string, producing output like `[NAME]L]ME]
  +[PHONE]` — corrupt text with un-redacted PII beside it. Overlapping spans are
  merged into disjoint ones covering the union before being applied
  right-to-left. Tested:
  `tests/test_leak_invariant.py::test_overlay_is_not_corrupted_by_overlapping_spans`.
- **The same defect was still live in ANONYMOUS_JSON mode**, which the entry
  above did not cover and should not have implied. `anonymous_json.anonymize_text`
  kept its own copy of the broken loop, so the mode whose entire purpose is
  cloud egress spliced the tail of an account number back in behind its own
  placeholder (`[ANON_IBAN_1]30 00, Karte …`). It now shares the redactor's
  `merge_replacements`, which is public for that reason. Tested:
  `tests/test_leak_invariant.py::test_anonymous_json_overlay_is_not_spliced_by_overlapping_spans`.
- **The local-endpoint guard checked the address but not the transport.**
  `httpx` and the `openai` client built on it default to `trust_env=True`, so
  with `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` set, an endpoint that passed the
  loopback check still built a proxy transport and sent raw un-redacted text to
  the configured proxy. The send paths now build their client with
  `trust_env=False`, and both local-provider probes (`httpx` and the `urllib`
  fallback) run without the environment's proxy. Tested:
  `tests/test_proxy_transport_guard.py`.
- **A fourth client was missed by that fix**, because the list of sites was
  drawn from memory. `privacy_shield_embeddings` built its OpenAI client with
  no `http_client` at all. Worse than the transport: `PIIContextMatcher._embed`
  sends the first 8000 characters of raw, pre-redaction document text, it is
  reachable from the main scan path, and `PRIVACY_SHIELD_SEMANTIC_ENABLED`
  defaults to `"1"` — silent only because the context store ships empty. Run
  the documented `embed_pii_contexts()` setup once and every chunk of every
  scanned document leaves the machine, which is the
  `egress_original_unredacted_text` this skill's governance block prohibits.
  The client is now built off the environment proxy, and document chunks go
  through the same loopback/unix-socket endpoint guard as every other send
  path. Tested:
  `tests/test_privacy_shield_embeddings.py::TestEmbeddingEgressGuard`.
  The set of HTTP client constructions is now enumerated from the AST on every
  run, each with a written justification, so a fifth fails the build until it
  is accounted for. Tested:
  `tests/test_proxy_transport_guard.py::test_every_http_client_construction_is_accounted_for`,
  `::test_every_client_site_passes_an_explicit_http_client`.
- **Layer-2 patterns ran off the end of a line and destroyed the overlay.**
  `\s` matches a newline, so a four-line German sign-off collapsed to
  `[NAME][NAME] 12\nAnlage` — the closing formula, the street name, the
  trailing word and every line break gone. The overlay is what the cloud model
  receives, so this was fail-closed on confidentiality and fail-open on the
  product's reason to exist. Every pattern whose tokens are separate *fields* —
  both name patterns, both street patterns, postal-code-and-city,
  date-of-birth, age, and both phone patterns — now matches per line.
  Signature-block detection is unaffected. Layer 3 and Layer 4 deliberately
  keep `\s`, because a keyword phrase broken by word wrap is still that phrase.
  Tested: `tests/test_overlay_structure.py`.
- Letter closings and name-free salutations (`Mit freundlichen Grüßen`,
  `Sehr geehrte Damen und Herren`, `Best regards`, …) joined the allowlist;
  they are fixed formulas, and the name pattern was redacting them. Formulas
  that *precede* a name were deliberately left out. Tested:
  `tests/test_overlay_structure.py::test_a_four_line_sign_off_survives_redaction`,
  `::test_the_name_is_still_found_on_its_own_line`.

### Removed (behaviour)

- **The placeholder-email allowlist entry is gone.** It listed
  `(example|test|noreply|info|contact)@(example|test).com` and had stopped
  doing anything once the email rescue landed: a validating detector claims
  every RFC-shaped address before a suppressor is consulted. It was deleted
  rather than revived, because reviving it means letting a suppressor overrule
  a validated identifier — the structure this release was rejected for.
  `test@example.com` is now reported as an email. Tested:
  `tests/test_leak_invariant.py::test_allowlist_cannot_suppress_a_validated_identifier`,
  `::test_placeholder_addresses_are_reported_rather_than_allowlisted`.
- **Semantic context matching against a remote embedding endpoint.** An
  installation with `OPENAI_API_KEY` set that had run `embed_pii_contexts()`
  was getting matches from a cloud endpoint; it now gets none until
  `OPENAI_BASE_URL` names a local embedding server. It degrades to the
  regex/lexicon floor rather than failing, and logs once saying why. The setup
  call is unaffected — it embeds the fixed context phrases in the module's own
  source, which are nobody's personal data. Tested:
  `tests/test_privacy_shield_embeddings.py::TestEmbeddingEgressGuard::test_setup_may_still_use_a_remote_endpoint`.
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
