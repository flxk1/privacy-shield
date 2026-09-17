<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Changelog

## Unreleased

The name layer becomes per-language: German is main's rules unchanged, English
is a separate design, and the other twenty-two official EU languages are
`unmeasured` and say so. No dependency is added. Two of this change's own
mechanisms were removed again after an ablation showed they bought nothing,
and four existing libraries were evaluated against the same corpora instead of
growing more of our own - the evaluation is in `docs/limits.md`.

### Added

- `privacy_shield.name_layer`, a per-language registry. One language is one
  module registering one `Ruleset`; evidence is per language, exclusions are
  the union over every registered language. Adding a language cannot widen
  what another claims. Tested:
  `tests/test_name_layer_mechanism.py::test_adding_a_language_cannot_widen_what_another_language_claims`,
  `::test_a_language_is_one_module_and_nothing_imports_another_language`.
- English rules (`name_layer/en.py`): honorific, salutation without an
  honorific, signature (one word is enough, unlike German), `Attn`/`FAO`/`c/o`
  and address block, a table column whose header declares people, and the
  agency frame (`prepared by`, `reviewed by`, `signed off by`, `contact`,
  `on behalf of`). Measured on 77 clean English documents: **10
  false-positive spans, 1.21% character loss**, in three named classes; 24/36
  on 18 named documents and 8/21 on independent positions. Tested:
  `tests/test_name_layer_english.py`.
- `name_layer/detect.py`: language declared by the caller, else detected from
  closed-class markers, else **every registered ruleset is applied**. No
  language-identification library, and a wrong guess costs a wider union
  rather than a missed name. Tested:
  `tests/test_name_layer_cross_language.py::test_a_document_with_no_marker_from_any_language_gets_every_ruleset`,
  `::test_a_mixed_language_document_gets_both_languages`,
  `::test_a_declared_language_with_no_ruleset_does_not_look_like_a_clean_document`.
- `name_layer/recogniser.py`: the seam a statistical recogniser plugs into,
  with no model in it and no download. A registered recogniser is held to the
  same exclusion union as the rules, and one that raises is dropped rather
  than taking the scan down. Tested:
  `tests/test_name_layer_mechanism.py::test_a_registered_recogniser_is_held_to_the_same_exclusions_as_the_rules`,
  `::test_a_recogniser_that_raises_does_not_take_the_scan_down`.
- Per-language measurement of the checksum-validated layer: **135
  schwifty-generated IBANs, five per member state**, are all found inside
  prose, and IBAN, card and e-mail detection fires unchanged in Greek,
  Cyrillic, Maltese and mixed-script text. Tested:
  `tests/test_identifier_layer_per_language.py`.
- The zero-dependency floor is now a tested property rather than a remembered
  one: `dependencies = []`, and every name-layer module imports only the
  standard library, checked at the import graph and again with `numpy` and
  `onnxruntime` blocked. Tested:
  `tests/test_name_layer_mechanism.py::test_the_package_declares_no_runtime_dependencies`,
  `::test_every_name_layer_module_imports_only_the_standard_library`,
  `::test_the_name_layer_works_with_the_optional_extras_blocked`.

### Changed

- **The English counterpart of probe A is withdrawn before it ever shipped.**
  A value after a person-role label (`Caseworker: Ashcroft`, `CC: Ingrid
  Bauer`) measured 0 false positives on 77 clean English documents, 49 of them
  written to break it, and it is still withdrawn: the enumeration that decides
  whether a label's value is a person fails OPEN, and German's identical probe
  was also free on its own corpora before costing 18 false-positive spans on
  an independent one. It costs 12 of 36 named occurrences and 6 of 21
  independent ones, and it is kept in `en.CANDIDATE_PROBES` with that cost
  measured. Tested:
  `tests/test_name_layer_english.py::test_the_unshipped_english_probes_stay_unshipped`,
  `::test_the_measured_english_recall_on_the_independent_positions`.
- **The English table probe judges shape only**, once a header has declared
  the column to hold people - main's rule, in English. A status word in a
  person column is redacted, which is what the table says it is: `Not
  Allocated` and `Vacant` are two of the ten measured false positives. Tested:
  `tests/test_name_layer_english.py::test_an_english_table_cell_is_a_name_only_under_a_person_column`.
- **Every language's rules are held to every language's exclusions.** The
  German signature rule has always been able to fire on an English letter, its
  closing formulae including `Kind regards` and `Yours sincerely`, and with the
  German table alone it claimed `Accounts Payable`. Measured: English rules
  over 42 clean German documents and German rules over 77 clean English
  documents both claim nothing. Tested:
  `tests/test_name_layer_cross_language.py::test_german_rules_claim_nothing_in_clean_english_documents`,
  `::test_english_rules_claim_nothing_in_clean_german_documents`.
- **The per-country IBAN corpus is generated by `schwifty`, not by this
  package.** The arithmetic it replaces produced strings that are not IBANs in
  seven member states - Bulgaria, Ireland, Italy, Latvia, Malta, the
  Netherlands and Romania require alphabetic bank codes where it put digits -
  and the test passed because the detector is length-and-checksum only: the
  same blind spot in the checker and in the checked. Without `schwifty` those
  tests skip loudly rather than falling back. Tested:
  `tests/test_identifier_layer_per_language.py::test_our_own_iban_arithmetic_was_wrong_and_this_is_how_we_know`.

### Removed

- **The 410-entry ISO 20275 legal-form table and the six-character stem
  match**, both added earlier in this same change. With the fail-open label
  probe withdrawn they changed the false-positive count by **zero** in both
  languages: the enumeration exposure was a property of the position, not of
  the length of the list. The measured cost of not carrying them is 6 false
  positives on eight documents where a member state's legal form signs a
  letter, and the table is not restored because GLEIF publishes the code list
  with no licence statement. Tested:
  `tests/test_name_layer_enumeration_limit.py::test_the_enumeration_fixes_are_gone`,
  `::test_the_word_lists_that_remain_still_earn_their_place`,
  `::test_the_measured_cost_of_not_carrying_the_iso_table`.

### Fixed

- **A table's header applies to that table only** - in English as well. The
  shared probe held one flag over the whole document, so a parts table after a
  person table had its product column claimed and a person table after a parts
  table was not read at all. Tested:
  `tests/test_name_layer_tables.py::test_each_table_carries_its_own_header`,
  `::test_a_parts_table_after_a_person_table_keeps_its_product_column`,
  `::test_a_person_table_after_a_parts_table_is_still_read`.
- The **glued-and-wrapped card number** that cleared the egress gate at the
  previous tip is caught by main's identifier repair, and the pin that
  recorded it as an open leak is now an assertion that it stays closed, in six
  languages. Tested:
  `tests/test_identifier_layer_per_language.py::test_the_glued_and_wrapped_card_is_caught_now`,
  `::test_the_closed_leak_is_closed_in_every_language`.
- **The exclusion union costs no name**: 0 of 307 common member-state surnames
  are refused by any of its four classes. Tested:
  `tests/test_name_layer_enumeration_limit.py::test_no_common_eu_surname_is_refused_by_the_remaining_lists`.

### Found, not fixed

- **An eighth residue class in the identifier layer**, found by
  `tests/test_leak_invariant.py::test_release_gate_property` during this change
  and reproducing unchanged at `521fec2`: a Luhn-valid window assembled from a
  UUID tail and the digits after a redacted IBAN leaves 8 characters of
  residue in the overlay. The input is written out in `docs/limits.md`. The
  property draws the shape at random, so the leak-gate job will fail
  intermittently until it is fixed; that is the alarm working.

### Evaluated, not adopted

- **No NER model clears the licence gate together with EU coverage, ONNX and
  size**, each licence read from the model's own metadata:
  `urchade/gliner_multi` is CC-BY-NC-4.0 as suspected, GLiNER v2.1 is
  genuinely Apache-2.0 and 1.16 GB, spaCy's per-language models are MIT only
  for English, German and the multilingual one (Greek and Italian are
  non-commercial), and XLM-R's NER heads are non-commercial, unlicensed or
  CoNLL-2003-derived.
- **Microsoft Presidio (MIT)**: doubles recall and doubles to triples the
  false positives on the same corpora (German 10 FP against our 0, English 22
  against our 10), and its identifier recognizers find 85 of 135
  schwifty-generated IBANs against our 135 and **none** of the six
  extraction-artefact leak shapes. Consume the operator model and the overlap
  resolution as a design; do not adopt the detectors.
- **python-stdnum (LGPL-2.1-or-later)**: 27 EU national-identifier validators,
  0 false positives over 951 tokens from 119 clean documents, 8 of 8 real
  identifiers validated. Proposed behind an optional extra, gated on a
  token-level candidate pass this package does not have and on country
  scoping - `111222333` is a valid Dutch, Czech and Slovak identifier at once.
- **libpostal**: rejected. 1.8-2.2 GB of model data, a C build, mixed data
  licences, and it answers a question this layer does not ask.

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
    `::test_a_line_break_is_now_an_inline_separator`.
  - A line break is never a joiner, so an identifier wrapped across two lines
    is a known gap, pinned rather than hidden by
    `tests/test_leak_invariant.py::test_a_line_wrapped_identifier_is_no_longer_a_gap`.
  - **Gap WIDTH was the next hole in the same wall.** The rule ended a
    candidate at the second consecutive joiner, so a `pdftotext` column gap,
    fixed-width padding, a dot leader and a monospaced table each egressed a
    whole card number with `pii_detected` False. Any number of consecutive
    joiners now continues a candidate, and the layout is bounded instead: at
    most four times the identifier's own length, no more groups than half that
    length, and no interior group longer than twelve where three or more groups
    are covered. Tested:
    `tests/test_leak_invariant.py::test_a_multi_character_gap_does_not_hide_a_card`,
    `::test_a_multi_character_gap_does_not_hide_an_iban`,
    `::test_reported_extraction_artefact_shapes`,
    `::test_mixed_gap_widths_within_one_identifier`.
  - **The gate could not have caught it.** The oracle was a line-by-line
    structural copy of the run rule, down to the same `ahead - position == 1`,
    so for any input whose gap was two characters or more it returned no
    identifiers and every assertion passed vacuously. The oracle now has no run
    rule at all: it takes every subsequence of alphanumerics within 136
    characters of each position and asks the validator, and finds addresses by
    trying every substring around each `@`. It is quadratic on purpose. The
    battery's ground-truth net, which compared only the COMPACT identifier and
    so could not fire on a spaced write either, now checks the form actually
    written.
  - Precision after admitting wide gaps: eight card false positives on the
    realistic corpus (from six) and eight on the hostile one (from three), no
    IBAN false positives on either.
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
