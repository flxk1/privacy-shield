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
  `on behalf of`). Measured on 77 clean English documents, through the
  dispatcher (German always resolved - see Fixed below): **10 false-positive
  spans, 1.21% character loss**, in three named classes; 28/36 on 18 named
  documents and 10/21 on independent positions - English's own rules alone
  measure 24/36 and 7/21; the difference is German's GIVEN rule recovering
  the label positions whose value is also a German given name plus surname.
  Tested: `tests/test_name_layer_english.py`.
- `name_layer/detect.py`: language declared by the caller, else detected from
  closed-class markers plus German unconditionally, else **every registered
  ruleset is applied**. No language-identification library, and a wrong
  guess costs a wider union rather than a missed name. Tested:
  `tests/test_name_layer_cross_language.py::test_a_document_with_no_marker_from_any_language_gets_every_ruleset`,
  `::test_a_mixed_language_document_gets_both_languages`,
  `::test_a_declared_language_with_no_ruleset_does_not_look_like_a_clean_document`,
  `::test_german_given_names_are_found_even_when_english_is_the_detected_language`,
  `::test_detection_only_adds_languages_never_drops_german`.
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

- **An e-mail address written with a full-width `＠` or full-width letters is
  detected.** `erika＠example.com` went out whole with pii_detected False in
  every egress mode: the finder expanded only around an ASCII `@`. It now
  folds digits and letters as a run does, reads every character NFKC maps
  to `@ . _ % + -` as that, and reads the ideographic full stops `。` and
  `｡` as `.` in a domain that has no reading without them. `iban_ok` and `email_ok` read the same fold, so a full-width
  IBAN or address is no longer rejected by its own validator. Addresses the
  finder still cannot read - an IDN domain, decomposed Unicode, a zero-width
  character, a wrapped address - are listed in `docs/limits.md`. Tested:
  `tests/test_leak_invariant.py::test_an_address_written_in_full_width_is_an_address`,
  `tests/test_privacy_shield_regex_only.py::test_no_finding_of_a_validated_type_fails_its_own_validator`.

- **A card or IBAN written in full-width or non-Latin digits is detected.**
  Identifier runs were built from ASCII alphanumerics, so
  `Karte ４１１１ １１１１ １１１１ １１１１` went out as `Karte [PHONE] １１１１`
  in every egress mode with egress allowed. A run now takes any Unicode
  decimal digit and any alphanumeric compatibility-equal to one ASCII letter,
  as the character it stands for; symbols and modifier letters such as the
  katakana `ー` join groups. Non-Latin text now over-redacts at the ASCII
  rate. Tested:
  `tests/test_leak_invariant.py::test_a_card_in_non_ascii_digits_is_a_card`,
  `::test_a_full_width_iban_is_an_iban`,
  `::test_a_card_of_mixed_widths_is_one_card`,
  `::test_a_symbol_between_groups_joins_them`.

- **One occurrence no longer comes back as two findings.** When two patterns
  of the same type reached into a checksum-validated span, both were trimmed
  back to the same interval and both were reported: `001 4111 1111 1111 1111`
  gave two `phone` spans at (0, 4). The redaction was unaffected; the span
  list and its counts were not. The stronger of identical findings is kept;
  findings of different types on one interval are both kept.

- **`--out` can no longer destroy a file.** Overlays are named after their
  flattened source path and were written with a plain `write_text`, so
  `scan . --out .` replaced a user's own `a.txt.overlay.txt` with `a.txt`'s
  overlay, and `sub/b.md` and `sub__b.md` wrote one file between them while
  the CLI reported both. Every target is now checked before anything is
  written, and on any conflict the CLI writes nothing, creates no folder and
  exits 1, naming each file. An existing file needs the new `--overwrite`,
  which replaces any file at an overlay's name. Even with it, these are
  refused: a scanned file (by file identity), a symbolic link, a directory,
  and two overlays with one name (compared case- and
  normalisation-insensitively). Writes are staged and moved into place. A new
  overlay never replaces anything that appeared after the check, and a failure
  part-way, including a name the filesystem rejects, removes what the run
  created. Tested:
  `tests/test_cli_out_guard.py`.

- **The random IBAN-in-prose test asserted exact equality and failed
  intermittently.** A coincidental mod-97 pass can extend the claimed span
  forward or backward, kept by the union rule (`docs/limits.md`); the test
  now asserts coverage, and the reproduced shapes, forward and backward, are
  pinned exactly.

- **`scan --redaction-mode hash` works from the CLI.** `scan()` took a
  `hash_salt` but the CLI had no way to pass one, so the mode always exited 1.
  The salt now comes from `--hash-salt` or `PRIVACY_SHIELD_HASH_SALT`, and the
  flag wins if both are set. The environment variable is the one to use: an
  argument shows in the process list and shell history, and a known salt lets
  anyone test guessed values against the hashes. With neither set, the CLI
  exits 1 and names both. The salt reaches no output. `SKILL.md` tells an
  agent to rely on the variable and never to pass, read or print the salt.
  Tested: `tests/test_cli_hash_salt.py`.

- **`RedactionResult.to_dict()` no longer carries the originals.** Under
  `pseudonymize` and `hash`, `mappings` is keyed by the detected value, and a
  `Redactor` keeps that map across calls, so a result also carried every
  earlier document's originals. `mappings` is now `null` unless
  `include_original=True`, and `mappings_withheld` names the omission.
  `scan()` and the CLI never serialised a `RedactionResult`. Tested:
  `tests/test_redaction_result_boundary.py`, every `RedactionMode`, with an
  `include_original` negative control.

- **`scan --json` no longer prints an overlay the originals are still in.** Under `detect_only` nothing redacts, and under `block` the redactor may refuse (it does for an IBAN), and then `overlay` was the untouched original while `egress_allowed` was True; `to_dict()` already omitted the span `value`/`context` but returned `overlay` as is, and verbatim emails and IBANs reached stdout. `overlay` is now `null` whenever a detected value is still in it, the omission is named in `overlay_withheld`, `--out` writes no `.overlay.txt` for that document, and the human output says it withheld one. `include_original=True` / `--include-original-values` still returns it. `egress_allowed` is unchanged: it answers the source-classification question, not a residual one (`docs/limits.md`). New `DocumentScan.overlay_residual`, read per detected span: its `value` still in the overlay, or a `value` that is empty or is not the source at its offsets, since the local-model layer records a hint as `value` with `end = start + 10`. Tested: `tests/test_overlay_residual_boundary.py`, every `RedactionMode` × `PrivacyMode` over German, English, IBAN, email and name-only input, with an `include_original` negative control.

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
- **Detection dropped German entirely once any other language's marker
  appeared**, so a document scoring one English marker and zero German ones
  never ran the German GIVEN rule at all - "Meeting with Julia Schmidt and
  Jan Müller on Monday.", "Kind regards\nJan Müller" and "From: Sarah
  Villanueva" lost their German names, contradicting this file's own promise
  that "a wrong guess costs a wider union rather than a missed name."
  `detect.resolve` now always includes German (when registered) in its
  undeclared-language result; an explicit declaration still isolates one
  language exactly, which is what the cross-language cost measurements need.
  Tested: `tests/test_name_layer_cross_language.py::test_german_given_names_are_found_even_when_english_is_the_detected_language`,
  `::test_detection_only_adds_languages_never_drops_german`,
  `::test_a_declared_language_still_isolates_when_it_excludes_german`.
- **`name_layer/shared.claim` (the dispatcher's and English's claim rule) was
  still the pre-`6b0f7e5` first-overlap-wins version**, despite its own
  docstring calling it "main's rule": it inspected the first overlapping span
  and returned, so a correct wider claim was discarded on the strength of one
  earlier partial one. Ported main's covers-every-overlap version. Tested:
  `tests/test_name_layer_mechanism.py::test_shared_claim_replaces_every_span_it_covers_not_just_the_first`,
  `::test_shared_claim_is_all_or_nothing_over_multiple_overlaps`.
- **`de._is_organisational` used the full exclusion union, including every
  registered language's TEMPORAL set**, which exists to keep month names out
  of the GIVEN rule and not to gate a signature line: "Mit freundlichen
  Gruessen\nMai Schmidt" lost its own signature, "Mai" being German for May
  as well as a given name. Restricted to the ORGANISATIONAL and LEGAL_FORMS
  unions, which cost nothing measured and keep the cross-language protection
  ("Kind regards\nAccounts Payable", "...\nNordstern Limited") the union was
  for. Tested:
  `tests/test_name_layer_enumeration_limit.py::test_a_temporal_given_name_signs_a_letter`,
  `::test_english_organisational_and_legal_form_words_still_refuse_a_german_signature`.

  **Decided by the owner (Felix, 2026-09-24): the restricted union is
  kept.** An adversarial differential (3,724 generated inputs) found 30
  where this restricted union claims less than main's own
  `_is_organisational` (German's ORGANISATIONAL table alone, no union at
  all), and they are not one shape: 25 are a fuzzer-built "[given name from
  `{Karl-Heinz, Mai}`] [organisational-union word from `{Finance, Sales,
  Office, Legal, Payable}` standing in as a fake surname]" - main's simpler
  check does not recognise any of those five as organisational (they are
  English words, absent from German's own table) and claims the two-word
  string as a person, which this layer correctly refuses. The other 5 are
  the two real false positives the restricted union exists to close,
  reappearing under main's simpler check: `Accounts Payable` (×3 - the bare
  "Kind regards" form, the "...Shared Service Centre..." form, and the "Mit
  freundlichen Gruessen" form), `Customer Services` (×1), `Nordstern
  Limited` (×1). Matching main exactly (dropping the ORGANISATIONAL/
  LEGAL_FORMS union too) would close the 25 but reopen those 5 in the real
  77-document English corpus (10 -> 12 FP spans, 1.21% -> 1.61% character
  loss) and fail 7 tests already in this suite; the restricted union kept
  here costs the 25, all adversarially generated and none in this
  repository's own corpus, and keeps every existing measurement unchanged.
  See commit `a4c28fd` for the full 30-input list and both options' numbers.

### Found, not fixed

- **The local-model layer's spans have made-up offsets.** `scanner.py` gives a
  layer-5 finding `end = start + 10` and its `value_hint` as `value`, so under
  `redact` the redactor replaces ten characters from the start position and
  the rest of the detected text stays in `DocumentScan.overlay`. The serialised
  report withholds such an overlay; the object still carries it.
- **`AnonymisationResult.to_dict()` carries the input.** In `assess` mode
  `processed_text` is the text unchanged. A separate skill API, not the scan
  overlay.

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

## 2.1.1

### Fixed

- `privacy_shield.__version__` reported `2.0.0` on the 2.1.0 release. It is a second
  version literal beside `pyproject.toml`'s and nothing compared the two, so the
  release bump moved the packaging metadata and left it behind: an install of the
  `v2.1.0` tag reported `2.0.0` from `__version__` while
  `importlib.metadata.version` reported `2.1.0`. The `v2.1.0` tag was withdrawn
  rather than left installable; its commit remains on `main` as this release's
  parent, and everything it introduced — recorded below under 2.1.0 — ships here.
  Tested: `tests/test_2_0_0_surface.py::test_dunder_version_agrees_with_the_packaging_metadata`,
  which fails if they ever disagree again.

## 2.1.0

### Fixed

- The 8 `tests/test_simplifier.py` LLM-path tests run instead of failing at setup.
  They patched `privacy_shield.services.llm_runtime` — an upstream gateway this
  package does not ship — and six of them an older `privacy_shield.runtime.llm_gateway`
  that never existed; `mock.patch` cannot resolve a module that is not importable, so
  every one failed before reaching the code, and the branches they name had no
  coverage at all. They now inject a stand-in module. `.github/workflows/ci.yml` no
  longer deselects them by name. Runtime behaviour is unchanged: with no gateway
  installed, `simplify_response*` still returns the response untouched.
  Tested: `tests/test_simplifier.py::test_the_gateway_really_is_absent_from_the_distribution`
  (the premise — it fails if the gateway ever ships), plus the 8 restored cases.

- `HASH` redaction is reachable again. `Redactor` has required an explicit
  `hash_salt` for `HASH` since DSK K-03 and refuses to invent one, but neither
  `scan()` nor `PrivacyShield` accepted the argument, so every `HASH` call through
  them raised `ValueError` whatever the caller passed — a mode the signature
  advertised and the API could not reach. `hash_salt` now threads
  `scan()` -> `PrivacyShield` -> `Redactor`, and `redact_text()` takes it too.
  Absent, `HASH` still fails closed; a salt is never invented.
  Tested: `tests/test_privacy_shield_runner.py::test_hash_mode_is_reachable_through_scan`,
  `::test_hash_mode_without_a_salt_still_fails_closed_through_scan`,
  `::test_the_hash_is_stable_for_a_salt_and_changes_with_it`,
  `::test_redact_text_also_takes_a_salt`.

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


- Serialised findings no longer carry the ORIGINAL text by default.
  `SpanFinding.to_dict()`, `DocumentScan.to_dict()`, `ScanReport.to_dict()`,
  `scanner.Finding.to_dict()` and `scanner.ScanResult.to_dict()` gained a
  keyword-only `include_original=False`, and omit `value` / `context` unless
  it is passed. `scan --json` omits them too; `--include-original-values`
  restores them. The values stay on the objects, so in-process telemetry is
  unchanged -- only the serialised form defaults closed. The reason is the
  skill's own `prohibited: egress_original_unredacted_text`: `SKILL.md` grants
  `Bash(privacy-shield:*)`, and in a skill context stdout IS the model's
  context, so `--json` carrying the original put it one pipe from an external
  model. Both surfaces moved together; fixing only the CLI would have left the
  prohibited kind live one call away in `ScanResult.to_dict`. Tested:
  `tests/test_serialised_original_boundary.py::test_the_serialised_report_carries_no_original_by_default`,
  `::test_the_serialised_report_is_invariant_under_the_original_values`,
  `::test_the_scanner_path_has_the_same_default`,
  `::test_the_cli_only_prints_the_original_when_asked`.
- `ScanReport.walk_errors` changed type: `List[str]` -> `List[WalkError]`
  (`WalkError` is `(kind: WalkErrorKind, message: str)`, `str(entry)` still
  gives the old message text). A consumer that did `"; ".join(report.
  walk_errors)` needs `str(e) for e in report.walk_errors`, or better,
  `report.unreadable_errors` / `imposed_filtered_files` /
  `chosen_filtered_files`, which already return plain strings. The old type
  classified imposed/chosen/unreadable by `str.startswith` on the message,
  which an OS-reported filename could coincidentally satisfy for the WRONG
  tag; `kind` is now a field set once by the branch of the walk that produced
  the entry and is never re-derived from the message. Tested:
  `tests/test_privacy_shield_runner.py::test_an_unreadable_directory_named_like_a_filter_tag_is_not_misclassified`,
  `::test_walk_error_kind_is_set_by_the_branch_not_read_from_the_message`.
- `ScanReport.to_dict()["walk_errors"]` changed shape: a list of strings ->
  a list of `{"kind", "message"}` objects, `kind` one of `unreadable` /
  `filtered_default` / `filtered_chosen`. Flattening to strings threw `kind`
  away at exactly the boundary (JSON, an agent or a shell script) `WalkError`
  itself says not to re-derive it at. A new top-level `"unreadable_errors"`
  key carries the plain-string form for a consumer that only wants that.
  Tested: `tests/test_privacy_shield_runner.py::test_json_walk_errors_keep_kind_a_consumer_must_not_reconstruct`.

### Additions

- `scan()` gained `extensions` (keyword-only) and the CLI gained
  `--extensions .txt,.csv` / `--all-files`: which file suffixes a folder walk
  reads. Not passing `extensions` at all IMPOSES `DEFAULT_EXTENSIONS` (the
  caller does not know what it excludes, and a skipped file counts against
  `ScanReport.all_allowed` / exit code `2`); passing it explicitly — CHOSEN,
  including naming `DEFAULT_EXTENSIONS` by hand, or `None` for every file —
  records the skip (`chosen_filtered_files`) without moving `all_allowed`.
  Tested: `tests/test_privacy_shield_runner.py::test_imposed_default_extension_filter_breaks_all_allowed`,
  `::test_chosen_extension_filter_is_recorded_but_does_not_break_all_allowed`,
  `::test_naming_default_extensions_explicitly_is_still_a_choice`,
  `::test_all_files_disables_filtering_entirely`.
- `privacy_shield.freshness` + the `[freshness]` extra: a staleness verdict
  for the `[national]` table (`national.PERSON_NUMBER_MODULES`) against
  whatever `python-stdnum` is installed, via the optional `norm-freshness`
  plane. Off unless both `[national]` and `[freshness]` are installed; the
  underlying dead-module / unreviewed-validator checks still run off
  `[national]` alone. `norm-freshness` is not on PyPI as of this writing —
  `pip install ".[freshness]"` cannot succeed from PyPI today; it is
  installable from its own source tree. Tested:
  `tests/test_national_table_freshness.py`, `tests/test_stdnum_floor.py`.
- The CLI's human output now names, per file or path, which of the four
  terms behind a `False` `all_allowed` failed (gate-blocked, incompletely
  read, unreadable, imposed-extension-skipped), and separately — regardless
  of `all_allowed` — names every file a CHOSEN `--extensions` scope excluded,
  so a typo'd suffix or an empty `--extensions` that matches nothing is not
  silently indistinguishable from an empty, fully-read folder. Tested:
  `tests/test_privacy_shield_runner.py::test_cli_human_output_names_the_cause_of_a_non_document_block`,
  `::test_cli_human_output_names_a_chosen_filter_that_matched_nothing`.

### Fixed

- **A card written in four groups of four still leaked, and the gate could not
  see it.** Round 19 covered the remainder of a validating window only where
  the window sat inside one unbroken group. That read as a discriminator and
  was a refusal wearing a precondition — the exact thing the rule it
  implemented says may never decide a redaction — so a grouped card whose first
  group a coincidental IBAN claim happened to cover lost nothing but its label:
  `Beleg BE84 6613 1860    4526    0181    5908    3012    Ende` egressed twelve
  of the card's sixteen digits, in all three egress modes, with
  `is_safe_for_external_llm` reporting "No PII detected". Measured on 400
  documents of each shape: contiguous 400/400 leaking before round 19 and 0/400
  after, grouped 400/400 both times.

  Every unowned piece of a validating window that is at least `MATERIAL_RESIDUE`
  characters long is claimed now, with no condition on the window's shape.
  Eight is the gate's own `RESIDUE_RUN`, shared deliberately and asserted equal,
  so every piece the detector leaves is shorter than the shortest fragment the
  gate can report and the two agree by construction rather than by measurement.
  A floor of thirteen — the shortest card — fails the grouped case, because the
  remainder there is twelve. The cost is recorded rather than softened: 6 spans
  over 82 characters on 300 payment documents became **66 over 1350**. Tested:
  `tests/test_leak_invariant.py::test_a_grouped_card_under_a_coincidental_iban_claim`,
  `::test_the_detector_covers_down_to_this_files_own_materiality_floor`,
  `tests/test_identifier_runs.py::test_a_genuine_card_under_a_coincidental_iban_claim_is_covered_whole`.
- **The gate's oracle refused to look at the window that was leaking.** It
  dropped any Luhn-valid window overlapping a span already claimed as another
  validated identifier, so the grouped card above was never a validated
  identifier and its residue was never counted: `leaks_in` returned nothing and
  the gate certified the document clean. Identity decides a label; coverage
  decides whether the promise held. The oracle claims every Luhn-valid window
  now and measures it. The pinning test built only a contiguous card, so the
  grouped shape had never been measured; grouping is a parameter of it.
- **`min_confidence` read the pattern's confidence, not the finding's.** It was
  applied once, before any pass that can change a confidence, so the card shape
  demoted to MEDIUM in the validation pass came back from a scan at
  `min_confidence=HIGH`, at `medium` — while the release note said it did not.
  The note was corrected on public main; the filter now reads the confidence a
  finding ends up with, so the claim is true rather than trimmed. Tested:
  `tests/test_privacy_shield_regex_only.py::test_min_confidence_reads_the_confidence_a_finding_ends_up_with`.
- **Eight country codes validated as configurable and detected nothing.**
  `cy`, `gr`, `hu`, `lu`, `lv`, `mt`, `pt` and `si` carried empty validator
  tuples, so `configured_countries(['pt'])` returned `('pt',)` in silence — the
  `stdnum.at.svnr` defect in a different spelling, in the same table, with `pt`
  joining the set in round 19. Three were not limitations at all:
  `python-stdnum` ships a person number for Greece, Portugal and Slovenia and
  none had been looked for, because the table was written from the EU country
  list rather than from the library. Greece and Slovenia are configured (1 and
  0 false positives on 200 clean documents); Portugal's `pt.cc` is dropped on a
  measurement, because it accepts a repeated digit at every digit across every
  length from 12 to 20, all zeros included, and matched an IMEI. A code with no
  validator is excluded from `configured_countries` with the reason logged at
  WARNING. Full-scope false positives 61 → **62**, with two more countries
  live. Tested:
  `tests/test_national_ids.py::test_a_country_with_no_validator_is_not_configurable`,
  `::test_every_country_either_validates_or_says_why_not`,
  `::test_an_unvalidatable_country_has_nothing_but_company_identifiers`,
  `::test_no_configured_validator_accepts_a_string_of_zeros`.

- **A coincidental IBAN suppressed a genuine one, and a genuine card
  underneath one.** The claim rule stated in this release — no character
  belongs to two identifiers — was implemented on the card layer only.
  `_iban_spans_in_run` claimed the leftmost mod-97-valid registered-length
  window and advanced by its whole length, so a coincidence that validated
  stepped the search over a real IBAN starting inside it:
  `B.E54.7/<a real IBAN>` yielded `[IBAN]` plus eleven digits of the account
  number in a payload cleared for egress, about one document in seventy-four
  on realistic German text. The symmetric case lost a genuine card whole: the
  coincidental claim was handed to `find_cards` as `avoid`, which refused every
  window overlapping it, leaving fifteen digits of a Luhn-valid card under an
  `[IBAN]` label — in 165 of 400 constructed documents of that shape, and in
  none after the fix. Non-reuse now decides a LABEL and never a redaction: no
  validating window is left partially covered. Tested:
  `tests/test_identifier_runs.py::test_a_coincidental_iban_does_not_suppress_a_genuine_one`,
  `::test_a_genuine_card_under_a_coincidental_iban_claim_is_covered_whole`,
  `::test_covering_a_remainder_costs_this_much_beside_an_iban`.
- **The release gate was red on 3 of 400 hypothesis seeds, for reasons nobody
  decided.** Two mechanisms, both removed. The detector carried two layout
  heuristics the brute-force oracle could not see — a span limit of sixteen
  times a candidate's length and an interior-group limit of twelve — so a
  checksum-valid identifier written across a long neighbouring token, or with
  gaps wider than eighty characters, was claimed by the oracle, refused by the
  detector and reported as a leak. Sweeping either bound never moved the
  false-positive count, so both are removed rather than shared: a heuristic in
  the checker is how the line-break filter hid a whole leak class. And
  `_compact()` deleted the space a placeholder left behind, making characters
  adjacent that a redaction had separated, so a fragment that never existed in
  the source "survived" in the overlay; compaction now stops at a placeholder.
  Measured with explicit seeds: 6 of 25 seeds red before at 4000 examples, 0 of
  25 after, and 0 of 400 at the shipped example count. Tested:
  `tests/test_leak_invariant.py::test_there_is_no_width_at_which_the_detector_stops_claiming`,
  `::test_a_long_neighbouring_token_does_not_make_the_detector_decline`,
  `::test_the_property_holds_under_a_varied_hypothesis_seed`,
  `::test_a_placeholder_is_a_hard_break_when_counting_residue`.
- **The gate's oracle looked up its own spans by first occurrence.** `already`
  was rebuilt with `text.index(written)`, so a document containing the same
  IBAN twice registered the first one's span twice and the second one's not at
  all, and every Luhn-valid window made from the second copy's digits was
  reported as a card. A fail-open in the rule that stops the oracle counting one
  run of characters as two identifiers; offsets are now carried. Tested:
  `tests/test_leak_invariant.py::test_the_oracle_sees_both_copies_of_a_repeated_identifier`.
- **A labelled card with one transcription typo was dropped.** Demoting the
  Layer-1 patterns to candidate generators was measured both ways over 200
  documents each: the IBAN pattern's false positives fell sharply, the card
  pattern's did not move by a single span, and labelled cards carrying one
  wrong digit went from 3 in 200 unclaimed to 73. A single wrong digit always
  defeats Luhn — that is what Luhn is for. A `credit_card` pattern match no
  checksum accepts is now kept at MEDIUM with `checksum_validated=False`:
  redacted by default and unable to outrank anything, because the rank rule
  asks the finding rather than its type. It was NOT filtered out at
  `min_confidence=HIGH`, because that filter read the pattern's declared
  confidence and the demotion happens after it — **fixed since; see the entry
  above.** This sentence is left standing rather than trimmed, so the sequence
  is readable: a claim, its correction, and then the behaviour made true.
  Tested: `tests/test_privacy_shield_regex_only.py::test_a_labelled_card_with_one_transcription_typo_is_still_claimed`,
  `::test_a_card_shape_cannot_outrank_a_checksum`.
- **Four defects in the optional national layer, and a fifth in its speed.**
  `stdnum.at.svnr` does not exist — the module is `at.vnr` — and the
  ImportError was swallowed at debug level, so `at` was a silently dead country
  whose code still validated as configurable; a missing module is now a loud
  `MissingValidator`. Four validators could not fire for a person at any input
  because their minimum came from the scheme's total length rather than its
  digit count (`ie.pps`, `es.nie`, `fi.hetu`, `it.codicefiscale`); the column is
  now a minimum alphanumeric length, checked against `python-stdnum`'s own
  documented numbers in their bare form. `es.nif` and `pt.nif` are dropped
  because they accept company identifiers, and the Italian codice fiscale is
  held to its personal sixteen-character form. And `candidate_tokens`
  enumerated every sub-token pair, slicing and running a regex substitution over
  each before testing its length and never stopping once past the maximum: 4 KB
  of extracted text took 6.95 seconds on the egress path, and takes 0.001
  seconds now, with an identical candidate set. Full-scope false positives on
  200 clean documents: 75 before, 61 after, despite five validators being
  resurrected. Tested:
  `tests/test_national_ids.py::test_every_configured_validator_can_actually_fire`,
  `::test_a_module_that_is_not_there_is_a_loud_failure`,
  `::test_no_company_identifier_is_configured_as_a_person_number`,
  `::test_candidate_tokens_is_not_superlinear`,
  `::test_the_full_scope_false_positive_rate_is_what_it_is`.
- **`docs/limits.md` cited tests nobody checked existed.** The citation
  resolver covered the CHANGELOG only, and limits.md — the document a reader
  consults for what the product does NOT do — carried a citation pointing at
  the wrong file. Both documents are resolved now. Tested:
  `tests/test_2_0_0_surface.py::test_every_test_a_document_cites_exists`.

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


- `national.PERSON_NUMBER_MODULES["be"]` used `stdnum.be.ssn`, which does
  not exist below `python-stdnum` 2.0 — below `[national]`'s own declared
  floor (`python-stdnum>=1.19`). At that floor every scan with `be`
  configured raised `MissingValidator` uncaught out of `find_national_ids`,
  for every document, not only a Belgian one. Replaced with `stdnum.be.nn` +
  `stdnum.be.bis` (both present at the floor; together they accept exactly
  what `be.ssn` accepts, since `be.ssn` is defined as `be.nn` OR `be.bis`).
  Tested: `tests/test_stdnum_floor.py`.
- Before that, `be.ssn` itself corrected a live leak: `national.
  PERSON_NUMBER_MODULES["be"]` was `stdnum.be.nn`, and `freshness.
  REVIEWED_UNUSED` excused `be.ssn` as "alias of be.nn" — `be.ssn` is `be.nn`
  OR `be.bis`, and a BIS number (issued to non-residents) validated under
  `ssn` and not under `nn` alone, so it reached the overlay unredacted.
  Tested: `tests/test_national_table_freshness.py::test_the_reproduced_niss_case_is_closed`.
- The differential search behind `REVIEWED_UNUSED`'s "alias of" entries
  (`tests/test_national_table_freshness.py::_falsify_alias`) generated
  digits only, so it could never construct a value distinguishing a
  letter-containing scheme (`es.nif`'s company CIF `B64717838` from
  `es.dni`, which rejects it) and reported "no counterexample" — the same
  green as never having searched. The search now also checks the excluded
  module's own documented examples directly, narrows its brute-forced
  prefix to the alphabet those examples actually use per position, and
  fails loudly if it never once got the excluded module to accept anything
  it tried, rather than treating that as a passing "no counterexample".
  Tested: `tests/test_national_table_freshness.py::test_the_search_itself_finds_a_known_non_alias`.
- `tests/test_2_0_0_surface.py::_probe` ran its subprocess without pinning
  `sys.path`, so `import privacy_shield` inside it resolved through the
  ambient `PYTHONPATH` / site-packages rather than this checkout — on a
  machine with no per-checkout virtualenv, a stale `pip install`ed copy
  (a sibling session's, or an earlier run's) could silently be what every
  `test_the_*_still_*_with_every_extra_absent` test exercised. The
  subprocess now prepends this repo's `src/` to `sys.path` before anything
  else. Tested:
  `tests/test_2_0_0_surface.py::test_the_probe_subprocess_resolves_the_worktree_not_a_stale_install`.

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
