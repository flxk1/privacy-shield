# Limits, gaps and test split

Moved out of the README (README canon, `repo-standards/STANDARDS.md` § README canon).

## Limits of the runner and CLI

- **The egress verdict is a source classification, not proof of anonymity.** The
  gate blocks LOCAL_ONLY / confidential / berufsgeheimnis / Art. 9 sources; a
  non-confidential PII document passes and its redacted overlay leaves. The gate
  leaves the overlay unscanned, so "cleared" stays short of a zero-residual
  certificate.
- **Overlapping findings no longer splice the overlay.** This entry used to say
  placeholder fragments were "a known redactor artefact" of overlapping
  findings. They were not cosmetic — a spliced replacement left un-redacted PII
  beside the fragment. Overlapping spans are merged into disjoint ones covering
  the union before anything is applied, in `redactor.py` and in
  `anonymous_json.py`, which had its own unfixed copy of the same loop.
- **Over-redaction of long digit runs is deliberate.** Card detection applies
  Luhn to every 13–19 digit window at every offset, with no issuer-prefix
  table, so a Luhn-valid window inside a longer digit run is redacted — on
  twenty realistic German business documents carrying no payment identifier,
  six were affected (tracking numbers, an IMEI, long internal references). An
  issuer table would cut that to one, at the price of a stale BIN range
  standing between a real card and the gate. IBAN detection is held to the
  ISO 13616 registered length per country and produced no false positives on
  the same corpus. A false positive can only consume digits and the joiners
  written inside a number, never prose. Measured by
  `tests/test_identifier_runs.py`.
  Admitting gaps wider than one character raised this from six to eight, and
  the hostile corpus from three to eight. The new shape is a window assembled
  across ONE separator out of two adjacent numbers in a list. Refusing it needs
  a condition on the candidate's edges, and every such condition tried refuses
  a real leak shape instead — text glued to both ends of a spaced number clips
  both edges, and `Art. 6 DSGVO4111 1111 1111 1111Ref ` then egresses the card
  whole. Fail-closed wins. Measured by
  `tests/test_identifier_runs.py::test_precision_under_deliberately_hostile_punctuation`
  and `::test_card_precision_on_clean_business_text`.
- **UUID fragments are over-redacted when they satisfy Luhn.** The tail of a
  UUID plus the first character of the next token can form fifteen Luhn-valid
  digits, and nothing in the text distinguishes that from a fifteen-digit card
  written with a hyphen and a space, so it is redacted.
- **What counts as one identifier, in one sentence:** *a candidate is any
  maximal sequence of ASCII alphanumerics joined by runs of characters that are
  not alphanumeric at all, interrupted by at most one line terminator.* That is
  the whole rule. There is deliberately no bound on the NUMBER of groups, on
  the WIDTH of a gap, on the SPAN of the candidate, or on how long a group
  inside it may be. Joiners are defined by exclusion rather than listed,
  because three successive rules were walked around: the literal `" \t-"`, then
  the Unicode categories `Zs`/`Pd`/`Cf` (which miss `Pc` underscore and `Po`
  colon, dot, slash), then a hard limit of one joiner per gap (which a
  `pdftotext` column gap, fixed-width padding, a dot leader and a monospaced
  table all defeat).

  **Two layout bounds were removed in round 19** — a span limit of sixteen
  times the candidate's length, and an interior-group limit of twelve — and the
  reason is the release gate rather than precision. The brute-force oracle has
  no layout rule, so every bound the detector had and the oracle did not was a
  disagreement the gate reported as a leak whenever the property test happened
  to draw one: 3 reds in 400 hypothesis seeds at the shipped example count, and
  6 of 25 seeds at 4000 measured here. Sharing them with the oracle is not
  available — a heuristic in the checker is how the line-break filter hid a
  whole leak class in round 14 — so the heuristics went and the definitional
  bound stayed. Measured before removing them: on 93 realistic documents and
  300 wide-column documents nothing moved at all; on 3000 deliberately
  digit-dense documents, card spans 2999 → 2998 and IBAN spans 10 → 13.

  **What it costs, stated:** within its two lines a claim now has no width
  limit, so a mod-97-valid assembly spread across a wide table row is redacted
  along with everything between its groups. Nothing in the measured corpora
  does that, but the blast radius when it happens is a line rather than a
  field. The terminator bound is what keeps it from being a page. Tested:
  `tests/test_identifier_runs.py::test_every_joiner_category_groups_an_identifier`
  (joiners generated from `unicodedata`, not from a list),
  `tests/test_leak_invariant.py::test_there_is_no_width_at_which_the_detector_stops_claiming`,
  `::test_a_long_neighbouring_token_does_not_make_the_detector_decline`,
  `tests/test_leak_invariant.py::test_a_multi_character_gap_does_not_hide_a_card`,
  `::test_reported_extraction_artefact_shapes`.
- **One line TERMINATOR inside an identifier is a joiner; two are not.** A
  terminator is one break however it is written — `\n`, `\r`, `\r\n`, `\n\r`,
  `\u2028`, `\u2029` — because the bound counts terminators and not
  characters. It counted characters until round 17, so a single CRLF scored two
  and a wrapped identifier terminated the ordinary Windows and MIME way was
  refused: `is_safe_for_external_llm` returned "No PII detected" for an e-mail
  body containing all sixteen digits of a card, while the same body with `\n`
  was detected. That was the eighth leak class in this package's history and it
  is fixed; the entry that described it as a live defect is gone because the
  defect is gone, not because the wording softened.

  The gate could not see it either — its oracle applied the same arithmetic to
  the same two characters, the sixth time the checker shared an assumption with
  the checked. The oracle now counts terminators with its own implementation
  and the generator emits CRLF, `\n\r` and mixtures within one document. The
  claim that the terminator set is "derived from Unicode rather than typed" was
  decoration and is withdrawn: it derived categories `Zl` and `Zp`, which are
  the two characters the list beside it already typed. The set is now checked
  against CPython's own `str.splitlines`, which knows three separators this
  package does not — `\x1c`, `\x1d`, `\x1e` — and which both layers treat as
  joiners, so an identifier written across one is claimed rather than refused.
  Tested: `tests/test_leak_invariant.py::test_a_wrapped_identifier_is_found_whatever_ends_the_line`,
  `::test_is_safe_for_external_llm_agrees_across_terminators`,
  `::test_the_terminator_set_is_no_shorter_than_cpythons`,
  `::test_a_mixture_of_terminators_in_one_document`.

  **The bound itself remains**, and so does what it costs: an identifier
  interrupted more than once — needing a column narrower than about eight
  characters — is not found. Assembly across ONE terminator is **accepted**,
  because `4111111111\n111111` is a card wrapped once and
  `5100004821\n5100004822` is two document numbers, and nothing in the text
  separates them: 11 over-redaction spans over 5 stacked-column documents,
  pinned by
  `tests/test_identifier_runs.py::test_stacked_numeric_columns_are_over_redacted`.
  A bound exists at all because making every line
  break a joiner without limit would glue a document's lines into one run and
  let a column of figures be assembled into a checksum. Pinned by
  `tests/test_leak_invariant.py::test_the_line_break_bound_is_one_and_this_is_what_it_costs`.
- **National person numbers need the `[national]` extra AND a country.** With
  `python-stdnum` installed and `PRIVACY_SHIELD_NATIONAL_COUNTRIES` set, 20
  check-digit validators across 19 EU countries are applied to token-level
  candidates; all of them import and all of them fire on the library's own
  documented numbers, which round 19 had to fix and now tests. Both conditions are load-bearing and neither comes from the
  library: `identifiers.identifier_runs` joins across every non-alphanumeric
  character including line terminators, so an ordinary four-line letter is ONE
  79-character run that every validator rejects; and `111222333` is a valid
  Dutch BSN *and* a valid Czech *and* a valid Slovak birth number, so running
  every country manufactures false positives and reports them as detections.
  **Nothing is enabled by default.** Without the extra, or with no country
  configured, this layer produces nothing and no other layer changes — the base
  package keeps `dependencies = []` and the regex/lexicon floor is unaffected.
  What is lost is a national number that no pattern covers.

  **The evaluation's zero did not reproduce as evaluated.** It reported 0 false
  positives over 951 tokens from 119 clean documents; over 136 candidate tokens
  from 62 clean German business documents, three validators produced 20:
  `de.stnr` 14 (it accepts invoice and order numbers — its check is too weak),
  `si.ddv` 3 and `nl.bsn` 3 (stdnum accepts the eight-digit legacy form, and an
  eight-digit customer number passes an eleven-test about one time in eleven).
  `de.stnr` is dropped on that measurement; `si.ddv` and `lv.pvn` are dropped
  because they are VAT — identifiers of an organisation — which contradicted
  this layer's own person-only rule; `nl.bsn` is held to nine digits, the
  current length.

  **That zero does not hold, and the claim stays withdrawn.** It was measured on
  62 documents carrying 2.2 candidate tokens each; German business text carries
  far more. The number that means something is measured on 200 generated
  documents of ordinary German business field shapes — invoice, order, meter,
  contract, personnel and file numbers — with every country enabled:

  | | 0719c79 | round 19 |
  |---|---|---|
  | false positives, 200 clean documents, all 27 countries | 75 | **61** |
  | `de` alone / `fr` alone / `it` alone | 0 / 0 / 1 | **0 / 0 / 0** |

  It is lower *despite* five validators having been resurrected, which is the
  honest shape of the trade: dropping the company schemes and the
  check-digit-free legacy forms took more away than the repairs added back. The
  remaining count is dominated by ten- and eleven-digit schemes whose mod-11
  check accepts roughly one arbitrary string in eleven (`hr.oib` 17, `at.vnr`
  15, `nl.bsn` 13, `dk.cpr` 10). **No minimum length will fix that**, and no
  further validator will be dropped to make the number look better — that is how
  it was 0 in the first place. What works is country scoping. What would fix the
  full-scope number is corroborating evidence beside the token, and that is a
  design decision, not a constant. Pinned as both a ceiling and a floor by
  `tests/test_national_ids.py::test_the_full_scope_false_positive_rate_is_what_it_is`.

  **The four reported defects are fixed.** `stdnum.at.svnr` does not exist — the
  module is `at.vnr` — and the ImportError was swallowed at debug level, so `at`
  was a silently dead country whose code still validated as configurable; a
  missing module is now a loud `MissingValidator`. The minimum column was read
  as a digit COUNT while four of its values had been taken from the scheme's
  total LENGTH, so `ie.pps`, `es.nie`, `fi.hetu` and the personal
  `it.codicefiscale` could not fire for a person at any input; the column is now
  a minimum alphanumeric length, and every value is checked against
  `python-stdnum`'s own documented examples, in their bare form, by
  `::test_every_configured_validator_can_actually_fire`. `es.nif` and `pt.nif`
  are dropped because they accept the CIF and the NIPC — company identifiers —
  and the Italian codice fiscale is held to its sixteen-character personal form,
  because its eleven-digit form is a partita IVA. Five dead validators, each
  reporting zero false positives, is the same failure as a corpus too small to
  produce one.

  **Still true: the layer is off by default, and the full-scope rate is about
  one spurious `[NATIONAL_ID]` per three documents.** Enable only the countries
  whose documents you actually scan, and measure on your own corpus before
  trusting any count here.

  Not adopted, with the measurements in this document: **Presidio** and
  **libpostal**. The **English label probe** is not restored.
- **The run-based layer owns IBAN, card and e-mail detection.** It is
  anchor-free, it validates, and it finds these whatever is glued to them. The
  Layer-1 regexes are kept as candidate generators because they reach some
  layouts differently, but for any type with a validator a pattern finding that
  does not validate is dropped. Until round 18 the IBAN pattern emitted HIGH
  confidence unvalidated, so it claimed a German VAT number
  (`USt-IdNr. DE136695976`) with a span that crossed a line terminator, while
  `find_ibans` correctly returned nothing — an unvalidated pattern outranking a
  checksum, which is the structure this package was rejected for in round 9.
  Tested: `tests/test_privacy_shield_regex_only.py::test_a_vat_number_is_not_an_iban`,
  `::test_no_finding_of_a_validated_type_fails_its_own_validator`.
- **No character belongs to two identifiers — but non-reuse decides a LABEL,
  never a redaction.** A Luhn-valid window built from an IBAN's tail plus the
  digits after it is the same characters counted twice, not a third identifier,
  and neither the detector nor the gate's oracle reports it as one. Round 18
  implemented that as a REFUSAL, which reduced coverage, and two leaks followed:
  a coincidental IBAN claim suppressed a genuine IBAN starting inside it
  (`B.E54.7/` in front of a real IBAN left eleven digits of the account number
  in a payload cleared for egress, about one document in seventy-four), and a
  coincidental IBAN claim reaching into a card's first digits suppressed every
  window covering the rest of it, leaving fifteen digits of a genuine card under
  an `[IBAN]` label — in 165 of 400 constructed documents of that shape.

  The rule as implemented now: **no validating window is ever left partially
  covered.** Every mod-97-valid registered-length window is claimed, the IBAN
  search advances one character at a time instead of skipping a claim's length,
  and overlapping claims are merged into their union. Where a Luhn-valid window
  overlaps characters another validated identifier owns, the part nobody owns is
  claimed provided the window sits inside ONE unbroken group — the discriminator
  between a genuine card under a coincidental claim and a window running out of
  a genuine IBAN into the amount beside it. Claiming the remainder
  unconditionally cost 117 spans over 1718 characters on 300 realistic payment
  documents; restricted this way it costs exactly what refusing it cost, 6 spans
  over 82 characters, the same to the character as 0719c79. Tested:
  `tests/test_leak_invariant.py::test_a_card_may_not_be_assembled_from_another_identifiers_digits`,
  `tests/test_identifier_runs.py::test_a_coincidental_iban_does_not_suppress_a_genuine_one`,
  `::test_a_genuine_card_under_a_coincidental_iban_claim_is_covered_whole`,
  `::test_claiming_a_remainder_does_not_eat_the_fields_beside_an_iban`.
- **A card SHAPE is kept without a checksum; an IBAN shape is not.** Demoting
  the Layer-1 patterns to candidate generators was measured both ways over 200
  documents each: the IBAN pattern's false positives fell sharply and the CARD
  pattern's did not move by a single span, while labelled cards carrying one
  transcription typo went from 3 in 200 unclaimed to 73. A single wrong digit
  always defeats Luhn — that is what Luhn is for — and it is the most ordinary
  defect in an OCR'd or hand-typed document. So a `credit_card` pattern match
  that no checksum accepts is kept at **MEDIUM** confidence with
  `checksum_validated=False`: redacted by default and ranked with the patterns
  rather than in front of them. **It is NOT filtered out at
  `min_confidence=HIGH`** — an earlier version of this paragraph said it was,
  and that was wrong. `_match_patterns` filters on the *pattern's* declared
  confidence; the demotion happens later, in the validation pass, and nothing
  re-filters afterwards. A scan at `min_confidence=HIGH` still returns the
  finding, at `medium`. Both tests cited below run at `LOW`, so neither
  checked it. The rank rule now asks the FINDING whether a checksum stands behind it
  instead of asking its type. Tested:
  `tests/test_privacy_shield_regex_only.py::test_a_labelled_card_with_one_transcription_typo_is_still_claimed`,
  `::test_a_card_shape_cannot_outrank_a_checksum`.
- **The leak gate checks IBAN, card and e-mail, and nothing else.** Its oracle
  independently validates those three, so a failure of the NAME layer — or of
  the phone, date or national-number layers — cannot turn `leak-gate` red. Two
  known German names written with no separator between them
  (`Anna SchmidtKlaus Weber`, a `pdftotext` artefact of the class this package
  exists for) produce `pii_detected=False` and an unchanged overlay, and the
  gate is silent about it by construction. Extending the oracle to a category
  with no checksum is not a small change — it needs an independent notion of
  what a name IS — and it is not done here.
- **A folder scan that could not read everything is not a clean result.**
  `walk_errors` lists the directories the walk could not enter,
  `scan_complete` is False when it is non-empty, and `all_allowed` is False as
  well — "every document is cleared" cannot be asserted about documents that
  were never read. Until round 17 the walk caught `OSError` around `next()` on
  a generator, which cannot work (a generator that raises is finished), so on
  Python 3.10 an unreadable directory produced a silent partial scan certified
  `all_allowed=True`. Tested:
  `tests/test_privacy_shield_runner.py::test_an_unreadable_directory_does_not_silently_truncate_the_scan`.
- **A local part may contain non-ASCII letters** (RFC 6531), so
  `müller@kanzlei.de` is claimed whole. Expanding over ASCII only clipped it
  to `ller@kanzlei.de` and let the first two characters egress. A letter
  directly before ASCII local-part characters may be part of the mailbox name
  or a word run into it, and nothing in the characters tells them apart, so the
  whole run is claimed — which over-redacts a glued word rather than clipping
  an address.
- **Person names are found by evidence, not by capitalisation.** German
  capitalises every noun, so "capitalised word followed by capitalised word"
  claimed 75% of every character of ordinary business documents containing no
  personal data — 121 spans across twenty documents, 90% on one memo. A name is
  now claimed only where a title, a signature block, an addressee position or a
  known given name says a person is being named. Measured on a development and
  a held-out corpus: false positives on clean documents went 73/48 spans to
  **0**, precision 24%/25% to **100%**, recall 86%/89% to **100%**.
  **Positions the name layer COVERS**, by name, because this is the list the
  release is shipping on: a salutation (`Sehr geehrte Frau Schneider`); after a
  title or address form (`Herr Dr. Baumann`, `von Herrn Stefan Braun`); the
  first name-shaped line after a closing formula; an addressee block above a
  street or postcode or below a bare `An`; a known German given name followed
  by a surname in running prose, INCLUDING two names side by side
  (`Anna Schmidt Peter Weber`) — the second name's given name used to be
  swallowed; a surname carrying a nobiliary or toponymic particle
  (`Karl-Heinz von der Tann`, `Ludwig van Beethoven`); and a table cell whose
  column header names a person's role, including the second and later tables
  in a document and tables with no blank line between them.

  **Positions it does NOT cover**, also by name: a value after a label that
  names a person's role (`Sachbearbeiter:`, `Von:`, `An:`, `CC:`,
  `Im Auftrag von:`) and comma-separated lists after one — this probe was
  approved, then withdrawn before release because a label and a colon are
  evidence that a value follows and not that it is a person, so it claimed
  company names, systems and statuses; a bare surname in running
  prose with nothing around it; a speaker attribution (`Ebersbach: Der Termin
  …`); a line that is only a name outside a signature or address block (a bare
  participant list); a footnote citation (`Vgl. Kowalczyk, Gutachten …`); a
  bare given name on its own; and **any full name whose given name is not in
  the German given-name list** — `Aleksandra Nowakowska`, `Mateusz Wisniewski`
  and `Yuki Tanaka` are invisible in running prose. The speaker-attribution and
  name-only-line positions were measured and deliberately not shipped: they
  cost 1 and 17 false-positive spans on clean documents respectively.

  **Probe A — a value after a person-role label — was approved and then
  withdrawn.** It was approved on a zero measured over 20 documents; an
  independent corpus produced 18 false-positive spans over 20. Its two
  enumerations could not be completed (foreign legal forms such as `Oy` and
  `Kft`, and German inflection defeating an uninflected value list), and its
  only unique contribution is the bare surname after a label, which is
  structurally identical to `Sachbearbeiter: Unbesetzt` and `An: Nordica Oy`.
  Deciding it needs the lexicon described below. Withdrawing it cost 4 of 21
  name occurrences on the independent corpus: recall went 11/21 to
  **7/21 (33%)**.

  **The cost, re-measured against document classes specified from outside this
  work:** recall is **7 of 21** name occurrences (33%) on correspondence that is
  not a formal letter — nothing after a colon, in a CC list, in an e-mail body
  without a title, in a footnote, in minutes, in a table cell or in a subject
  line, and **nothing for a non-German full name in prose**, because the rule is
  gated on a German given-name list. The earlier claim that the cost was "a bare
  surname in running prose" named a corner; this is the class. Pinned by
  `tests/test_name_layer_precision.py::test_the_measured_recall_on_correspondence_that_is_not_a_formal_letter`.
  What each additional position would cost in precision is measured in that
  file's comment; none of it is shipped, because widening this rule is what
  produced 75% character loss and the choice belongs to the owner.
### The stoplist inversion — analysis for the next round, not shipped

A positive given-name list cannot close the gap above: it is unbounded and
multilingual, and no list of names is ever finished. The tractable form is the
inverse — claim a capitalised word pair *unless* its words are ordinary
vocabulary. `Ihr Schreiben` and `Interne Mitteilung` are in a dictionary;
`Nowakowska` is not, in any dictionary but Polish. Written down here so the
next round starts from this rather than rediscovering it:

- **Which list.** A German lemma-and-inflection frequency list, not a lemma
  list alone — German inflects, and `Schreibens` must match as readily as
  `Schreiben`. The DeReWo full-form frequency lists (IDS Mannheim, CC-BY-NC) or
  a Wiktionary-derived full-form list (CC-BY-SA) are the realistic candidates;
  licence matters here, because this package is Apache-2.0 and NC terms are not
  compatible with it.
- **What size.** Coverage of German business prose flattens around the top
  100k–200k full forms; below ~50k the tail of compounds starts leaking
  through as false names. Compressed, that is roughly 1–3 MB — an order of
  magnitude more than everything this package currently ships.
- **What it costs to ship.** A data file of that size cannot go in the wheel
  without changing what the package is; it needs an optional extra, a download
  step or a system dictionary, and each of those breaks the current property
  that the regex floor works with zero dependencies. That property is worth
  more than the recall, so the stoplist has to be optional and the floor has to
  stay correct without it.
- **How it degrades.** Badly on compound nouns, which German coins freely:
  `Foerderbandsteuerung` will not be in any list and reads as a surname.
  Badly on loanwords and product names (`Dockingstation`, `Nordstern`). And it
  is one list per language, so a document in a language with no list loaded
  degrades to the current behaviour rather than to nothing — which is the
  right failure direction, but means the gap above persists per-language.
- **What it does not fix.** A bare surname in prose is still ambiguous with a
  capitalised noun the list happens to be missing; the inversion raises recall
  and moves the false positives from "every capitalised pair" to "every
  capitalised pair the dictionary does not know", which is much smaller but not
  zero. It needs the same clean-corpus measurement before shipping.
- **The layout bound's cliff is gone.** This entry used to say an identifier
  whose groups are spaced more than about eighty characters apart is not found,
  and that the cliff was pinned rather than discovered. Pinned was not safe: the
  gate's oracle has no width rule, so at eighty-one spaces it claimed the
  identifier, the detector did not, and the gate reported a leak — the same
  mechanism as the interior-group bound, reproduced at 3 reds in 400 hypothesis
  seeds. The bound bought no precision at any setting from 4x to 1000x, so it is
  removed rather than moved, and the test that pinned the cliff is replaced by
  `tests/test_leak_invariant.py::test_there_is_no_width_at_which_the_detector_stops_claiming`.
  What this costs in over-redaction is under "What counts as one identifier".
- **Single-character groups are accepted, so dotted prose is over-redacted.**
  "4 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1" is what `pdftotext` emits for a
  letter-spaced form field, and "4.1.1.1..." is punctuated prose. Nothing in
  the text separates them, so both are redacted.
- **The IBAN country/length table is a transcription and cannot self-check.**
  ISO 13616 is amended about twice a year; the table was missing 40
  registrations including Honduras and Yemen, whose IBANs were therefore not
  IBANs to this package, with every test green.
  `tests/test_iban_registry.py` compares it against `schwifty`, a maintained
  external implementation, and fails on any drift. Without that dependency
  installed the check skips loudly rather than passing.
- **Detection is ASCII for the validated types.** Identifier runs are built
  from ASCII alphanumerics; an account number written in full-width or
  Arabic-Indic digits is not offered to the validators. Invisible characters
  (Unicode `Cf` — soft hyphen, zero-width space, BOM) are removed first and
  never break a run. ASCII is a FINDING rule and not a definition here:
  `luhn_ok` accepts Arabic-Indic and full-width digits that neither the
  detector nor the gate's oracle will ever offer it. Pinned by
  `tests/test_leak_invariant.py::test_non_ascii_digits_are_a_documented_limit_not_a_silent_one`.
- **Folder walk** defaults to known text/document extensions
  (`runner.DEFAULT_EXTENSIONS`); use `--all-files` to consider every file.
  Binary/undecodable files are recorded as per-document `errors`, not fatal.
- **Semantic and local-LLM passes are optional.** With neither the `[semantic]`
  extras nor a local model present, detection is the deterministic regex/lexicon
  floor only (the modules degrade gracefully). `[extract]` extras
  (PyMuPDF, which is AGPL, and opencv) are needed for PDF/image extraction; without them those
  documents surface an extraction error.
- **The semantic pass needs a LOCAL embedding endpoint.** `PIIContextMatcher`
  sends document chunks — raw, pre-redaction text — so it is held to the same
  loopback-or-unix-socket rule as the local-model send paths. Point
  `OPENAI_BASE_URL` at a local embedding server; against anything else the
  semantic layer declines, logs once, and the scan continues on the regex
  floor. The one-off `embed_pii_contexts()` setup is exempt: it embeds the
  fixed context phrases in the module's own source, not anybody's data.
- **The local-LLM layer talks to local HTTP endpoints.**
  `services/local_model_runtime.py` discovers providers on
  `http://localhost:11434` (Ollama), `:1234` (LM Studio), `:1337` (Jan) and
  `:4891` (GPT4All). Detection stays on the machine; it is local HTTP rather
  than an in-process model.
- **The MCP tool is the enriched path, not the only path.** `scan()` and the
  `privacy-shield` CLI are the callable capability with nothing else
  installed; the `privacy-shield` skill's `privacy_scan` tool requires
  `loomground-mcp`.

## Limits of the media paths (images, audio, video, file metadata)

- **A media overlay is TEXT, never a re-encoded media file.** `DocumentScan.overlay`
  is a `str`. For an image it is the redacted OCR text, for audio the redacted
  transcript, for video transcript plus frame text. `scan()` never produces a
  cleaned image, audio file or video: `redact_image`, `redact_audio`,
  `redact_video` and `strip_metadata` are separate, caller-driven APIs that are
  **not on the `egress_allowed` path at all** and are reached only through
  `PrivacyShield.strip_metadata` or the media classes directly. So "only the
  overlay egresses" is true of a media file in the narrow sense that the only
  thing the pipeline hands back is a redacted text projection — and the source
  media file is never made safe to send. If you need to forward the file, that
  is the redaction API's job, and you must check its return value.
- **The raw metadata VALUE is local-only telemetry; the field NAME travels.**
  `ShieldResult.metadata_pii_fields` and `DocumentScan.findings_by_type` carry
  names (`GPS`, `Artist`, `gps`), never values. `ImageMetadata.to_dict()`,
  `AudioMetadata.to_dict()` and `VideoMetadata.to_dict()` **do** carry raw
  values (`gps`, `owner`, `artist`, `comment`, `camera_make`) and are not
  reachable from `ShieldResult`; `MetadataFinding.value` likewise. Nothing in
  the package forwards them, and `tests/test_media_egress_promise.py::test_the_media_overlay_is_text_and_never_the_raw_metadata_value`
  pins that. Treat them the way `SpanFinding.value` is treated: on-machine only.
- **Every media PII channel needs a backend this package does not declare, and
  in CI's own configuration NONE of them is present.** `[extract]` installs
  PyMuPDF and opencv; it does **not** install Pillow, and image EXIF reading is
  Pillow-only. OCR needs `paddleocr`, `pytesseract` or `python-doctr`; STT needs
  `faster-whisper`, `openai-whisper` or `vosk`; container tags need `ffprobe` on
  PATH or `mutagen`; frame and audio-track extraction need `ffmpeg` on PATH;
  the comprehensive metadata reader needs `exiftool` on PATH; the PDF and Office
  metadata fallbacks need `pypdf` and `python-docx`. None of these is in any
  extra. So with `pip install ".[dev,semantic,extract,openai]"` an image is
  scanned with no EXIF reader, no OCR engine and no face detector, an mp3 with
  no tag reader and no transcriber, and a video with nothing at all.
- **An unavailable channel is now visible, and that is the whole of the fix.**
  Each missing channel records a per-document error prefixed
  `media_channel_unavailable:` — the same mechanism the folder walk uses for an
  undecodable binary, above. It does **not** change the egress verdict: a media
  file whose channels could not run is still `egress_allowed=True`, because the
  gate decides on source classification. **`all_allowed` is therefore not a
  statement that every media file was read.** A consumer that needs that must
  check `any(e.startswith("media_channel_unavailable") for e in doc.errors)`.
  Before this, those channels returned empty-handed in silence: a photograph of
  a letter, an interview recording and a geotagged site video all came back
  `pii_detected=False, errors=[], egress_allowed=True`.
- **Face detection has no working backend at the declared floor.** `[extract]`
  pins `opencv-python-headless>=4.8` with no ceiling; opencv 5.0, which that
  floor resolves to today, ships **no Haar cascade XML**, so the fallback
  detector stopped existing on a transitive upgrade. With `mediapipe` absent as
  well, no face is ever detected. This is reported, not silent, but a face in an
  image is not found in the shipped configuration.
- **`redact_image`, `redact_audio` and `redact_video` return False rather than
  report a redaction they did not perform.** Specifically: `blur_faces=True`
  with no detector, or on a processor built with `detect_faces=False`, refuses;
  a `cv2.imwrite` that fails refuses (its return value used to be discarded, so
  a pre-existing file at the output path was reported as the redacted copy);
  `redact_video(blur_faces=True)` refuses, because video face blurring is not
  implemented; `redaction_type="beep"` refuses, because it built the same
  `volume=0` filter as `silence`. **`redact_audio` with no speech segments no
  longer copies the input to the output.** It used to `shutil.copy` and return
  True — the artefact cleared for egress was the original file, tags, cover art
  and all — and an empty segment list is the default outcome, since no STT
  engine is declared.
- **Face blurring in video is not implemented**, and text-box blackout in video
  is not implemented. Asking for either returns False.
- **`strip_metadata` verifies its own output and refuses when it cannot prove
  the metadata is gone.** It re-reads the output through the same parsers AND
  searches the output **bytes** for each value the input carried, in UTF-8,
  UTF-16-BE and Latin-1. Two consequences. First, the PDF path is now correct:
  `set_metadata({})` clears only the DocInfo dictionary, the XMP packet holds
  the same author and title, and a default PyMuPDF save keeps the superseded
  objects in the file, so the author's name and the document subject stayed
  recoverable from a file the function had returned True about. Second, the
  check **deliberately over-refuses**: a metadata value that also appears in
  the page's visible text cannot be removed by a metadata strip, and
  `strip_metadata` will return False rather than claim it is gone. Fail-closed
  wins, as with the digit-run over-redaction above. Values shorter than six
  characters are not byte-searched, because they collide with ordinary binary
  content.
- **Only `.jpg`, `.jpeg`, `.png` and `.pdf` can be stripped without `exiftool`,
  and the PDF path additionally needs `PRIVACY_SHIELD_ENABLE_PYMUPDF=1`.**
  Everything else returns False. Note that `extractor.py` latches that
  environment variable at **import** time while `media/metadata.py` reads it per
  call, so setting it after the package is imported changes metadata handling
  and not text extraction.
- **Container tag classification is one table.** `media/metadata.tag_pii_type`
  is the single entry point; `audio.py` and `video.py` consume it. It normalises
  ID3 frame ids (`TPE1`, `COMM::eng`, `APIC:cover`), Vorbis/QuickTime words
  (`ARTIST`, `©xyz`) and namespaced names (`EXIF:Artist`,
  `Composite:GPSPosition`) to the word form the field tables use. Previously
  each module carried its own subset — audio flagged `artist` and `comment`
  only and matched no ID3 frame id at all, so a fully installed `mutagen`
  still reported an mp3 as carrying no tag PII; video flagged `artist` plus two
  literal GPS keys and dropped `author`, `title`, `comment` and
  `creation_time` into `raw_tags`, which no result object exposes.
- **Video GPS is looked for under every spelling a phone writes**, at format
  AND stream level: `location`, `location-eng`, `com.apple.quicktime.location.*`,
  `com.android.location`, `gps*`, `©xyz`. Two exact keys were matched before,
  at format level only.
- **Cover art and embedded payloads are reported by presence, not content.**
  An ID3 `APIC` frame or an ffprobe `attached_pic` stream is a photograph
  inside an audio file, with its own EXIF block; it is flagged as
  `embedded_payload` and is **not** recursively scanned.
- **An EXIF thumbnail (IFD1) is reported as `EXIFThumbnail`, not examined.**
  A crop, rotation or downscale by an editor that rewrites the main image and
  not IFD1 leaves the original frame in the thumbnail. The merged dict
  `_getexif()` returns drops IFD1 entirely, so nothing had looked; presence is
  now flagged, but the thumbnail's own content is not OCR'd or face-detected.
- **`MakerNote` is flagged and not parsed.** It is an opaque per-vendor blob
  that routinely repeats the serial number, the owner name and the GPS fix;
  presence is the finding.
- **External media tools are invoked through one seam**, `media/_tools.py`:
  list-form argv, never `shell=True`, every file operand resolved to an
  absolute path, and every call bounded by a timeout. The absolute path is the
  fix for a real reachable case — `runner.scan` passes a single file straight
  through with no extension filter, so a file named `-delete_original!` or `-i`
  reached `exiftool`/`ffprobe` as a bare option token; none of these tools
  honours the `--` end-of-options convention, so resolving the path is the
  portable answer. The timeout is the fix for a malformed container blocking a
  folder scan indefinitely.
- **`security_scanner.py` is not on the egress path.** It is a prompt-injection
  / jailbreak / hidden-instruction detector for documents on their way **into**
  an LLM prompt — the inbound mirror of the PII scanner. It is exported from
  `privacy_shield/__init__.py` and listed in `docs/pipeline.md`, but nothing in
  `scanner.py`, `shield.py`, `runner.py` or `gate.py` calls it, so no
  `egress_allowed` verdict depends on it. Pinned by
  `tests/test_media_egress_promise.py::test_security_scanner_is_not_on_the_egress_path`,
  which fails if it is ever wired in.

## Known gaps

The ONNX contextual model is shadow-only (no promotion); there is no bundled
pre-embedded PII-context file.

**A PDF's DocInfo values are reported by field name and never scanned.**
`extractor.py` reads `/Author`, `/Title`, `/Subject`, `/Creator` and
`/Producer` into `ExtractionResult.metadata`, and `shield._process_document`
turns `author`, `creator` and `last_modified_by` into
`metadata_pii_fields` entries — field names only. The VALUES are not appended
to `extracted_text`, so they are never offered to the scanner and never
redacted. A `/Subject` reading `Patientenakte 4711` is reported as
`{"metadata": 1}`. Fixing this means changing `extractor.py` or `shield.py`,
neither of which is in the media territory. PDF annotation contents and AcroForm
field values ARE reached, because PyMuPDF's `page.get_text()` includes their
appearance streams — measured, not assumed, and one of the things this round
could not break.

**`PrivacyShield(enable_ocr=False)` silently disables the EXIF and
face-detection channels too**, because `shield._process_image` returns before
constructing the processor. The flag is named for one channel and gates three.
`shield.py` is outside the media territory; recorded here rather than fixed.

## Test split

All numbers below are measured in **CI's environment**, which is
`pip install ".[dev,semantic,extract,openai]"` and nothing else — notably
**without `httpx`**, which is in no extra and which CI does not install:

```
python3 -m pytest -q      # python 3.12, .[dev,semantic,extract,openai]
1051 passed, 8 failed, 4 skipped
```

`--collect-only` reports 971 items; the run above reports 972 outcomes,
because two of the skips are module-level `importorskip` skips rather than
collected items. The same numbers on python 3.14, CI's other matrix leg.
Two of the 4 skips are the `httpx` transport assertions in
`tests/test_proxy_transport_guard.py` and
`tests/test_privacy_shield_embeddings.py`; they do not run in CI either, and
a previously reported "886 passed / 8 failed" was measured in a richer
environment than CI's and was not reproducible. The other 2 are the
Pillow-gated EXIF assertions in `tests/test_media_egress_promise.py` — Pillow is
declared by no extra, so they skip loudly in CI's configuration and pass where
it is installed. The 8
failures are all in `tests/test_simplifier.py`'s LLM path, which patches
`privacy_shield.services.llm_runtime` — an upstream gateway this package does
not ship; they fail identically on the tip before this round's changes.
`openai` is installed here (and by CI's `tests` job) so
`tests/test_local_model_endpoint_guard.py`'s send-path assertions run rather
than skip.
`.github/workflows/ci.yml` deselects the 8 llm_runtime tests by name, so the
`tests` job runs 1051 passed, 8 deselected.

### The media paths' coverage, before and after

Measured with `coverage run --source src/privacy_shield/media -m pytest`:

```
                 before (521fec2)          after
media/__init__.py     0%                   100%
media/_tools.py       -  (did not exist)   100%
media/audio.py        0%   (308 stmts)      46%
media/image.py        0%   (321 stmts)      45%
media/metadata.py     0%   (256 stmts)      59%
media/video.py        0%   (203 stmts)      79%
media/ TOTAL          0%  (1093 stmts,      57%  (1298 stmts)
                           0 executed)
helpers/documents.py 18%                    31%
security_scanner.py  35% (import only)      57%
```

**`media/` was at 0.0% — not one of 1,093 statements executed by the whole
902-test suite.** `tests/test_privacy_shield_media_inputs.py`, the only file
named for media, replaces every processor with a `SimpleNamespace`, so it tests
`shield.py`'s plumbing and never imports `privacy_shield.media` at all; that is
why the modules did not even appear in a coverage report. The `security_scanner.py`
35% was its module-level pattern definitions running on import, with no
behavioural test anywhere.

The 43–57% remainder in `image.py` and `audio.py` is the engine-specific
bodies — the paddleocr, tesseract, doctr, mediapipe, faster-whisper, whisper
and vosk branches — which cannot execute without those packages. That is the
undeclared-dependency limit above, measured.

`tests/test_media_egress_promise.py` is the media counterpart of the leak
invariant: 69 tests, 67 of which run in CI's configuration. Its fixtures are
assembled from the format specifications as raw bytes (JPEG APP1/TIFF for EXIF
including a hand-built IFD1 thumbnail, ID3v2.3 for audio tags, ISO-BMFF `udta`
for the QuickTime location atom) rather than with Pillow's, mutagen's or
ffmpeg's writers, and its EXIF field vectors are tag names transcribed from
EXIF 2.32 rather than derived from `PII_EXIF_FIELDS`. That is deliberate: the
seventh time a check in this package shared an assumption with the code it
checked was an IBAN test that generated its vectors from the package's own
definition of an IBAN and therefore could not fail.

The leak invariant is its own CI job that `tests` waits on:
`tests/test_leak_invariant.py`, 428 tests including a 300-document generated
battery in each of the four privacy modes and a hypothesis property run. With
`hypothesis` absent the property half is skipped and the rest still runs.

**What the gate costs: about 3 seconds**, with every extra installed as
CI now installs them. Measured with `--durations`: 3.0s total, of which the
property run is 0.7s and each 300-document battery is 0.25s. Its oracle is deliberately quadratic — every subsequence of alphanumerics
within 136 characters of each position — and that is still cheap, because the
documents are short.

If it ever appears to hang, delete `.hypothesis/`. A stale example database
replays previously-failing inputs and re-shrinks them, which turned this same
2.9s run into several minutes here more than once; that directory is generated,
is in `.gitignore`, and should never be carried between checkouts.

Every privacy-shield core test file passes: regex-only, embeddings, semantic
wiring, overlay, local-model runtime, config, onnx contextual PII, media inputs,
review profiles, the optional external-enforcement seam
(`tests/test_privacy_gate_external_enforcement.py`), and the runner + CLI on synthetic
PII fixtures (`tests/test_privacy_shield_runner.py`, 13 tests).
