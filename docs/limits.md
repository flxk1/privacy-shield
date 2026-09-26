# Limits, gaps and test split

Moved out of the README (README canon, `repo-standards/STANDARDS.md` § README canon).

## Limits of the runner and CLI

- **The egress verdict is a source classification, not proof of anonymity.** The
  gate blocks LOCAL_ONLY / confidential / berufsgeheimnis / Art. 9 sources; a
  non-confidential PII document passes, whatever its overlay still holds. The
  gate leaves the overlay unscanned, so "cleared" stays short of a zero-residual
  certificate — and under `detect_only` (nothing redacts), or `block` when
  the redactor refuses (it does for an IBAN), the overlay is the untouched
  original while `egress_allowed` is True. That verdict is unchanged on purpose; the residual
  is held at serialisation instead (next entry).
- **A serialised report never carries an overlay a detected value is still in.**
  `to_dict()` (and so `scan --json`) used to omit the span `value`/`context` but
  return `overlay` as is, so `--json` printed verbatim emails and IBANs in 18 of
  80 cells (the 20 mode × redaction combinations over German, English, IBAN
  and email input) — every one under `detect_only` or `block`. `overlay` is
  now `null` whenever `DocumentScan.overlay_residual` is non-zero, and the omission is named in
  `overlay_withheld` rather than dropped silently; `--out` writes no
  `.overlay.txt` for such a document and the human output says it withheld one.
  `include_original=True` / `--include-original-values` still returns it.
  `anonymous_json` builds its overlay from anonymised JSON whatever the
  redaction mode, and no input in the matrix leaves it a residual. The residual
  is read per detected span: its `value` still in the overlay, or a `value`
  that is empty or is not the source at the span's offsets — the local-model
  layer records a hint as `value` with `end = start + 10`, so the redactor
  rewrites ten characters, not what the layer found. A value no layer found
  is not withheld and not counted, so this bounds the serialiser, not
  detection. It is read by substring, so it errs towards withholding: a
  detected `Berg` withholds the overlay of a text that also says `Bergbau`.
  Pinned by `tests/test_overlay_residual_boundary.py`.
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
  maximal sequence of identifier characters joined by runs of characters that are
  not alphanumeric at all or are modifier letters, interrupted by at most one
  line terminator.* That is
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
  `python-stdnum` installed and `PRIVACY_SHIELD_NATIONAL_COUNTRIES` set, 22
  check-digit validators across 21 EU countries are applied to token-level
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

  | | 0719c79 | round 19 | round 20 |
  |---|---|---|---|
  | false positives, 200 clean documents, all 27 countries | 75 | 61 | **62** |
  | `de` alone / `fr` alone / `it` alone | 0 / 0 / 1 | 0 / 0 / 0 | **0 / 0 / 0** |
  | countries that actually validate anything | 19 | 19 | **21** |

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

  **Eight country codes validated as configurable and detected nothing.**
  `cy`, `gr`, `hu`, `lu`, `lv`, `mt`, `pt` and `si` carried empty validator
  tuples, so `configured_countries(['pt'])` returned `('pt',)` without a word
  and the caller read an empty result as "no national numbers in this
  document". That is the `stdnum.at.svnr` defect in a different spelling,
  sitting in the same table — and `pt` joined the set in round 19 when
  `pt.nif` was dropped.

  Three of the eight were not limitations at all. `python-stdnum` ships a
  person number for Greece (`gr.amka`), Portugal (`pt.cc`) and Slovenia
  (`si.emso`), and none had been looked for, because the table was written from
  the EU country list rather than from what the library has. **Greece and
  Slovenia are now configured** (`gr.amka` costs 1 false positive on 200 clean
  documents and 1 on the 62-document set; `si.emso` costs 0).

  **Portugal is dropped on a measurement**, and this is the one place a
  validator was removed after round 19 said none would be: `stdnum.pt.cc`
  accepts a repeated digit at every one of the ten digits across every length
  from 12 to 20, twelve zeros included, so it matched a 15-digit IMEI and a
  contract number written in groups — 6 false positives on 200 documents. Every
  other configured validator accepts at most one or two repeated strings at a
  single length. A check that accepts all zeros is a format match, and
  `::test_no_configured_validator_accepts_a_string_of_zeros` now asks every
  validator that question rather than waiting for a corpus to reveal it.

  **A code with no validator is no longer configurable.** It is excluded and
  the reason is logged at WARNING — not debug, which is where the `at` defect
  lived for a round — so "configured" means "will be validated". The five that
  remain (`cy`, `hu`, `lu`, `lv`, `mt`) have nothing but VAT or company
  modules in `python-stdnum`, and a test reads that from the library rather
  than from a list kept here, so the day one of them gains a person number it
  fails and asks for a decision.

  **Still true: the layer is off by default, and the full-scope rate is about
  one spurious `[NATIONAL_ID]` per three documents.** Enable only the countries
  whose documents you actually scan, and measure on your own corpus before
  trusting any count here. Tested:
  `tests/test_national_ids.py::test_a_country_with_no_validator_is_not_configurable`,
  `::test_every_country_either_validates_or_says_why_not`,
  `::test_an_unvalidatable_country_has_nothing_but_company_identifiers`,
  `::test_no_configured_validator_accepts_a_string_of_zeros`.

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
  overlaps characters another validated identifier owns, **every piece of it
  nobody owns that is at least `MATERIAL_RESIDUE` characters long is claimed.**

  The union rule's price, measured not assumed: the whole IBAN is always
  covered and there are no split spans.

  **Forward:** a coincidental header-shaped window anywhere inside a
  letter-bearing BBAN passes mod-97 (~1 in 97 once such a window exists) and
  stretches the claimed span into following text, bounded by that window's
  own registered length - a few characters in a short sentence, 24 characters
  over three words in the pinned FR case. Pinned: MT, IE, BG, LV, RO, FR
  (`test_the_forward_overclaim_is_pinned_not_fixed`,
  `test_the_forward_overclaim_can_run_past_the_first_word`).

  **Backward:** for any country's IBAN, a header-shaped token right before it
  (e.g. `GB82`) forms a window with the IBAN's own opening characters and
  pulls the span's start back, about 1% of draws, measured on DE, AT, FI,
  NL, MT, IE, BG and FR. Not a letter-bearing-BBAN mechanism. Pinned: MT, DE
  (`test_the_overclaim_can_run_backward_from_a_preceding_header_shaped_token`).

  Measured, not pinned - per-IBAN forward rate in this package's own three
  test sentences: BG ~0.5%, IE ~0.3%, MT ~0.2–0.4%, RO <0.1%, LV ~0.01%.

  Kept deliberately: the over-claim never leaks and never leaves a
  validating window partially covered.

  Round 19 restricted that to windows sitting inside one unbroken group, and
  that was **a refusal wearing a precondition** — the very thing the sentence
  above says may never decide a redaction. A card written in four groups of
  four is not contiguous, so its remainder was never claimed:
  `Beleg BE84 6613 1860    4526    0181    5908    3012    Ende` egressed
  twelve of the card's sixteen digits, with the gate clean in all three modes
  and `is_safe_for_external_llm` reporting "No PII detected". Four groups of
  four is the `pdftotext` and hand-written shape this package exists for.

  Measured on 400 documents of each shape, generated from layouts rather than
  from the rule:

  | rule | grouped card leaking | contiguous card leaking | cost on 300 payment documents |
  |---|---|---|---|
  | refuse the window | 200/200 | 200/200 | 6 spans / 82 chars |
  | require contiguity (round 19) | 200/200 | 0/200 | 6 spans / 82 chars |
  | piece ≥ 13 | 200/200 | 200/200 | 61 spans / 1311 chars |
  | **piece ≥ 8** | **0/200** | **0/200** | **66 spans / 1350 chars** |
  | any piece at all | 0/200 | 0/200 | 117 spans / 1718 chars |

  **Eight is the gate's own `RESIDUE_RUN`**, shared deliberately and asserted
  equal by `tests/test_leak_invariant.py::test_the_detector_covers_down_to_this_files_own_materiality_floor`.
  That makes the two agree by construction: every piece the detector leaves is
  shorter than the shortest fragment the gate reports, so no decision taken in
  the detector can make the gate red. Thirteen — the length of the shortest
  card — fails the grouped case, because the remainder there is twelve.

  **The cost went up fivefold** and is recorded rather than softened: 6 spans
  over 82 characters became 66 over 1350 on the same 300 payment documents,
  about one over-redacted neighbour field in every five. Tested:
  `tests/test_leak_invariant.py::test_a_card_is_not_LABELLED_out_of_another_identifiers_digits`,
  `::test_a_grouped_card_under_a_coincidental_iban_claim`,
  `tests/test_identifier_runs.py::test_a_coincidental_iban_does_not_suppress_a_genuine_one`,
  `::test_a_genuine_card_under_a_coincidental_iban_claim_is_covered_whole`,
  `::test_covering_a_remainder_costs_this_much_beside_an_iban`.
- **A card SHAPE is kept without a checksum; an IBAN shape is not.** Demoting
  the Layer-1 patterns to candidate generators was measured both ways over 200
  documents each: the IBAN pattern's false positives fell sharply and the CARD
  pattern's did not move by a single span, while labelled cards carrying one
  transcription typo went from 3 in 200 unclaimed to 73. A single wrong digit
  always defeats Luhn — that is what Luhn is for — and it is the most ordinary
  defect in an OCR'd or hand-typed document. So a `credit_card` pattern match
  that no checksum accepts is kept at **MEDIUM** confidence with
  `checksum_validated=False`: redacted by default and ranked with the patterns
  rather than in front of them. The rank rule asks the FINDING whether a
  checksum stands behind it instead of asking its type.

  **It is filtered out at `min_confidence=HIGH` — as of round 20, and it was
  not before.** The paragraph here claimed it was, the claim was false, and it
  was corrected on public main. `min_confidence` was applied once, to the
  *pattern's* declared confidence, before any pass that can change it, so a
  finding demoted later escaped it and a scan at HIGH returned the card at
  `medium`. The filter now reads the confidence a finding ends up with, which
  makes the sentence true rather than trimming the sentence to fit. Both tests
  cited beside the old claim ran at `LOW`, which is why neither caught it; the
  one below runs at all three. Tested:
  `tests/test_privacy_shield_regex_only.py::test_a_labelled_card_with_one_transcription_typo_is_still_claimed`,
  `::test_a_card_shape_cannot_outrank_a_checksum`,
  `::test_min_confidence_reads_the_confidence_a_finding_ends_up_with`.
- **The gate's oracle claims overlapping windows rather than refusing them.**
  It used to refuse any Luhn-valid window overlapping a span already claimed as
  another validated identifier, on the reasoning that the same characters
  cannot be two identifiers. The reasoning is sound and it was answering the
  wrong question: identity decides a LABEL, coverage decides whether the
  product kept its promise, and an oracle that will not look at a window cannot
  say what remains of it. That refusal is what made the grouped-card leak above
  invisible to the gate as well as to the detector — the same shape as the
  defect the package was rejected for in round 9, relocated into the checker.
  The oracle now measures every Luhn-valid window for residue, and the
  detector's `MATERIAL_RESIDUE` floor is what keeps the two from disagreeing.
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
## The name layer, per language

`find_names(text)` applies the rules of every language a document evidences,
of all of them when it evidences none, and of German always in addition to
whatever else it evidences - German is the only language with independent
measurements and detection is a routing hint, so it may only ADD a language,
never drop German (`name_layer/detect.py::resolve`). `find_names(text, "en")`
applies one declared language exactly, with no addition - that isolation is
what the cross-language cost measurements below need. A language is one
module registering one `Ruleset` in `privacy_shield/name_layer/`, evidence is
per language, and the exclusions are the union over every registered
language plus the ISO 20275 legal forms — `name_layer/shared.py` states why
that split and not another. German's own signature-line filter
(`de._is_organisational`) draws on the ORGANISATIONAL and LEGAL_FORMS unions
only, never the TEMPORAL one - a month name is not a reason to refuse a
signature, and "Mai"/"Jan" are both German calendar abbreviations and German
given names.

**Two languages have rules. Twenty-two do not, and are `unmeasured`.**
`unmeasured` is not `unsupported`: an unrecognised or undeclared language is
offered every ruleset, so the structural positions that happen to transfer (an
`Attn:` line, a table column, a street or postcode line, a German or English
honorific) may still fire. Nobody has measured what that claims or misses in
Estonian, and this table says so rather than counting it as coverage.

| language | corpus | clean docs | FP spans | char loss | named docs | recall | precision |
|---|---|---|---|---|---|---|---|
| German (`de`) | in-repo, `tests/corpora_german.py` | 42 | 0 | 0.00% | 18 | 26/26 | 26/26 |
| German (`de`) | independent positions | — | — | — | 11 | 7/21 | 7/7 |
| English (`en`), through the dispatcher | in-repo, `tests/corpora_english.py` | 77 | 10 | 1.21% | 18 | 28/36 | 28/28 |
| English (`en`), through the dispatcher | independent positions | — | — | — | 11 | 10/21 | 10/10 |
| other 22 official languages | none | — | — | — | — | unmeasured | unmeasured |

English rules alone (no German addition, `en.find_names` directly) measure
24/36 and 7/21 - the ablation table in
`tests/test_name_layer_english.py` has the detail. The 4-name gap on the
named corpora (3 on the independent one) is German's GIVEN rule firing on the
label positions the withdrawn English probe would have covered, where the
label's value is also a German given name plus surname ("From: Sarah
Villanueva").

The English 77 clean documents are 12 development, 8 held out, 29 adversarial,
20 written against the probes and 8 written against the exclusions. The
held-out 8 stayed sealed while the rules were being shaped and then scored 0
false positives on first contact.

The German numbers are main's, unchanged: probe A is withdrawn there and its
English counterpart is withdrawn here, for the same reason - a label and a
colon are evidence that a VALUE follows, and the enumeration that decides
whether the value is a person fails OPEN. That withdrawal is the largest
single recall loss in English's OWN rules: 12 of 36 named occurrences and 6
of 21 independent ones, for no false positive measured on any of the 77
documents - German's always-on GIVEN rule recovers 4 and 3 of those
respectively (see the recall table above), by a different mechanism than the
withdrawn probe. It is withdrawn anyway, because German's identical probe was also
free on its own corpora and cost 18 false-positive spans on the first
independent corpus it met. The ten false positives are three named
classes — a proper noun used as an agent (`Charles Schwab`, `Thames Valley`),
a status word in a declared person column (`Not Allocated`, `Vacant`, which is
main's deliberate probe-D trade), and a member state's legal form standing
where a person stands (`Nordica Oy`, `Mediatech Kft`, `Lisboa Lda`, `Vilnius`,
`Praha`). Measured by `tests/test_name_layer_english.py`.

**The English numbers come from corpora written here, exactly like the German
0 above, so expect them to degrade against a corpus written elsewhere.** The
mechanism by which they will degrade is known and is not a mystery to be
discovered: an enumerated exclusion that is missing a member state's legal
form or an inflected variant. That mechanism is measured on purpose in
`tests/test_name_layer_enumeration_limit.py`, and it is 3 of 27 and 2 of 12
there - on top of the 2 above, and on documents this layer was built against,
so it is a floor and not a ceiling.

### Positions covered, per language

**German** (unchanged by this round): a salutation; after a title or address
form; the first name-shaped line after a closing formula; an addressee block
above a street or postcode or below a bare `An`; a known German given name
followed by a surname in prose; a value after a person-role label; a table cell
under a person-role column header.

**English** — a different design, not German with a swapped word list. German
capitalises every noun so capitalisation is not evidence there; English does
not, so capitalisation is the candidate generator and what it evidences is a
proper noun rather than a person:

- an honorific (`Dear Mr Ashcroft`, `Dear Professor Lindqvist`);
- a salutation with no honorific (`Dear Priya Raman`, `Hello Marta Kovacs`) —
  a position German does not have;
- the first name-shaped line after a closing formula, **one word being enough**
  (`Regards` / `Ben`), unlike German, which requires two;
- `Attn`, `FAO`, `c/o`, `For the attention of`, and a name-shaped line above a
  street line or a town-and-postcode line (UK, Irish and continental forms);
- a table cell under a column header that DECLARES a column of people, judged
  on shape alone once the header has said so (main's probe-D rule, in
  English);
- the **agency frame**: a document verb, then `by`, then the name (`prepared
  by`, `reviewed by`, `signed off by`, `audited by`), plus `contact`,
  `on behalf of`, `care of`.

**Positions English does NOT cover**, by name: a value after a person-role
label (`Caseworker: Ashcroft`, `CC: Ingrid Bauer`) - built, measured at 0 false
positives on 77 documents, and WITHDRAWN, because the enumeration that decides
whether a label's value is a person fails open and German's identical probe
cost 18 false positives on an independent corpus; a bare surname in prose with
no frame; a speaker attribution in minutes (`Wisniewski: The date cannot be
met.`); a name line under a participant list; a footnote citation (`See
Kowalczyk,`); `Name said` attribution; two people joined by `and` after an
agency frame (`prepared by Jane Elliott and Nils Berg` claims neither, because
`supplied by Marks and Spencer` is the same shape); a name with initials
(`J. Elliott`); a name with a particle (`van der Berg`). The first five were
built and measured; the option table with what each costs is in
`tests/test_name_layer_english.py`, and promoting one is the owner's decision.

**The irreducible English false positive**, and it is a class rather than two
words: a proper noun used as an agent that is not a person. `issued by Charles
Schwab` and `compiled by Thames Valley` are claimed, and nothing in the text
separates either from `issued by Charles Schneider`. A company named after a
person and a site used as an author need vocabulary to resolve, and vocabulary
is what the licence gate below refuses. Re-measured after the per-language split (dropping `"agency"` from
`en._ORDER` on a scratch copy): English's false positives on the 77-document
clean corpus halve, 10 to 5, and recall on the independent positions drops
from 7/21 to 4/21 counting English's rules alone, 10/21 to 8/21 for the
shipped dispatcher (German's always-on GIVEN rule keeps 8 that agency's
withdrawal would cost) — above German's own 7/21 either way. That switch is
the owner's.

### Why there is no NER model behind the `semantic` extra

A multilingual NER model was the obvious mechanism for twenty-four languages
and the evaluation rejected it. Licence is a hard gate, and every licence below
was read from the model's own metadata rather than remembered:

| candidate | EU coverage | licence (code / weights) | ONNX | size | verdict |
|---|---|---|---|---|---|
| XLM-R base/large, fine-tuned for NER | 23/24 official languages; **Maltese absent** from the card's language list | encoder MIT; **every multilingual NER head found is worse**: `Babelscape/wikineural-multilingual-ner` CC-BY-NC-SA-4.0, `Davlan/*-ner-hrl` AFL-3.0, `xlm-roberta-large-finetuned-conll03-english` **no licence declared** | yes | 709 MB–1.9 GB | **fails**: the NER heads are non-commercial, unlicensed, or CoNLL-2003-derived (Reuters, research-only) |
| GLiNER v0 (`urchade/gliner_multi`) | multilingual | **CC-BY-NC-4.0**, card says "Research purpose" | via export | 209 M params | **fails the gate** — the owner's suspicion confirmed from the card |
| GLiNER v2.1 (`urchade/gliner_multi-v2.1`) | multilingual (mDeBERTa-v3; its card lists only 6 EU languages, the 100-language claim is in the paper) | Apache-2.0 code, Apache-2.0 weights, training set `urchade/pile-mistral-v0.1` Apache-2.0 | ONNX exports exist but **`onnx-community/gliner_*` declare no licence** | **1.16 GB** weights | **clears the licence gate, fails on size and integration**: 1.16 GB cannot go in a wheel, and the span-decoding logic is GLiNER's own |
| spaCy per-language | 16/24 official languages. **No Maltese, Irish, Estonian, Bulgarian, Czech, Slovak, Hungarian, Latvian** | **not MIT across the board**: en/de/xx MIT, **el and it CC-BY-NC-SA-3.0**, ca/es/pl GPL-3.0, fr LGPL-LR, da/fi/hr/lt/nl/pt/ro/sl/sv CC-BY-SA-4.0 | no | ~15 MB per language | **fails**: two EU languages are non-commercial and the rest are per-language copyleft |
| Stanza | 12/24 official languages (no el, pt, ro, cs, sk, sl, hr, lv, lt, ga, mt, et) | code Apache-2.0; German and English default NER models are **CoNLL-2003-derived** | no | per language | **fails** on coverage and on training-corpus terms |
| Flair | `flair/ner-multi` covers 5 | code MIT; **`flair/ner-multi` declares no licence**, `flair/ner-english-large` is `flukes-nc-1.0` | no | large | **fails** |
| Microsoft Presidio | framework, not a model | MIT, core deps include spaCy | via its gliner extra | small | **does not answer the question**: Presidio is a recogniser framework whose person detection *is* one of the models above, so it inherits this table's licence problem rather than solving it |

So: **nothing clears licence, EU coverage, ONNX and size together.** The
package therefore ships a seam and no model — `name_layer/recogniser.py`,
in-process registration only, no download, no import from an environment
variable, and a registered recogniser is held to the same exclusion union as
the rules. Absent a registration the layer is the rule floor, which is the
documented degradation and is asserted by
`tests/test_name_layer_mechanism.py::test_with_no_recogniser_registered_the_layer_is_the_rule_floor`.

**The measurement that would refute the model route, stated in advance:** every
multilingual NER model above is trained on Wikipedia or newswire (WikiNER,
WikiNEuRal, CoNLL-2003, Pile-NER), and their published per-language F1 is
news-domain. Business correspondence — `Attn:` blocks, signature blocks,
tables, subject lines, letterheads — is out of distribution for all of them.
Evaluating one on Wikipedia-like text would inherit the model's own
distribution and report a number that does not survive contact with
correspondence, which is the failure this programme has repeated five times.
A per-language business-correspondence corpus, built by somebody who reads the
language, is the precondition for the model route — not an afterthought to it.

### Language detection is a routing hint, never a correctness condition

Declared by the caller when it knows (`find_names(text, "de")`), detected from
closed-class marker counts when it does not, and **when detection is
undecided the document is offered to every registered ruleset**. There is no
language-identification model and no vocabulary: being wrong costs a wider
union, not a missed name. A declared language with no ruleset in this package
also falls back to the union, so a caller cannot make the layer silent by
naming Finnish.

Mixed-language documents are therefore the normal path rather than a special
case, which matters because in EU correspondence they are. Measured:
`tests/test_name_layer_cross_language.py` runs each language's rules over the
other language's clean corpora — **English rules over 42 clean German
documents: 0 false-positive spans; German rules over 69 clean English
documents: 0** — and that zero is what the exclusion union buys. Before it,
the German signature rule claimed `Accounts Payable` under `Kind regards`,
because its closing formulae have always included the English ones.

### The enumeration limits, and the two mechanisms that were removed

- **A legal-form list cannot cover the EU by hand.** A 37-word list read
  `An: Nordica Oy` as a person. It was replaced with the EU rows of the ISO
  20275 Entity Legal Form code list (410 normalised abbreviations, 26 of 27
  member states, Cyprus not covered), and a six-character stem match was added
  so that `Automatische` refuses `Automatischer Rechnungslauf`. Together those
  took the measured failures from 7 of 27 and 5 of 12 to 3 of 27 and 2 of 12.
- **Both are now deleted, because the position they defended is gone.** With
  probe A withdrawn on main and its English counterpart withdrawn here, the
  same corpus measures **0 of 27 and 0 of 12** with neither mechanism present,
  and ablating them over 69 clean English and 42 clean German documents changed
  the false-positive count by zero in each direction. **The enumeration
  exposure was a property of the POSITION, not of the length of the list.**
  Recorded in `tests/test_name_layer_enumeration_limit.py`; restoring the label
  probe means restoring them with it.
- **What the ablation could not see, and the cost of the licence gate.** Not
  one of those 111 documents had a foreign legal form in a signature block.
  `Kind regards` / `Nordica Oy` is claimed now and was refused by the ISO
  table. `EN_CLEAN_ADVERSARIAL_FOREIGN` is that shape and it costs **6 false
  positives**; the table was not restored, because **GLEIF publishes the ISO
  20275 code list with no licence statement** and licence is a hard gate for
  data as well as code. There is no ISO 20275 package on PyPI — checked — so
  there is no maintained alternative either. **Owner decision:** verify the
  GLEIF terms and restore the table, or accept the six.
- **What remains and still earns its place:** the four word-list classes as the
  exclusion union. Ablated the same way, removing them takes English from 10
  false-positive spans to 32. Cost against names: 0 of 307 common member-state
  surnames are refused.

### A table's header is evidence about that table

The shared table probe held one `seen_header` flag over the whole document, so
the first table's header decided every later table's columns: a parts table
after a handler table had its product column claimed, and a handler table after
a parts table was not read at all. A table is now a run of adjacent pipe rows
and each carries its own header, in both languages
(`tests/test_name_layer_tables.py`).

### The validated identifier layer is language-independent — measured, not assumed

- All **27 member states** are present in `IBAN_LENGTHS`, and a generated
  mod-97-valid IBAN of the registered length for each is found inside German,
  English and Finnish prose. IBAN, card and e-mail detection also fires
  unchanged inside **Greek, Cyrillic, Maltese and mixed-script** sentences.
  `tests/test_identifier_layer_per_language.py`.
- **That was not a clean bill of health for this layer**, and is fixed by main's
  identifier repair rather than by this change: a word character glued to
  the front of a grouped card number **and** a line break inside it —
  `Ref4111 1111\n1111 1111` — used to clear the egress gate with "No PII
  detected" and the whole card left. Now caught, in every language this layer
  measures. Tested:
  `tests/test_identifier_layer_per_language.py::test_the_glued_and_wrapped_card_is_caught_now`,
  `::test_the_closed_leak_is_closed_in_every_language`.

## Existing libraries: what to consume, what to keep, measured

The instruction was to stop growing our own detection primitives where a
maintained library already does the job. Four candidates, each with its licence
read from the package itself and one comparison measured on the corpora this
package already has. Nothing below is adopted in code except the last line of
the schwifty row, which is a test-side change; the rest is a proposal.

| candidate | licence, read firsthand | measured against our corpora | verdict |
|---|---|---|---|
| **schwifty** | MIT (package metadata + classifier) | our IBAN detector finds **135 of 135** schwifty-generated IBANs, 5 per member state, in three languages. Conversely schwifty **rejects 7 of 27** IBANs this package's own test arithmetic used to generate | **adopt as the ORACLE, not as the table** — done, in the tests |
| **python-stdnum** | **LGPL-2.1-or-later** (module header, verbatim) | 27 EU national-identifier validators load. **0 false positives** over 951 tokens (645 distinct) from 119 clean documents; 8 of 8 real identifiers validated by the right scheme. Our layer currently reads a German VAT number as an IBAN | **adopt behind an optional extra**, with two conditions below |
| **libpostal** | MIT code; model data **1.8–2.2 GB** from S3; training data "various licenses, mostly CC-BY" plus OpenStreetMap (ODbL) | not measured | **reject**: it parses addresses, and the addressee rule needs to know whether a LINE IS ONE, which parsing does not answer. 2 GB and a C build for a question we are not asking |
| **Microsoft Presidio** | MIT (analyzer and anonymizer); its person detection needs spaCy, and **only en, de and xx are MIT** — el and it are CC-BY-NC-SA-3.0, ca/es/pl GPL-3.0 | see the two tables below | **consume the ARCHITECTURE, not the detectors** |

### Presidio versus this package, on the same corpora

Person detection, Presidio + spaCy `en_core_web_sm` / `de_core_news_sm` (both
MIT, and the only two EU languages whose spaCy models are):

| | clean docs | FP spans | char loss | named recall | independent recall |
|---|---|---|---|---|---|
| German, ours | 42 | **0** | 0.00% | 26/26 | 7/21 |
| German, Presidio | 42 | 10 | 1.63% | 20/26 | **14/21** |
| English, ours (through the dispatcher) | 77 | **10** | 1.21% | 28/36 | 10/21 |
| English, Presidio | 77 | 22 | 3.50% | **33/36** | **17/21** |

**Presidio doubles the recall and doubles-to-triples the false positives.**
Its false positives are the classes these rules were built to refuse:
`Order Confirmation`, `Change Request` and `Betreff` (headings), `Milton
Keynes`, `Avon`, `Muenchen Sued` and `Praha` (places), `Madam`, `Chair`,
`Menge`, `Dichtungsring`, and spans that run across line breaks
(`Manchester North\nMilton Keynes\nStratford`) or keep a table cell's padding.
For a layer whose output is the overlay a cloud model receives, a multi-line
span is over-deletion of three lines.

Identifier detection, same corpora, the oracle being schwifty rather than
either implementation:

| | schwifty-generated IBANs (135) | extraction-artefact leak shapes (6) | FP on 119 clean docs |
|---|---|---|---|
| ours | **135/135** | **6/6** | 0 |
| Presidio | 85/135 — misses AT, BE, CZ, EE, ES, LT, LU, RO, SE, SK entirely | **0/6** | 0 |

Presidio catches a plain sixteen-digit card and **none** of the shapes this
programme's entire leak history is about: a word character glued to the front,
a line break inside, letter-spaced `pdftotext` output, a glued IBAN. On
mod-97-valid strings whose BBAN structure is invalid, ours claims all 27 and
Presidio 12 — for an egress gate, claiming them is fail-closed and refusing
them is a leak.

### The proposal, in order

1. **schwifty as the IBAN oracle in the tests — done.** Not as the table:
   `IBAN_LENGTHS` must keep working with `dependencies = []`, and schwifty's
   structure awareness would make detection fail OPEN on a mod-97-valid string
   with an invalid BBAN, which is the wrong direction for a gate. What it
   replaces is this package's own IBAN arithmetic in the test corpus —
   `tests/test_identifier_layer_per_language.py::test_our_own_iban_arithmetic_was_wrong_and_this_is_how_we_know`
   records the seven member states where that arithmetic produced strings that
   are not IBANs, and the per-country tests now SKIP loudly without schwifty
   rather than falling back to it.
2. **python-stdnum behind a new optional extra, for national identifiers.**
   0 false positives measured, 27 EU schemes, and it is the EU coverage we
   would otherwise write by hand country by country. Two conditions, neither
   optional:
   - **It needs a TOKEN-level candidate pass, which this package does not
     have.** `identifier_runs` yields one maximal run per document
     (`Rechnung2026004871UStIdNrDE136695976Gesamtbetrag134900EUR`) because it
     exists to defeat extraction artefacts. stdnum's validators never see a
     candidate they could accept. That is the integration work, and it is the
     reason the first false-positive measurement of stdnum in this session
     read 0 while testing nothing.
   - **Country scoping.** `111222333` is a valid Dutch BSN, a valid Czech
     birth number and a valid Slovak one. Validating against 27 schemes at
     once turns one number into three identifiers.
3. **Presidio's operator model and overlap resolution, as a reference to copy
   from rather than a dependency** — replace/redact/hash/encrypt as named
   operators is a better shape than this package's redactor, and it is MIT, so
   the design can be read. Adopting the package would mean taking spaCy into
   the dependency tree for person detection that is measurably worse on
   precision in both measured languages, and identifier detection that misses
   every artefact shape.
4. **Not libpostal.**

### Which candidate gives us an oracle we could not have written our own blindness into

**schwifty, and it already has.** The leak gate has now shared an assumption
with the detector six times; the seventh instance was found in this session
and it was in a TEST, not in the detector: 27 per-country IBANs generated by
this package's own definition of an IBAN (registered length, mod-97) and
therefore incapable of failing. schwifty implements the BBAN structure per
country from the ISO 13616 registry, rejected seven of them, and our detector
still finds all 135 of its own generated ones — so the detector is fine and
the *test* was the blind one. python-stdnum is the same kind of asset for
national identifiers: 27 schemes whose check digits nobody here computed.

Presidio is NOT that asset, because its recognizers are regexes with the same
authorship risk as ours and are measurably weaker on the shapes we care about.
Its value is architectural, and architecture cannot be an oracle.

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
- **An identifier character is a decimal digit of any script, or an
  alphanumeric that is compatibility-equal to one ASCII letter.** ASCII used
  to be the finding rule, and `Karte ４１１１ １１１１ １１１１ １１１１` went
  out as `Karte [PHONE] １１１１` in all three egress modes, egress allowed.
  Runs now fold each character to the ASCII one it stands for, one for one,
  so offsets still index the text: full-width, Arabic-Indic, Devanagari, Thai
  and every other Unicode `Nd` digit, full-width Latin letters, and a card of
  mixed widths. A symbol is not folded even when NFKC spells it as a letter
  (a circled or squared letter joins two groups), a modifier letter joins
  (the katakana `ー` is typed as the dash in Japanese numbers), and circled,
  superscript and Hanzi numerals are not decimal digits. The detector and the
  gate hold the same definition. Invisible characters (Unicode `Cf` — soft
  hyphen, zero-width space, BOM) are removed first and never break a run.
  Tested:
  `tests/test_leak_invariant.py::test_a_card_in_non_ascii_digits_is_a_card`,
  `::test_a_full_width_iban_is_an_iban`,
  `::test_a_card_of_mixed_widths_is_one_card`,
  `::test_a_symbol_between_groups_joins_them`,
  `::test_the_gate_sees_full_width_residue`,
  `::test_the_gate_sees_full_width_iban_residue`,
  `::test_a_digit_is_a_decimal_digit_on_both_sides`,
  `::test_release_gate_property_in_other_digits`.
- **Non-Latin text now over-redacts at the ASCII rate.** A digit is a digit
  in any script, so a run of numbers that happens to pass Luhn is claimed
  whatever it is written in. Measured, not pinned, on realistic Japanese
  lines: postcodes, phone numbers, prices and prose 0%; date ranges such as
  `２００５/９/２２～２０２２/３/１５` about 25%, as they are when written in
  ASCII.
- **An e-mail address is read through the same fold, plus its punctuation.**
  `erika＠example.com`, a fully full-width address, a full-width domain or dot,
  and the small `﹫` are all addresses; each went out with pii_detected False
  when the finder expanded only around an ASCII `@`. Digits and letters fold
  as in a run; every character NFKC reads as `@ . _ % + -` reads as that; and
  the ideographic full stops `。` and `｡`, which RFC 3490 accepts as label
  dots, read as `.` - but only right of the `@`, and only when the domain has
  no reading without them, because `。` is also how a Japanese or Chinese
  sentence ends. Read everywhere, it claimed the sentence before an address as
  its local part and `。Thanks` after it as a top-level domain. A letter with no ASCII form - an umlaut in a local part -
  stays itself, as RFC 6531 allows. A `＠` alone does not make an address
  (`5＠3.50`, `りんご3個＠100円`). The validators read the same fold, so a
  finding is never rejected by its own validator for its width. Tested:
  `tests/test_leak_invariant.py::test_an_address_written_in_full_width_is_an_address`,
  `::test_the_at_signs_are_every_character_nfkc_reads_as_at`,
  `::test_a_sentence_ending_before_or_after_an_address_stays`,
  `::test_an_address_is_reported_as_it_was_written`,
  `::test_the_gate_sees_a_full_width_address`,
  `::test_the_gate_sees_a_full_width_local_part_left_behind`,
  `::test_the_gate_sees_an_identifier_that_changed_width_on_the_way_out`,
  `::test_a_full_width_at_is_not_an_address_by_itself`,
  `tests/test_privacy_shield_regex_only.py::test_no_finding_of_a_validated_type_fails_its_own_validator`.
- **An address is read through combining marks and invisible characters.**
  Invisible characters (Unicode `Cf` - zero-width space, soft hyphen, word
  joiner, bidi controls) and combining marks (`M*`, spacing marks included)
  are not there, anywhere in the address; a Latin letter with a diacritic
  reads as its base letter; a character NFKC reads as one ASCII letter or
  digit (superscript `ⁱ`, modifier `ᵉ`, ordinal `ª`, circled `ⓔ`) reads as
  that; and a Latin letter with none of these (`ß`, `ø`, `ł`, `æ`) reads as
  a letter, since only the shape is judged and the claim is cut from the
  original. So an address in decomposed Unicode (NFD, as macOS file names and
  much copied text are) is one address, and so is a Latin-script
  internationalised domain in either normal form (`erika@müller.de`,
  `m.weiß@straße.de`). NFD `josé@…` and `erika<U+200B>@…` went out whole, NFD
  `René.Müller＠…` kept `René.Mü`, `eri<U+00AD>ka@…` kept `eri`, and
  `erika@müller.de` and `erika@straße.de` were not found. The gate reads addresses the same way.
  Tested:
  `tests/test_leak_invariant.py::test_an_address_with_marks_or_invisibles_is_claimed_whole`,
  `::test_the_gate_sees_an_address_with_marks_or_invisibles`,
  `::test_a_local_part_with_a_spacing_mark_is_claimed_whole`,
  `::test_the_gate_sees_a_decomposed_local_part_left_behind`,
  `tests/test_privacy_shield_regex_only.py::test_no_finding_of_a_validated_type_fails_its_own_validator`.
- **Two addresses run together are both claimed.** The first domain runs on
  into the second local part, with nothing or only an invisible character
  between them; the claims overlap and the redaction covers both. Clipping
  the second claim at the end of the first left `@firma.de` in the overlay.
  Tested: `tests/test_leak_invariant.py::test_two_addresses_run_together_are_both_claimed`.
- **A zero-width space does not separate a word from an address.** Read
  through, `Hallo<U+200B>erika@…` claims `Hallo` with the local part and
  `…example.com<U+200B>Sie` claims `Sie` with the top-level domain - the
  over-redaction a text that separates words with zero-width spaces (Thai,
  some CJK web copy) pays, as a glued word already does. Pinned by
  `tests/test_leak_invariant.py::test_a_word_before_a_zero_width_space_goes_with_the_address`.
- **Addresses not found, in any width.** An internationalised domain in a
  non-Latin script (`erika@例え.jp` rather than its punycode); an address
  wrapped across a line; an address written
  backwards under a right-to-left override. The gate shares these
  blind spots, and it reports a left-behind local part only when the whole
  local part survives. Pinned by
  `tests/test_leak_invariant.py::test_an_address_the_finder_cannot_read_is_a_documented_limit`,
  `::test_the_gate_misses_a_partly_surviving_local_part`.
- **Not found: an IBAN whose country code is in look-alike Cyrillic letters
  (`ДЕ89…`).** A country code is two Latin letters; `Д` is not one in any
  width. Pinned by
  `tests/test_leak_invariant.py::test_a_cyrillic_country_code_is_a_documented_limit`.
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
- **An unavailable channel is visible, and it counts against the verdict.**
  Each missing channel records a per-document error prefixed
  `media_channel_unavailable:` — the same mechanism the folder walk uses for an
  undecodable binary, above — and surfaces as `DocumentScan.scan_complete =
  False`, `DocumentScan.incomplete_channels`,
  `ScanReport.incomplete_documents` and **`ScanReport.all_allowed = False`**.
  The folder walk had already settled the question for the other kind of
  incompleteness: completeness is part of the verdict, because "every document
  is cleared" cannot be asserted about documents nobody read. A partly-read
  document is the same assertion about the same nothing, and a consumer
  reading the documented aggregate was shipping a geotagged video no channel
  had opened.
  The per-document `egress_allowed` is deliberately **unchanged**: it answers
  a different question — the gate's verdict on source classification — and is
  documented as answering it. Read `scan_complete` for the other one.
  **Blast radius, measured:** `DEFAULT_EXTENSIONS` carries no media extension,
  so an ordinary folder scan never reaches a media file and its verdict does
  not move. The rule bites where media is actually scanned — a file passed
  directly, or `--all-files` / `extensions=None`. Pinned by
  `tests/test_media_egress_promise.py::test_the_default_text_walk_is_not_affected_by_the_completeness_rule`.
  Note what this means in practice: no OCR or STT engine is installable from
  any declared extra, so in the shipped configuration **every image and every
  audio file is permanently incomplete** and a folder scanned with
  `--all-files` will not report `all_allowed`. That is the honest answer —
  nothing read them — and it is the cost of the rule.
- **Face detection works at the declared floor, but only just.** `[extract]`
  now pins `opencv-python-headless>=4.8,<5`. The cap is load-bearing: opencv
  5.0 ships **no Haar cascade XML**, so with an uncapped floor the fallback
  detector stopped existing on a transitive upgrade and every face went
  undetected. With `mediapipe` absent the Haar cascade is the only detector
  there is.
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
  searches the output for each value the input carried, in UTF-8, UTF-16-BE
  and Latin-1, over the raw bytes **and over the decompressed contents** — PDF
  object definitions, PDF streams, PDF embedded files, PNG `zTXt`/`iTXt`
  chunks. The decompression matters: a PDF's content lives in deflated
  streams, so a raw scan of one reads as clean over anything inside it, which
  is not "reading the bytes" in any sense the leak gate would recognise.
  Decompression is bounded at 64 MB and 4,096 objects, so a crafted file
  cannot turn verification into a decompression bomb.
  Three consequences. First, the PyMuPDF path is correct: `set_metadata({})`
  clears only the DocInfo dictionary, the XMP packet holds the same author and
  title, and a default save keeps the superseded objects, so the author's name
  stayed recoverable from a file the function had returned True about.
  Second, the check **deliberately over-refuses**: a metadata value that also
  appears in the page's visible text cannot be removed by a metadata strip,
  and `strip_metadata` returns False rather than claim it is gone. Fail-closed
  wins, as with the digit-run over-redaction above. Values shorter than six
  characters are not searched, because they collide with ordinary binary
  content. Third, the verification skips the `File:`, `System:` and
  `ExifTool:` namespaces, which are facts about the file's place on this
  filesystem rather than anything stored in it — see below.
- **exiftool is never used to strip a PDF, because it cannot.**
  `exiftool -all=` on a PDF is an *incremental update*: it appends a revision
  marking the tags deleted and leaves the original DocInfo object in the file,
  so the output is LARGER than the input and exiftool itself prints
  `Warning: [minor] ExifTool PDF edits are reversible. Deleted tags may be
  recovered!`. Both exiftool and PyMuPDF then re-read that output as clean, so
  every reader-based check passes while the author's name is plainly in the
  bytes — the same shape as the PyMuPDF `garbage=0` defect, in the other
  backend. PDF goes straight to the rewriting path. Measured and pinned by
  `::test_a_pdf_is_never_stripped_with_exiftool_because_that_is_reversible`,
  which first asserts that exiftool still behaves this way, so the rule
  becomes a failing test rather than a silent no-op if that ever changes.
- **Filesystem timestamps are not metadata, and counting them made
  `strip_metadata` inert.** exiftool's `-G` output always carries
  `File:FileModifyDate`, `File:FileAccessDate` and `File:FileInodeChangeDate`.
  The substring rule in `_classify_pii_type` reads every one as a `datetime`
  finding, and they cannot be stripped — they are not in the file, and writing
  the output re-creates them. Verification that counted them could never
  succeed, so **with exiftool installed `strip_metadata()` returned False for
  every file of every type**, having correctly removed the author. It failed
  closed, so it was never a leak; the function was simply inert in the one
  configuration it is meant for. `MetadataExtractor.extract()` still reports
  those fields — they are readable facts — so `MetadataResult.has_pii` is True
  for essentially every file when exiftool is present. Only the verification
  skips them.
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

### Three PII channels that do not exist yet

These are places identifying data sits where **no channel looks**. Each is a
new channel rather than a repair, so each is scoped and costed here and pinned
by a test that fails the day it is built. Measured, not assumed.

**1. A PDF's embedded attachments — the worst of the three, because it looks
complete.** A PDF with innocuous page text and PII only in an attached
`zeugenliste.txt` scans to `pii_detected=False, findings={}, errors=[],
egress_allowed=True` **and `scan_complete=True`**. Nothing anywhere says the
file was partly read. *Scope:* enumerate `doc.embfile_count()`, extract each
payload, dispatch it back through the pipeline by type. *Cost:* recursion —
an attachment can be a PDF containing an attachment, so it needs a depth
limit, a total-size budget and a cycle guard, and the same decompression-bomb
bound the verification already carries. It also changes what an overlay *is*
for a container document: either the attachment's redacted text joins the
parent's overlay, or the result grows a per-attachment structure. That is an
API decision, not an implementation detail. *Interim:* the cheap half is a
detector — flag `embedded_payload` on presence, as cover art already is —
which costs nothing and would at least stop the file reading as complete.
Pinned by `::test_a_pdf_embedded_attachment_is_an_undetected_channel`.

**2. Image XMP and IPTC.** `image.py` reads EXIF through Pillow and nothing
else. A JPEG whose identifying data is in `XMP:Creator`, `IPTC:By-line` and
`XMP-exif:GPSLatitude/Longitude` — which is what Lightroom and Photoshop
write, and increasingly what phones write alongside EXIF — has
`pii_fields == []`. **`MetadataExtractor` reads all of those from the same
bytes via exiftool**: two readers of one file, disagreeing about what is in
it, and the pipeline uses the blind one. *Scope:* route `ImageProcessor`
through `MetadataExtractor` for the non-EXIF namespaces, or add an XMP packet
parser. *Cost:* the exiftool route makes a binary this package does not
declare the difference between finding a photographer's name and not, so it
needs its own `media_channel_unavailable: xmp_iptc` marker — which, under the
completeness rule above, makes **every image incomplete until exiftool is
installed**. That is the real price and it is the owner's call. A pure-Python
XMP reader (the packet is XML between `<?xpacket` markers) avoids the
dependency for XMP but not for IPTC IIM, which is binary. Pinned by
`::test_image_xmp_and_iptc_are_an_undetected_channel`.

**3. Video soft subtitle tracks.** A `mov_text` track carrying
`Zeugin Erika Mustermann, IBAN …` gives `full_transcript=''` and
`all_visual_text=''`. It does not leak through redaction — ffmpeg's stream
selection drops it — but it is invisible to detection, which is the half this
package is for. *Scope:* `ffmpeg -map 0:s -f webvtt -` per subtitle stream,
feed the text through the scanner like a transcript. *Cost:* one more ffmpeg
invocation per subtitle stream, bounded by the existing timeout; the text is
attacker-controlled and goes straight to the scanner, which is already true
of every transcript. This is the cheapest of the three and the most contained.
Pinned by `::test_a_video_subtitle_track_is_an_undetected_channel`.

**Chapter titles were the fourth and are fixed**, because they were a widening
of the container-tag channel rather than a new one: ffprobe reports them given
`-show_chapters`, and they flow through `tag_pii_type` like any other tag. A
recording chaptered `Vernehmung Mustermann` now reports `title` in
`pii_fields`; it previously did not appear even in `raw_tags`.

**`de._is_organisational`'s restricted union (ORGANISATIONAL + LEGAL_FORMS,
not TEMPORAL) is not a strict superset of main's own check on every input -
decided by the owner (Felix, 2026-09-24): the restricted union is kept.** An
adversarial differential of 3,724 generated inputs finds 30, and they are NOT
all one shape:

  - **25 are the accepted shape** - a given name from `{Karl-Heinz, Mai}`
    followed by an ORGANISATIONAL-union word standing in as a fake surname,
    from `{Finance, Sales, Office, Legal, Payable}` - where main's simpler
    check (German's own ORGANISATIONAL table alone; German has no word for
    any of those five) claims the two-word string as a person and this
    layer, correctly refusing an organisational word as a surname, does not.
    The 25: `Karl-Heinz Finance` (×4, one per template it recurs in),
    `Karl-Heinz Sales` (×4), `Karl-Heinz Office` (×2), `Karl-Heinz Payable`
    (×2), `Karl-Heinz Legal` (×1), `Mai Finance` (×2), `Mai Sales` (×4),
    `Mai Office` (×2), `Mai Payable` (×1), `Mai Legal` (×3).
  - **5 are CORRECTED main false positives** - real people this layer no
    longer claims because they never were people, which is the union
    working as designed, not a differential loss: `Accounts Payable` (×3 -
    the bare "Kind regards" form, the "...\nShared Service Centre\nNorthern
    Operations" form, and the "Mit freundlichen Gruessen" form),
    `Customer Services` (×1, the `EN_CLEAN_DEV[0]` corpus document),
    `Nordstern Limited` (×1).

  Matching main exactly (dropping the ORGANISATIONAL/LEGAL_FORMS union too)
  closes the 25 but reopens the 5 - moving the measured cost from 10 FP /
  1.21% to 12 FP / 1.61% on the real 77-document English corpus and failing
  7 tests already in this suite. Tested (both directions, so a future change
  to either side is visible here):
  `tests/test_name_layer_enumeration_limit.py::test_a_temporal_given_name_signs_a_letter`,
  `tests/test_name_layer_enumeration_limit.py::test_english_organisational_and_legal_form_words_still_refuse_a_german_signature`;
  the 30-input differential itself is not in this repository's suite - it is
  adversarially generated, not corpus-measured - see commit `a4c28fd` for the
  full list and the numbers behind both options.

### Recorded as open, already closed

**The Luhn-window residue the name-layer change reported against `521fec2`
was already closed on main.** In STANDARD mode at `521fec2`:

```
input   'UUID 550e8400-e29b-41d4-a716-446655440000 DE89370400440532013000 00 00 7'
overlay 'UUID 550e8400-e29b-41d4-a716-446655440000 [IBAN] 00 00 7'
leak    validated credit_card left 8 of 15 characters of residue in overlay
```

The overlay is the same on main today and the gate is clean. The "residue" was
the gate compacting the overlay across the placeholder, which joined three of
the UUID's trailing zeros to the `00 00 7` after `[IBAN]` as `00000007`; no
eight characters of the window stand together in the overlay. Main closed it in
2.0.0, before the name-layer change merged: `d79dc72` silenced it by having the
gate refuse windows that overlap another identifier, a refusal that hid a
genuine card and was removed in `52a3b25`; `b652788` closed it for good, since
the gate never compacts across a placeholder. The input is pinned in all three
egress modes, and restoring whole-overlay compaction fails it in each:
`tests/test_leak_invariant.py::test_a_card_is_not_LABELLED_out_of_another_identifiers_digits`
(`uuid_then_iban_then_trailing_digits`).

## Test split

### What CI's green covers for media, and what it does not

**CI installs no media binary at all.** There is no `exiftool`, no `ffmpeg`,
no `ffprobe` and no `mutagen` on a CI runner, so every `_check_exiftool()` is
False, every `tool_available()` is False and every `mutagen` import fails.
The suite CI certifies therefore exercises the media paths **not taken**.

This is not a hypothetical. Two tests in
`tests/test_media_egress_promise.py` were green on the runner and red the
moment the tools they were about existed:

```
same commit, same extras, from-scratch install, only PATH differs

no media binaries (CI's shape)  ->  8 failed / 1107 passed
+ exiftool                      ->  9 failed  (strip_metadata on a PDF)
+ exiftool + mutagen            -> 10 failed  (audio container tags)
```

Both were passing because the code's preferred backend was absent — a test
that never reaches its subject, which is the same defect as a test that
monkeypatches its subject away. Both are fixed; the suite is now **8 failed
in every one of the five configurations** below, and the skip count is what
moves:

```
                                  failed  passed  skipped
no media binaries (CI's shape)         8    1165       10
+ exiftool                             8    1169        6
+ exiftool + mutagen                   8    1169        6
+ exiftool + ffmpeg                    8    1172        3
everything                             8    1172        3
```

The two columns that matter are **failed** and **skipped**: the pass count
moves with every other workstream, the failure count must not move with the
tool inventory, and the skips name what is not covered.

The skips are the signal: they name, one per line under `-rs`, the paths CI's
green does not cover. To cover them:

```
brew install exiftool ffmpeg && pip install mutagen && pytest -rs
```

Measured on python 3.12 with `.[dev,semantic,extract,openai]`. The 8
`tests/test_simplifier.py` LLM-path failures these columns used to carry are gone;
see below.

All other numbers below are measured in **CI's environment**, which is
`pip install ".[dev,semantic,extract,openai]"` and nothing else — notably
**without `httpx`**, which is in no extra and which CI does not install:

```
python3 -m pytest -q      # python 3.12, .[dev,semantic,extract,openai]
1165 passed, 8 failed, 10 skipped     # BEFORE the llm_runtime fixture, for reference
```

That run is kept as the before. The 8 failures are fixed, so the counts above are
stale and have to be re-measured in CI's environment, which is not reproducible
here — the number below was measured with `.[dev]` plus numpy and pyyaml, a
different extras set, so it is not comparable column to column:

```
python3 -m pytest -q      # python 3.12, .[dev] + numpy + pyyaml
1249 passed, 17 skipped
```

`--collect-only` reports 1182 items; the run above reports 1183 outcomes,
because two of the skips are module-level `importorskip` skips rather than
collected items. The same numbers on python 3.14, CI's other matrix leg.

The per-language name layer, merged onto this, added 165 tests of its own:
`tests/test_identifier_layer_per_language.py` (68 - one per member state, per
script, and the record of the IBAN arithmetic that was wrong),
`tests/test_name_layer_english.py` (44),
`tests/test_name_layer_mechanism.py` (24, including seven pathological-input
cases: the English word shape has a quantifier inside a quantifier and this
layer reads documents nobody here wrote),
`tests/test_name_layer_cross_language.py` (14),
`tests/test_name_layer_enumeration_limit.py` (8) and
`tests/test_name_layer_tables.py` (7). Of those, 33 SKIP without `schwifty`:
the per-country IBAN corpus is generated by schwifty on purpose and must not
fall back to this package's own arithmetic. See "Measured after the merge"
below for the combined total. Two of the 10 skips above are the `httpx`
transport assertions in
`tests/test_proxy_transport_guard.py` and
`tests/test_privacy_shield_embeddings.py`; they do not run in CI either, and
a previously reported "886 passed / 8 failed" was measured in a richer
environment than CI's and was not reproducible. **The other 8 are the media
backends CI does not install** — exiftool, ffmpeg/ffprobe, mutagen — and they
are listed one per line by `pytest -rs`. That list is the honest statement of
what CI's green does not cover; see the matrix at the top of this section. The 8
failures that used to sit in `tests/test_simplifier.py`'s LLM path are fixed. They
patched `privacy_shield.services.llm_runtime` — an upstream gateway this package
does not ship and never did — and six of them an even older
`privacy_shield.runtime.llm_gateway`; `mock.patch` cannot resolve a module that is
not importable, so all eight failed at setup and the branches they name were never
executed. They now inject a stand-in module, so those branches run.
`simplify_response*` still degrades to the unchanged response at runtime when the
gateway is absent, which is every install of this package, and
`test_the_gateway_really_is_absent_from_the_distribution` holds that premise: it
fails if the gateway ever ships, which is when these tests should patch it instead.
`openai` is installed here (and by CI's `tests` job) so
`tests/test_local_model_endpoint_guard.py`'s send-path assertions run rather
than skip.
`.github/workflows/ci.yml` no longer deselects them: the list of 8 names it
carried is gone, and the `tests` job runs the whole suite.

### The media paths' coverage, before and after

Measured with `coverage run --source src/privacy_shield/media -m pytest`:

```
                 before (521fec2)   after, CI's shape   after, all backends
media/__init__.py     0%                  100%                 100%
media/_tools.py       - (did not exist)    88%                  88%
media/audio.py        0%  (308 stmts)      47%                  59%
media/image.py        0%  (321 stmts)      57%                  57%
media/metadata.py     0%  (256 stmts)      62%                  57%
media/video.py        0%  (203 stmts)      79%                  83%
media/ TOTAL          0%  (1093 stmts,     61%                  62%  (1384 stmts)
                           0 executed)
helpers/documents.py 18%                                        31%
runner.py             -                                         95%
security_scanner.py  35% (import only)                          57%
```

The two right-hand columns are the same commit under two PATHs — the point of
the section above. Installing exiftool, ffmpeg and mutagen moves media
coverage by a point or two - in different directions per module, since a
present backend takes a different branch - and the *failures* not at all,
which is the property
that was missing before: the suite used to change its verdict when the tools
appeared.

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
invariant: 84 tests, 76 of which run in CI's configuration; the other 8
require a media backend and skip loudly without it. Its fixtures are
assembled from the format specifications as raw bytes (JPEG APP1/TIFF for EXIF
including a hand-built IFD1 thumbnail, ID3v2.3 for audio tags, ISO-BMFF `udta`
for the QuickTime location atom) rather than with Pillow's, mutagen's or
ffmpeg's writers, and its EXIF field vectors are tag names transcribed from
EXIF 2.32 rather than derived from `PII_EXIF_FIELDS`. That is deliberate: the
seventh time a check in this package shared an assumption with the code it
checked was an IBAN test that generated its vectors from the package's own
definition of an IBAN and therefore could not fail.

### Measured after the merge

The counts above are two separate measurements - main's, and the
per-language split's own - taken before the two histories were combined.
The combined suite's pass/fail/skip counts, measured once in one
environment after the merge, are recorded in the release notes for the
version that ships this change rather than duplicated here; this section
exists so that number has a named home instead of silently becoming a third,
uncombined count.

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

## Loomground: what was measured, what was mapped, what was not

This section records a measurement so the next round starts from it rather than
repeating it. Nothing here is installed by default; the base package keeps
`dependencies = []` and every plane is optional.

### Mapped: the national-number table has a freshness verdict

`national.PERSON_NUMBER_MODULES` is pinned to a `python-stdnum` release and
checked against the installed library
(`privacy_shield/freshness.py`, `tests/test_national_table_freshness.py`).
Every validator the library ships for a country this layer declares is either
looked for or carries a written reason in `freshness.REVIEWED_UNUSED`; an
unreviewed one fails the suite. Measured at pin 2.2: no dead module paths, six
countries admitted with no validator at all (`cy hu lu lv mt pt`, already loud
at runtime), and eight shipped validators deliberately not used.

`norm-freshness` turns the pin and the observation into a verdict and is
optional — without it the staleness check still runs and the verdict is simply
not offered. What crosses into the plane is a rule id, two opaque version
strings and a change kind. Which modules count as a person-number validator is
decided in `freshness.PERSON_NUMBER_BASENAMES` and stays here: the plane never
learns what a national identification number is.

The IBAN table was deliberately left alone. `tests/test_iban_registry.py`
already checks it against `schwifty` and it is current; mapping its loud
failure-when-schwifty-is-absent onto a softer verdict would weaken a guard that
is correctly loud today.

### Not built, and worth building: naming which term took a scan to zero

`ScanReport.all_allowed` is a fail-closed conjunction of three named terms —
the tree was fully walked, every document cleared the gate, every channel of
every document was read — folded into one bool before any caller sees it. A
caller that reads `False` cannot tell which term did it without separately
interrogating `walk_errors`, `blocked_documents` and `incomplete_documents`.

`loomground-collapse` names the limiting term and, more usefully, separates
"a rule refused" from "nobody looked". Run against the three real terms:

| case | overall | limiting term |
|---|---|---|
| folder read, one document blocked by classification | `NOT_SATISFIED` | `every_document_cleared_by_the_gate` |
| the silent partial folder scan | `OPEN` | `tree_fully_walked` |
| the geotagged video nobody parsed | `OPEN` | `every_channel_of_every_document_read` |

That `NOT_SATISFIED` / `OPEN` split is the false-zero family this document
already records twice — a document nobody read being reported with the same
`False` as a document a rule refused. The refusal paths already carry enough
structure for it: all three terms exist as named properties today. The cost is
an optional extra and a reporting surface; the decision is whether the verdict
becomes a three-valued thing in public API.

### Not the mapping: the `loomground-vertical` registration surface

A registration of this package through `loomground-vertical`'s three artifacts
was built and then withdrawn — not because it failed, but because it was the
wrong surface. Recorded so nobody builds it again by accident:

- **Vocabulary — fits.** The egress decision is a function of source class,
  privacy mode and destination. Those are real facets with controlled value
  sets, and `berufsgeheimnis → confidential → internal` is a real subsumption
  chain the plane resolves correctly.
- **Detector taxonomy — does not fit.** `EMAIL`, `IBAN`, `CREDIT_CARD` are not
  facets of a subject: a facet is a property of the whole document, while a
  finding is a property of a span and carries a confidence and an offset the
  card has no place for. Every field lands in `[unmapped]` notes. Forcing it in
  would mean teaching a universal plane what PII is, which is the land-grab in
  the other direction.
- **Jurisdiction pack — shares nothing but the word.** The pack is courts,
  judgment-marker patterns and instrument role-steps. This package reads no
  judgments; its per-country data is IBAN lengths, national-number validators
  and per-language name lists, which are detector tables.
- **Requirements house — does not fit as the builder stands.** `build_house`
  assigns an obligation to a room through `_ARTIFACT_HINT`, a hardcoded
  legal-instrument vocabulary (`dpia`, `fria`, `ropa`, `conformity-assessment`,
  `technical-documentation`, `dpo`, `privacy-policy`, `dpa`). None of this
  package's obligations match it and there is no seam for a vertical to say
  which artifact discharges which duty, so all eleven norms collapse into one
  bearer-keyed room. The only way to get informative rooms is to put the
  discharging surface in the `bearer` field — but the bearer of
  `only_the_overlay_egresses` is this skill, not the overlay. An explicit
  `artifact_key` on the obligation atom would make it fit; that is an upstream
  change.

No defect from twenty rounds of adversarial verification would have been caught
by registering. The case for it was consistency, not defect-finding, and it is
recorded as the weaker case it was. The mapping actually wanted is grounding
this package's policy into a `loomground-versum` store on the full 5D+nD
coordinate, which is knowledge work in a store and not a Python registry.

### Compiling the governance block: what it can and cannot see

`policy-compiler` compiles the block's fifteen norms with all four planes live
and reports **zero conflicts** among the four prohibitions and three
obligations. That zero is close to uninformative: `detect_conflicts` keys on
bearer plus action after case and whitespace folding, and the block's action
slugs are pairwise distinct, so they cannot collide by construction. A single
hyphen (`value placeholder map` vs `value-placeholder map`) defeats it, and so
does any paraphrase.

The consequence worth recording: `resolve()` returns **`undetermined`** for
"egress the original file byte for byte" — the `redact_audio` defect this
document records — because the matcher is substring containment against
`egress original unredacted text`. A compiled norm that cannot recognise its
own flagship violation is not a gate. What the compiling was good for was
forcing each norm to be checked for a binding, which found three that had none.

## A third way a document went unread, and where it stopped

`_iter_files` filtered `extensions` with a bare `continue`: a file the walk
saw and did not open because its suffix was not in `extensions` left no trace
anywhere — not in `walk_errors`, not in `scan_complete`, not in `all_allowed`.
A folder of only unsupported extensions reported `document_count=0`,
`all_allowed=True`, `scan_complete=True`, CLI exit 0. The other two ways a
document goes unread — an unreadable directory (`walk_errors`) and an
unavailable media channel (`incomplete_documents`) — already broke both
flags; this one broke neither.

The skip is now recorded in `walk_errors`, tagged `EXTENSION_FILTERED_DEFAULT`
or `EXTENSION_FILTERED_CHOSEN` so it reads apart from an `OSError` entry
(`ScanReport.unreadable_errors` / `imposed_filtered_files` /
`chosen_filtered_files` / `filtered_files`, the union). `scan_complete` is
False whenever `walk_errors` is non-empty for any reason, unconditionally —
including a filter the caller chose on purpose (`--extensions .txt`): a scope
decision is still a decision about what got looked at, not a claim that the
rest was read.

`all_allowed` splits on a line that is not "was a filter applied" but "did the
caller choose it". `extensions` not passed at all resolves to
`DEFAULT_EXTENSIONS` **imposed** on the caller, who has no way to know a
`.xlsx` fell out of an ordinary, no-flags scan — the case that hits a real
user, and `all_allowed` is False for it, the same as an unreadable directory.
`extensions` passed explicitly — `--extensions .txt`, or `DEFAULT_EXTENSIONS`
named by hand — is **chosen**: recorded, `scan_complete` still goes False, but
`all_allowed` is unaffected, because the caller already knows what that scope
excludes. The signature could not use `extensions is DEFAULT_EXTENSIONS` to
tell the two apart — a caller who names `DEFAULT_EXTENSIONS` explicitly would
misclassify as "not chosen" — so `extensions` defaults to a private sentinel,
resolved to `DEFAULT_EXTENSIONS` only after the imposed/chosen split is
already decided. The CLI carries the same split across its boundary: no flag
imposes the default; `--all-files` or the new `--extensions` flag chooses a
scope. Tested:
`tests/test_privacy_shield_runner.py::test_imposed_default_extension_filter_breaks_all_allowed`,
`tests/test_privacy_shield_runner.py::test_imposed_default_extension_filter_is_reported_by_the_cli_with_exit_2`,
`tests/test_privacy_shield_runner.py::test_chosen_extension_filter_is_recorded_but_does_not_break_all_allowed`,
`tests/test_privacy_shield_runner.py::test_chosen_extension_filter_via_the_cli_exits_0`,
`tests/test_privacy_shield_runner.py::test_naming_default_extensions_explicitly_is_still_a_choice`,
`tests/test_privacy_shield_runner.py::test_all_files_disables_filtering_entirely`.

An earlier round of this fix took the milder reading throughout — `all_allowed`
unaffected by any extension skip, chosen or not — because
`tests/test_media_egress_promise.py::test_the_default_text_walk_is_not_affected_by_the_completeness_rule`
already asserted `all_allowed is True` **and** `scan_complete is True` for a
default folder scan that silently skipped a `.jpg`, and that file was outside
the fix's declared territory. Reported rather than resolved in place, per
that boundary. The owner drew the imposed/chosen line instead and granted
that one test into territory; its assertions and docstring are corrected to
the line above (`all_allowed is False`, `scan_complete is False`) — it was the
same blind spot this section closes, encoded as a passing assertion, not its
rebuttal.

Two entry points disagree on `extensions` by design, and now visibly so: a
folder walk filters, a directly-passed single file never does (`"A single
file passed directly — no extension filter."`, `runner.py`). The same
`.xlsx` file is silently read when named directly and recorded-and-skipped
when reached by walking its parent — tested,
`tests/test_privacy_shield_runner.py::test_folder_walk_and_direct_single_file_disagree_on_the_same_extension`.

Not fixed, same shape, found while reading `_iter_files`: hidden
files/directories and `__pycache__` are pruned from the walk with a bare
`continue` (no `walk_errors` entry), and `if not path.is_file(): continue`
silently drops any non-regular path — a broken symlink, a FIFO, a socket —
with no record either. Both are a document going unaccounted for exactly the
way the extension filter was; neither is exercised by the fix above.
