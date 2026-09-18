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

Measured on python 3.12 with `.[dev,semantic,extract,openai]`. The 8 failures
are the documented `tests/test_simplifier.py` LLM-path cases in every column.

All other numbers below are measured in **CI's environment**, which is
`pip install ".[dev,semantic,extract,openai]"` and nothing else — notably
**without `httpx`**, which is in no extra and which CI does not install:

```
python3 -m pytest -q      # python 3.12, .[dev,semantic,extract,openai]
1165 passed, 8 failed, 10 skipped
```

`--collect-only` reports 1182 items; the run above reports 1183 outcomes,
because two of the skips are module-level `importorskip` skips rather than
collected items. The same numbers on python 3.14, CI's other matrix leg.
Two of the 10 skips are the `httpx` transport assertions in
`tests/test_proxy_transport_guard.py` and
`tests/test_privacy_shield_embeddings.py`; they do not run in CI either, and
a previously reported "886 passed / 8 failed" was measured in a richer
environment than CI's and was not reproducible. **The other 8 are the media
backends CI does not install** — exiftool, ffmpeg/ffprobe, mutagen — and they
are listed one per line by `pytest -rs`. That list is the honest statement of
what CI's green does not cover; see the matrix at the top of this section. The 8
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
