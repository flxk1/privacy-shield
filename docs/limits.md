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
  not alphanumeric at all and not a line break, spanning at most sixteen times
  its own length, with no interior group longer than twelve where it covers
  three groups or more.* There is deliberately no bound on the NUMBER of
  groups: one was tried and it refused a letter-spaced form field, which is
  what `pdftotext` emits and which leaked a whole card number. Joiners
  are defined by exclusion rather than listed, and their WIDTH is unbounded,
  because three successive rules were walked around: the literal `" \t-"`, then
  the Unicode categories `Zs`/`Pd`/`Cf` (which miss `Pc` underscore and `Po`
  colon, dot, slash), then a hard limit of one joiner per gap (which a
  `pdftotext` column gap, fixed-width padding, a dot leader and a monospaced
  table all defeat). Only the interior groups are bounded, because only they
  are never clipped by the candidate's own edges and so are whole tokens — four
  digits in a real layout, thirteen in a list of article numbers. Tested:
  `tests/test_identifier_runs.py::test_every_joiner_category_groups_an_identifier`
  (joiners generated from `unicodedata`, not from a list),
  `::test_the_layout_bounds_reject_assembled_prose`,
  `tests/test_leak_invariant.py::test_a_multi_character_gap_does_not_hide_a_card`,
  `::test_reported_extraction_artefact_shapes`.
- **A single line break inside an identifier is a joiner; two are not — and
  `\r\n` counts as two. THIS IS A KNOWN DEFECT, not a designed limit.** An
  identifier wrapped across two lines is claimed when the terminator is one
  character (`\n`, or a bare `\r`), and is NOT claimed when it is the
  two-character CRLF sequence, because the bound counts `\r` and `\n`
  separately. Measured on the installed package:

  ```
  is_safe_for_external_llm("Kreditkartennummer 4111 1111\r\n1111 1111\r\n…")
    -> (True, 'No PII detected', [])      all sixteen digits in the overlay
  the same string with \n
    -> (False, 'PII detected by pattern matching', ['credit_card'])
  ```

  CRLF is the line terminator of MIME e-mail bodies by specification and of
  Windows text generally, and `is_safe_for_external_llm` on an e-mail body is a
  documented use, so this is not a corner. The leak gate does not catch it
  because its oracle applies the same arithmetic to the same two characters —
  the sixth time in this package's history that the checker has shared an
  assumption with the detector. Do not rely on the egress verdict for CRLF
  documents until this entry is gone.

  The reason a bound exists at all: making every line break a joiner without
  limit would glue a document's lines into a single run and let a column of
  figures be assembled into a checksum.
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
  by a surname in running prose, except where two names are adjacent (the
  second name's given name is swallowed); and a table cell whose column header
  names a person's role.

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

`find_names(text)` applies the rules of every language a document evidences and
of all of them when it evidences none; `find_names(text, "en")` applies one
declared language. A language is one module registering one `Ruleset` in
`privacy_shield/name_layer/`, evidence is per language, and the exclusions are
the union over every registered language plus the ISO 20275 legal forms —
`name_layer/shared.py` states why that split and not another.

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
| English (`en`) | in-repo, `tests/corpora_english.py` | 77 | 10 | 1.21% | 18 | 24/36 | 24/24 |
| English (`en`) | independent positions | — | — | — | 11 | 8/21 | 8/8 |
| other 22 official languages | none | — | — | — | — | unmeasured | unmeasured |

The English 77 clean documents are 12 development, 8 held out, 29 adversarial,
20 written against the probes and 8 written against the exclusions. The
held-out 8 stayed sealed while the rules were being shaped and then scored 0
false positives on first contact.

The German numbers are main's, unchanged: probe A is withdrawn there and its
English counterpart is withdrawn here, for the same reason - a label and a
colon are evidence that a VALUE follows, and the enumeration that decides
whether the value is a person fails OPEN. That withdrawal is the largest
single recall loss in the English layer: 12 of 36 named occurrences and 6 of
21 independent ones, for no false positive measured on any of the 77
documents. It is withdrawn anyway, because German's identical probe was also
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
is what the licence gate below refuses. Dropping the one entry `"agency"` from
`en.PROBES` takes English to 0 false positives on all 61 documents and drops
recall on the independent positions from 13/21 to 10/21 counting the English
rules alone (14/21 to 11/21 for the shipped dispatcher, where the German
ruleset also runs) — at or below German's 11/21. That switch is the owner's.

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
- **That is not a clean bill of health for this layer.** A leak class reported
  by independent verification reproduces at this tip: a word character glued to
  the front of a grouped card number **and** a line break inside it —
  `Ref4111 1111\n1111 1111` — clears the egress gate with "No PII detected"
  and the whole card leaves. Each half of the class is handled; the
  intersection is not. It is language-independent, it is pinned by
  `tests/test_identifier_layer_per_language.py::test_the_glued_and_wrapped_card_is_a_known_open_leak`
  so that a fix fails loudly, and **the fix is not in this change**.

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
| English, ours | 77 | **10** | 1.21% | 24/36 | 8/21 |
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
- **The layout bound has a cliff at about eighty characters of gap.** An
  identifier whose groups are spaced further apart than that is not found.
  Sweeping the bound from 4x to 1000x the identifier length does not change the
  false-positive count at all, so it buys no precision; it is kept only to stop
  two numbers at opposite ends of a long line being assembled, and set where no
  real column reaches. Pinned by
  `tests/test_leak_invariant.py::test_the_span_bound_has_a_cliff_and_this_is_where_it_is`.
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

## Known gaps

**An eighth residue class, found by the gate's own property run during this
change and reproducing unchanged at `521fec2`.** In STANDARD mode:

```
input   'UUID 550e8400-e29b-41d4-a716-446655440000 DE89370400440532013000 00 00 7'
overlay 'UUID 550e8400-e29b-41d4-a716-446655440000 [IBAN] 00 00 7'
leak    validated credit_card left 8 of 15 characters of residue in overlay
```

A Luhn-valid 14-to-15-digit window is assembled from the tail of the UUID and
the digits that follow the redacted IBAN; the IBAN is replaced, the card-shaped
window is not, and eight of its characters stay in the overlay. It is **not
caused by this change** - the name layer does not touch identifiers, and the
exact input was fed to `521fec2` and leaks identically there. It is recorded
here rather than pinned as a test, because the finder is
`tests/test_leak_invariant.py::test_release_gate_property` and that test is
already the right alarm: it draws this shape at random, so **the leak-gate CI
job will fail intermittently until the class is fixed**, which is a property
of the class and not a flake to be silenced. The fix belongs to the identifier
layer.



The ONNX contextual model is shadow-only (no promotion); there is no bundled
pre-embedded PII-context file.

## Test split

All numbers below are measured in **CI's environment**, which is
`pip install ".[dev,semantic,extract,openai]"` and nothing else — notably
**without `httpx`**, which is in no extra and which CI does not install:

```
python3 -m pytest -q      # python 3.12, .[dev,semantic,extract,openai]
1069 passed, 8 failed, 2 skipped
```

1079 tests collected. The per-language name layer added 165:
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
fall back to this package's own arithmetic. The 2 skips are the `httpx` transport assertions in
`tests/test_proxy_transport_guard.py` and
`tests/test_privacy_shield_embeddings.py`; they do not run in CI either, and
a previously reported "886 passed / 8 failed" was measured in a richer
environment than CI's and was not reproducible. The 8
failures are all in `tests/test_simplifier.py`'s LLM path, which patches
`privacy_shield.services.llm_runtime` — an upstream gateway this package does
not ship; they fail identically on the tip before this round's changes.
`openai` is installed here (and by CI's `tests` job) so
`tests/test_local_model_endpoint_guard.py`'s send-path assertions run rather
than skip.
`.github/workflows/ci.yml` deselects the 8 llm_runtime tests by name, so the
`tests` job runs 1069 passed, 8 deselected.

The leak invariant is its own CI job that `tests` waits on:
`tests/test_leak_invariant.py`, 383 tests including a 300-document generated
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
