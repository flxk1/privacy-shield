"""Precision and recall of the ENGLISH name layer, measured and pinned.

English is its own design, not German with a swapped word list, and the reason
is one sentence of orthography: German capitalises every noun, so
capitalisation is not evidence there; English does not, so capitalisation is
the candidate generator - and what it evidences is a PROPER NOUN, not a
person.

MEASURED through the scanner, on 77 English documents containing no personal
data (12 development, 8 held out, 29 adversarial, 20 written against the
probes, 8 written against the exclusions) and on 29 documents with names:

                            clean docs                documents with names
                            FP spans  char loss       recall    precision
    development                 0        0.00%        13/21       13/13
    held out                    0        0.00%        11/15       11/11
    adversarial (three batches) 10       1.21%          -           -
    independent positions       -          -           8/21        8/8

THE TEN FALSE POSITIVES ARE THREE NAMED CLASSES, not a number:

  * a proper noun used as an agent that is not a person - `issued by Charles
    Schwab`, `compiled by Thames Valley`. Undecidable without vocabulary.
  * a status word in a declared person COLUMN - `Not Allocated`, `Vacant`.
    This is main's deliberate trade for probe D: once the header says the
    column holds people, the value is judged on SHAPE alone, because judging
    it would need the value vocabulary that sank probe A. A status word in a
    person column is redacted, which is what the table says it is.
  * a company whose legal form is a member state's and not England's -
    `Nordica Oy`, `Mediatech Kft`, `Lisboa Lda`, `Vilnius UAB`, `Praha AS` -
    standing where a person stands. A 410-entry ISO 20275 transcription
    refused all six and was REMOVED: GLEIF publishes the code list with no
    licence statement, licence is a hard gate for data as well as code, and
    an ablation over the first 69 documents showed it changing nothing -
    because not one of them had a foreign legal form in a signature block.
    The eight documents that do are `EN_CLEAN_ADVERSARIAL_FOREIGN`, and this
    is the measured cost of not carrying that data: 6 spans, 16% of the
    characters of those eight short documents.

WHAT EACH PROBE COSTS AND BUYS, over the same 77 clean documents, English
rules alone (the shipped dispatcher scores one name higher on the independent
corpus because the German GIVEN rule also runs):

    variant                          FP    named   independent
    core + table + agency [SHIPPED]  10    24/36      7/21
      + label (fail-open)            10    36/36     13/21
      + speaker                      13    24/36     10/21
      + list_block                   12    24/36     10/21
      + citation                      11   24/36      8/21
      + attribution                  10    24/36      7/21
      + name_line                    25    24/36     10/21
      + all six candidates           29    36/36     20/21

THE LABEL PROBE IS WITHDRAWN, and it is the largest single recall loss in this
file: 12 of 36 named occurrences and 6 of 21 independent ones, for no measured
false positive on any of the 77 documents. It is withdrawn anyway, because
German's identical probe was also free on its own corpora - the owner approved
it on a measured zero - and produced 18 false-positive spans on the first
independent corpus it met. A label and a colon are evidence that a VALUE
follows, not that the value is a person, and the enumeration that decides the
difference fails OPEN. See the note in `name_layer/en.py`.

THE HELD-OUT HALVES were written before the rules and not looked at until the
design was frozen. The second adversarial batch was written against the probes
and the third against the exclusions, because every measurement in this
programme that shared an assumption with the thing it measured reported a
number that did not survive an independent corpus.
"""

from __future__ import annotations

import pytest

from corpora_english import (
    EN_CLEAN_ADVERSARIAL,
    EN_CLEAN_ADVERSARIAL_FOREIGN,
    EN_CLEAN_ADVERSARIAL_PROBES,
    EN_CLEAN_DEV,
    EN_CLEAN_HELD_OUT,
    EN_INDEPENDENT,
    EN_NAMED_DEV,
    EN_NAMED_HELD_OUT,
)
from privacy_shield.name_layer import en, find_names
from privacy_shield.scanner import Confidence, PIIType, PrivacyScanner


def _name_chars(text, scanner):
    chars = set()
    spans = 0
    for finding in scanner.scan(text).findings:
        if finding.pii_type is PIIType.NAME:
            chars.update(range(finding.start, finding.end))
            spans += 1
    return chars, spans


@pytest.fixture
def scanner():
    return PrivacyScanner(min_confidence=Confidence.MEDIUM)


@pytest.mark.parametrize(
    "corpus, label",
    [(EN_CLEAN_DEV, "development"), (EN_CLEAN_HELD_OUT, "held out")],
)
def test_no_name_is_claimed_in_an_english_document_that_has_none(
    corpus, label, scanner
):
    """Zero, not "fewer" - including the held-out half.

    These documents carry Title Case headings, product names, place names,
    company names, month names, `Dear Sir or Madam`, signature blocks signed
    by departments, CC lists and subject lines. In German that inventory
    produced 75% character loss; in English it is the inventory a
    capitalisation rule has to survive.
    """
    offenders = []
    for text in corpus:
        chars, spans = _name_chars(text, scanner)
        if spans:
            offenders.append((spans, sorted(chars)[:1], text[:60]))
    assert not offenders, f"{label}: {offenders}"


#: The FP set on the adversarial halves, pinned by VALUE rather than by count,
#: because the count is meaningless without knowing which class it is.
KNOWN_ENGLISH_FALSE_POSITIVES = {
    # a proper noun used as an agent
    "Charles Schwab", "Thames Valley",
    # a status word in a declared person column (main's probe-D trade)
    "Not Allocated", "Vacant",
    # a member state's legal form where a person stands, after the ISO 20275
    # transcription was removed on licence grounds
    "Nordica Oy", "Mediatech Kft", "Lisboa Lda", "Vilnius", "Praha",
}


def test_the_adversarial_false_positives_are_exactly_the_named_class(scanner):
    """Pinned in both directions.

    More means the rule widened. Fewer means somebody found a signal that
    separates a company named after a person from a person - which would be a
    real result and belongs in this docstring, not in a silently greener test.
    """
    claimed = []
    for text in (
        EN_CLEAN_ADVERSARIAL
        + EN_CLEAN_ADVERSARIAL_PROBES
        + EN_CLEAN_ADVERSARIAL_FOREIGN
    ):
        claimed.extend(
            finding.value
            for finding in scanner.scan(text).findings
            if finding.pii_type is PIIType.NAME
        )
    assert set(claimed) == KNOWN_ENGLISH_FALSE_POSITIVES, claimed
    assert len(claimed) == 10, claimed


#: Recall on the named corpora, pinned in BOTH directions. It is no longer
#: 100%: withdrawing the label probe made every name that occurs only after a
#: label invisible, and that is 12 of the 36.
NAMED_RECALL = {"development": (13, 21), "held out": (11, 15)}


@pytest.mark.parametrize(
    "corpus, label",
    [(EN_NAMED_DEV, "development"), (EN_NAMED_HELD_OUT, "held out")],
)
def test_english_names_are_found_where_names_actually_occur(corpus, label, scanner):
    found = 0
    total = 0
    missed = []
    for text, truth in corpus:
        chars, _spans = _name_chars(text, scanner)
        for start, end, value in truth:
            total += 1
            if any(index in chars for index in range(start, end)):
                found += 1
            else:
                missed.append(value)
    assert (found, total) == NAMED_RECALL[label], (label, found, total, missed)


@pytest.mark.parametrize(
    "corpus, label",
    [(EN_NAMED_DEV, "development"), (EN_NAMED_HELD_OUT, "held out")],
)
def test_nothing_but_the_english_name_is_claimed(corpus, label, scanner):
    """The honorific, the role and the company stay in the document."""
    extra = []
    for text, truth in corpus:
        chars, _spans = _name_chars(text, scanner)
        truth_chars = set()
        for start, end, _value in truth:
            truth_chars.update(range(start, end))
        surplus = chars - truth_chars
        if surplus:
            extra.append((text[min(surplus):max(surplus) + 1], text[:50]))
    assert not extra, f"{label}: {extra}"


ENGLISH_INDEPENDENT_RECALL = 8
ENGLISH_INDEPENDENT_TOTAL = 21


def test_the_measured_english_recall_on_the_independent_positions(scanner):
    """Pinned at the measured value, in BOTH directions.

    The positions are the ones the German layer was measured against from
    outside this work - after a colon, in a CC list, in an e-mail body with no
    honorific, in a footnote, in minutes, in a table cell, in a subject line
    and in running prose - written in English with non-Anglo names throughout.
    """
    found = 0
    for text, truth in EN_INDEPENDENT:
        chars, _spans = _name_chars(text, scanner)
        for start, end, _value in truth:
            if any(index in chars for index in range(start, end)):
                found += 1
    assert found == ENGLISH_INDEPENDENT_RECALL, (
        f"English recall on the independent positions is "
        f"{found}/{ENGLISH_INDEPENDENT_TOTAL}, pinned at "
        f"{ENGLISH_INDEPENDENT_RECALL}; re-measure the 61 name-free documents "
        "and re-state the trade before changing this"
    )


# ---------------------------------------------------------------------------
# The rule must do what its docstring says
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        pytest.param("Dear Sir or Madam,\n", id="sir_or_madam"),
        pytest.param("Dear Sirs,\n", id="sirs"),
        pytest.param("Dear Customer,\n", id="customer"),
        pytest.param("Dear Hiring Manager,\n", id="hiring_manager"),
        pytest.param("Kind regards\nAccounts Payable\n", id="department_signs"),
        pytest.param("Best wishes\nThe Procurement Team\n", id="team_signs"),
        pytest.param("Attn: Goods Inwards\n", id="attn_is_a_department"),
        pytest.param("Quality Assurance Report\n", id="title_case_heading"),
        pytest.param("Delivery is due on Monday in March.\n", id="temporal"),
        pytest.param("Issued by Northstar Limited\n", id="agency_is_a_company"),
        pytest.param("Audited by Ernst & Young\n", id="firm_joined_by_ampersand"),
        pytest.param("Supplied by Marks and Spencer\n", id="firm_joined_by_and"),
        pytest.param("Approved by Legal and signed by the Board\n", id="agency_is_a_function"),
        pytest.param("Caseworker: Vacant\n", id="label_value_is_a_placeholder"),
        pytest.param("From: Central Administration\n", id="label_value_is_a_department"),
        pytest.param("CC: Technical Distribution List\n", id="cc_is_a_distribution_list"),
    ],
)
def test_an_english_non_person_is_not_claimed(text, scanner):
    claimed = [
        f.value for f in scanner.scan(text).findings if f.pii_type is PIIType.NAME
    ]
    assert not claimed, claimed


@pytest.mark.parametrize(
    "text, expected",
    [
        ("Dear Mr Ashcroft,\n", ["Ashcroft"]),
        ("Dear Priya Raman,\n", ["Priya Raman"]),
        ("Hello Marta Kovacs,\n", ["Marta Kovacs"]),
        ("Dear Professor Lindqvist,\n", ["Lindqvist"]),
        ("Kind regards\nLaura Whitfield\nHead of Procurement\n", ["Laura Whitfield"]),
        ("Regards\nBen\n", ["Ben"]),
        ("Attn: Helen Ferreira\n", ["Helen Ferreira"]),
        # and the position the withdrawn label probe used to cover, now empty
        ("Caseworker: Ashcroft\n", []),
        ("From: Sarah Villanueva\n", []),
        ("Liam O'Donnell\n12 Bridge Street\nBristol BS1 5TR\n", ["Liam O'Donnell"]),
        ("The report was prepared by Jane Elliott.\n", ["Jane Elliott"]),
        ("The audit was signed off by Paul Mensah.\n", ["Paul Mensah"]),
        ("Please contact Helen Ferreira on extension 4471.\n", ["Helen Ferreira"]),
        ("On behalf of Ruth Ebersbach I confirm the date.\n", ["Ruth Ebersbach"]),
    ],
)
def test_an_english_person_is_claimed_and_nothing_else_is(text, expected, scanner):
    claimed = [
        f.value for f in scanner.scan(text).findings if f.pii_type is PIIType.NAME
    ]
    assert claimed == expected, claimed


def test_a_title_is_evidence_and_is_not_itself_redacted(scanner):
    """"Mr" is not personal data. It is the reason the next word is."""
    findings = [
        f for f in scanner.scan("Dear Mrs Hartley,").findings
        if f.pii_type is PIIType.NAME
    ]
    assert [f.value for f in findings] == ["Hartley"]


def test_an_english_table_cell_is_a_name_only_under_a_person_column():
    people = (
        "| Reference | Caseworker | Status |\n"
        "| 10        | Ashcroft   | open   |\n"
    )
    products = (
        "| Product       | Quantity | Status |\n"
        "| Sealing Ring  | 200      | Open   |\n"
    )
    assert [v for _s, _e, v in en.PROBES["table"](people)] == ["Ashcroft"]
    assert en.PROBES["table"](products) == []


def test_the_english_probes_are_separable_and_named():
    """A regression names the probe that caused it, and the owner can drop
    one without touching the others."""
    assert set(en.PROBES) == {
        "title",
        "salutation",
        "signature",
        "address",
        "table",
        "agency",
    }
    blame = en.find_names_by_probe("The report was prepared by Jane Elliott.\n")
    assert [v for _s, _e, v in blame["agency"]] == ["Jane Elliott"]
    assert blame["table"] == []


def test_the_unshipped_english_probes_stay_unshipped():
    """The option table above is the owner's decision, not this file's.

    Promoting one of these is allowed; doing it without re-measuring the 61
    name-free documents is what produced 75% character loss in German.
    """
    assert set(en.CANDIDATE_PROBES) == {
        "label",
        "speaker",
        "list_block",
        "citation",
        "attribution",
        "name_line",
    }
    assert not set(en.CANDIDATE_PROBES) & set(en.PROBES)


def test_the_two_agency_guards_are_what_they_claim_to_be():
    """Both look at what FOLLOWS the candidate, not at a word list of firms."""
    assert en.PROBES["agency"]("Issued by Charles Schwab Corporation.") == []
    assert en.PROBES["agency"]("Audited by Ernst & Young.") == []
    assert [v for _s, _e, v in en.PROBES["agency"]("Audited by Nils Berg.")] == [
        "Nils Berg"
    ]


def test_two_people_joined_by_and_after_an_agency_frame_are_refused():
    """The stated cost of the firm-join guard, pinned so it stays honest.

    `prepared by Jane Elliott and Nils Berg` claims neither, because
    `supplied by Marks and Spencer` is the same shape. Naming the cost is the
    point: this is a known uncovered position, not an accident.
    """
    assert find_names("Prepared by Jane Elliott and Nils Berg.", "en") == []
