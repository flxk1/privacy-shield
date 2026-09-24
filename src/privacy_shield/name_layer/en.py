"""English: capitalisation is evidence, but only of a proper noun.

NOT GERMAN WITH A SWAPPED WORD LIST. The German rules exist because German
capitalises every noun, so capitalisation carries no information at all and a
name has to be evidenced by a title, a signature block, an addressee position
or a known given name. English does not capitalise nouns, so a capitalised
word in running prose IS informative - and what it tells you is that a proper
noun is there, not that a person is.

`Milton Keynes`, `Morgan Stanley`, `Land Rover`, `Marks and Spencer`,
`Monday`, `Framework Agreement`, `Quality Assurance` and `Accounts Payable`
are all capitalised sequences in ordinary English business prose, and none of
them is personal data. So the English design keeps capitalisation as the
CANDIDATE GENERATOR - which is what German cannot do - and requires a FRAME
around the candidate before claiming it:

  TITLE      Mr, Mrs, Ms, Dr, Prof, Sir. The title is evidence, not data.
  SALUTATION `Dear`, `Hi`, `Hello`, `Good morning` and then a name. English
             opens with the addressee's name far more often than German, which
             puts an address form in front of it - this is a position German
             does not have and it is worth its own rule.
  SIGNATURE  the first name-shaped line after a closing formula. One word is
             enough here, unlike German: `Regards` / `Ben` is an ordinary
             English sign-off and the exclusion union keeps `Regards` /
             `Finance` out.
  ADDRESS    a name after `Attn`, `FAO`, `c/o`, or a name-shaped line directly
             above a street or a town-and-postcode line.
  TABLE      a cell whose column header DECLARES a column of people, judged
             on shape alone once the header has said so.
  AGENCY     the frame English actually marks agency with: a document verb,
             then `by`, then the name - `prepared by`, `reviewed by`,
             `signed off by` - plus `contact`, `on behalf of`, `c/o`.
The SPEAKER position - `Name: sentence.` in minutes - was built, measured and
NOT shipped. Gating it on a document-level `Minutes` header made it affordable
against the first adversarial batch, and then twenty documents written to
break it specifically claimed `Decision`, `Eastgate` and `Thames Valley`:
business minutes label their lines with decisions, departments and SITES, and
`Eastgate: The site remains closed.` is the same shape as `Ebersbach: The date
cannot be met.` Its cost is in the option table in
tests/test_name_layer_english.py, where the owner can see it.

Two guards do most of the precision work in the AGENCY frame, and both are
about English orthography rather than about vocabulary:

  * A firm joined by `&` or by `and` is a firm, not a person. `Ernst & Young`,
    `Marks and Spencer` and `Deloitte and Touche` have exactly the shape the
    rule wants. The cost is named: two people joined by `and` after an agency
    frame (`prepared by Jane Elliott and Nils Berg`) are refused too.
  * A candidate followed by a legal form or an organisational word is that
    organisation. `issued by Northstar Limited` claims nothing.

What is left over, and cannot be fixed without the vocabulary this programme
rejected: a company named after a person. `issued by Charles Schwab` is
claimed, and no signal in the text distinguishes it from `issued by Charles
Schneider`. It is measured, not asserted - see
tests/test_name_layer_english.py.
"""

from __future__ import annotations

import re
from typing import List

from . import registry
from .shared import Exclusions, Ruleset, Span, claim, line_spans

_UPPER = "A-ZÀ-ÖØ-Þ"
_LOWER = "a-zß-öø-ÿ"

#: One capitalised word, including O'Donnell, McBride and Anne-Marie.
_CORE = rf"[{_UPPER}](?:[{_LOWER}]+|'[{_UPPER}][{_LOWER}]+)"
_WORD = rf"{_CORE}(?:[-'’]{_CORE})*"

#: One to three of them.
_NAME = rf"{_WORD}(?:[ \t]+{_WORD}){{0,2}}"

_TITLE = (
    r"(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Professor|Sir|Dame|Lord|Lady|Rev|Reverend|"
    r"Fr|Hon|Capt|Col|Sgt|Messrs)\.?"
)

TITLE_ANCHORED = re.compile(rf"\b(?:{_TITLE}[ \t]+)+({_NAME})")

NAME_LINE = re.compile(rf"^[ \t]*(?:{_TITLE}[ \t]+)*({_NAME})[ \t]*$")

SALUTATION = re.compile(
    rf"^[ \t]*(?:Dear|Hi|Hello|Hey|Good[ \t]+(?:morning|afternoon|evening))"
    rf"[ \t]+(?:{_TITLE}[ \t]+)*({_NAME})(?=[,;:!.]|[ \t]*$)",
    re.MULTILINE,
)

CLOSING = re.compile(
    r"^[ \t]*(?:(?:Kind|Best|Warm|Warmest)[ \t]+regards|Regards|"
    r"Sincerely(?:[ \t]+yours)?|Yours(?:[ \t]+(?:sincerely|faithfully|truly))?|"
    r"(?:Best|Warm)[ \t]+wishes|Many[ \t]+thanks|With[ \t]+thanks|Thanks|"
    r"Thank[ \t]+you|All[ \t]+the[ \t]+best|Cheers)[ \t]*,?[ \t]*$",
    re.IGNORECASE,
)

_STREET_SUFFIX = (
    r"(?:Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Drive|Close|Court|Crescent|Way|"
    r"Place|Square|Row|Terrace|Hill|Gardens|Mews|Walk|Parade|Grove|Rise|View|"
    r"Wharf|Quay|Estate|Park)"
)

#: A street line needs a number or a unit designator as well as the suffix:
#: "Eastgate Industrial Estate" is a site, "12 Bridge Street" is an address.
STREET_LINE = re.compile(
    rf"^[ \t]*(?:(?:Unit|Suite|Flat|Apartment|Apt|Block|Floor|PO[ \t]+Box)"
    rf"[ \t]+\w+,?[ \t]*)?\d+[a-zA-Z]?,?[ \t]+[^\n]*?\b{_STREET_SUFFIX}\.?[ \t]*$"
)

#: Town and postcode: UK ("Manchester M1 2AB"), Ireland, and the continental
#: four-or-five-digit form with the town after it.
POSTCODE_LINE = re.compile(
    rf"^[ \t]*(?:{_WORD}(?:[ \t]+{_WORD})*[ \t]+)?"
    rf"(?:[{_UPPER}]{{1,2}}\d[{_UPPER}\d]?[ \t]*\d[{_UPPER}]{{2}}|"
    rf"[{_UPPER}]\d{{2}}[ \t]?[{_UPPER}]\d{{2}}|\d{{4,5}})[ \t]*$"
)

ADDRESSEE_INLINE = re.compile(
    rf"^[ \t]*(?:Attn|ATTN|Attention|FAO|F\.A\.O\.|For[ \t]+the[ \t]+attention"
    rf"[ \t]+of|c/o|C/O)[:.]?[ \t]+(?:{_TITLE}[ \t]+)*({_NAME})[ \t]*$",
    re.MULTILINE,
)

ADDRESSEE_MARKER = re.compile(
    r"^[ \t]*(?:Attn|ATTN|Attention|FAO|c/o|C/O)[:.]?[ \t]*$"
)

MINUTES_HEADER = re.compile(
    r"^[ \t]*(?:Minutes|Minutes[ \t]+of[ \t]+(?:the[ \t]+)?\w+|Note[s]?[ \t]+of"
    r"[ \t]+(?:the[ \t]+)?meeting|Meeting[ \t]+(?:minutes|notes)|Transcript)"
    r"[ \t]*:?[ \t]*$",
    re.IGNORECASE,
)

#: A speaker line's value is a SENTENCE. That is what separates
#: "Wisniewski: The date cannot be met." from "Status: Open", and it is the
#: only reason this probe is affordable at all.
SPEAKER_LINE = re.compile(
    rf"^[ \t]*({_NAME})[ \t]*:[ \t]+([{_UPPER}][^\n]*[.!?])[ \t]*$",
    re.MULTILINE,
)

ORGANISATIONAL = frozenset("""
Department Departments Division Section Branch Team Teams Group Unit Board
Committee Council Office Headquarters Management Directorate Secretariat
Reception Accounts Accounting Accountancy Finance Financial Payroll Payable
Receivable Procurement Purchasing Sales Marketing Communications Support
Service Services Helpdesk Servicedesk Desk Operations Logistics Warehouse
Stores Storeroom Dispatch Despatch Goods Inwards Outwards Production
Manufacturing Engineering Maintenance Facilities Technical Technology
Infrastructure Quality Assurance Compliance Legal Audit Risk Security Privacy
Personnel Recruitment Training Administration Admin Distribution Fleet
Transport Centre Center Plant Works Site Depot Region Regional District
Central Northern Southern Eastern Western Corporate Practice Consulting
Consultancy Chair Chairman Chairwoman Manager Director Officer Secretary
Registrar Treasurer Head Lead Supervisor Coordinator Administrator Programme
Program Project Portfolio Estate Industrial Commercial Mailroom Postroom
Switchboard Staff Employees Workforce Union Authority Agency Bureau Ministry
Commission Tribunal Registry Panel Forum Workstream Helpline Hotline
""".split())

LEGAL_FORMS = frozenset("""
Ltd Ltd. Limited PLC Plc plc LLP LLC Inc Inc. Incorporated Corp Corp.
Corporation Company Co Co. Holdings Group Partnership Partners Trust
Foundation Association Society Charity CIC LP Enterprises Ventures
International Worldwide Global Industries Systems Solutions Technologies
""".split())

NON_PERSON_VALUES = frozenset("""
Sir Sirs Madam Madams Gentlemen Ladies All Everyone Anyone Nobody None Not Yet
Appointed Unappointed Vacant Vacancy Unassigned Unallocated Allocated
Automatic Assignment TBC TBA TBD Pending Various Multiple Several Open Closed
Ongoing Internal External Unknown Anonymous Occupier Resident Tenant Landlord
Applicant Candidate Hiring Valued Customer Customers Client Clients Member
Members Supplier Suppliers Contractor Contractors Subcontractor Attendees
Attendee Present Apologies Participants Recipients Recipient Distribution
Shared List Lists The A An Same Above Below See Refer Attached Enclosed
Whom Concerned Subject Reference Status Priority Deadline Reason Title Target
Outcome Findings Scope Location Language Note Notes Date Effective Start End
Amount Quantity Item Items Position Description Stock Bay Condition Duration
Shift Asset Lot Access Constraints Colleagues Colleague Everybody Anybody
Overnight Freight Carrier Standard Terms Conditions Invoice Order Quotation
""".split())

TEMPORAL = frozenset("""
January February March April May June July August September October November
December Jan Feb Mar Apr Jun Jul Aug Sep Sept Oct Nov Dec
Monday Tuesday Wednesday Thursday Friday Saturday Sunday Mon Tue Tues Wed Thu
Thur Thurs Fri Sat Sun Today Tomorrow Yesterday Christmas Easter
""".split())

PERSON_ROLE_LABELS = frozenset("""
Caseworker Handler Adviser Advisor Author Signatory Interviewer Assessor
Approver Reviewer Contact From To Cc CC Bcc BCC Attendees Present Apologies
""".split())

PHRASE_LABELS = (
    "Prepared by", "Reviewed by", "Approved by", "Checked by", "Signed by",
    "Submitted by", "Authorised by", "Authorized by", "Completed by",
    "Raised by", "Reported by", "Verified by", "Witnessed by",
    "On behalf of", "Enquiries to", "Inquiries to", "Contact person",
    "Case officer", "Case worker", "Account manager", "Relationship manager",
    "For the attention of", "Attention", "Attn", "Copied to",
)

EXCLUSIONS = Exclusions(
    legal_forms=LEGAL_FORMS,
    organisational=ORGANISATIONAL,
    non_person_values=NON_PERSON_VALUES,
    temporal=TEMPORAL,
)

MARKERS = frozenset(
    """
the and or of to for with from is are was were will shall be been has have had
not please we our your yours you dear sincerely faithfully regards kind best
wishes thanks subject invoice order delivery contract agreement letter further
receipt attached enclosed hereby herewith prepared reviewed approved signed
caseworker handler attn enquiries behalf
""".split()
)

_DOCUMENT_VERB = (
    r"(?:[Pp]repared|[Pp]roduced|[Ww]ritten|[Dd]rafted|[Cc]ompiled|[Rr]eviewed|"
    r"[Cc]hecked|[Vv]erified|[Aa]pproved|[Aa]uthorised|[Aa]uthorized|"
    r"[Ss]igned(?:[ \t]+off)?|[Cc]ountersigned|[Ss]ubmitted|[Cc]ompleted|"
    r"[Ii]ssued|[Aa]udited|[Ii]nspected|[Cc]onducted|[Cc]arried[ \t]+out|"
    r"[Hh]andled|[Pp]rocessed|[Rr]aised|[Ww]itnessed|[Aa]ttested|[Cc]haired|"
    r"[Pp]resented|[Ee]ndorsed)"
)

AGENCY_FRAME = re.compile(
    rf"\b{_DOCUMENT_VERB}[ \t]+by[ \t]+(?:{_TITLE}[ \t]+)*({_NAME})"
)

#: The trigger may start a sentence, so its first letter is a class rather
#: than a literal: "On behalf of Ruth Ebersbach" is the position this rule
#: exists for and it is sentence-initial every time.
CONTACT_FRAME = re.compile(
    rf"\b(?:[Cc]ontact(?:ed|ing)?|[Oo]n[ \t]+behalf[ \t]+of|[Cc]are[ \t]+of|"
    rf"[Cc]/[Oo]|[Ss]p(?:oke|eak)[ \t]+(?:to|with)|[Mm]et[ \t]+with|"
    rf"[Ll]iaise[ \t]+with|[Aa]ddressed[ \t]+to)[ \t]+(?:{_TITLE}[ \t]+)*({_NAME})"
)

#: A firm joined by "&" or by "and" is a firm. Ernst & Young, Marks and
#: Spencer, Deloitte and Touche - all of them are the shape the rule wants.
_FIRM_JOIN = re.compile(rf"^[ \t]*(?:&|and[ \t]+[{_UPPER}])")

_NEXT_WORD = re.compile(rf"^[ \t]+({_WORD})")


def _person_shaped(candidate: str) -> bool:
    """One to three capitalised words, none of them a reason not to claim."""
    match = NAME_LINE.match(candidate.strip())
    if not match:
        return False
    return not registry.exclusions().blocks(match.group(1).split())


def value_is_a_person(value: str) -> bool:
    return _person_shaped(value)


def _label_is_a_person_role(label: str) -> bool:
    cleaned = label.strip().rstrip(".")
    if cleaned in PERSON_ROLE_LABELS:
        return True
    return any(cleaned.lower() == phrase.lower() for phrase in PHRASE_LABELS)


def _frame_claim_survives_the_guards(text: str, start: int, end: int) -> bool:
    """The two AGENCY guards, applied to one candidate.

    Both look at what FOLLOWS the candidate, because that is where English
    puts the thing that tells you it was an organisation all along.
    """
    tail = text[end:]
    if _FIRM_JOIN.match(tail):
        return False
    following = _NEXT_WORD.match(tail)
    if following:
        word = following.group(1)
        exclusions = registry.exclusions()
        if word in exclusions.legal_forms or word in exclusions.organisational:
            return False
    return True


def _title_names(text: str) -> List[Span]:
    spans: List[Span] = []
    for match in TITLE_ANCHORED.finditer(text):
        if _person_shaped(match.group(1)):
            spans.append((match.start(1), match.end(1), match.group(1)))
    return spans


def _salutation_names(text: str) -> List[Span]:
    spans: List[Span] = []
    for match in SALUTATION.finditer(text):
        if _person_shaped(match.group(1)):
            spans.append((match.start(1), match.end(1), match.group(1)))
    return spans


def _signature_names(text: str) -> List[Span]:
    spans: List[Span] = []
    lines = line_spans(text)
    for index, (_start, _end, line) in enumerate(lines):
        if not CLOSING.match(line):
            continue
        for following in range(index + 1, min(index + 5, len(lines))):
            line_start, _line_end, candidate = lines[following]
            if not candidate.strip():
                continue
            match = NAME_LINE.match(candidate)
            if match and _person_shaped(match.group(1)):
                spans.append((
                    line_start + match.start(1),
                    line_start + match.end(1),
                    match.group(1),
                ))
            break
    return spans


def _address_names(text: str) -> List[Span]:
    spans: List[Span] = []
    for match in ADDRESSEE_INLINE.finditer(text):
        if _person_shaped(match.group(1)):
            spans.append((match.start(1), match.end(1), match.group(1)))

    lines = line_spans(text)
    for index, (line_start, _line_end, line) in enumerate(lines):
        match = NAME_LINE.match(line)
        if not match or not _person_shaped(match.group(1)):
            continue
        below = lines[index + 1][2] if index + 1 < len(lines) else ""
        above = lines[index - 1][2] if index > 0 else ""
        if (
            STREET_LINE.match(below)
            or POSTCODE_LINE.match(below)
            or ADDRESSEE_MARKER.match(above)
        ):
            spans.append((
                line_start + match.start(1),
                line_start + match.end(1),
                match.group(1),
            ))
    return spans


#: Column headers that DECLARE a column of people, the English counterpart of
#: German's PERSON_COLUMN_HEADERS. This enumeration fails CLOSED: a header word
#: missing from it costs a missed name, not a false positive on a clean
#: document.
PERSON_COLUMN_HEADERS = frozenset("""
Caseworker Handler Adviser Advisor Author Signatory Interviewer Assessor
Approver Reviewer Owner Contact Name Surname Forename Firstname Lastname
Employee Customer Client Applicant Claimant Attendee Participant Recipient
Sender Signature Responsible Assignee Requester Requestor Reporter Manager
""".split())

_CELL_NAME = re.compile(rf"\A(?:{_TITLE}[ \t]+)*({_WORD}(?:[ \t]+{_WORD}){{0,3}})\Z")

_TABLE_ROW = re.compile(r"^[ \t]*\|(?P<body>.+)\|[ \t]*$", re.MULTILINE)


def _is_a_person_column(header: str) -> bool:
    cleaned = header.strip().rstrip(".:")
    if cleaned in PERSON_COLUMN_HEADERS:
        return True
    return any(cleaned.lower() == phrase.lower() for phrase in PHRASE_LABELS)


def _table_names(text: str) -> List[Span]:
    """A table cell whose COLUMN is a person column.

    Main's implementation, in English. Two things in it are not obvious and
    both were paid for: the header is tracked PER TABLE (a handler table
    followed by a parts table otherwise reused column 0 and claimed every
    product in it, and the other way round the person column was never learned
    and the name egressed - the only difference between destroying the
    document and leaking was the order of two tables), and a row that names a
    person column IS a header wherever it sits.

    And the value test is SHAPE ONLY. The header already declared this column
    to hold people, so there is nothing left to decide - and deciding it would
    need exactly the value vocabulary that sank probe A. A status word in a
    person column is redacted, which is what the table says it is.
    """
    spans: List[Span] = []
    person_columns: set = set()
    previous_end = None
    for row in _TABLE_ROW.finditer(text):
        gap = text[previous_end:row.start()] if previous_end is not None else None
        contiguous = gap is not None and gap.count("\n") == 1 and not gap.strip()
        previous_end = row.end()

        body = row.group("body")
        cells = body.split("|")
        starts = []
        position = row.start("body")
        for cell in cells:
            starts.append(position)
            position += len(cell) + 1

        declared = {
            index for index, cell in enumerate(cells) if _is_a_person_column(cell)
        }
        if not contiguous or declared:
            person_columns = declared
            continue

        for index in sorted(person_columns):
            if index >= len(cells):
                continue
            cell = cells[index]
            stripped = cell.strip()
            if not stripped:
                continue
            match = _CELL_NAME.match(stripped)
            if not match:
                continue
            begin = starts[index] + cell.index(stripped) + match.start(1)
            spans.append((begin, begin + len(match.group(1)), match.group(1)))
    return spans


# PROBE A DOES NOT SHIP IN ENGLISH EITHER.
#
# `Caseworker: Ashcroft`, `CC: Ingrid Bauer`, `Prepared by: Anneli Virtanen`.
# It measured 0 false-positive spans over 69 clean English documents including
# 49 written to break it, and it was still the second-largest recall
# contributor - and it is withdrawn, because the asymmetry main established
# for German applies here word for word:
#
#   a table header enumeration fails CLOSED  - a missing header costs a name;
#   a label VALUE enumeration fails OPEN     - a missing value word costs a
#                                              false positive on a clean
#                                              document.
#
# German's probe A was approved on the same kind of zero and produced 18
# false-positive spans on the first independent corpus, from exactly the two
# holes this layer also has and measured in
# tests/test_name_layer_enumeration_limit.py: a member state's legal form
# nobody wrote down, and an inflected form of a word that is on the list. The
# English lists are longer than the German ones were, which means the
# independent corpus that breaks them has not been written yet - not that it
# does not exist.
#
# What is left over, and the entire reason to want it, is the BARE SURNAME
# after a label. That is structurally identical to `Caseworker: Vacant`,
# `To: Nordica Oy` and `Handler: Automated Routing`. A label and a colon are
# evidence that a value follows; nothing in the text says whether the value is
# a person.
#
# It is kept in CANDIDATE_PROBES with its cost measured, because the decision
# to accept a fail-open probe is the owner's and not this module's.


def _label_names(text: str) -> List[Span]:
    """WITHDRAWN. A value after a person-role label. See the note above."""
    spans: List[Span] = []
    for match in LABEL_LINE.finditer(text):
        if not _label_is_a_person_role(match.group("label")):
            continue
        value_start = match.start("value")
        offset = 0
        for part in match.group("value").split(","):
            stripped = part.strip()
            if stripped and value_is_a_person(stripped):
                begin = value_start + offset + part.index(stripped)
                spans.append((begin, begin + len(stripped), stripped))
            offset += len(part) + 1
    return spans


LABEL_LINE = re.compile(
    r"^[ \t]*(?P<label>[A-ZÀ-ÖØ-Þ][A-Za-zÀ-ÖØ-Þà-öø-ÿ.\- ]{1,24}?)"
    r"[ \t]*:[ \t]*(?P<value>.+?)[ \t]*$",
    re.MULTILINE,
)


def _agency_names(text: str) -> List[Span]:
    spans: List[Span] = []
    for pattern in (AGENCY_FRAME, CONTACT_FRAME):
        for match in pattern.finditer(text):
            candidate = match.group(1)
            if not _person_shaped(candidate):
                continue
            if not _frame_claim_survives_the_guards(
                text, match.start(1), match.end(1)
            ):
                continue
            spans.append((match.start(1), match.end(1), candidate))
    return spans


def _speaker_names(text: str) -> List[Span]:
    """`Name: sentence.`, but only in a document that says it is minutes."""
    lines = line_spans(text)
    if not any(MINUTES_HEADER.match(line) for _s, _e, line in lines):
        return []
    spans: List[Span] = []
    for match in SPEAKER_LINE.finditer(text):
        candidate = match.group(1)
        if _label_is_a_person_role(candidate):
            continue
        if _person_shaped(candidate):
            spans.append((match.start(1), match.end(1), candidate))
    return spans


PROBES = {
    "title": _title_names,
    "salutation": _salutation_names,
    "signature": _signature_names,
    "address": _address_names,
    "table": _table_names,
    "agency": _agency_names,
}

#: Order matters: the structural positions carry the most evidence, so they
#: claim first and win any overlap with a frame in prose.
_ORDER = (
    "title",
    "salutation",
    "address",
    "signature",
    "table",
    "agency",
)


# ---------------------------------------------------------------------------
# Measured and NOT shipped. The cost of each is in
# tests/test_name_layer_english.py, the same way the German option table is in
# tests/test_name_layer_precision.py. They stay out of PROBES.
# ---------------------------------------------------------------------------

LIST_HEADER = re.compile(
    r"^[ \t]*(?:Attendee[s]?(?:[ \t]+list)?|Participant[s]?(?:[ \t]+list)?|"
    r"Present|Distribution(?:[ \t]+list)?|Circulation|Invitees|Apologies)"
    r"[ \t]*:?[ \t]*$",
    re.IGNORECASE,
)


def _list_block_names(text: str) -> List[Span]:
    """Consecutive name-shaped lines under a person-list header."""
    spans: List[Span] = []
    lines = line_spans(text)
    inside = False
    for line_start, _line_end, line in lines:
        if LIST_HEADER.match(line):
            inside = True
            continue
        if not inside:
            continue
        if not line.strip():
            inside = False
            continue
        match = NAME_LINE.match(line)
        if match and _person_shaped(match.group(1)):
            spans.append((
                line_start + match.start(1),
                line_start + match.end(1),
                match.group(1),
            ))
        else:
            inside = False
    return spans


ATTRIBUTION = re.compile(
    rf"\b({_NAME})[ \t]+(?:said|says|wrote|writes|confirmed|confirms|advised|"
    rf"reported|requested|noted|asked|agreed|explained|added|resigned|"
    rf"apologised|apologized)\b"
)


def _attribution_names(text: str) -> List[Span]:
    spans: List[Span] = []
    for match in ATTRIBUTION.finditer(text):
        if _person_shaped(match.group(1)):
            spans.append((match.start(1), match.end(1), match.group(1)))
    return spans


CITATION = re.compile(rf"\b(?:See|see|[Cc]f\.)[ \t]+({_NAME})[ \t]*,")


def _citation_names(text: str) -> List[Span]:
    spans: List[Span] = []
    for match in CITATION.finditer(text):
        if _person_shaped(match.group(1)):
            spans.append((match.start(1), match.end(1), match.group(1)))
    return spans


def _name_line_names(text: str) -> List[Span]:
    """Any line that is only a name. The English form of German probe B."""
    spans: List[Span] = []
    for line_start, _line_end, line in line_spans(text):
        match = NAME_LINE.match(line)
        if match and _person_shaped(match.group(1)):
            spans.append((
                line_start + match.start(1),
                line_start + match.end(1),
                match.group(1),
            ))
    return spans


CANDIDATE_PROBES = {
    "label": _label_names,
    "speaker": _speaker_names,
    "list_block": _list_block_names,
    "attribution": _attribution_names,
    "citation": _citation_names,
    "name_line": _name_line_names,
}


def find_names(text: str) -> List[Span]:
    """Every English person name in *text* that a frame around it evidences."""
    spans: List[Span] = []
    for name in _ORDER:
        for start, end, _value in PROBES[name](text):
            claim(spans, start, end, text)
    spans.sort(key=lambda span: span[0])
    return spans


def find_names_by_probe(text: str) -> "dict[str, List[Span]]":
    return {name: probe(text) for name, probe in PROBES.items()}


RULESET = Ruleset(
    language="en",
    find=find_names,
    probes=PROBES,
    exclusions=EXCLUSIONS,
    markers=MARKERS,
    candidate_probes=CANDIDATE_PROBES,
)

registry.register(RULESET)
