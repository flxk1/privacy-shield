"""English business documents for measuring the name layer, per language.

Same two axes and the same development / held-out split as
`corpora_german.py`, and the same inline guillemet marking so a document and
its ground truth cannot drift apart.

WHY ENGLISH IS NOT GERMAN WITH A SWAPPED WORD LIST. German capitalises every
noun, so capitalisation carries no information and the German rules take names
only where a title, a signature, an addressee position or a known given name
says a person is being named. English does not capitalise nouns, so a
capitalised word in running prose IS evidence - of a proper noun. It is not
evidence of a PERSON: `Milton Keynes`, `Morgan Stanley`, `Land Rover`,
`Monday`, `Framework Agreement` and `Quality Assurance` are all capitalised
sequences in ordinary English business prose and none of them is personal data.

So the adversarial-clean corpus below is the one that decides the English
design, and it was written before the rules were: Title Case headings, product
names, place names, company names that are also person names, month and weekday
names, `Dear Sir or Madam`, signature blocks signed by departments, `Kind
regards` followed by a role, CC lists holding distribution lists, and subject
lines full of proper nouns.

Every name used is a documentation placeholder or an ordinary surname in the
way a textbook uses one. No real person's data is in this file.
"""

from __future__ import annotations

from corpora_german import strip_marks


def _build(marked_documents):
    return [strip_marks(marked) for marked in marked_documents]


# ---------------------------------------------------------------------------
# CLEAN: ordinary English business documents containing NO personal data.
# Every NAME finding on these is a false positive.
# ---------------------------------------------------------------------------

EN_CLEAN_DEV = [
    "Dear Sir or Madam,\n\nFurther to your letter of 14 March 2026, we confirm "
    "that the delivery\nwas completed within the agreed period.\n\n"
    "Kind regards\nCustomer Services",

    "Invoice\n\nInvoice number 2026-004871\nService period March 2026\n"
    "Payment terms 30 days net\nTotal due GBP 1,349.00",

    "Order Confirmation\n\nWe confirm your order for the supply of spare parts.\n"
    "Dispatch will be by pallet carrier.\nOur Standard Terms and Conditions "
    "apply in their current form.",

    "Internal Memorandum\n\nSubject: Change to the Filing Structure\n\n"
    "From the coming quarter all records will be captured digitally.\n"
    "The paper archive will be withdrawn. Please note the new folder layout.",

    "Quality Assurance Report\n\nScope: Annual Inspection\nOutcome: No Findings\n"
    "Next Inspection: March 2027\nInspection Body: Technical Surveillance",

    "Meeting Notes\n\nThe Steering Group reviewed the Framework Agreement and "
    "agreed to\nextend the Statement of Work to the end of the Financial Year.\n"
    "Actions were recorded against the Project Plan.",

    "Notice of Price Change\n\nWith effect from 1 July 2026 the list price of "
    "the Titan Pro 400\nand the Vantage Compact will increase by four per cent.\n"
    "Existing framework prices are unaffected until December.",

    "Delivery Note\n\nConsignment 88213-4\nCollected Tuesday, dispatched "
    "Wednesday\nCarrier: Overnight Freight\nCondition on arrival: Good",

    "Staff Notice\n\nThe office in Milton Keynes will close on Friday for "
    "planned\nmaintenance. Colleagues based in Reading and Swindon should work "
    "from\nhome. Access to the Birmingham site is unaffected.",

    "Terms of Reference\n\nThe Audit Committee shall meet four times a year.\n"
    "The Chair shall be appointed by the Board.\nQuorum shall be three "
    "members.\nMinutes shall be circulated to Finance and to Legal.",

    "Service Desk Update\n\nIncident INC-4471 has been closed. The root cause "
    "was a failed\nbattery in the Uninterruptible Power Supply at the Thames "
    "Valley\ndata centre. A replacement has been fitted.",

    "Purchase Requisition\n\nDepartment: Facilities\nCost Centre: 65000\n"
    "Supplier: Northstar Limited\nGoods: Replacement Seals\n"
    "Delivery Address: Unit 4, Eastgate Industrial Estate",
]

EN_CLEAN_HELD_OUT = [
    "Dear Sirs,\n\nWe acknowledge receipt of your tender for the Cleaning "
    "Services Lot Two.\nThe evaluation panel will report in May.\n\n"
    "Yours faithfully\nProcurement Team",

    "Credit Note\n\nCredit note number CN-2026-119\nAgainst invoice "
    "2026-004102\nReason: Short delivery\nAmount credited EUR 418.20",

    "Health and Safety Bulletin\n\nAll contractors must sign in at Reception "
    "before entering the Works.\nHigh visibility clothing is mandatory in the "
    "Yard.\nThe muster point is the North Car Park.",

    "Change Request\n\nTitle: Migration of the Reporting Database\n"
    "Priority: High\nStatus: Awaiting Approval\nTarget Release: Autumn",

    "Subject: Christmas and New Year Opening Hours\n\nThe warehouse will close "
    "on Christmas Eve and reopen on the second of\nJanuary. Orders placed after "
    "Friday will ship in the New Year.",

    "| Product           | Quantity | Status    |\n"
    "| Sealing Ring      | 200      | Open      |\n"
    "| Bolt Set          | 50       | Delivered |",

    "Site Survey\n\nLocation: Stratford upon Avon\nAccess: Via Bridge Street\n"
    "Constraints: Listed Building consent required\nSurvey Date: 4 February",

    "Escalation Notice\n\nThe outstanding actions on the Northern Depot fit-out "
    "remain open.\nThey were raised with Operations in January and with "
    "Facilities in\nFebruary. The matter is referred to the Programme Board.",
]

# ---------------------------------------------------------------------------
# ADVERSARIAL-CLEAN: English documents containing NO personal data, written to
# break the rule "capitalisation in running prose is evidence".
#
# Company names that are person names are the hardest class in English and are
# here on purpose: `Morgan Stanley`, `John Lewis Partnership`, `Marks and
# Spencer`, `Charles Schwab` have exactly the shape a name rule wants, and
# `Ernst & Young` is a pair of given names.
# ---------------------------------------------------------------------------

EN_CLEAN_ADVERSARIAL = [
    "Subject: Framework Agreement\nStatus: Open\nPriority: High",

    "Department: Sales\nLocation: Manchester\nCost Centre: 65000",

    "Supplier: Northstar Limited\nOrder Number: 4400218836\nStatus: Delivered",

    "Subject: Termination of the Northstar Contract\nDeadline: 30 June 2026",

    "Client: Example Public Limited Company\nContractor: Probe Engineering "
    "Limited\nContract Type: Works Contract",

    "From: Central Administration\nTo: All Staff\nCC: Technical Distribution "
    "List\nSubject: New Filing Structure",

    "Contact: Central Helpdesk\nOpening Hours: Monday to Friday\n"
    "Language: English",

    "Account Manager: Not yet appointed\nCaseworker: Vacant\n"
    "Handler: Automatic Assignment",

    "Attendees: All Heads of Department\nLocation: Large Meeting Room\n"
    "Start: Nine o'clock",

    "On behalf of: The Board\nEnquiries to: Customer Services North\n"
    "Effective: Immediately",

    "Scope: Maintenance of the Test Rig\nManufacturer: Pattern Machinery "
    "Limited\nYear of Manufacture: 2019",

    "Project: New Warehouse\nClient: Example Properties PLC\n"
    "Architect: Northern Design Practice\nStatus: In Progress",

    "The account was transferred to Morgan Stanley in April. Statements are\n"
    "issued by Charles Schwab and audited by Ernst & Young.",

    "We buy through the John Lewis Partnership and through Marks and Spencer.\n"
    "Land Rover supplies the site vehicles and Rolls Royce the generators.",

    "Travel to Paris is booked for Thursday. The team will continue to Milton\n"
    "Keynes on Friday and return from Frankfurt on Monday.",

    "The report was approved by Legal, signed by the Board and circulated to\n"
    "Finance. It was reviewed by Internal Audit and noted by the Audit "
    "Committee.",

    "Monday's meeting was moved to Wednesday. April's figures were confirmed "
    "by\nFinance and March's by Operations.",

    "The Thames Valley office reports to the Northern Region. Requests from\n"
    "Reading should be sent to Swindon and copied to Bristol.",

    "| Product           | Quantity | Status    |\n"
    "| Sealing Ring      | 200      | Open      |\n"
    "| Bolt Set          | 50       | Delivered |",

    "| Location          | Bay | Condition |\n"
    "| Manchester North  | 2   | Good      |\n"
    "| Milton Keynes     | 4   | Servicing |",

    "| Caseworker        | Region  | Status |\n"
    "| Not Allocated     | North   | Open   |\n"
    "| Vacant            | South   | Open   |",

    "| Part Number       | Description        | Stock |\n"
    "| 4029764001807     | Long Bolt          | 120   |\n"
    "| 4006381333931     | Short Nut          | 340   |",

    "Fault Report\n\nAsset: Conveyor Three\nFault Code: E 4711\n"
    "Shift: Early\nStatus: Cleared\nDuration: Two Hours",

    "Invitation to Tender\n\nContracting Authority: Borough of Eastgate\n"
    "Service: Cleaning of Administrative Buildings\nLot: Two\n"
    "Deadline: 14 May 2026",

    "Kind regards\nAccounts Payable\nShared Service Centre\n"
    "Northern Operations",

    "Best wishes\nThe Procurement Team\nHead Office",

    "Dear Hiring Manager,\n\nI am writing in response to the advertisement for "
    "the Quality\nEngineer vacancy.\n\nYours sincerely\nApplicant Reference "
    "4471",

    "Dear Customer,\n\nYour Broadband Plus service will be upgraded on Tuesday. "
    "No action\nis required.\n\nRegards\nService Operations",

    "Attn: Goods Inwards\nEastgate Industrial Estate\nUnit 4, Bridge Street\n"
    "Manchester M1 2AB",
]

# ---------------------------------------------------------------------------
# ADVERSARIAL-CLEAN, SECOND BATCH: written after the first measurement and
# aimed at the three probes the first batch did not attack, because they did
# not exist yet when it was written - the minutes SPEAKER line, the
# person-list block, and the citation frame. A probe measured only against
# documents that were not trying to break it is the mistake this programme
# already made once: probes A and D were approved on a zero that a wider
# corpus turned into 10 and 28 false-positive spans.
# ---------------------------------------------------------------------------

EN_CLEAN_ADVERSARIAL_PROBES = [
    # SPEAKER: a minutes document whose label lines are full sentences.
    "Minutes\n\nStatus: The work is complete.\nNext steps: The team will "
    "report in May.\nDecision: The Board approved the budget.",

    "Minutes of the meeting\n\nApologies: None were received.\n"
    "Finance: The forecast has been revised.\nOperations: Two shifts are "
    "running.",

    "Meeting notes\n\nQuality: The audit closed without findings.\n"
    "Procurement: The tender has been published.\nLegal: The contract is "
    "under review.",

    "Minutes\n\nEastgate: The site remains closed.\nNorthern Region: Two "
    "vehicles are off the road.\nThames Valley: Power has been restored.",

    # LIST BLOCK: a person-list header followed by lines that are not people.
    "Distribution list\nFinance\nProcurement\nInternal Audit\nQuality "
    "Assurance",

    "Attendees\nCentral Administration\nNorthern Operations\nShared Service "
    "Centre",

    "Present:\nThe Chair\nThe Company Secretary\nTwo Board Members",

    "Circulation\nAccounts Payable\nGoods Inwards\nFleet Transport",

    "Invitees\nNorthstar Limited\nExample Properties PLC\nProbe Engineering "
    "Limited",

    "Distribution list\nManchester North\nMilton Keynes\nStratford upon Avon",

    # CITATION: a reference that is not to a person.
    "See Appendix B, page 14, for the full specification.",

    "See Schedule 2, paragraph 4, and cf. Annex One, for the payment terms.",

    "See Attachment A, and see Drawing 4471, before starting work.",

    "See Section 7, the Framework Agreement, and the Standard Terms.",

    # AGENCY: document verbs followed by organisations rather than people.
    "The certificate was issued by Technical Surveillance and countersigned "
    "by Internal Audit.",

    "The survey was carried out by Northern Design Practice and reviewed by "
    "the Programme Board.",

    "The tender was prepared by Procurement, checked by Legal and approved by "
    "Finance.",

    "The report was compiled by Thames Valley and endorsed by Northern "
    "Region.",

    "Please contact Customer Services or contact Accounts Payable for a "
    "statement.",

    "On behalf of the Audit Committee and on behalf of Internal Audit we "
    "confirm receipt.",
]

# ---------------------------------------------------------------------------
# NAMED: English documents with names in the positions they really occur.
# ---------------------------------------------------------------------------

EN_NAMED_DEV_MARKED = [
    "Dear Mr «Ashcroft»,\n\nThank you for your letter of 3 April.\n\n"
    "Kind regards\n«Laura Whitfield»\nHead of Procurement",

    "Dear «Priya Raman»,\n\nThe documents have been sent out. Let me know if "
    "anything is missing.\n\nBest wishes\n«Tom Bradley»",

    "Attn: «Helen Ferreira»\nNorthstar Limited\n12 Bridge Street\n"
    "Manchester M1 2AB",

    "Dear Dr «Okonkwo»,\n\nThe inspection has been scheduled for Tuesday.\n\n"
    "Yours sincerely\n«Martin Cole»\nQuality Manager",

    "From: «Sarah Villanueva»\nTo: «Andrzej Nowak»\nCC: «Ingrid Bauer», "
    "«Marek Kowalski»\nSubject: Delivery date query",

    "The report was prepared by «Jane Elliott» and reviewed by «Nils Berg».",

    "| Reference | Caseworker        | Status |\n"
    "| 10        | «Ashcroft»        | open   |\n"
    "| 20        | «Ferreira»        | closed |",

    "Minutes\n\nPresent: «Laura Whitfield», «Tom Bradley», «Priya Raman»\n"
    "Apologies: «Nils Berg»\n\nThe Board noted the Framework Agreement.",

    "Please contact «Helen Ferreira» on extension 4471 with any questions.",

    "Yours faithfully\n«Katarzyna Lewandowska»\nCompany Secretary\n"
    "Northstar Limited",
]

EN_NAMED_HELD_OUT_MARKED = [
    "Dear Mrs «Hartley»,\n\nWe enclose the certificate for the annual "
    "inspection.\n\nYours sincerely\n«Owen Griffiths»\nTechnical Services",

    "Attn: «Liam O'Donnell»\nEastgate Works\nUnit 4, Mill Lane\n"
    "Bristol BS1 5TR",

    "Hello «Marta Kovacs»,\n\nThe revised drawings are attached.\n\n"
    "Regards\n«Ben»",

    "The audit was carried out by «Anneli Virtanen» and signed off by "
    "«Paul Mensah».",

    "From: «Owen Griffiths»\nTo: «Marta Kovacs»\nSubject: Site access on "
    "Thursday",

    "Prepared by: «Anneli Virtanen»\nApproved by: «Paul Mensah»\n"
    "Date: 4 February 2026",

    "Dear Professor «Lindqvist»,\n\nThank you for agreeing to chair the "
    "panel.\n\nKind regards\n«Elena Rossi»",

    "| Item | Reviewed by       | Outcome |\n"
    "| 1    | «Griffiths»       | pass    |\n"
    "| 2    | «Mensah»          | pass    |",
]

# ---------------------------------------------------------------------------
# INDEPENDENT-STYLE: the same name positions the German independent corpus
# specified from outside this work, written in English - after a colon, in a CC
# list, in an e-mail body with no title, in a footnote, in minutes with speaker
# attributions, in a table cell, in a subject line, and in running prose with
# no honorific. Non-Anglo names throughout, because English correspondence
# carries them and a rule gated on English given names would miss them.
# ---------------------------------------------------------------------------

EN_INDEPENDENT_MARKED = [
    "Caseworker: «Ashcroft»\nReference: 2026-4471",

    "From: «Priya Raman»\nTo: «Andrzej Nowak»\nCC: «Ingrid Bauer», "
    "«Marek Kowalski»\nSubject: Delivery date query",

    "Hi «Ruth Ebersbach»,\n\nthe documents are out. Shout if anything is "
    "missing.\n\nThanks\n«Tim»",

    "Subject: Handover to «Aleksandra Nowakowska»\n\nResponsibility transfers "
    "at the end of the month.",

    "Minutes\n\n«Wisniewski»: The date cannot be met.\n«Tanaka»: We will "
    "follow up with the figures.\n«Ebersbach»: Agreed.",

    "The analysis was produced by «Mateusz Wisniewski» and checked by "
    "«Yuki Tanaka».",

    "| Position | Handler           | Status |\n"
    "| 10       | «Ashcroft»        | open   |\n"
    "| 20       | «Ferreira»        | done   |",

    "Footnote 3: See «Kowalczyk», Opinion of 4 February 2026, page 17.",

    "Attendee list\n«Ingrid Bauer»\n«Marek Kowalski»\n«Priya Raman»",

    "On behalf of «Ruth Ebersbach» I am writing to confirm the new date.",

    "Enquiries to: «Tim Ashcroft», extension 4471.",
]

EN_NAMED_DEV = _build(EN_NAMED_DEV_MARKED)
EN_NAMED_HELD_OUT = _build(EN_NAMED_HELD_OUT_MARKED)
EN_INDEPENDENT = _build(EN_INDEPENDENT_MARKED)


# ---------------------------------------------------------------------------
# ADVERSARIAL-CLEAN, THIRD BATCH: a company with a member state's legal form
# standing where a person stands - signing a letter, receiving one, producing
# a document. No personal data in any of them.
#
# Written after an ablation showed that removing a 410-entry ISO 20275 table
# changed the false-positive count on the first two batches by ZERO - which
# was true and was an artefact of those batches, because not one of their 69
# documents had a foreign legal form in a signature block. This batch is the
# shape the ablation could not see.
# ---------------------------------------------------------------------------

EN_CLEAN_ADVERSARIAL_FOREIGN = [
    "Kind regards\nNordica Oy\nHelsinki",
    "Yours faithfully\nMediatech Kft\nBudapest",
    "Best wishes\nBaltic SIA\nRiga",
    "Attn: Tallinn OU\nEastgate Works\n12 Bridge Street\nBristol BS1 5TR",
    "The certificate was issued by Nordica Oy and countersigned by Praha AS.",
    "The survey was carried out by Vilnius UAB.",
    "Regards\nLisboa Lda",
    "Dear Aarhus ApS,\n\nWe acknowledge your tender.",
]
