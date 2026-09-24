"""A table's header is evidence about THAT table.

"Use the column header as the evidence" transfers across languages - a header
is layout, not vocabulary - so the probe is shared (`shared.table_probe`) and
both German and English use it. That makes a bug in it a bug in every
language, which is what happened: one `seen_header` flag was held over the
whole document and never reset, so the FIRST table's header decided every
later table's columns.

The two consequences, both measured below: a parts table following a handler
table had its product column claimed as people, and a handler table following
a parts table was not read at all. Over-redaction in one direction and a
missed name in the other, from one flag.
"""

from __future__ import annotations

import pytest

from privacy_shield.name_layer import de, en

GERMAN_PERSON_TABLE = (
    "| Position | Bearbeiter | Status |\n"
    "| 10       | Osterloh   | offen  |\n"
)
GERMAN_PARTS_TABLE = (
    "| Produkt       | Menge | Status |\n"
    "| Dichtungsring | 200   | offen  |\n"
)
ENGLISH_PERSON_TABLE = (
    "| Reference | Caseworker | Status |\n"
    "| 10        | Ashcroft   | open   |\n"
)
ENGLISH_PARTS_TABLE = (
    "| Product      | Quantity | Status |\n"
    "| Sealing Ring | 200      | Open   |\n"
)


@pytest.mark.parametrize(
    "language, person_table, parts_table, expected",
    [
        ("de", GERMAN_PERSON_TABLE, GERMAN_PARTS_TABLE, ["Osterloh"]),
        ("en", ENGLISH_PERSON_TABLE, ENGLISH_PARTS_TABLE, ["Ashcroft"]),
    ],
)
def test_each_table_carries_its_own_header(
    language, person_table, parts_table, expected
):
    """Both orders, in both languages. The bug was order-dependent."""
    module = de if language == "de" else en
    person_first = f"{person_table}\n{parts_table}"
    parts_first = f"{parts_table}\n{person_table}"
    assert [v for _s, _e, v in module.find_names(person_first)] == expected
    assert [v for _s, _e, v in module.find_names(parts_first)] == expected


def test_a_parts_table_after_a_person_table_keeps_its_product_column():
    """The over-redaction half, named: `Dichtungsring` is a sealing ring."""
    document = f"{GERMAN_PERSON_TABLE}\n{GERMAN_PARTS_TABLE}"
    claimed = [v for _s, _e, v in de.find_names(document)]
    assert "Dichtungsring" not in claimed, claimed
    assert "Menge" not in claimed, claimed


def test_a_person_table_after_a_parts_table_is_still_read():
    """The missed-name half, named."""
    document = f"{GERMAN_PARTS_TABLE}\n{GERMAN_PERSON_TABLE}"
    assert [v for _s, _e, v in de.find_names(document)] == ["Osterloh"]


def test_three_tables_are_three_headers():
    document = (
        f"{GERMAN_PARTS_TABLE}\n{GERMAN_PERSON_TABLE}\n"
        "| Standort | Halle |\n| Muenchen | 4 |\n"
    )
    assert [v for _s, _e, v in de.find_names(document)] == ["Osterloh"]


def test_a_heading_between_two_tables_also_ends_the_first():
    """A table ends where the pipe rows stop, whatever stopped them."""
    document = (
        f"{GERMAN_PERSON_TABLE}"
        "Anlage 2\n"
        f"{GERMAN_PARTS_TABLE}"
    )
    claimed = [v for _s, _e, v in de.find_names(document)]
    assert claimed == ["Osterloh"], claimed


def test_one_table_with_many_rows_keeps_its_header():
    """The reset must not be so eager that a long table loses its header."""
    document = (
        "| Position | Bearbeiter | Status |\n"
        "| 10       | Osterloh   | offen  |\n"
        "| 20       | Domke      | fertig |\n"
        "| 30       | Thelen     | offen  |\n"
    )
    assert [v for _s, _e, v in de.find_names(document)] == [
        "Osterloh",
        "Domke",
        "Thelen",
    ]
