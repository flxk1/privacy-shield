"""Identifiers synthesised at runtime, with real check digits.

INPUT generators, not oracles. The leak gate's independence is about how a
candidate is FOUND and what decides whether it is valid; neither lives here.
What lives here is the construction of test material, and two copies of that
drift apart and go stale in exactly the way the duplicated IBAN registry did.

Nothing in this file is a literal identifier. Every value is built from a
seeded generator and closed with a computed check digit, so no test fixture
carries a number that could ever have been issued to anybody.
"""

from __future__ import annotations

import random
from typing import Dict

#: A spread of registered IBAN countries and their registered total lengths,
#: so a battery built from this is not all one national format.
#:
#: Deliberately unchanged from the list the leak gate's battery was measured
#: against: widening it reshuffles every document the deterministic battery
#: draws, which would make this round's evidence incomparable with the last
#: one's for no gain. A country a case needs and this does not have is passed
#: to `make_iban` explicitly.
IBAN_COUNTRIES: Dict[str, int] = {
    "DE": 22, "AT": 20, "NL": 18, "BE": 16, "ES": 24, "IT": 27, "NO": 15,
}


def make_iban(rng: random.Random, country: str = "DE") -> str:
    """A syntactically real IBAN for *country*, with a computed check digit."""
    bban = "".join(rng.choice("0123456789") for _ in range(IBAN_COUNTRIES[country] - 4))
    rotated = bban + "".join(str(int(ch, 36)) for ch in country) + "00"
    check = 98 - int(rotated) % 97
    return f"{country}{check:02d}{bban}"


def make_card(rng: random.Random, length: int = 16) -> str:
    """A Luhn-closed digit string of *length* digits."""
    body = "4" + "".join(rng.choice("0123456789") for _ in range(length - 2))
    total = 0
    for index, char in enumerate(reversed(body)):
        value = int(char)
        if index % 2 == 0:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return body + str((10 - total % 10) % 10)


def make_email(rng: random.Random) -> str:
    local = rng.choice(["abcdef1234", "erika.mustermann", "m.mueller", "deadbeef99"])
    return f"{local}@{rng.choice(['example.com', 'kanzlei.de', 'firma.org'])}"
