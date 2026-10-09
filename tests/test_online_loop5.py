import pytest

from privacy_shield.runner import scan


@pytest.mark.parametrize("text, hidden", [
    ("Mail: max.mustermann [at] example [dot] org", "mustermann"),
    ("max(at)example.org", "example"),
    ("IPv6 2001:db8:85a3::8a2e:370:7334", "8a2e"),
    ("MAC 00:1A:2B:3C:4D:5E", "4D:5E"),
    ("Standort 52.520008, 13.404954", "13.404954"),
    ("GPS: 52.5200, 13.4049", "13.4049"),
    ("GPS: 48°08'N 11°34'E", "11°34"),
    ("Kontonummer 1234567890", "1234567890"),
    ("Instagram: @max_mustermann", "max_mustermann"),
    ("IMEI 490154203237518", "490154203237518"),
    ("FIN WVWZZZ1JZ3W386752", "386752"),
    ("Twitter https://twitter.com/maxmuster", "maxmuster"),
    ("LinkedIn linkedin.com/in/max-mustermann-123", "mustermann"),
])
def test_online_device_and_location_identifiers_are_masked(text, hidden):
    assert hidden not in scan(text).documents[0].overlay


def test_a_card_security_code_blocks():
    doc = scan("Karte gültig bis 12/27, CVV 123").documents[0]
    assert doc.egress_allowed is False and "123" not in doc.overlay and "12/27" not in doc.overlay


@pytest.mark.parametrize("text", [
    "Uhrzeit 12:30:45", "Version 1.2345, 6.7890", "Wir treffen uns at 5",
    "Preis 12.5000, 3.4000 EUR", "Siehe https://github.com/features", "linkedin.com/company/acme",
])
def test_online_look_alikes_stay(text):
    assert scan(text).documents[0].overlay == text


@pytest.mark.parametrize("text, placeholder", [
    ("IMEI 490154203237518", "[DEVICE]"),
    ("Standort 52.520008, 13.404954", "[GEO]"),
    ("Kontonummer 1234567890", "[IBAN]"),
])
def test_a_label_or_coordinate_settles_the_type(text, placeholder):
    assert placeholder in scan(text).documents[0].overlay
