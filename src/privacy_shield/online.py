"""Online and device identifiers, location coordinates and card security data.

GDPR Art. 4(1) names "an online identifier" and "location data" beside a
name. Each finder returns (start, end, value, kind); a labelled kind
("imei", "vin", "account", "cvv", "card_expiry") replaces whatever shape
another finder guessed for the same digits - an IMEI passes the card Luhn
check by design.
"""

from __future__ import annotations

import ipaddress
import re
from typing import List, Tuple

Hit = Tuple[int, int, str, str]

_OBFUSCATED_EMAIL = re.compile(
    r"(?<![\w.])[A-Za-z0-9._%+-]+[ \t]*(?:\[at\]|\(at\)|\{at\}|\[ät\])[ \t]*[A-Za-z0-9-]+"
    r"(?:[ \t]*(?:\[dot\]|\(dot\)|\{dot\}|\[punkt\]|\(punkt\)|\.)[ \t]*[A-Za-z0-9-]+)+",
    re.IGNORECASE,
)
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
_MAC = re.compile(r"(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}(?![0-9A-Fa-f:-])")
_DECIMAL_COORDS = re.compile(r"(?<![\d.])([-+]?\d{1,2}\.\d{4,})[ \t]*,[ \t]*([-+]?\d{1,3}\.\d{4,})(?![\d.])")
_DMS = r"\d{1,3}°[ \t]?\d{1,2}['′](?:[ \t]?\d{1,2}(?:[.,]\d+)?[\"″])?[ \t]?"
_DMS_COORDS = re.compile(_DMS + r"[NS][ \t,]+" + _DMS + r"[EOW]\b")
_PROFILE_URL = re.compile(
    # nothing of a domain before the host: "netflix.com" is not "x.com"
    r"(?<![A-Za-z0-9.-])(?:https?://)?(?:www\.)?(?:(?:twitter\.com|x\.com|instagram\.com|facebook\.com|tiktok\.com|threads\.net|"
    r"github\.com)/@?|linkedin\.com/in/|xing\.com/profile/)([A-Za-z0-9_.-]{2,})",
    re.IGNORECASE,
)
# a site's own pages, not a person
_SITE_PAGES = frozenset("""
features about pricing login signup settings topics explore marketplace search help home privacy
terms policies company jobs careers business solutions enterprise sponsors security apps trending
collections events watch reel p tos legal blog press developers docs i share hashtag intent
""".split())
_COORD_LABEL = re.compile(
    r"(?i)\b(?:gps|koordinaten|coordinates|standort|position|lat(?:itude)?|location|geo)\b[^\n]{0,20}$")
_HANDLE = re.compile(
    # "X" only as "X:" - "3 x @2x" is a size
    r"(?:\b(?i:Instagram|Twitter|TikTok|Telegram|Threads|Mastodon|Snapchat|Bluesky)[ \t]*[:(]?|\bX[ \t]*:)[ \t]*"
    r"(@[A-Za-z_][A-Za-z0-9_.]{1,29}(?:@[A-Za-z0-9.-]+\.[a-z]{2,})?)"
)
_CARD_CONTEXT = re.compile(
    r"(?i)\b(?:karte|kreditkarte|karteninhaber|kartennummer|card|visa|mastercard|amex|maestro|debitkarte)")
_LABELLED = [
    ("imei", r"IMEI", r"\d{15}"),
    ("vin", r"FIN|VIN|Fahrgestellnummer|Fahrzeug-?Identifizierungsnummer", r"[A-HJ-NPR-Z0-9]{17}"),
    ("account", r"Kontonummer|Konto-?Nr\.?|Kto\.?-?Nr\.?", r"\d{6,10}"),
    ("cvv", r"CVV2?|CVC2?|Kartenprüfnummer|Sicherheitscode", r"\d{3,4}"),
    ("card_expiry", r"gültig[ \t]+bis|Ablaufdatum|valid[ \t]+thru|expiry|exp\.", r"(?:0[1-9]|1[0-2])/(?:\d{2}|\d{4})"),
]
_LABELLED_RES = [
    (kind, re.compile(r"\b(?i:" + label + r")[ \t]*[:.]?[ \t]*(" + value + r")(?![A-Za-z0-9])"))
    for kind, label, value in _LABELLED
]
LABELLED_KINDS = frozenset(kind for kind, _l, _v in _LABELLED) | {"fediverse"}


def _luhn(digits: str) -> bool:
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d) * (2 if i % 2 else 1)
        total += n - 9 if n > 9 else n
    return total % 10 == 0


def find(text: str) -> List[Hit]:
    out: List[Hit] = []
    for m in _OBFUSCATED_EMAIL.finditer(text):
        out.append((m.start(), m.end(), m.group(0), "email"))
    for m in _IPV6.finditer(text):
        try:
            address = ipaddress.ip_address(m.group(0))
            # 2001:db8::/32 is reserved for documentation (RFC 3849)
            if address in ipaddress.ip_network("2001:db8::/32"):
                continue
            if address.version == 6 and m.group(0).count(":") >= 3:
                out.append((m.start(), m.end(), m.group(0), "ip"))
        except ValueError:
            continue
    for m in _MAC.finditer(text):
        # 00:00:… and ff:ff:… stand for no device
        if len(set(m.group(0).lower().replace(":", "").replace("-", ""))) == 1:
            continue
        out.append((m.start(), m.end(), m.group(0), "device"))
    for m in _DECIMAL_COORDS.finditer(text):
        lat, lon = m.group(1), m.group(2)
        if abs(float(lat)) > 90 or abs(float(lon)) > 180:
            continue
        # prices, versions, measurements and exchange rates carry up to five
        # decimals; an unlabelled position has six or more ("52.520008")
        precise = min(len(lat.split(".")[1]), len(lon.split(".")[1])) >= 6
        if precise or _COORD_LABEL.search(text[max(0, m.start() - 30):m.start()]):
            out.append((m.start(), m.end(), m.group(0), "geo"))
    for m in _DMS_COORDS.finditer(text):
        out.append((m.start(), m.end(), m.group(0), "geo"))
    for m in _PROFILE_URL.finditer(text):
        if m.group(1).lower().strip(".") in _SITE_PAGES:
            continue
        out.append((m.start(), m.end(), m.group(0), "online"))
    for m in _HANDLE.finditer(text):
        # "@erika@social.example.org" is a handle; the e-mail finder took the tail
        out.append((m.start(1), m.end(1), m.group(1), "fediverse" if m.group(1).count("@") == 2 else "online"))
    for kind, regex in _LABELLED_RES:
        for m in regex.finditer(text):
            if kind == "imei" and not _luhn(m.group(1)):
                continue
            # "Das Angebot ist gültig bis 12/2025" has no card in it
            if kind == "card_expiry" and not _CARD_CONTEXT.search(text[max(0, m.start() - 80):m.end() + 40]):
                continue
            out.append((m.start(1), m.end(1), m.group(1), kind))
    return out
