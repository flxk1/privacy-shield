import base64
import random

import pytest

from privacy_shield.gate import PrivacyGate, is_external_destination
from privacy_shield.runner import scan
from privacy_shield.scanner import PIIType, PrivacyScanner


def _verdict(text, destination="external_llm"):
    return PrivacyGate()._decide_local({"text": text}, destination)


@pytest.mark.parametrize("destination", ["OpenAI", "gemini", "deepseek", " openai", "Mistral", "", "x", None])
def test_unknown_and_unnormalised_destinations_are_external(destination):
    assert is_external_destination(destination) is True


@pytest.mark.parametrize("destination", ["ollama", "Local_LLM", "lm-studio", " localhost "])
def test_named_local_destinations_are_local(destination):
    assert is_external_destination(destination) is False


def test_health_text_to_an_unlisted_cloud_is_blocked():
    assert _verdict("Diagnose: Depression, Behandlung läuft.", "gemini").allowed is False


_RND = random.Random(20261009)


def _r(n, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"):
    return "".join(_RND.choice(alphabet) for _ in range(n))


_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_SECRETS = [
    "AKIA" + _r(16, _B32),
    "ghp_" + _r(36),
    "github_pat_" + _r(22) + "_" + _r(59),
    "glpat-" + _r(20),
    "xoxb-" + _r(11, "0123456789") + "-" + _r(12, "0123456789") + "-" + _r(24),
    "sk-ant-api03-" + _r(93) + "AA",
    "sk-proj-" + _r(74) + "T3BlbkFJ" + _r(74),
    "sk_live_" + _r(24),
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI" + _r(20) + "In0." + _r(43),
    "-----BEGIN RSA PRIVATE KEY-----\n" + _r(64) + "\n" + _r(64) + "\n-----END RSA PRIVATE KEY-----",
    "AIza" + _r(35),
    "npm_" + _r(36),
    "https://hooks.slack.com/services/T" + _r(8, _B32) + "/B" + _r(10, _B32) + "/" + _r(24),
    "postgres://app:" + _r(14) + "@db.internal:5432/main",
    "redis://:" + _r(16) + "@cache:6379",
    "Authorization: Bearer " + _r(40),
    "Authorization: Basic " + base64.b64encode(("alice:" + _r(14)).encode()).decode(),
]


_GUESSES = [
    'password = "' + _r(16) + '"',
    "Passwort: " + _r(18),
    "DB_PASSWORD=" + _r(10) + "#!" + _r(6) + "3",
    "Server=db;User Id=sa;Password=" + _r(12) + "%" + _r(3) + "5;",
    "client_secret: " + _r(12) + "@" + _r(5) + "1",
]


@pytest.mark.parametrize("guess", _GUESSES)
def test_label_and_entropy_guesses_are_redacted_but_do_not_block(guess):
    text = f"Konfiguration: {guess} bitte nicht teilen"
    findings = [f for f in PrivacyScanner().scan(text).findings if f.pii_type == PIIType.SECRET]
    assert findings and all(f.confidence.value == "medium" for f in findings)
    assert _verdict(text).allowed is True


@pytest.mark.parametrize("text", [
    "Key-Account: KA-Vertrieb-Sued-2026",
    "Access-Point: AP-Nord-3OG-07-Flur",
    "password: <Ihr-Passwort-2026>",
    "Passwort: https://intranet.example/pw-reset?ticket=42",
])
def test_german_look_alikes_never_block(text):
    assert _verdict(text).allowed is True


@pytest.mark.parametrize("secret", _SECRETS)
def test_secrets_are_found_and_block_external(secret):
    text = f"Konfiguration: {secret} bitte nicht teilen"
    assert PIIType.SECRET in [f.pii_type for f in PrivacyScanner().scan(text).findings]
    assert _verdict(text).allowed is False


@pytest.mark.parametrize("text", [
    "Das Passwort wird separat versandt.",
    "Passwort: mindestens zwölf Zeichen, Wechsel alle 90 Tage.",
    "Password: required",
    "access_token: abgelaufen",
    "Zugangsdaten: siehe Anlage 4",
    "ftp://anonymous:gast@ftp.example.org",
    "AKIAIOSFODNN7EXAMPLE",
    "Kennwort: Schulneubau2026",
    "Kennwort = Gemeindehaus",
    "Passwort: vergessen?",
    "pwd: /home/nutzer/projekt",
    "api_key: ${API_KEY}",
    "password: <your-password>",
    "Das Passwort ist vergessen worden.",
])
def test_labels_without_a_credential_value_are_not_secrets(text):
    assert PIIType.SECRET not in [f.pii_type for f in PrivacyScanner().scan(text).findings]


def test_utf16_with_bom_is_read_and_redacted(tmp_path):
    f = tmp_path / "brief.txt"
    f.write_bytes("Sehr geehrte Frau Dr. Hanna Roth,\nIBAN DE89370400440532013000".encode("utf-16"))
    doc = scan(str(f)).documents[0]
    assert "not fully read" not in (doc.blocked_reason or "")
    assert "Sehr geehrte" in (doc.overlay or "")
    assert "Hanna Roth" not in doc.overlay
    assert "DE89370400440532013000" not in doc.overlay


@pytest.mark.parametrize("name, payload", [
    ("blob.bin", b"\x00\x01\x02\x03binary\x00\xff"),
    ("data.xlsx", b"PK\x03\x04 not really a spreadsheet"),
    ("unmarked16.txt", "Hanna Roth".encode("utf-16-le")),
])
def test_unread_input_is_never_cleared(tmp_path, name, payload):
    f = tmp_path / name
    f.write_bytes(payload)
    doc = scan(str(f)).documents[0]
    assert doc.egress_allowed is False
    assert "not fully read" in (doc.blocked_reason or "")


def test_a_pdf_without_a_parser_is_never_cleared(tmp_path, monkeypatch):
    import privacy_shield.extractor as ex
    monkeypatch.setattr(ex, "HAS_PYMUPDF", False)
    import builtins
    real_import = builtins.__import__

    def no_pypdf(name, *a, **k):
        if name == "pypdf":
            raise ImportError("no pypdf")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_pypdf)
    f = tmp_path / "vertrag.pdf"
    f.write_bytes(b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF")
    doc = scan(str(f)).documents[0]
    assert doc.egress_allowed is False


@pytest.mark.parametrize("text", [
    'password = "aaaaaaaaaaaaaaaa1"',
    'password = "AbcdefghijkLMNOPqrstuvWx"',
    'password = "abcdefghijklmnopqrstuvwxyz0123"',
    'password = "Xq7Xq7Xq7Xq7Xq7Xq"',
    'password = "TrQvLmZpXkWbNcYdHs"',
    "Passwort: TrQvLmZpXkWbNcYdHs",
    "password: <Ihr-Passwort-2026>",
    "Passwort: https://intranet.example/pw-reset?ticket=42",
    "Basic Einstellungen: Standardwerte2026",
    "Authorization: Basic " + base64.b64encode(b"no-colon-here-2026").decode(),
])
def test_gitleaks_floors_entropy_digit_and_stopwords(text):
    from privacy_shield.credentials import find_credentials
    assert find_credentials(text) == []


def test_only_the_secret_is_redacted_not_its_label():
    from privacy_shield.credentials import find_credentials
    value = "Xq7Zt9Lm2PkW3vR8"
    [(start, end, found, _rule)] = find_credentials(f'password = "{value}"')
    assert found == value


@pytest.mark.parametrize("line", [
    "export GITHUB_TOKEN=ghp_" + _r(36),
    "token: ghp_" + _r(36),
    "STRIPE_KEY=sk_live_" + _r(24),
    "api_key: AKIA" + _r(16, _B32),
])
def test_a_labelled_issuer_key_still_blocks(line):
    assert _verdict(f"Konfiguration: {line}").allowed is False
