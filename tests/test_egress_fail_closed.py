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


@pytest.mark.parametrize("text", [
    "Konfession: rk",
    "Kirchensteuermerkmal ev",
    "Herr Kowalski ist Mitglied der IG Metall.",
    "Sie ist Mitglied der SPD.",
    "Aufnahme auf Station Onkologie, Herr Brandt.",
    "Diagnose F32.1 Depression",
    "Long-COVID U09.9",
    "Er ist Kommunist.",
])
def test_art9_content_is_not_cleared(text):
    assert _verdict(text).allowed is False


@pytest.mark.parametrize("text", [
    "Nach Wahl des Vermieters wird die Wohnung links übergeben.",
    "Die Parteien vereinbaren den Stellplatz links der Zufahrt.",
    "Option nach Wahl des Käufers.",
    "Siehe Anlage A12.3 und Version M51.2.",
    "Bitte rechts oben unterschreiben.",
])
def test_contract_wording_is_not_art9(text):
    assert PrivacyGate().check_art9(text) == []


@pytest.mark.parametrize("secret", [
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_" + "a" * 36,
    "github_pat_" + "B" * 50,
    "glpat-" + "c" * 20,
    "xoxb-" + "1234567890-abcdef",
    "sk-ant-" + "d" * 30,
    "sk-proj-" + "e" * 30,
    "sk_live_" + "f" * 24,
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abcdefghijk",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
    "Passwort: Sommer2026!",
    "api_key=abcd1234efgh",
])
def test_secrets_are_found_and_block_external(secret):
    text = f"Konfiguration: {secret} bitte nicht teilen"
    assert PIIType.SECRET in [f.pii_type for f in PrivacyScanner().scan(text).findings]
    assert _verdict(text).allowed is False


def test_ordinary_words_after_password_label_need_a_value():
    assert PIIType.SECRET not in [f.pii_type for f in PrivacyScanner().scan("Das Passwort wird separat versandt.").findings]


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
