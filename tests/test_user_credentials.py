"""The credential store must never silently write or read a secret in
cleartext. Regression coverage for the ``key_salt="fallback"`` plaintext
downgrade that `reject_legacy_env()` alone did not stop, at the actual public
functions a caller uses (`add_credential`, `get_decrypted_key`,
`revalidate_credential`) rather than the private choke point directly.
"""
import json

import pytest

from privacy_shield._legacy_env import LEGACY_ENV, LegacyEnvironmentError
from privacy_shield import user_credentials as uc
from privacy_shield.user_credentials import (
    CredentialEncryptionUnavailable,
    add_credential,
    get_decrypted_key,
    revalidate_credential,
    update_credential,
)

OPENAI_KEY = "sk-" + "x" * 25


class _FakeFernet:
    """A minimal stand-in for cryptography.fernet.Fernet, so these tests
    exercise the LegacyEnvironmentError-propagation path itself without
    requiring the real `cryptography` package (not installed in this test
    environment, which is exactly the condition covered separately below by
    test_add_credential_raises_when_cryptography_is_unavailable)."""

    def __init__(self, key):
        self.key = key

    def encrypt(self, data: bytes) -> bytes:
        return b"FAKE:" + data

    def decrypt(self, token: bytes) -> bytes:
        assert token.startswith(b"FAKE:")
        return token[len(b"FAKE:"):]


@pytest.fixture()
def fake_fernet(monkeypatch):
    monkeypatch.setattr(uc, "Fernet", _FakeFernet)


def _no_fallback_records_written(user_root):
    store = user_root / "credentials"
    if not store.is_dir():
        return
    for f in store.glob("*.json"):
        for rec in json.loads(f.read_text()).values():
            assert rec.get("key_salt") != "fallback", f"plaintext credential written: {f}"


def _plant_credential(user_root, credential_id, *, key_salt, encrypted_key="ciphertext"):
    """Write a raw credential record directly, as if a prior (possibly
    corrupted) build had stored it — bypassing add_credential/_encrypt_key
    entirely, so key_salt can be any value including a corrupted one."""
    store = user_root / "credentials"
    store.mkdir(parents=True, exist_ok=True)
    (store / "alice.json").write_text(json.dumps({
        credential_id: {
            "credential_id": credential_id, "provider": "openai", "label": "x",
            "created_at": "now", "updated_at": "now", "encrypted_key": encrypted_key,
            "key_salt": key_salt,
        }
    }))


@pytest.mark.parametrize("legacy", sorted(LEGACY_ENV))
def test_add_credential_rejects_a_legacy_name(legacy, monkeypatch, tmp_path, fake_fernet):
    monkeypatch.setenv(legacy, "1")
    with pytest.raises(LegacyEnvironmentError, match=LEGACY_ENV[legacy]):
        add_credential("alice", "openai", OPENAI_KEY, validate=False, user_root=tmp_path)
    _no_fallback_records_written(tmp_path)


def test_get_decrypted_key_rejects_a_legacy_name(monkeypatch, tmp_path, fake_fernet):
    cred, err = add_credential("alice", "openai", OPENAI_KEY, validate=False, user_root=tmp_path)
    assert cred is not None, err
    assert cred.key_salt != "fallback"
    monkeypatch.setenv("BRAIN_CREDENTIALS_MASTER_KEY", "1")
    with pytest.raises(LegacyEnvironmentError, match="PRIVACY_SHIELD_CREDENTIALS_MASTER_KEY"):
        get_decrypted_key("alice", cred.credential_id, user_root=tmp_path)


def test_revalidate_credential_rejects_a_legacy_name(monkeypatch, tmp_path, fake_fernet):
    cred, err = add_credential("alice", "openai", OPENAI_KEY, validate=False, user_root=tmp_path)
    assert cred is not None, err
    monkeypatch.setenv("BRAIN_CREDENTIALS_MASTER_KEY", "1")
    with pytest.raises(LegacyEnvironmentError, match="PRIVACY_SHIELD_CREDENTIALS_MASTER_KEY"):
        revalidate_credential("alice", cred.credential_id, user_root=tmp_path)


def test_update_credential_does_not_touch_key_material(monkeypatch, tmp_path, fake_fernet):
    """update_credential only edits metadata (label/default_model/endpoint_url/
    organization_id); it never calls _encrypt_key/_decrypt_key, so a legacy
    name has nothing to trip here. Documented, not assumed: the coordinator's
    fix list named this function among the four to cover at the public
    boundary, but it is not on the encrypt/decrypt call path at all (grep
    confirms the only three callers of _encrypt_key/_decrypt_key are
    add_credential, revalidate_credential and get_decrypted_key)."""
    cred, err = add_credential("alice", "openai", OPENAI_KEY, validate=False, user_root=tmp_path)
    assert cred is not None, err
    monkeypatch.setenv("BRAIN_CREDENTIALS_MASTER_KEY", "1")
    updated = update_credential("alice", cred.credential_id, label="renamed", user_root=tmp_path)
    assert updated is not None and updated.label == "renamed"  # no raise: no key material touched


@pytest.mark.parametrize("bad_salt", ["not-hex!!", "abc"], ids=["non-hex", "odd-length"])
def test_get_decrypted_key_degrades_on_a_corrupted_salt(bad_salt, tmp_path, fake_fernet):
    """A corrupted/odd-length key_salt must degrade like 1.0.0 (None), not
    raise ValueError out of the public boundary — this is exactly the data
    revalidate_credential/get_decrypted_key exist to triage safely."""
    _plant_credential(tmp_path, "cred1", key_salt=bad_salt)
    assert get_decrypted_key("alice", "cred1", user_root=tmp_path) is None


@pytest.mark.parametrize("bad_salt", ["not-hex!!", "abc"], ids=["non-hex", "odd-length"])
def test_revalidate_credential_degrades_on_a_corrupted_salt(bad_salt, tmp_path, fake_fernet):
    _plant_credential(tmp_path, "cred1", key_salt=bad_salt)
    is_valid, error = revalidate_credential("alice", "cred1", user_root=tmp_path)
    assert is_valid is False and error == "Cannot decrypt key"


def test_add_credential_raises_when_cryptography_is_unavailable(monkeypatch, tmp_path):
    """Force the Fernet-unavailable condition explicitly (rather than relying
    on `cryptography` being absent from this environment's install, which is
    incidental and not guaranteed run to run) — proving the plaintext
    fallback is gone for the general case, not just the legacy-env-triggered
    one."""
    monkeypatch.setattr(uc, "Fernet", None)
    monkeypatch.setattr(uc, "_DEFAULT_USER_ROOT", tmp_path / "masterkey")  # isolate _master_secret_bytes' own state
    with pytest.raises(CredentialEncryptionUnavailable):
        add_credential("alice", "openai", OPENAI_KEY, validate=False, user_root=tmp_path)
    _no_fallback_records_written(tmp_path)


def test_get_decrypted_key_warns_on_a_pre_fix_fallback_record(tmp_path, fake_fernet, caplog):
    """A successful read of key_salt="fallback" is the only moment the
    system learns a secret sat in cleartext — it must not be silent."""
    _plant_credential(tmp_path, "cred1", key_salt="fallback",
                       encrypted_key=uc.base64.b64encode(OPENAI_KEY.encode()).decode())
    with caplog.at_level("WARNING", logger="privacy_shield.user_credentials"):
        result = get_decrypted_key("alice", "cred1", user_root=tmp_path)
    assert result == OPENAI_KEY
    assert any("cred1" in r.message and "cleartext" in r.message for r in caplog.records)


def test_revalidate_credential_re_encrypts_a_fallback_record_under_a_real_salt(tmp_path, fake_fernet, caplog):
    """revalidate_credential opportunistically re-encrypts a pre-fix
    plaintext record once it has the decrypted key in hand and is about to
    rewrite the record anyway — this is its own test, per the instruction
    that a re-encrypt decision needs one."""
    _plant_credential(tmp_path, "cred1", key_salt="fallback",
                       encrypted_key=uc.base64.b64encode(OPENAI_KEY.encode()).decode())
    with caplog.at_level("WARNING", logger="privacy_shield.user_credentials"):
        revalidate_credential("alice", "cred1", user_root=tmp_path)
    assert any("cred1" in r.message and "cleartext" in r.message for r in caplog.records)

    stored = json.loads((tmp_path / "credentials" / "alice.json").read_text())["cred1"]
    assert stored["key_salt"] != "fallback"
    # and it decrypts back to the same secret through the normal (non-fallback) path
    assert get_decrypted_key("alice", "cred1", user_root=tmp_path) == OPENAI_KEY


def test_add_credential_and_get_decrypted_key_round_trip_with_real_cryptography(tmp_path):
    """No fake_fernet fixture: exercises genuine cryptography.fernet.Fernet
    end to end, not the _FakeFernet stand-in every other test in this file
    uses. Skipped where `cryptography` is not installed (this repo's `dev`
    extra does not pull it in); CI's dedicated `.[dev,credentials]` leg
    always has it, so at least one leg exercises the real encrypt path."""
    pytest.importorskip("cryptography")
    cred, err = add_credential("alice", "openai", OPENAI_KEY, validate=False, user_root=tmp_path)
    assert cred is not None, err
    assert cred.key_salt != "fallback"
    assert get_decrypted_key("alice", cred.credential_id, user_root=tmp_path) == OPENAI_KEY
