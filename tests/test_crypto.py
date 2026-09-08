import pytest
from cryptography.exceptions import InvalidTag
from password_manager.crypto_utils import generate_salt, derive_key, encrypt, decrypt, generate_password

def test_key_derivation_is_deterministic():
    salt = generate_salt()
    assert derive_key("correct horse battery", salt) == derive_key("correct horse battery", salt)

def test_salt_changes_key():
    assert derive_key("same password", generate_salt()) != derive_key("same password", generate_salt())

def test_encrypt_roundtrip_and_tamper_detection():
    key = derive_key("test password", generate_salt())
    blob = encrypt(key, b"secret")
    assert decrypt(key, blob) == b"secret"
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(InvalidTag): decrypt(key, tampered)

def test_password_generator_length():
    assert len(generate_password(24)) == 24
