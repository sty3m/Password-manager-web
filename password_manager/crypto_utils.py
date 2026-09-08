import os
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ITERATIONS = 600_000
SALT_SIZE_BYTES = 16
KEY_SIZE_BYTES = 32
NONCE_SIZE_BYTES = 12

def generate_salt() -> bytes:
    return secrets.token_bytes(SALT_SIZE_BYTES)

def derive_key(master_password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    if not isinstance(master_password, str) or master_password == "":
        raise ValueError("master_password must be a non-empty string")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_SIZE_BYTES, salt=salt, iterations=iterations)
    return kdf.derive(master_password.encode("utf-8"))

def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    nonce = os.urandom(NONCE_SIZE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, associated_data)

def decrypt(key: bytes, data: bytes, associated_data: bytes = b"") -> bytes:
    if len(data) < NONCE_SIZE_BYTES:
        raise ValueError("Ciphertext too short to contain a valid nonce")
    return AESGCM(key).decrypt(data[:NONCE_SIZE_BYTES], data[NONCE_SIZE_BYTES:], associated_data)

def generate_password(length: int = 20, use_symbols: bool = True) -> str:
    if length < 8:
        raise ValueError("Password length should be at least 8 characters")
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?/"
    return "".join(secrets.choice(alphabet) for _ in range(length))
