import pytest
import base64
from backend.rsa.key_generation import generate_rsa_keypair
from backend.rsa.encryption import encrypt_message
from backend.rsa.decryption import decrypt_message


@pytest.fixture(scope="module")
def keypairs():
    return {
        "primary": generate_rsa_keypair(2048),
        "secondary": generate_rsa_keypair(2048),
    }


def test_decrypt_valid_ciphertext(keypairs):
    msg = "Confidential Academic Research Data"
    enc = encrypt_message(msg, keypairs["primary"]["public_key_pem"])
    dec = decrypt_message(enc["ciphertext_base64"], keypairs["primary"]["private_key_pem"])

    assert dec["status"] == "success"
    assert dec["decrypted_plaintext"] == msg
    assert dec["key_size"] == 2048
    assert dec["decryption_time_ms"] >= 0.0


def test_decrypt_wrong_key_fails(keypairs):
    msg = "Secret message"
    enc = encrypt_message(msg, keypairs["primary"]["public_key_pem"])
    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt_message(enc["ciphertext_base64"], keypairs["secondary"]["private_key_pem"])


def test_decrypt_corrupted_ciphertext_fails(keypairs):
    msg = "Integrity test"
    enc = encrypt_message(msg, keypairs["primary"]["public_key_pem"])
    raw = bytearray(base64.b64decode(enc["ciphertext_base64"]))
    raw[10] ^= 0xAA  # corrupt a byte
    corrupted_b64 = base64.b64encode(bytes(raw)).decode("ascii")

    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt_message(corrupted_b64, keypairs["primary"]["private_key_pem"])


def test_decrypt_invalid_base64(keypairs):
    with pytest.raises(ValueError, match="Invalid Base64"):
        decrypt_message("!! Not valid b64 !!", keypairs["primary"]["private_key_pem"])


def test_decrypt_wrong_modulus_length(keypairs):
    short_b64 = base64.b64encode(b"too_short").decode("ascii")
    with pytest.raises(ValueError, match="does not match the expected key modulus"):
        decrypt_message(short_b64, keypairs["primary"]["private_key_pem"])


def test_decrypt_empty_input(keypairs):
    with pytest.raises(ValueError, match="must be a non-empty"):
        decrypt_message("", keypairs["primary"]["private_key_pem"])
