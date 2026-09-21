import pytest
import base64
from backend.rsa.key_generation import generate_rsa_keypair
from backend.rsa.encryption import encrypt_message, get_oaep_max_plaintext_length


@pytest.fixture(scope="module")
def sample_keypair():
    return generate_rsa_keypair(2048)


def test_encrypt_valid_message(sample_keypair):
    msg = "Hello, RSA-OAEP Test!"
    res = encrypt_message(msg, sample_keypair["public_key_pem"])

    assert res["status"] == "success"
    assert res["algorithm"] == "RSA-OAEP"
    assert res["hash_algorithm"] == "SHA-256"
    assert res["key_size"] == 2048
    assert res["plaintext_bytes_length"] == len(msg.encode("utf-8"))
    assert res["ciphertext_bytes_length"] == 256
    # Ciphertext must be valid base64 decoding to 256 bytes
    raw = base64.b64decode(res["ciphertext_base64"])
    assert len(raw) == 256


def test_encrypt_randomized_oaep(sample_keypair):
    msg = "Deterministic encryption check"
    res1 = encrypt_message(msg, sample_keypair["public_key_pem"])
    res2 = encrypt_message(msg, sample_keypair["public_key_pem"])
    assert res1["ciphertext_base64"] != res2["ciphertext_base64"], "OAEP must be randomized"


def test_encrypt_boundary_capacities():
    kp1024 = generate_rsa_keypair(1024)
    max_1024 = get_oaep_max_plaintext_length(1024)  # 62 bytes
    assert max_1024 == 62

    # Exactly max bytes should succeed
    exact_msg = "X" * max_1024
    res = encrypt_message(exact_msg, kp1024["public_key_pem"])
    assert res["status"] == "success"

    # Max + 1 bytes should fail
    overflow_msg = "X" * (max_1024 + 1)
    with pytest.raises(ValueError, match="exceeds maximum allowable"):
        encrypt_message(overflow_msg, kp1024["public_key_pem"])


def test_encrypt_empty_message(sample_keypair):
    with pytest.raises(ValueError, match="must not be empty"):
        encrypt_message("", sample_keypair["public_key_pem"])


def test_encrypt_invalid_public_key():
    with pytest.raises(ValueError, match="Failed to parse public key PEM"):
        encrypt_message("test", "INVALID_KEY_PEM")