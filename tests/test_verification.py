import pytest
from backend.rsa.key_generation import generate_rsa_keypair
from backend.verification.verifier import verify_messages, verify_rsa_roundtrip


@pytest.fixture(scope="module")
def keypairs():
    return {
        "valid": generate_rsa_keypair(2048),
        "alt": generate_rsa_keypair(2048),
    }


def test_verify_messages_match():
    res = verify_messages("Hello World", "Hello World")
    assert res["status"] == "VERIFICATION PASSED"
    assert res["passed"] is True
    assert res["original_sha256"] == res["decrypted_sha256"]


def test_verify_messages_mismatch():
    res = verify_messages("Hello World", "Different World")
    assert res["status"] == "VERIFICATION FAILED"
    assert res["passed"] is False
    assert res["original_sha256"] != res["decrypted_sha256"]


def test_verify_roundtrip_success(keypairs):
    msg = "Verification test message 12345"
    res = verify_rsa_roundtrip(
        msg,
        keypairs["valid"]["public_key_pem"],
        keypairs["valid"]["private_key_pem"],
    )
    assert res["status"] == "VERIFICATION PASSED"
    assert res["passed"] is True
    assert res["original_message"] == msg
    assert res["decrypted_message"] == msg
    assert res["original_sha256"] == res["decrypted_sha256"]


def test_verify_roundtrip_wrong_key(keypairs):
    msg = "Should fail roundtrip"
    res = verify_rsa_roundtrip(
        msg,
        keypairs["valid"]["public_key_pem"],
        keypairs["alt"]["private_key_pem"],
    )
    assert res["status"] == "VERIFICATION FAILED"
    assert res["passed"] is False
    assert res["error_phase"] == "decryption"


def test_verify_roundtrip_oversized_message(keypairs):
    msg = "A" * 1000
    res = verify_rsa_roundtrip(
        msg,
        keypairs["valid"]["public_key_pem"],
        keypairs["valid"]["private_key_pem"],
    )
    assert res["status"] == "VERIFICATION FAILED"
    assert res["passed"] is False
    assert res["error_phase"] == "encryption"
