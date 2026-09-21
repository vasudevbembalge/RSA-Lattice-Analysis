import pytest
from backend.rsa.key_generation import (
    generate_rsa_keypair,
    SUPPORTED_KEY_SIZES,
    DEFAULT_KEY_SIZE,
    PUBLIC_EXPONENT,
)
from backend.rsa.key_info import get_public_key_info, get_private_key_info


def test_rsa_keygen_default():
    result = generate_rsa_keypair()
    assert result["status"] == "success"
    assert result["key_size"] == DEFAULT_KEY_SIZE
    assert result["public_exponent"] == PUBLIC_EXPONENT
    assert "BEGIN PUBLIC KEY" in result["public_key_pem"]
    assert "BEGIN PRIVATE KEY" in result["private_key_pem"]
    assert result["generation_time_ms"] >= 0.0


@pytest.mark.parametrize("key_size", [1024, 2048])
def test_rsa_keygen_supported_sizes(key_size):
    result = generate_rsa_keypair(key_size)
    assert result["key_size"] == key_size
    assert result["public_exponent"] == 65537
    assert len(result["public_key_pem"]) > 0
    assert len(result["private_key_pem"]) > 0


@pytest.mark.parametrize("invalid_size", [0, -1, 512, 999, 1500, 8192])
def test_rsa_keygen_unsupported_sizes(invalid_size):
    with pytest.raises(ValueError, match="Unsupported key size"):
        generate_rsa_keypair(invalid_size)


def test_rsa_key_info_extraction():
    keypair = generate_rsa_keypair(1024)
    pub_info = get_public_key_info(keypair["public_key_pem"])
    assert pub_info["algorithm"] == "RSA"
    assert pub_info["key_type"] == "Public Key"
    assert pub_info["key_size"] == 1024
    assert pub_info["public_exponent"] == 65537
    assert "PEM" in pub_info["format"]

    priv_info = get_private_key_info(keypair["private_key_pem"])
    assert priv_info["algorithm"] == "RSA"
    assert priv_info["key_type"] == "Private Key"
    assert priv_info["key_size"] == 1024
    assert priv_info["public_exponent"] == 65537


def test_rsa_key_info_invalid_pem():
    with pytest.raises(ValueError):
        get_public_key_info("NOT_A_VALID_PEM")

    with pytest.raises(ValueError):
        get_private_key_info("NOT_A_VALID_PEM")

    with pytest.raises(ValueError):
        get_public_key_info("")
