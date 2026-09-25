import pytest

from backend.lattice.educational_lwe import decrypt_lattice, encrypt_lattice
from backend.lattice.lattice_crypto_native import (
    decrypt_lattice_block_native,
    encrypt_lattice_block_native,
    generate_lattice_keypair_native,
    native_backend_available,
)


pytestmark = pytest.mark.skipif(
    not native_backend_available(),
    reason="Native LWE DLL is unavailable or blocked by operating-system application policy.",
)


def _parameters(dimension):
    return {
        "dimension": dimension,
        "modulus": 1000003,
        "message_modulus": 256,
        "noise_bound": 2,
        "samples": max(8, dimension),
    }


@pytest.mark.parametrize("dimension", [2, 4, 8])
def test_native_lattice_block_roundtrip(dimension):
    public_key, private_key = generate_lattice_keypair_native(_parameters(dimension))
    block = list(range(dimension))
    ciphertext = encrypt_lattice_block_native(block, public_key)
    assert decrypt_lattice_block_native(ciphertext, private_key) == block


def test_native_ciphertext_decrypts_with_python_reference():
    public_key, private_key = generate_lattice_keypair_native(_parameters(4))
    native_block = encrypt_lattice_block_native([65, 66, 67, 0], public_key)
    ciphertext = {
        "ciphertexts": [{"samples": native_block["samples"]}],
        "message_modulus": public_key["message_modulus"],
    }
    assert decrypt_lattice(ciphertext, private_key) == "ABC"


def test_python_ciphertext_decrypts_with_native_backend():
    public_key, private_key = generate_lattice_keypair_native(_parameters(4))
    ciphertext = encrypt_lattice("ABC", public_key)
    recovered = []
    for block in ciphertext["ciphertexts"]:
        recovered.extend(decrypt_lattice_block_native(block, private_key))
    assert bytes(recovered).rstrip(b"\x00").decode("utf-8") == "ABC"
