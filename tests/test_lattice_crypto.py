import pytest

from backend.lattice.educational_lwe import (
    DEFAULT_LATTICE_PARAMETERS,
    generate_lattice_keypair,
    encrypt_lattice,
    decrypt_lattice,
    get_message_capacity,
    validate_lattice_parameters,
)


@pytest.mark.parametrize("dimension", [2, 3, 4, 8])
def test_lattice_roundtrip_for_multiple_dimensions(dimension):
    params = DEFAULT_LATTICE_PARAMETERS.copy()
    params["dimension"] = dimension
    params = validate_lattice_parameters(params)

    public_key, private_key = generate_lattice_keypair(dimension, params)

    for message in ["A", "HELLO", "Hello World", "12345"]:
        ciphertext = encrypt_lattice(message, public_key)
        decrypted = decrypt_lattice(ciphertext, private_key)
        assert decrypted == message, (dimension, message, decrypted)


@pytest.mark.parametrize("bad_dimension", [0, 1, -1, 1000])
def test_lattice_rejects_invalid_dimension(bad_dimension):
    with pytest.raises(ValueError, match="dimension"):
        validate_lattice_parameters({"dimension": bad_dimension, "modulus": 97, "message_modulus": 2, "noise_bound": 1})


@pytest.mark.parametrize(
    "params",
    [
        {"dimension": 2, "modulus": 7, "message_modulus": 2, "noise_bound": 2},
        {"dimension": 4, "modulus": 17, "message_modulus": 5, "noise_bound": 1},
    ],
)
def test_lattice_rejects_incompatible_parameters(params):
    with pytest.raises(ValueError, match="compatible|modulus|noise"):
        validate_lattice_parameters(params)


@pytest.mark.parametrize("bad_ciphertext", [None, {}, {"u": [1, 2], "v": 7}, {"u": "bad", "v": 7}])
def test_lattice_rejects_malformed_ciphertext(bad_ciphertext):
    with pytest.raises((ValueError, TypeError)):
        decrypt_lattice(bad_ciphertext, {"dimension": 2, "secret": [1, 2]})


@pytest.mark.parametrize("dimension", [2, 3, 4, 8])
def test_lattice_supports_unicode_message(dimension):
    params = DEFAULT_LATTICE_PARAMETERS.copy()
    params["dimension"] = dimension
    params = validate_lattice_parameters(params)

    public_key, private_key = generate_lattice_keypair(dimension, params)
    message = "π ≈ 3.14159"
    ciphertext = encrypt_lattice(message, public_key)
    assert decrypt_lattice(ciphertext, private_key) == message


def test_lattice_parameters_report_bounded_noise_correctness():
    parameters = validate_lattice_parameters({
        "dimension": 4,
        "modulus": 1000003,
        "message_modulus": 256,
        "noise_bound": 2,
        "samples": 8,
    })

    assert parameters["message_scale"] == 3906
    assert parameters["max_decryption_noise"] == 34
    assert parameters["correctness_margin"] > 0
    assert parameters["correctness_guaranteed"] is True


def test_lattice_block_encoding_does_not_require_message_modulus_power_below_q():
    parameters = validate_lattice_parameters({
        "dimension": 8,
        "modulus": 1000003,
        "message_modulus": 256,
        "noise_bound": 1,
        "samples": 8,
    })
    public_key, private_key = generate_lattice_keypair(8, parameters)

    assert decrypt_lattice(encrypt_lattice("LWE", public_key), private_key) == "LWE"


def test_lattice_key_metadata_matches_validated_parameters():
    parameters = validate_lattice_parameters({
        "dimension": 4,
        "modulus": 1000003,
        "message_modulus": 256,
        "noise_bound": 2,
        "samples": 8,
    })
    public_key, private_key = generate_lattice_keypair(4, parameters)

    for key in (public_key, private_key):
        assert key["message_modulus"] == 256
        assert key["noise_bound"] == 2
        assert key["samples"] == 8
        assert key["correctness"]["margin"] > 0


def test_lattice_message_length_preserves_trailing_zero_byte():
    parameters = validate_lattice_parameters({
        "dimension": 4,
        "modulus": 1000003,
        "message_modulus": 256,
        "noise_bound": 2,
        "samples": 8,
    })
    public_key, private_key = generate_lattice_keypair(4, parameters)
    message = "ABC\x00"
    ciphertext = encrypt_lattice(message, public_key)

    assert ciphertext["message_length_bytes"] == len(message.encode("utf-8"))
    assert decrypt_lattice(ciphertext, private_key) == message


def test_lattice_capacity_is_explicitly_unbounded_by_parameters():
    parameters = validate_lattice_parameters({
        "dimension": 3,
        "modulus": 1000003,
        "message_modulus": 256,
        "noise_bound": 2,
        "samples": 8,
    })
    capacity = get_message_capacity(parameters)

    assert capacity["maximum_plaintext_bytes"] is None
    assert capacity["capacity_type"] == "unbounded_by_lwe_parameters"
    assert capacity["bytes_per_block"] == 3


@pytest.mark.parametrize("message", ["", "A" * 128, "π" * 64, "LWE " * 1024])
def test_lattice_message_size_roundtrips_without_silent_truncation(message):
    if not message:
        with pytest.raises(ValueError, match="empty"):
            encrypt_lattice(message, generate_lattice_keypair(3, {**DEFAULT_LATTICE_PARAMETERS, "dimension": 3})[0])
        return

    parameters = validate_lattice_parameters({**DEFAULT_LATTICE_PARAMETERS, "dimension": 3})
    public_key, private_key = generate_lattice_keypair(3, parameters)
    ciphertext = encrypt_lattice(message, public_key)

    assert ciphertext["message_length_bytes"] == len(message.encode("utf-8"))
    assert decrypt_lattice(ciphertext, private_key) == message
