"""
Educational n-dimensional LWE-style lattice encryption module.

This implementation is intentionally small and educational. It is designed to
illustrate the core concepts of lattice-based public-key encryption in a
configurable n-dimensional setting:
  - public matrix A
  - secret vector s
  - small noise terms
  - public ciphertext samples (u, v)
  - decryption via secret-key linear relation

It is not a production cryptographic scheme and must not be used to protect
real data.
"""

from __future__ import annotations

import secrets
from typing import Any, Dict, List, Tuple


DEFAULT_LATTICE_PARAMETERS = {
    "dimension": 4,
    "modulus": 2**127 - 1,
    "message_modulus": 256,
    "noise_bound": 2,
    "samples": 8,
}


def _secure_int(low: int, high: int) -> int:
    if low >= high:
        return low
    return secrets.randbelow(high - low + 1) + low


def _random_small_vector(length: int, bound: int) -> List[int]:
    return [_secure_int(-bound, bound) for _ in range(length)]


def _secure_binary_vector(length: int) -> List[int]:
    return [secrets.randbelow(2) for _ in range(length)]


def _vector_dot(lhs: List[int], rhs: List[int]) -> int:
    return sum(a * b for a, b in zip(lhs, rhs))


def _matrix_vector_product(matrix: List[List[int]], vector: List[int], modulus: int) -> List[int]:
    if not matrix or not vector:
        raise ValueError("Matrix and vector must be non-empty.")
    if len(matrix[0]) != len(vector):
        raise ValueError("Matrix columns must match vector length.")

    result: List[int] = []
    for row in matrix:
        total = sum(a * x for a, x in zip(row, vector)) % modulus
        result.append(total)
    return result


def _transpose(matrix: List[List[int]]) -> List[List[int]]:
    if not matrix:
        return []
    return [list(column) for column in zip(*matrix)]


def _message_to_blocks(message: str, dimension: int) -> List[List[int]]:
    if not isinstance(message, str):
        raise TypeError("Plaintext must be a Python string.")
    raw_bytes = list(message.encode("utf-8"))
    if not raw_bytes:
        return []

    blocks: List[List[int]] = []
    for index in range(0, len(raw_bytes), dimension):
        block = raw_bytes[index:index + dimension]
        if len(block) < dimension:
            block.extend([0] * (dimension - len(block)))
        blocks.append(block)
    return blocks


def _reconstruct_message(blocks: List[List[int]]) -> str:
    raw = []
    for block in blocks:
        raw.extend(block)

    while raw and raw[-1] == 0:
        raw.pop()
    return bytes(raw).decode("utf-8", errors="strict")


def _centered_residue(value: int, modulus: int) -> int:
    residue = value % modulus
    return residue - modulus if residue > modulus // 2 else residue


def _nearest_message_symbol(value: int, scale: int, message_modulus: int) -> int:
    magnitude = abs(value)
    quotient = (magnitude + (scale // 2)) // scale
    rounded = quotient if value >= 0 else -quotient
    return rounded % message_modulus


def get_message_capacity(parameters: Dict[str, Any]) -> Dict[str, Any]:
    """Describe the actual byte-capacity semantics of the blockwise encoding."""
    config = validate_lattice_parameters(parameters)
    return {
        "maximum_plaintext_bytes": None,
        "capacity_type": "unbounded_by_lwe_parameters",
        "bytes_per_block": config["dimension"],
        "message_modulus": config["message_modulus"],
        "encoding": "UTF-8 bytes, grouped into blocks of n symbols",
        "padding": "zero padding in the final block; exact byte length is stored in the ciphertext",
        "explanation": (
            "This construction has no cryptographic plaintext-size limit: messages are split into "
            "additional independent blocks. Practical limits are system resource and transport limits."
        ),
    }


def validate_lattice_parameters(parameters: Dict[str, Any]) -> Dict[str, Any]:
    """Validate the educational LWE parameter set for the selected dimension."""
    if not isinstance(parameters, dict):
        raise ValueError("Lattice parameters must be provided as a dictionary.")

    dimension = int(parameters.get("dimension", DEFAULT_LATTICE_PARAMETERS["dimension"]))
    modulus = int(parameters.get("modulus", DEFAULT_LATTICE_PARAMETERS["modulus"]))
    message_modulus = int(parameters.get("message_modulus", DEFAULT_LATTICE_PARAMETERS["message_modulus"]))
    noise_bound = int(parameters.get("noise_bound", DEFAULT_LATTICE_PARAMETERS["noise_bound"]))
    samples = int(parameters.get("samples", DEFAULT_LATTICE_PARAMETERS["samples"]))

    if dimension <= 1 or dimension > 64:
        raise ValueError("Invalid dimension: must be an integer in the range [2, 64].")
    if modulus <= 1 or modulus % 2 == 0:
        raise ValueError("Invalid modulus: use an odd modulus larger than 1.")
    if message_modulus < 256:
        raise ValueError("Invalid message modulus: must be at least 256 for lossless UTF-8 byte encoding.")
    if message_modulus >= modulus:
        raise ValueError("The message modulus must be smaller than the lattice modulus for compatibility.")
    if noise_bound < 1:
        raise ValueError("Invalid noise bound: must be at least 1.")
    if samples < dimension:
        raise ValueError("Invalid number of samples: must be >= dimension for the educational construction.")

    scale = modulus // message_modulus
    if scale <= 0:
        raise ValueError(
            "Selected parameters are not mathematically compatible: "
            "floor(modulus / message_modulus) must be positive."
        )

    max_decryption_noise = (samples * noise_bound) + noise_bound + (dimension * noise_bound * noise_bound)
    decoding_threshold = scale / 2
    correctness_margin = decoding_threshold - max_decryption_noise
    if max_decryption_noise >= decoding_threshold:
        raise ValueError(
            "Selected parameters are not mathematically compatible: "
            "the bounded decryption noise must be less than half the message-level spacing."
        )

    return {
        "dimension": dimension,
        "modulus": modulus,
        "message_modulus": message_modulus,
        "noise_bound": noise_bound,
        "samples": samples,
        "message_scale": scale,
        "max_decryption_noise": max_decryption_noise,
        "decoding_threshold": decoding_threshold,
        "correctness_margin": correctness_margin,
        "correctness_guaranteed": True,
    }


def generate_lattice_keypair(dimension: int, parameters: Dict[str, Any] | None = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Generate an educational LWE-style keypair.

    Mathematical construction:
      A <- Z_q^(m x n)
      s <- Z_q^n with small coefficients
      e <- Z_q^m with small coefficients
      b = A * s + e (mod q)

    Public key: (A, b)
    Private key: s
    """
    config = validate_lattice_parameters(parameters or DEFAULT_LATTICE_PARAMETERS)
    if dimension != config["dimension"]:
        config = {**config, "dimension": dimension}
        config = validate_lattice_parameters(config)

    modulus = config["modulus"]
    noise_bound = config["noise_bound"]
    samples = config["samples"]

    A: List[List[int]] = []
    for _ in range(samples):
        A.append([_secure_int(0, modulus - 1) for _ in range(dimension)])

    secret = _random_small_vector(dimension, noise_bound)
    error = _random_small_vector(samples, noise_bound)

    b: List[int] = []
    for row_index in range(samples):
        total = 0
        for col_index in range(dimension):
            total += A[row_index][col_index] * secret[col_index]
        b.append((total + error[row_index]) % modulus)

    public_key = {
        "dimension": dimension,
        "modulus": modulus,
        "message_modulus": config["message_modulus"],
        "noise_bound": noise_bound,
        "samples": samples,
        "matrix_A": A,
        "vector_b": b,
        "correctness": {
            "message_scale": config["message_scale"],
            "max_decryption_noise": config["max_decryption_noise"],
            "decoding_threshold": config["decoding_threshold"],
            "margin": config["correctness_margin"],
            "guaranteed_under_bounded_noise": config["correctness_guaranteed"],
        },
        "description": (
            "Educational LWE-style public key: (A, b = A*s + e mod q). "
            "This is for demonstration and analysis only."
        ),
    }

    private_key = {
        "dimension": dimension,
        "modulus": modulus,
        "message_modulus": config["message_modulus"],
        "noise_bound": noise_bound,
        "samples": samples,
        "secret": secret,
        "correctness": public_key["correctness"],
        "description": "Educational LWE-style secret key: the small vector s.",
    }

    return public_key, private_key


def encrypt_lattice(plaintext: str, public_key: Dict[str, Any]) -> Dict[str, Any]:
    """
    Encrypt plaintext with a small, educational LWE-style construction.

    For each message block m = [m_0, ..., m_{n-1}], where each m_j is a byte or byte-like symbol,
    we create one independent LWE sample for each component j:

      u_j = A^T r_j + e1_j (mod q)
      v_j = b^T r_j + floor(q/p) * m_j + e2_j (mod q)

    The block is encoded as a vector of n integer symbols in Z_p^n; the scheme is generic in n.
    """
    if not isinstance(public_key, dict):
        raise TypeError("Public key must be a dictionary.")
    if plaintext is None:
        raise ValueError("Plaintext cannot be None.")

    dimension = int(public_key.get("dimension", DEFAULT_LATTICE_PARAMETERS["dimension"]))
    modulus = int(public_key.get("modulus", DEFAULT_LATTICE_PARAMETERS["modulus"]))
    samples = int(public_key.get("samples", DEFAULT_LATTICE_PARAMETERS["samples"]))
    message_modulus = int(public_key.get("message_modulus", DEFAULT_LATTICE_PARAMETERS["message_modulus"]))
    noise_bound = int(public_key.get("noise_bound", DEFAULT_LATTICE_PARAMETERS["noise_bound"]))

    config = validate_lattice_parameters({
        "dimension": dimension,
        "modulus": modulus,
        "message_modulus": message_modulus,
        "noise_bound": noise_bound,
        "samples": samples,
    })
    capacity = get_message_capacity(config)

    if dimension <= 1:
        raise ValueError("Public key dimension must be valid.")

    blocks = _message_to_blocks(plaintext, dimension)
    if not blocks:
        raise ValueError("Plaintext is empty and cannot be encrypted.")

    matrix_a = public_key.get("matrix_A")
    vector_b = public_key.get("vector_b")
    if not isinstance(matrix_a, list) or not isinstance(vector_b, list):
        raise ValueError("Public key is malformed: matrix_A and vector_b must be present.")

    ciphertexts: List[Dict[str, Any]] = []
    for block in blocks:
        if len(block) != dimension:
            raise ValueError("Each message block must have the configured dimension length.")

        independent_samples: List[Dict[str, Any]] = []
        for component_index, symbol in enumerate(block):
            if not 0 <= symbol < message_modulus:
                symbol = int(symbol) % message_modulus

            r = _secure_binary_vector(samples)
            e1 = _random_small_vector(dimension, noise_bound)
            e2 = _secure_int(-noise_bound, noise_bound)

            at_r = _matrix_vector_product(_transpose(matrix_a), r, modulus)
            u = [(value + e1[index]) % modulus for index, value in enumerate(at_r)]
            v = (_vector_dot(vector_b, r) + (modulus // message_modulus) * symbol + e2) % modulus

            independent_samples.append({
                "u": u,
                "v": v,
                "symbol": symbol,
                "component_index": component_index,
            })

        ciphertexts.append({
            "dimension": dimension,
            "message_block": list(block),
            "samples": independent_samples,
        })

    return {
        "status": "success",
        "encryption_type": "educational_lwe",
        "dimension": dimension,
        "modulus": modulus,
        "message_modulus": message_modulus,
        "noise_bound": noise_bound,
        "message_length_bytes": len(plaintext.encode("utf-8")),
        "padding_bytes": (dimension - (len(plaintext.encode("utf-8")) % dimension)) % dimension,
        "encoded_message_bytes": list(plaintext.encode("utf-8")),
        "block_count": len(blocks),
        "message_capacity": capacity,
        "correctness": {
            "message_scale": config["message_scale"],
            "max_decryption_noise": config["max_decryption_noise"],
            "decoding_threshold": config["decoding_threshold"],
            "margin": config["correctness_margin"],
            "guaranteed_under_bounded_noise": config["correctness_guaranteed"],
        },
        "ciphertexts": ciphertexts,
        "disclaimer": (
            "This uses a small educational lattice construction for demonstration only. "
            "It is not production cryptography."
        ),
    }


def decrypt_lattice(ciphertext: Dict[str, Any], private_key: Dict[str, Any]) -> str:
    """
    Decrypt the educational LWE ciphertext using the private key.

    For each LWE sample corresponding to a component of the message block:
      t = v - u^T s (mod q)
      m = round((p/q) * t) mod p
    """
    if not isinstance(ciphertext, dict):
        raise TypeError("Ciphertext must be a dictionary.")
    if not isinstance(private_key, dict):
        raise TypeError("Private key must be a dictionary.")

    if not isinstance(ciphertext.get("ciphertexts"), list):
        raise ValueError("Malformed ciphertext: missing ciphertext list.")

    dimension = int(private_key.get("dimension", DEFAULT_LATTICE_PARAMETERS["dimension"]))
    modulus = int(private_key.get("modulus", DEFAULT_LATTICE_PARAMETERS["modulus"]))
    samples = int(private_key.get("samples", DEFAULT_LATTICE_PARAMETERS["samples"]))
    secret = private_key.get("secret")
    if not isinstance(secret, list) or len(secret) != dimension:
        raise ValueError("Malformed private key: secret vector length does not match dimension.")

    message_modulus = int(ciphertext.get("message_modulus", DEFAULT_LATTICE_PARAMETERS["message_modulus"]))
    scale = modulus // message_modulus
    noise_bound = int(private_key.get("noise_bound", DEFAULT_LATTICE_PARAMETERS["noise_bound"]))
    validate_lattice_parameters({
        "dimension": dimension,
        "modulus": modulus,
        "message_modulus": message_modulus,
        "noise_bound": noise_bound,
        "samples": samples,
    })

    recovered_bytes: List[int] = []
    for block in ciphertext["ciphertexts"]:
        if not isinstance(block, dict):
            raise ValueError("Malformed ciphertext block.")

        samples = block.get("samples")
        if not isinstance(samples, list):
            raise ValueError("Malformed ciphertext block: missing component samples.")

        for sample in samples:
            if not isinstance(sample, dict):
                raise ValueError("Malformed ciphertext sample.")
            u = sample.get("u")
            v = sample.get("v")
            if not isinstance(u, list) or not isinstance(v, (int, float)):
                raise ValueError("Malformed ciphertext sample: invalid u/v data.")

            if len(u) != dimension:
                raise ValueError("Malformed ciphertext sample: u length does not match dimension.")

            t = _centered_residue(int(v) - _vector_dot(u, secret), modulus)
            recovered_value = _nearest_message_symbol(t, scale, message_modulus)
            recovered_bytes.append(int(recovered_value))

    message_length = ciphertext.get("message_length_bytes")
    if message_length is None:
        while recovered_bytes and recovered_bytes[-1] == 0:
            recovered_bytes.pop()
    else:
        message_length = int(message_length)
        if message_length < 0 or message_length > len(recovered_bytes):
            raise ValueError("Malformed ciphertext: invalid message length.")
        recovered_bytes = recovered_bytes[:message_length]

    return bytes(recovered_bytes).decode("utf-8", errors="strict")


def run_lattice_demo(message: str, dimension: int = 4) -> Dict[str, Any]:
    """Generate a demonstration payload for the educational lattice construction."""
    params = DEFAULT_LATTICE_PARAMETERS.copy()
    params["dimension"] = dimension
    params = validate_lattice_parameters(params)
    public_key, private_key = generate_lattice_keypair(dimension, params)

    ciphertext = encrypt_lattice(message, public_key)
    decrypted = decrypt_lattice(ciphertext, private_key)

    return {
        "status": "success",
        "dimension": dimension,
        "modulus": params["modulus"],
        "message": message,
        "encoded_vectors": ciphertext["ciphertexts"],
        "public_key": {
            "dimension": public_key["dimension"],
            "modulus": public_key["modulus"],
            "samples": public_key["samples"],
            "matrix_A": public_key["matrix_A"],
            "vector_b": public_key["vector_b"],
        },
        "ciphertext": ciphertext,
        "decrypted_message": decrypted,
        "verification": "PASS" if decrypted == message else "FAIL",
        "disclaimer": ciphertext["disclaimer"],
    }


__all__ = [
    "DEFAULT_LATTICE_PARAMETERS",
    "validate_lattice_parameters",
    "generate_lattice_keypair",
    "encrypt_lattice",
    "decrypt_lattice",
    "get_message_capacity",
    "run_lattice_demo",
]
