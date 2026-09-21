"""
RSA Encryption Module
Implements standard RSA-OAEP encryption with SHA-256 digest and MGF1,
producing Base64-encoded ciphertext.
"""

import base64
import time
from typing import Dict, Any, Union
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization


def get_oaep_max_plaintext_length(key_size_bits: int, hash_len_bytes: int = 32) -> int:
    """
    Calculate maximum plaintext length in bytes for RSA-OAEP:
    max_len = floor(k / 8) - 2 * hLen - 2
    For SHA-256, hLen = 32 bytes.
    """
    key_bytes = key_size_bits // 8
    return key_bytes - (2 * hash_len_bytes) - 2


def encrypt_message(
    plaintext: Union[str, bytes],
    public_key_pem: str,
) -> Dict[str, Any]:
    """
    Encrypt a plaintext message using RSA-OAEP with SHA-256 and a PEM public key.

    Args:
        plaintext: String or bytes message to encrypt.
        public_key_pem: Standard PEM-encoded RSA public key string.

    Returns:
        Dict containing Base64 ciphertext, key size, metadata, and encryption time.

    Raises:
        ValueError: On empty input, invalid key, or message exceeding OAEP capacity.
    """
    if plaintext is None:
        raise ValueError("Plaintext cannot be None.")

    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode("utf-8")
    elif isinstance(plaintext, (bytes, bytearray)):
        plaintext_bytes = bytes(plaintext)
    else:
        raise ValueError("Plaintext must be a string or bytes.")

    if len(plaintext_bytes) == 0:
        raise ValueError("Plaintext message must not be empty.")

    if not public_key_pem or not isinstance(public_key_pem, str):
        raise ValueError("Invalid public key: PEM string must not be empty.")

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Failed to parse public key PEM: {str(exc)}") from exc

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Provided key is not an RSA public key.")

    key_size = public_key.key_size
    max_len = get_oaep_max_plaintext_length(key_size, hash_len_bytes=32)

    if len(plaintext_bytes) > max_len:
        raise ValueError(
            f"Message size ({len(plaintext_bytes)} bytes) exceeds maximum allowable "
            f"RSA-OAEP/SHA-256 capacity for a {key_size}-bit key ({max_len} bytes)."
        )

    # Standard RSA-OAEP with SHA-256 and MGF1(SHA-256)
    oaep_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

    start_time = time.perf_counter()
    ciphertext_bytes = public_key.encrypt(plaintext_bytes, oaep_padding)
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    b64_ciphertext = base64.b64encode(ciphertext_bytes).decode("ascii")

    return {
        "status": "success",
        "algorithm": "RSA-OAEP",
        "hash_algorithm": "SHA-256",
        "mgf": "MGF1 (SHA-256)",
        "key_size": key_size,
        "plaintext_bytes_length": len(plaintext_bytes),
        "ciphertext_base64": b64_ciphertext,
        "ciphertext_bytes_length": len(ciphertext_bytes),
        "encoding": "Base64",
        "encryption_time_ms": round(elapsed_ms, 3),
    }
