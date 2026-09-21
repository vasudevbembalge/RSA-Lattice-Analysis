"""
RSA Decryption Module
Implements standard RSA-OAEP decryption with SHA-256 digest, Base64 decoding,
and comprehensive error handling (corrupted ciphertext, wrong keys, encoding issues).
"""

import base64
import binascii
import time
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization


def decrypt_message(
    ciphertext_base64: str,
    private_key_pem: str,
    password: Optional[bytes] = None,
) -> Dict[str, Any]:
    """
    Decrypt a Base64-encoded ciphertext using RSA-OAEP with SHA-256 and a PEM private key.

    Args:
        ciphertext_base64: Base64-encoded ciphertext string.
        private_key_pem: Standard PEM-encoded RSA private key string.
        password: Optional passphrase if private key is encrypted.

    Returns:
        Dict containing decrypted plaintext string, metadata, and decryption time.

    Raises:
        ValueError: On invalid Base64, corrupted ciphertext, wrong key, or padding error.
    """
    if not ciphertext_base64 or not isinstance(ciphertext_base64, str):
        raise ValueError("Ciphertext must be a non-empty Base64-encoded string.")

    # 1. Base64 Decoding
    try:
        ciphertext_bytes = base64.b64decode(ciphertext_base64.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"Invalid Base64 ciphertext encoding: {str(exc)}") from exc

    if len(ciphertext_bytes) == 0:
        raise ValueError("Ciphertext contains 0 decoded bytes.")

    # 2. Private Key Parsing
    if not private_key_pem or not isinstance(private_key_pem, str):
        raise ValueError("Invalid private key: PEM string must not be empty.")

    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=password,
        )
    except Exception as exc:
        raise ValueError(f"Failed to parse private key PEM: {str(exc)}") from exc

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Provided key is not an RSA private key.")

    # 3. Modulus size check
    expected_cipher_len = private_key.key_size // 8
    if len(ciphertext_bytes) != expected_cipher_len:
        raise ValueError(
            f"Ciphertext length ({len(ciphertext_bytes)} bytes) does not match the expected "
            f"key modulus length for a {private_key.key_size}-bit RSA key ({expected_cipher_len} bytes)."
        )

    # 4. RSA-OAEP Decryption with SHA-256 and MGF1(SHA-256)
    oaep_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

    start_time = time.perf_counter()
    try:
        decrypted_bytes = private_key.decrypt(ciphertext_bytes, oaep_padding)
    except Exception as exc:
        raise ValueError(
            "Decryption failed: Ciphertext is corrupted, invalid, or was encrypted with a different key."
        ) from exc
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    try:
        plaintext = decrypted_bytes.decode("utf-8")
    except UnicodeDecodeError:
        plaintext = decrypted_bytes.decode("latin-1")

    return {
        "status": "success",
        "algorithm": "RSA-OAEP",
        "hash_algorithm": "SHA-256",
        "mgf": "MGF1 (SHA-256)",
        "key_size": private_key.key_size,
        "decrypted_plaintext": plaintext,
        "plaintext_bytes_length": len(decrypted_bytes),
        "decryption_time_ms": round(elapsed_ms, 3),
    }
