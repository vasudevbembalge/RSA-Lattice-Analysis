"""
RSA Key Generation Module
Provides standard, cryptographically secure RSA key pair generation using
the Python cryptography library (OpenSSL backend).
"""

import time
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Standard supported key bit sizes for academic and production demonstration
SUPPORTED_KEY_SIZES: Tuple[int, ...] = (1024, 2048, 3072, 4096)
DEFAULT_KEY_SIZE: int = 2048
PUBLIC_EXPONENT: int = 65537  # Standard Fermat F4 exponent


def generate_rsa_keypair(key_size: int = DEFAULT_KEY_SIZE) -> Dict[str, Any]:
    """
    Generate an RSA public and private key pair with standard PEM serialization.

    Args:
        key_size: Size of the RSA modulus in bits (1024, 2048, 3072, or 4096).

    Returns:
        Dict containing public and private PEM strings, key size, exponent, and generation time.

    Raises:
        ValueError: If key_size is not in SUPPORTED_KEY_SIZES.
    """
    if key_size not in SUPPORTED_KEY_SIZES:
        raise ValueError(
            f"Unsupported key size: {key_size}. Supported key sizes are: {list(SUPPORTED_KEY_SIZES)}."
        )

    start_time = time.perf_counter()

    # Generate cryptographically secure RSA private key using OS entropy pool
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=key_size,
    )

    elapsed_time_ms = (time.perf_counter() - start_time) * 1000.0

    public_key = private_key.public_key()

    # Standard PKCS#8 serialization for private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    # Standard SubjectPublicKeyInfo (X.509) serialization for public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return {
        "status": "success",
        "key_size": key_size,
        "public_exponent": PUBLIC_EXPONENT,
        "generation_time_ms": round(elapsed_time_ms, 3),
        "public_key_pem": public_pem,
        "private_key_pem": private_pem,
    }
