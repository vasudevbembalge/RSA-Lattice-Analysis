"""
RSA Key Information Module
Extracts and formats non-sensitive public and administrative metadata
from PEM-encoded RSA keys.
"""

from typing import Dict, Any
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def get_public_key_info(public_key_pem: str) -> Dict[str, Any]:
    """
    Parse a PEM-encoded public key and extract its metadata.

    Args:
        public_key_pem: Standard PEM string of the public key.

    Returns:
        Dict with public key characteristics (algorithm, key type, size, exponent, format).
    """
    if not public_key_pem or not isinstance(public_key_pem, str):
        raise ValueError("Invalid public key: PEM string must not be empty.")

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Failed to parse public key PEM: {str(exc)}") from exc

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Provided key is not an RSA public key.")

    numbers = public_key.public_numbers()
    key_size = public_key.key_size

    return {
        "algorithm": "RSA",
        "key_type": "Public Key",
        "key_size": key_size,
        "modulus_size_bits": key_size,
        "public_exponent": numbers.e,
        "format": "PEM (SubjectPublicKeyInfo)",
    }


def get_private_key_info(private_key_pem: str, password: bytes = None) -> Dict[str, Any]:
    """
    Parse a PEM-encoded private key and extract public-facing metadata.
    Does NOT expose private components (d, p, q, dP, dQ, qInv).

    Args:
        private_key_pem: Standard PEM string of the private key.
        password: Optional decryption password if encrypted.

    Returns:
        Dict with private key characteristics (algorithm, key type, size, format).
    """
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

    key_size = private_key.key_size
    public_numbers = private_key.public_key().public_numbers()

    return {
        "algorithm": "RSA",
        "key_type": "Private Key",
        "key_size": key_size,
        "modulus_size_bits": key_size,
        "public_exponent": public_numbers.e,
        "format": "PEM (PKCS#8)",
    }
