"""
RSA Cryptography Module
Handles secure RSA key generation, encryption, decryption, and key metadata inspection.
"""

from backend.rsa.key_generation import generate_rsa_keypair, SUPPORTED_KEY_SIZES, DEFAULT_KEY_SIZE
from backend.rsa.key_info import get_public_key_info, get_private_key_info
from backend.rsa.encryption import encrypt_message, get_oaep_max_plaintext_length
from backend.rsa.decryption import decrypt_message

__all__ = [
    "generate_rsa_keypair",
    "SUPPORTED_KEY_SIZES",
    "DEFAULT_KEY_SIZE",
    "get_public_key_info",
    "get_private_key_info",
    "encrypt_message",
    "get_oaep_max_plaintext_length",
    "decrypt_message",
]
