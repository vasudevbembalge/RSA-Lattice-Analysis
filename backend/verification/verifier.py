"""
RSA Verification Module
Provides end-to-end round-trip verification:
Original Message -> Encryption -> Decryption -> Plaintext Comparison -> PASS / FAIL
"""

import hashlib
import time
from typing import Dict, Any
from backend.rsa.encryption import encrypt_message
from backend.rsa.decryption import decrypt_message


def verify_messages(original_message: str, decrypted_message: str) -> Dict[str, Any]:
    """
    Compare original message against decrypted message and return verification status.
    """
    match = (original_message == decrypted_message)
    status_text = "VERIFICATION PASSED" if match else "VERIFICATION FAILED"

    orig_bytes = original_message.encode("utf-8") if isinstance(original_message, str) else b""
    dec_bytes = decrypted_message.encode("utf-8") if isinstance(decrypted_message, str) else b""

    return {
        "status": status_text,
        "passed": match,
        "original_sha256": hashlib.sha256(orig_bytes).hexdigest(),
        "decrypted_sha256": hashlib.sha256(dec_bytes).hexdigest(),
        "original_length": len(original_message) if original_message else 0,
        "decrypted_length": len(decrypted_message) if decrypted_message else 0,
    }


def verify_rsa_roundtrip(
    original_message: str,
    public_key_pem: str,
    private_key_pem: str,
) -> Dict[str, Any]:
    """
    Perform a complete automated RSA-OAEP encryption and decryption round-trip,
    measuring individual and aggregate latencies, and verifying exact data integrity.

    Args:
        original_message: The plain message string to verify.
        public_key_pem: PEM public key for encryption.
        private_key_pem: PEM private key for decryption.

    Returns:
        Dict containing verification status, step results, timings, and checksums.
    """
    start_total = time.perf_counter()

    # Step 1: Encrypt
    try:
        enc_result = encrypt_message(original_message, public_key_pem)
    except Exception as exc:
        total_time_ms = (time.perf_counter() - start_total) * 1000.0
        return {
            "status": "VERIFICATION FAILED",
            "passed": False,
            "error_phase": "encryption",
            "error_message": str(exc),
            "total_verification_time_ms": round(total_time_ms, 3),
        }

    # Step 2: Decrypt
    try:
        dec_result = decrypt_message(enc_result["ciphertext_base64"], private_key_pem)
    except Exception as exc:
        total_time_ms = (time.perf_counter() - start_total) * 1000.0
        return {
            "status": "VERIFICATION FAILED",
            "passed": False,
            "error_phase": "decryption",
            "error_message": str(exc),
            "ciphertext_base64": enc_result["ciphertext_base64"],
            "total_verification_time_ms": round(total_time_ms, 3),
        }

    # Step 3: Compare
    decrypted_text = dec_result["decrypted_plaintext"]
    comparison = verify_messages(original_message, decrypted_text)
    total_time_ms = (time.perf_counter() - start_total) * 1000.0

    return {
        "status": comparison["status"],
        "passed": comparison["passed"],
        "original_message": original_message,
        "decrypted_message": decrypted_text,
        "ciphertext_base64": enc_result["ciphertext_base64"],
        "original_sha256": comparison["original_sha256"],
        "decrypted_sha256": comparison["decrypted_sha256"],
        "encryption_time_ms": enc_result["encryption_time_ms"],
        "decryption_time_ms": dec_result["decryption_time_ms"],
        "total_verification_time_ms": round(total_time_ms, 3),
    }
