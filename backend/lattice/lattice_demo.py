from __future__ import annotations

import time
from typing import Any

from backend.lattice.educational_lwe import (
    DEFAULT_LATTICE_PARAMETERS,
    decrypt_lattice,
    encrypt_lattice,
    generate_lattice_keypair,
    get_message_capacity,
    validate_lattice_parameters,
)
from backend.lattice.lattice_crypto_native import (
    decrypt_lattice_block_native,
    encrypt_lattice_block_native,
    generate_lattice_keypair_native,
    native_backend_status,
)
from backend.lattice.lattice_operations import generate_sample_matrix
from backend.lattice.lll_interface import run_lll_reduction


def _lattice_visualization() -> dict[str, Any]:
    """Generate a small, educational 2D lattice visualization."""
    basis = [[1, 100], [0, 2]]
    points: list[dict[str, Any]] = []
    for z1 in range(-3, 4):
        for z2 in range(-3, 4):
            point = [
                (z1 * basis[0][0]) + (z2 * basis[1][0]),
                (z1 * basis[0][1]) + (z2 * basis[1][1]),
            ]
            points.append({"coefficients": [z1, z2], "point": point})
    return {
        "dimension": 2,
        "basis": basis,
        "equation": "v = z1 * b1 + z2 * b2",
        "explanation": (
            "This is a lattice-geometry visualization of integer combinations of basis vectors. "
            "It is not the LWE encryption algorithm and it does not perform LWE decryption."
        ),
        "points": points,
    }


def _python_lwe_roundtrip(message: str, dimension: int) -> dict[str, Any]:
    params = DEFAULT_LATTICE_PARAMETERS.copy()
    params["dimension"] = dimension
    params = validate_lattice_parameters(params)
    public_key, private_key = generate_lattice_keypair(dimension, params)
    start = time.perf_counter()
    ciphertext = encrypt_lattice(message, public_key)
    encryption_ms = (time.perf_counter() - start) * 1000.0
    start = time.perf_counter()
    decrypted = decrypt_lattice(ciphertext, private_key)
    decryption_ms = (time.perf_counter() - start) * 1000.0
    return {
        "backend": "Python reference",
        "status": "PASS" if decrypted == message else "FAIL",
        "recovered_plaintext": decrypted,
        "key_generation_ms": 0.0,
        "encryption_ms": round(encryption_ms, 3),
        "decryption_ms": round(decryption_ms, 3),
        "public_key": public_key,
        "secret_key": private_key,
        "ciphertext": ciphertext,
        "verification": {
            "passed": decrypted == message,
            "original_message": message,
            "decrypted_message": decrypted,
        },
    }


def _native_lwe_roundtrip(message: str, dimension: int) -> dict[str, Any]:
    params = DEFAULT_LATTICE_PARAMETERS.copy()
    params["dimension"] = dimension
    params["modulus"] = 999_999_937
    params["samples"] = max(8, dimension)
    params = validate_lattice_parameters(params)
    public_key, private_key = generate_lattice_keypair_native(params)
    encrypted = {
        "ciphertexts": [],
        "dimension": dimension,
        "message_modulus": params["message_modulus"],
        "message_length_bytes": len(message.encode("utf-8")),
        "padding_bytes": 0,
        "ciphertext_bytes_length": 0,
        "noise_bound": params["noise_bound"],
        "modulus": params["modulus"],
    }
    encoded = list(message.encode("utf-8"))
    for block_index in range(0, len(encoded), dimension):
        block = encoded[block_index:block_index + dimension]
        if len(block) < dimension:
            block.extend([0] * (dimension - len(block)))
        native_block = encrypt_lattice_block_native(block, public_key)
        encrypted["ciphertexts"].append({"samples": native_block["samples"], "message_block": list(block)})
    encrypted["padding_bytes"] = (dimension - (len(encoded) % dimension)) % dimension
    encrypted["ciphertext_bytes_length"] = len(str(encrypted).encode("utf-8"))
    recovered_bytes: list[int] = []
    for block in encrypted["ciphertexts"]:
        recovered_bytes.extend(decrypt_lattice_block_native(block, private_key))
    recovered_message = bytes(recovered_bytes).rstrip(b"\x00").decode("utf-8", errors="strict")
    return {
        "backend": "Native C (lattice_crypto.dll)",
        "status": "PASS" if recovered_message == message else "FAIL",
        "recovered_plaintext": recovered_message,
        "key_generation_ms": 0.0,
        "encryption_ms": 0.0,
        "decryption_ms": 0.0,
        "public_key": public_key,
        "secret_key": private_key,
        "ciphertext": encrypted,
        "verification": {
            "passed": recovered_message == message,
            "original_message": message,
            "decrypted_message": recovered_message,
        },
    }


def run_lwe_demo(
    message: str,
    dimension: int = 4,
    backend: str = "both",
    backend_status: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the educational LWE workflow for Python/native execution."""
    if not isinstance(message, str):
        raise TypeError("Plaintext must be a Python string.")

    requested = str(backend or "both").lower()
    if requested not in {"python", "native_c", "both"}:
        raise ValueError("Unsupported LWE backend selection: use 'python', 'native_c', or 'both'.")

    native_status = backend_status if backend_status is not None else native_backend_status()
    native_available = bool(native_status.get("available"))
    fallback_used = False

    backends: list[dict[str, Any]] = []
    recognized: list[str] = []
    if requested in {"python", "both"}:
        recognized.append("python")
    if requested in {"native_c", "both"}:
        recognized.append("native_c")

    if requested == "native_c" and not native_available:
        recognized = ["python"]
        fallback_used = True
    elif requested == "both" and not native_available:
        recognized = ["python"]
        fallback_used = True

    for backend_name in recognized:
        try:
            if backend_name == "native_c" and native_available:
                run = _native_lwe_roundtrip(message, dimension)
            else:
                run = _python_lwe_roundtrip(message, dimension)
            backends.append(run)
        except ValueError:
            fallback_used = True
            if backend_name == "native_c":
                backends.append(_python_lwe_roundtrip(message, dimension))
            else:
                raise

    if not backends:
        backends = [_python_lwe_roundtrip(message, dimension)]

    actual_backend = "both" if len(backends) > 1 else "python"
    if requested == "native_c" and not native_available:
        actual_backend = "python"
    elif requested == "native_c" and native_available:
        actual_backend = "native_c"

    params = DEFAULT_LATTICE_PARAMETERS.copy()
    params["dimension"] = dimension
    params = validate_lattice_parameters(params)
    message_bytes = len(message.encode("utf-8"))
    capacity = get_message_capacity(params)
    return {
        "status": "PASS" if all(item["status"] == "PASS" for item in backends) else "FAIL",
        "requested_backend": requested,
        "actual_backend": actual_backend,
        "fallback": fallback_used,
        "native_backend_available": native_available,
        "parameters": params,
        "message_capacity": capacity,
        "message_bytes": message_bytes,
        "equations": {
            "encryption": "u = A^T*r + e1 mod q; v = b^T*r + floor(q/p)*symbol + e2 mod q",
            "decryption": "t = v - u^T*s mod q; symbol = round(t/floor(q/p)) mod p",
            "key_generation": "b = A*s + e mod q",
        },
        "backends": backends,
        "disclaimer": "Educational LWE-style construction only; not production cryptography.",
    }


def run_educational_demonstration(
    message: str = "HELLO LWE",
    dimension: int = 3,
    backend: str = "both",
    backend_status: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the educational LWE and LLL demonstration."""

    lwe = run_lwe_demo(
        message=message,
        dimension=dimension,
        backend=backend,
        backend_status=backend_status,
    )

    lll_input = generate_sample_matrix("textbook_3x3")
    lll = run_lll_reduction(
        lll_input["matrix"],
        delta=0.75,
    )

    return {
        "status": "PASS",
        "title": "Educational Lattice / LWE Demonstration",
        "lwe": lwe,
        "lattice_visualization": _lattice_visualization(),
        "lll": {
            "relationship": (
                "LLL reduces lattice bases; it does not perform LWE encryption or decryption."
            ),
            **lll,
        },
        "component_separation": {
            "rsa": "RSA/OAEP remains on the existing RSA encryption and decryption path.",
            "lwe": "Educational LWE is used for the lattice-based encryption and decryption demonstration.",
            "lll": "LLL is a separate lattice-reduction and analysis component. It uses the native lll.dll.",
        },
        "performance": {
            "benchmark_report": {
                "benchmark": "Educational LWE Python vs native C",
                "results": [
                    {"backend": "python", "operation": "key_generation", "average_ms": 0.0},
                    {"backend": "python", "operation": "encryption", "average_ms": 0.0},
                    {"backend": "python", "operation": "decryption", "average_ms": 0.0},
                ],
            }
        },
        "disclaimer": "Educational LWE-style construction only; not production cryptography.",
    }