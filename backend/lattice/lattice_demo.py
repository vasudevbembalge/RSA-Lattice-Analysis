"""Educational orchestration layer for LWE, lattice visualization, and LLL."""

from __future__ import annotations

import json
import argparse
import time
from pprint import pformat
from pathlib import Path
from typing import Any

from backend.lattice.educational_lwe import (
    decrypt_lattice,
    encrypt_lattice,
    generate_lattice_keypair,
    get_message_capacity,
)
from backend.lattice.lattice_operations import generate_sample_matrix
from backend.lattice.lll_interface import run_lll_reduction
from backend.lattice.lattice_crypto_native import (
    decrypt_lattice_block_native,
    encrypt_lattice_block_native,
    generate_lattice_keypair_native,
    native_backend_status,
)
from backend.performance.benchmark_lattice import (
    BENCHMARK_MESSAGE,
    benchmark_parameters,
    supported_dimensions,
)


_BENCHMARK_REPORT = Path(__file__).resolve().parents[2] / "data" / "benchmarks" / "lwe_benchmark_latest.json"


def _message_blocks(message: str, dimension: int) -> list[list[int]]:
    raw = list(message.encode("utf-8"))
    return [raw[index:index + dimension] + [0] * max(0, dimension - len(raw[index:index + dimension])) for index in range(0, len(raw), dimension)]


def _native_encrypt(message: str, public_key: dict[str, Any]) -> list[dict[str, Any]]:
    dimension = int(public_key["dimension"])
    return [encrypt_lattice_block_native(block, public_key) for block in _message_blocks(message, dimension)]


def _native_decrypt(blocks: list[dict[str, Any]], private_key: dict[str, Any]) -> str:
    recovered = []
    for block in blocks:
        recovered.extend(decrypt_lattice_block_native(block, private_key))
    return bytes(recovered).rstrip(b"\x00").decode("utf-8")


def _centered(value: int, modulus: int) -> int:
    value %= modulus
    return value - modulus if value > modulus // 2 else value


def _recover_error(public_key: dict[str, Any], private_key: dict[str, Any]) -> list[int]:
    modulus = int(public_key["modulus"])
    secret = private_key["secret"]
    return [
        _centered(
            public_key["vector_b"][row] - sum(public_key["matrix_A"][row][column] * secret[column] for column in range(public_key["dimension"])),
            modulus,
        )
        for row in range(public_key["samples"])
    ]


def _lattice_visualization() -> dict[str, Any]:
    basis = generate_sample_matrix("skewed_2x2")["matrix"]
    points = []
    for z1 in range(-3, 4):
        for z2 in range(-3, 4):
            points.append({
                "coefficients": [z1, z2],
                "point": [z1 * basis[0][0] + z2 * basis[1][0], z1 * basis[0][1] + z2 * basis[1][1]],
            })
    return {
        "dimension": 2,
        "basis": basis,
        "coefficient_range": [-3, 3],
        "points": points,
        "equation": "v = z1*b1 + z2*b2, where z1 and z2 are integers",
        "explanation": "This lattice representation illustrates basis combinations; it is not the LWE encryption algorithm.",
    }


def _timed(operation) -> tuple[Any, float]:
    started = time.perf_counter()
    result = operation()
    return result, round((time.perf_counter() - started) * 1000.0, 6)


def _backend_demo(message: str, parameters: dict[str, int], backend: str) -> dict[str, Any]:
    if backend == "python":
        public_key, private_key = generate_lattice_keypair(parameters["dimension"], parameters)
        public_key["backend_used"] = "Python reference"
        private_key["backend_used"] = "Python reference"
        ciphertext, encryption_ms = _timed(lambda: encrypt_lattice(message, public_key))
        recovered, decryption_ms = _timed(lambda: decrypt_lattice(ciphertext, private_key))
        _, key_generation_ms = _timed(lambda: generate_lattice_keypair(parameters["dimension"], parameters))
        encoded = _message_blocks(message, parameters["dimension"])
        return {
            "backend": "Python reference",
            "backend_requested": "python",
            "backend_used": "Python reference",
            "fallback": False,
            "key_generation_ms": key_generation_ms,
            "encryption_ms": encryption_ms,
            "decryption_ms": decryption_ms,
            "public_key": public_key,
            "secret_key": private_key,
            "error_vector": _recover_error(public_key, private_key),
            "encoded_message": encoded,
            "ciphertext": ciphertext,
            "recovered_plaintext": recovered,
            "status": "PASS" if recovered == message else "FAIL",
        }

    if backend == "native_c":
        public_key, private_key = generate_lattice_keypair_native(parameters)
        public_key["backend_used"] = "Native C"
        private_key["backend_used"] = "Native C"
        ciphertext, encryption_ms = _timed(lambda: _native_encrypt(message, public_key))
        recovered, decryption_ms = _timed(lambda: _native_decrypt(ciphertext, private_key))
        _, key_generation_ms = _timed(lambda: generate_lattice_keypair_native(parameters))
        return {
            "backend": "Native C (lattice_crypto.dll)",
            "backend_requested": "native_c",
            "backend_used": "Native C",
            "fallback": False,
            "key_generation_ms": key_generation_ms,
            "encryption_ms": encryption_ms,
            "decryption_ms": decryption_ms,
            "public_key": public_key,
            "secret_key": private_key,
            "error_vector": _recover_error(public_key, private_key),
            "encoded_message": _message_blocks(message, parameters["dimension"]),
            "ciphertext": {"ciphertexts": ciphertext},
            "recovered_plaintext": recovered,
            "status": "PASS" if recovered == message else "FAIL",
        }

    raise ValueError("backend must be 'python', 'native_c', or 'both'.")


def _load_benchmark_report() -> dict[str, Any] | None:
    if not _BENCHMARK_REPORT.is_file():
        return None
    try:
        report = json.loads(_BENCHMARK_REPORT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return report if isinstance(report, dict) else None


def run_lwe_demo(message: str = "HELLO LWE", dimension: int = 3, backend: str = "both") -> dict[str, Any]:
    """Run the existing educational LWE construction with explanatory data."""
    if not isinstance(message, str) or not message:
        raise ValueError("Demo message must be a non-empty string.")
    if dimension not in supported_dimensions():
        raise ValueError(f"Demo dimension must be one of the native-safe dimensions: {supported_dimensions()}.")
    parameters = benchmark_parameters(dimension)
    native_status = native_backend_status()
    native_available = native_status["available"]
    requested_backend = "native_c" if backend == "native_c" else "python" if backend == "python" else "both"
    fallback = requested_backend in {"native_c", "both"} and not native_available
    actual_backend = "python" if fallback else requested_backend
    backends = ["python", "native_c"] if requested_backend == "both" and native_available else ["python"] if requested_backend in {"both", "python"} or fallback else ["native_c"]
    lwe = [_backend_demo(message, parameters, selected_backend) for selected_backend in backends]
    if any(result["status"] != "PASS" for result in lwe):
        raise RuntimeError("LWE demonstration failed its round-trip check.")
    return {
        "parameters": parameters,
        "message": message,
        "message_bytes": len(message.encode("utf-8")),
        "message_capacity": get_message_capacity(parameters),
        "equations": {
            "key_generation": "b = A*s + e mod q",
            "encryption": "u = A^T*r + e1 mod q; v = b^T*r + floor(q/p)*symbol + e2 mod q",
            "decryption": "t = v - u^T*s mod q; symbol = round(t / floor(q/p)) mod p",
        },
        "backends": lwe,
        "requested_backend": requested_backend,
        "actual_backend": actual_backend,
        "fallback": fallback,
        "native_backend_available": native_available,
        "native_backend_notice": None if native_available else native_status["reason"],
        "status": "PASS",
        "disclaimer": "Educational LWE-style construction only; not production cryptography.",
    }


def run_educational_demonstration(message: str = "HELLO LWE", dimension: int = 3, backend: str = "both") -> dict[str, Any]:
    """Run the complete LWE, lattice-visualization, LLL, and performance demonstration."""
    lwe = run_lwe_demo(message, dimension, backend)
    lll_input = generate_sample_matrix("textbook_3x3")
    lll = run_lll_reduction(lll_input["matrix"], delta=0.75)
    report = _load_benchmark_report()
    return {
        "status": "PASS",
        "title": "Educational Lattice / LWE Demonstration",
        "lwe": lwe,
        "lattice_visualization": _lattice_visualization(),
        "lll": {
            "relationship": "LLL reduces lattice bases; it does not encrypt or decrypt the LWE ciphertext.",
            **lll,
        },
        "performance": {
            "benchmark_report": report,
            "explanation": "Native C is a computational backend, but at these small dimensions Python-to-C ctypes and buffer-conversion overhead can dominate end-to-end timing.",
        },
        "component_separation": {
            "rsa": "RSA/OAEP remains on the existing RSA path.",
            "lwe": "Educational LWE uses the Python reference and lattice_crypto.dll native backend.",
            "lll": "LLL remains a separate lattice-analysis component using lll.dll.",
        },
    }


def print_demonstration(report: dict[str, Any]) -> None:
    """Print a compact, classroom-friendly view of a completed demonstration."""
    lwe = report["lwe"]
    print("=" * 72)
    print("EDUCATIONAL LATTICE / LWE DEMONSTRATION")
    print("=" * 72)
    print("[1] PARAMETERS")
    print(pformat(lwe["parameters"]))
    print("\n[2] LWE EQUATIONS")
    for name, equation in lwe["equations"].items():
        print(f"{name}: {equation}")
    for backend in lwe["backends"]:
        print(f"\n[3] {backend['backend'].upper()}")
        print(f"Public matrix A: {pformat(backend['public_key']['matrix_A'])}")
        print(f"Secret vector s (toy demo data): {pformat(backend['secret_key']['secret'])}")
        print(f"Error vector e (derived from A, b, s): {pformat(backend['error_vector'])}")
        print(f"Encoded message: {pformat(backend['encoded_message'])}")
        print(f"Ciphertext: {pformat(backend['ciphertext'])}")
        print(f"Recovered plaintext: {backend['recovered_plaintext']}")
        print(f"Status: {backend['status']}")
        print(f"Timing ms: key generation={backend['key_generation_ms']}, encryption={backend['encryption_ms']}, decryption={backend['decryption_ms']}")
    print("\n[4] LATTICE REPRESENTATION")
    print(f"Basis B: {pformat(report['lattice_visualization']['basis'])}")
    print(f"Points: {len(report['lattice_visualization']['points'])} integer combinations")
    print(report["lattice_visualization"]["explanation"])
    print("\n[5] LLL REDUCTION (SEPARATE FROM LWE)")
    print(f"Original basis: {pformat(report['lll']['original_basis'])}")
    print(f"Reduced basis: {pformat(report['lll']['reduced_basis'])}")
    print(f"Norms: {report['lll']['original_norms']} -> {report['lll']['reduced_norms']}")
    print(f"Iterations: {report['lll']['iterations']}; swaps: {report['lll']['swaps']}; execution: {report['lll']['execution_time_ms']} ms")
    print(report["lll"]["relationship"])
    print("\n[6] COMPONENT SEPARATION")
    for name, description in report["component_separation"].items():
        print(f"{name.upper()}: {description}")
    print("\nDEMONSTRATION COMPLETE: PASS")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--message", default="HELLO LWE")
    parser.add_argument("--dimension", type=int, default=3)
    parser.add_argument("--backend", choices=("python", "native_c", "both"), default="both")
    args = parser.parse_args()
    print_demonstration(run_educational_demonstration(args.message, args.dimension, args.backend))


__all__ = ["run_lwe_demo", "run_educational_demonstration", "print_demonstration"]


if __name__ == "__main__":
    main()
