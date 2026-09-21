"""
Performance Benchmarking Module
Measures actual empirical latencies for RSA operations and native C LLL reduction.
Persists results to data/benchmarks/ in JSON and CSV formats.
Strict rule: No simulated/fake numbers; records genuine system measurements.
"""

import os
import json
import csv
import time
from typing import Dict, Any, List

from backend.rsa.key_generation import generate_rsa_keypair, SUPPORTED_KEY_SIZES
from backend.rsa.encryption import encrypt_message, get_oaep_max_plaintext_length
from backend.rsa.decryption import decrypt_message
from backend.verification.verifier import verify_messages
from backend.lattice.lll_interface import run_lll_reduction
from backend.lattice.lattice_operations import generate_random_matrix, generate_sample_matrix
from backend.lattice.educational_lwe import (
    decrypt_lattice,
    encrypt_lattice,
    generate_lattice_keypair,
    validate_lattice_parameters,
)

BENCHMARK_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "benchmarks")
)


def run_rsa_benchmarks(
    key_sizes: List[int] = None,
    message: str = "Academic Benchmark Test Message",
) -> List[Dict[str, Any]]:
    """
    Execute empirical performance measurements for RSA key generation,
    RSA-OAEP encryption, and decryption across given key sizes.
    """
    if key_sizes is None:
        key_sizes = [1024, 2048, 3072]  # Default set; 4096 can be included

    results = []
    for bits in key_sizes:
        # 1. Keygen
        kg_start = time.perf_counter()
        kp = generate_rsa_keypair(bits)
        keygen_ms = (time.perf_counter() - kg_start) * 1000.0

        pub_pem = kp["public_key_pem"]
        priv_pem = kp["private_key_pem"]

        # 2. Encrypt
        enc_start = time.perf_counter()
        enc = encrypt_message(message, pub_pem)
        encrypt_ms = (time.perf_counter() - enc_start) * 1000.0

        # 3. Decrypt
        dec_start = time.perf_counter()
        dec = decrypt_message(enc["ciphertext_base64"], priv_pem)
        decrypt_ms = (time.perf_counter() - dec_start) * 1000.0

        # 4. Verify
        ver_start = time.perf_counter()
        ver = verify_messages(message, dec["decrypted_plaintext"])
        verify_ms = (time.perf_counter() - ver_start) * 1000.0

        results.append({
            "scheme": "RSA-OAEP",
            "key_size_bits": bits,
            "keygen_time_ms": round(keygen_ms, 3),
            "encryption_time_ms": round(encrypt_ms, 3),
            "decryption_time_ms": round(decrypt_ms, 3),
            "verification_time_ms": round(verify_ms, 3),
            "public_key_bytes": len(pub_pem.encode("utf-8")),
            "private_key_bytes": len(priv_pem.encode("utf-8")),
            "ciphertext_bytes": enc["ciphertext_bytes_length"],
            "total_time_ms": round(keygen_ms + encrypt_ms + decrypt_ms + verify_ms, 3),
            "plaintext_capacity_bytes": get_oaep_max_plaintext_length(bits),
            "verified": ver["passed"],
        })

    return results


def run_lattice_benchmarks() -> Dict[str, Any]:
    """
    Execute empirical performance measurements for native C LLL reduction
    across varying matrix dimensions and test vectors.
    """
    # 1. Benchmark LLL time vs dimension
    dim_results = []
    for dim in [2, 3, 4, 5, 6, 8]:
        mat = generate_random_matrix(dim, dim, min_val=-100, max_val=100)
        try:
            res = run_lll_reduction(mat, delta=0.75)
            dim_results.append({
                "dimension": f"{dim}x{dim}",
                "dim_n": dim,
                "execution_time_ms": res["execution_time_ms"],
                "iterations": res["iterations"],
                "swaps": res["swaps"],
            })
        except ValueError:
            # Skip if randomly chosen matrix is singular
            pass

    # 2. Textbook 3x3 vector norm reduction
    sample = generate_sample_matrix("textbook_3x3")
    sample_res = run_lll_reduction(sample["matrix"], delta=0.75)

    norm_comparison = {
        "vector_indices": [f"b_{i+1}" for i in range(len(sample["matrix"]))],
        "original_norms": sample_res["original_norms"],
        "reduced_norms": sample_res["reduced_norms"],
    }

    return {
        "dimension_scaling": dim_results,
        "norm_reduction": norm_comparison,
    }


def run_lwe_comparison_benchmarks(
    dimensions: List[int] = None,
    message: str = "Academic Benchmark Test Message",
) -> List[Dict[str, Any]]:
    """Measure the Python educational LWE path for the RSA comparison report."""
    if dimensions is None:
        dimensions = [2, 4, 8, 16]

    results = []
    for dimension in dimensions:
        parameters = validate_lattice_parameters({
            "dimension": dimension,
            "modulus": 999_999_937,
            "message_modulus": 256,
            "noise_bound": 2,
            "samples": max(8, dimension),
        })

        keygen_start = time.perf_counter()
        public_key, private_key = generate_lattice_keypair(dimension, parameters)
        keygen_ms = (time.perf_counter() - keygen_start) * 1000.0

        encrypt_start = time.perf_counter()
        ciphertext = encrypt_lattice(message, public_key)
        encrypt_ms = (time.perf_counter() - encrypt_start) * 1000.0

        decrypt_start = time.perf_counter()
        recovered = decrypt_lattice(ciphertext, private_key)
        decrypt_ms = (time.perf_counter() - decrypt_start) * 1000.0

        verify_start = time.perf_counter()
        verification = verify_messages(message, recovered)
        verify_ms = (time.perf_counter() - verify_start) * 1000.0

        results.append({
            "scheme": "Educational LWE",
            "dimension": dimension,
            "parameters": parameters,
            "keygen_time_ms": round(keygen_ms, 3),
            "encryption_time_ms": round(encrypt_ms, 3),
            "decryption_time_ms": round(decrypt_ms, 3),
            "verification_time_ms": round(verify_ms, 3),
            "public_key_bytes": len(json.dumps(public_key, separators=(",", ":")).encode("utf-8")),
            "private_key_bytes": len(json.dumps(private_key, separators=(",", ":")).encode("utf-8")),
            "ciphertext_bytes": len(json.dumps(ciphertext, separators=(",", ":")).encode("utf-8")),
            "total_time_ms": round(keygen_ms + encrypt_ms + decrypt_ms + verify_ms, 3),
            "plaintext_capacity_bytes": None,
            "capacity_type": "unbounded_by_lwe_parameters",
            "verified": verification["passed"],
            "message_bytes": len(message.encode("utf-8")),
        })

    return results


def run_full_benchmark_suite() -> Dict[str, Any]:
    """Run all RSA and Lattice empirical benchmarks and save to disk."""
    os.makedirs(BENCHMARK_DIR, exist_ok=True)

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    rsa_data = run_rsa_benchmarks()
    lwe_comparison_data = run_lwe_comparison_benchmarks()
    lattice_data = run_lattice_benchmarks()

    comparison_data = [
        *rsa_data,
        *lwe_comparison_data,
    ]

    full_report = {
        "timestamp": timestamp,
        "rsa_benchmarks": rsa_data,
        "lwe_comparison_benchmarks": lwe_comparison_data,
        "comparison_benchmarks": comparison_data,
        "lattice_benchmarks": lattice_data,
        "disclaimer": (
            "Empirically measured operational latencies. "
            "Private-key recovery is outside the scope of this implementation."
        ),
    }

    # Save JSON
    json_path = os.path.join(BENCHMARK_DIR, "benchmark_latest.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)

    # Save RSA CSV
    csv_path = os.path.join(BENCHMARK_DIR, "rsa_benchmarks.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "scheme",
                "key_size_bits",
                "keygen_time_ms",
                "encryption_time_ms",
                "decryption_time_ms",
                "verification_time_ms",
                "public_key_bytes",
                "private_key_bytes",
                "ciphertext_bytes",
                "total_time_ms",
                "plaintext_capacity_bytes",
                "verified",
            ],
        )
        writer.writeheader()
        for row in rsa_data:
            writer.writerow(row)

    return full_report


def load_latest_benchmarks() -> Dict[str, Any]:
    """Retrieve the most recent benchmark run or execute a new one if missing."""
    json_path = os.path.join(BENCHMARK_DIR, "benchmark_latest.json")
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return run_full_benchmark_suite()