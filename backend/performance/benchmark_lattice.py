"""Performance and dimensional validation for the educational LWE backends."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Callable

from backend.lattice.educational_lwe import (
    decrypt_lattice,
    encrypt_lattice,
    generate_lattice_keypair,
    validate_lattice_parameters,
)
from backend.lattice.lattice_crypto_native import (
    decrypt_lattice_block_native,
    encrypt_lattice_block_native,
    generate_lattice_keypair_native,
)


NATIVE_SAFE_MODULUS = 999_999_937
BENCHMARK_MESSAGE = "LWE benchmark message"
DEFAULT_DIMENSIONS = (2, 3)
DEFAULT_WARMUP = 3
DEFAULT_ITERATIONS = 30
DEFAULT_OUTPUT = Path(__file__).resolve().parents[2] / "data" / "benchmarks" / "lwe_benchmark_latest.json"


def benchmark_parameters(dimension: int) -> dict[str, int]:
    """Return parameters valid for both the Python reference and native ABI."""
    parameters = {
        "dimension": dimension,
        "modulus": NATIVE_SAFE_MODULUS,
        "message_modulus": 256,
        "noise_bound": 2,
        "samples": max(8, dimension),
    }
    return validate_lattice_parameters(parameters)


def supported_dimensions() -> tuple[int, ...]:
    """Return dimensions that pass both reference and native parameter constraints."""
    supported = []
    for dimension in range(2, 65):
        parameters = benchmark_parameters(dimension) if dimension in DEFAULT_DIMENSIONS else {
            "dimension": dimension,
            "modulus": NATIVE_SAFE_MODULUS,
            "message_modulus": 256,
            "noise_bound": 2,
            "samples": max(8, dimension),
        }
        try:
            validate_lattice_parameters(parameters)
        except ValueError:
            continue
        if parameters["modulus"] <= 1_000_000_000:
            supported.append(dimension)
    return tuple(supported)


def _message_blocks(message: str, dimension: int) -> list[list[int]]:
    raw = list(message.encode("utf-8"))
    return [raw[index:index + dimension] + [0] * max(0, dimension - len(raw[index:index + dimension])) for index in range(0, len(raw), dimension)]


def _native_encrypt(message: str, public_key: dict[str, Any]) -> list[dict[str, Any]]:
    return [encrypt_lattice_block_native(block, public_key) for block in _message_blocks(message, int(public_key["dimension"]))]


def _native_decrypt(blocks: list[dict[str, Any]], private_key: dict[str, Any]) -> str:
    recovered = []
    for block in blocks:
        recovered.extend(decrypt_lattice_block_native(block, private_key))
    return bytes(recovered).rstrip(b"\x00").decode("utf-8")


def _measure(operation: Callable[[], Any], warmup: int, iterations: int) -> dict[str, float | int]:
    for _ in range(warmup):
        operation()
    samples = []
    for _ in range(iterations):
        started = time.perf_counter()
        operation()
        samples.append((time.perf_counter() - started) * 1000.0)
    return {
        "iterations": iterations,
        "average_ms": sum(samples) / len(samples),
        "min_ms": min(samples),
        "max_ms": max(samples),
    }


def _result_row(dimension: int, operation: str, backend: str, timing: dict[str, float | int], success: bool) -> dict[str, Any]:
    return {
        "dimension": dimension,
        "operation": operation,
        "backend": backend,
        "iterations": timing["iterations"],
        "average_ms": round(float(timing["average_ms"]), 6),
        "min_ms": round(float(timing["min_ms"]), 6),
        "max_ms": round(float(timing["max_ms"]), 6),
        "success": success,
    }


def run_benchmark(
    dimensions: tuple[int, ...] = DEFAULT_DIMENSIONS,
    warmup: int = DEFAULT_WARMUP,
    iterations: int = DEFAULT_ITERATIONS,
    message: str = BENCHMARK_MESSAGE,
) -> dict[str, Any]:
    if warmup < 0 or iterations < 1:
        raise ValueError("warmup must be non-negative and iterations must be positive")

    started = time.perf_counter()
    rows = []
    correctness = []
    for dimension in dimensions:
        parameters = benchmark_parameters(dimension)
        python_public, python_private = generate_lattice_keypair(dimension, parameters)
        native_public, native_private = generate_lattice_keypair_native(parameters)

        python_ciphertext = encrypt_lattice(message, python_public)
        native_ciphertext = _native_encrypt(message, native_public)
        python_roundtrip = decrypt_lattice(python_ciphertext, python_private) == message
        native_roundtrip = _native_decrypt(native_ciphertext, native_private) == message
        if not python_roundtrip or not native_roundtrip:
            raise RuntimeError(f"Correctness check failed for dimension {dimension}.")
        correctness.append({"dimension": dimension, "python": "PASS", "native_c": "PASS"})

        python_keygen = lambda: generate_lattice_keypair(dimension, parameters)
        native_keygen = lambda: generate_lattice_keypair_native(parameters)
        python_encrypt = lambda: encrypt_lattice(message, python_public)
        native_encrypt = lambda: _native_encrypt(message, native_public)
        python_decrypt = lambda: decrypt_lattice(python_ciphertext, python_private)
        native_decrypt = lambda: _native_decrypt(native_ciphertext, native_private)

        for operation, python_operation, native_operation in (
            ("key_generation", python_keygen, native_keygen),
            ("encryption", python_encrypt, native_encrypt),
            ("decryption", python_decrypt, native_decrypt),
        ):
            python_timing = _measure(python_operation, warmup, iterations)
            native_timing = _measure(native_operation, warmup, iterations)
            rows.append(_result_row(dimension, operation, "python", python_timing, True))
            rows.append(_result_row(dimension, operation, "native_c", native_timing, True))

    for row in rows:
        if row["backend"] == "python":
            native = next(item for item in rows if item["dimension"] == row["dimension"] and item["operation"] == row["operation"] and item["backend"] == "native_c")
            row["speedup_vs_native"] = round(row["average_ms"] / native["average_ms"], 4) if native["average_ms"] else None

    return {
        "benchmark": "Educational LWE Python vs native C",
        "message_bytes": len(message.encode("utf-8")),
        "warmup_iterations": warmup,
        "timed_iterations": iterations,
        "dimensions": list(dimensions),
        "correctness": correctness,
        "results": rows,
        "total_duration_ms": round((time.perf_counter() - started) * 1000.0, 3),
        "native_modulus_limit": 1_000_000_000,
        "disclaimer": "Timings include the existing Python and ctypes wrapper call paths; random sources differ between backends.",
    }


def print_report(report: dict[str, Any]) -> None:
    print("=" * 72)
    print("Educational LWE Benchmark")
    print("=" * 72)
    print(f"Dimensions: {', '.join(map(str, report['dimensions']))}")
    print(f"Message bytes: {report['message_bytes']}; timed iterations: {report['timed_iterations']}; warm-up: {report['warmup_iterations']}")
    print()
    print(f"{'Dimension':<10}{'Operation':<18}{'Python Avg (ms)':>17}{'C Avg (ms)':>14}{'Python/C':>12}")
    print("-" * 72)
    for dimension in report["dimensions"]:
        for operation in ("key_generation", "encryption", "decryption"):
            python_row = next(row for row in report["results"] if row["dimension"] == dimension and row["operation"] == operation and row["backend"] == "python")
            native_row = next(row for row in report["results"] if row["dimension"] == dimension and row["operation"] == operation and row["backend"] == "native_c")
            print(f"{dimension:<10}{operation:<18}{python_row['average_ms']:>17.6f}{native_row['average_ms']:>14.6f}{python_row['speedup_vs_native']:>12.4f}x")
    print("-" * 72)
    for result in report["correctness"]:
        print(f"Dimension {result['dimension']}: Python {result['python']}; native C {result['native_c']}")
    print(f"Total duration: {report['total_duration_ms']:.3f} ms")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    dimensions = supported_dimensions()
    report = run_benchmark(dimensions, args.warmup, args.iterations)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print_report(report)
    print(f"JSON: {args.output}")


if __name__ == "__main__":
    main()
