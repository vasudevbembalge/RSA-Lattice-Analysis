"""ctypes wrapper for the separate educational native LWE backend."""

from __future__ import annotations

import ctypes
from pathlib import Path
from typing import Any


_DLL_PATH = Path(__file__).resolve().parents[2] / "c_lattice_crypto" / "bin" / "lattice_crypto.dll"
_MAX_SAFE_MODULUS = 1_000_000_000
_SEM_FAILCRITICALERRORS = 0x0001
_SEM_NOGPFAULTERRORBOX = 0x0002
_SEM_NOOPENFILEERRORBOX = 0x8000


class _LatticeParams(ctypes.Structure):
    _fields_ = [
        ("dimension", ctypes.c_int32),
        ("modulus", ctypes.c_int64),
        ("message_modulus", ctypes.c_int32),
        ("noise_bound", ctypes.c_int32),
        ("samples", ctypes.c_int32),
    ]


class _LatticePublicKey(ctypes.Structure):
    _fields_ = [
        ("dimension", ctypes.c_int32),
        ("samples", ctypes.c_int32),
        ("modulus", ctypes.c_int64),
        ("message_modulus", ctypes.c_int32),
        ("noise_bound", ctypes.c_int32),
        ("matrix_a", ctypes.POINTER(ctypes.c_int64)),
        ("vector_b", ctypes.POINTER(ctypes.c_int64)),
    ]


class _LatticePrivateKey(ctypes.Structure):
    _fields_ = [
        ("dimension", ctypes.c_int32),
        ("modulus", ctypes.c_int64),
        ("message_modulus", ctypes.c_int32),
        ("noise_bound", ctypes.c_int32),
        ("secret", ctypes.POINTER(ctypes.c_int64)),
    ]


class _LatticeCiphertextSample(ctypes.Structure):
    _fields_ = [
        ("dimension", ctypes.c_int32),
        ("u", ctypes.POINTER(ctypes.c_int64)),
        ("v", ctypes.c_int64),
        ("symbol", ctypes.c_int32),
    ]


class _LatticeCiphertextBlock(ctypes.Structure):
    _fields_ = [
        ("count", ctypes.c_int32),
        ("samples", ctypes.POINTER(_LatticeCiphertextSample)),
    ]


def _load_library() -> ctypes.CDLL:
    if not _DLL_PATH.is_file():
        raise FileNotFoundError(f"Native lattice library not found: {_DLL_PATH}")

    previous_error_mode = None
    if hasattr(ctypes, "windll"):
        kernel32 = ctypes.windll.kernel32
        kernel32.SetErrorMode.argtypes = [ctypes.c_uint]
        kernel32.SetErrorMode.restype = ctypes.c_uint
        previous_error_mode = kernel32.SetErrorMode(
            _SEM_FAILCRITICALERRORS | _SEM_NOGPFAULTERRORBOX | _SEM_NOOPENFILEERRORBOX
        )
    try:
        library = ctypes.CDLL(str(_DLL_PATH))
    except OSError as exc:
        raise OSError(
            f"Native LWE library could not be loaded from {_DLL_PATH}. "
            "The DLL may be unavailable or blocked by the operating-system application-control policy."
        ) from exc
    finally:
        if previous_error_mode is not None:
            ctypes.windll.kernel32.SetErrorMode(previous_error_mode)
    library.lattice_validate_params.argtypes = [ctypes.POINTER(_LatticeParams)]
    library.lattice_validate_params.restype = ctypes.c_int
    library.lattice_generate_keypair.argtypes = [
        ctypes.POINTER(_LatticeParams),
        ctypes.POINTER(_LatticePublicKey),
        ctypes.POINTER(_LatticePrivateKey),
    ]
    library.lattice_generate_keypair.restype = ctypes.c_int
    library.lattice_encrypt_block.argtypes = [
        ctypes.POINTER(_LatticePublicKey),
        ctypes.POINTER(ctypes.c_int32),
        ctypes.c_int32,
        ctypes.POINTER(_LatticeCiphertextBlock),
    ]
    library.lattice_encrypt_block.restype = ctypes.c_int
    library.lattice_decrypt_block.argtypes = [
        ctypes.POINTER(_LatticePrivateKey),
        ctypes.POINTER(_LatticeCiphertextBlock),
        ctypes.POINTER(ctypes.c_int32),
        ctypes.c_int32,
    ]
    library.lattice_decrypt_block.restype = ctypes.c_int
    library.lattice_free_public_key.argtypes = [ctypes.POINTER(_LatticePublicKey)]
    library.lattice_free_private_key.argtypes = [ctypes.POINTER(_LatticePrivateKey)]
    library.lattice_free_ciphertext_block.argtypes = [ctypes.POINTER(_LatticeCiphertextBlock)]
    library.lattice_free_ciphertext.argtypes = [ctypes.c_void_p]
    library.lattice_crypto_strerror.argtypes = [ctypes.c_int]
    library.lattice_crypto_strerror.restype = ctypes.c_char_p
    return library


def native_backend_status() -> dict[str, Any]:
    """Return native LWE availability and the reason when it cannot load."""
    try:
        _load_library()
    except FileNotFoundError as exc:
        return {"available": False, "reason": str(exc)}
    except OSError as exc:
        reason = str(exc)
        winerror = getattr(exc.__cause__, "winerror", None)
        if winerror is not None:
            reason = f"{reason} (Windows error {winerror})"
        return {"available": False, "reason": reason}
    return {"available": True, "reason": None}


def native_backend_available() -> bool:
    """Return whether the native LWE DLL can be loaded in this environment."""
    return native_backend_status()["available"]


def _check_status(library: ctypes.CDLL, status: int) -> None:
    if status:
        message = library.lattice_crypto_strerror(status).decode("ascii")
        raise ValueError(f"Native lattice operation failed: {message} ({status})")


def _params(parameters: dict[str, Any]) -> _LatticeParams:
    values = _LatticeParams(
        int(parameters["dimension"]),
        int(parameters["modulus"]),
        int(parameters["message_modulus"]),
        int(parameters["noise_bound"]),
        int(parameters["samples"]),
    )
    if values.modulus > _MAX_SAFE_MODULUS:
        raise ValueError("Native backend requires modulus <= 1000000000 for its int64 arithmetic contract.")
    return values


def generate_lattice_keypair_native(parameters: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    library = _load_library()
    native_params = _params(parameters)
    public_key = _LatticePublicKey()
    private_key = _LatticePrivateKey()
    _check_status(library, library.lattice_generate_keypair(ctypes.byref(native_params), ctypes.byref(public_key), ctypes.byref(private_key)))
    try:
        matrix = [[public_key.matrix_a[row * public_key.dimension + col] for col in range(public_key.dimension)] for row in range(public_key.samples)]
        vector = [public_key.vector_b[index] for index in range(public_key.samples)]
        secret = [private_key.secret[index] for index in range(private_key.dimension)]
        metadata = {
            "dimension": int(native_params.dimension),
            "modulus": int(native_params.modulus),
            "message_modulus": int(native_params.message_modulus),
            "noise_bound": int(native_params.noise_bound),
            "samples": int(native_params.samples),
        }
        return ({**metadata, "matrix_A": matrix, "vector_b": vector}, {**metadata, "secret": secret})
    finally:
        library.lattice_free_public_key(ctypes.byref(public_key))
        library.lattice_free_private_key(ctypes.byref(private_key))


def encrypt_lattice_block_native(message_block: list[int], public_key: dict[str, Any]) -> dict[str, Any]:
    library = _load_library()
    dimension = int(public_key["dimension"])
    matrix_values = (ctypes.c_int64 * (int(public_key["samples"]) * dimension))(*[value for row in public_key["matrix_A"] for value in row])
    vector_values = (ctypes.c_int64 * int(public_key["samples"]))(*public_key["vector_b"])
    native_key = _LatticePublicKey(dimension, int(public_key["samples"]), int(public_key["modulus"]), int(public_key["message_modulus"]), int(public_key["noise_bound"]), matrix_values, vector_values)
    message_values = (ctypes.c_int32 * dimension)(*message_block)
    ciphertext = _LatticeCiphertextBlock()
    _check_status(library, library.lattice_encrypt_block(ctypes.byref(native_key), message_values, dimension, ctypes.byref(ciphertext)))
    try:
        return {"samples": [{"u": [ciphertext.samples[index].u[column] for column in range(dimension)], "v": int(ciphertext.samples[index].v), "symbol": int(ciphertext.samples[index].symbol), "component_index": index} for index in range(ciphertext.count)]}
    finally:
        library.lattice_free_ciphertext_block(ctypes.byref(ciphertext))


def decrypt_lattice_block_native(ciphertext_block: dict[str, Any], private_key: dict[str, Any]) -> list[int]:
    library = _load_library()
    dimension = int(private_key["dimension"])
    secret_values = (ctypes.c_int64 * dimension)(*private_key["secret"])
    samples = (_LatticeCiphertextSample * len(ciphertext_block["samples"]))()
    u_buffers = []
    for index, sample in enumerate(ciphertext_block["samples"]):
        u_buffer = (ctypes.c_int64 * dimension)(*sample["u"])
        u_buffers.append(u_buffer)
        samples[index] = _LatticeCiphertextSample(dimension, u_buffer, int(sample["v"]), int(sample.get("symbol", 0)))
    native_key = _LatticePrivateKey(dimension, int(private_key["modulus"]), int(private_key["message_modulus"]), int(private_key["noise_bound"]), secret_values)
    native_block = _LatticeCiphertextBlock(len(samples), samples)
    recovered = (ctypes.c_int32 * len(samples))()
    _check_status(library, library.lattice_decrypt_block(ctypes.byref(native_key), ctypes.byref(native_block), recovered, len(samples)))
    return [int(value) for value in recovered]


__all__ = [
    "generate_lattice_keypair_native",
    "encrypt_lattice_block_native",
    "decrypt_lattice_block_native",
    "native_backend_available",
    "native_backend_status",
]
