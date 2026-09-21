"""
Python ctypes Interface to Native C LLL Dynamic Link Library (lll.dll).
Handles robust data marshalling, input validation, error code translation,
and numeric telemetry extraction.
"""

import os
import ctypes
import math
from typing import List, Dict, Any

# Path to compiled shared library
DLL_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "c_lll", "bin", "lll.dll")
)

# C Structure matching LLLResult in lll.h
class C_LLLResult(ctypes.Structure):
    _fields_ = [
        ("iterations", ctypes.c_int),
        ("swaps", ctypes.c_int),
        ("execution_time_ms", ctypes.c_double),
        ("status_code", ctypes.c_int),
        ("error_message", ctypes.c_char * 256),
    ]


def _load_lll_library():
    """Load the compiled native C library with ctypes."""
    if not os.path.exists(DLL_PATH):
        raise FileNotFoundError(
            f"Compiled C LLL library not found at: {DLL_PATH}. "
            "Please build the library using c_lll/build.bat."
        )

    lib = ctypes.CDLL(DLL_PATH)

    # Prototype: int lll_reduce(int, int, int64_t*, double, LLLResult*)
    lib.lll_reduce.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_int64),
        ctypes.c_double,
        ctypes.POINTER(C_LLLResult),
    ]
    lib.lll_reduce.restype = ctypes.c_int

    # Prototype: double lll_vector_norm_squared(const int64_t*, int)
    lib.lll_vector_norm_squared.argtypes = [
        ctypes.POINTER(ctypes.c_int64),
        ctypes.c_int,
    ]
    lib.lll_vector_norm_squared.restype = ctypes.c_double

    # Prototype: const char* lll_strerror(int)
    lib.lll_strerror.argtypes = [ctypes.c_int]
    lib.lll_strerror.restype = ctypes.c_char_p

    return lib


_LIB = None

def get_lib():
    global _LIB
    if _LIB is None:
        _LIB = _load_lll_library()
    return _LIB


def run_lll_reduction(
    matrix: List[List[int]],
    delta: float = 0.75,
) -> Dict[str, Any]:
    """
    Execute LLL lattice reduction on an integer matrix using the native C engine.

    Args:
        matrix: List of integer rows representing basis vectors B = [b_1, ..., b_n].
        delta: Lovasz reduction parameter (default 0.75, must be in (0.25, 1.0]).

    Returns:
        Dict containing original basis, reduced basis, telemetry, and academic disclaimer.

    Raises:
        ValueError: For validation failures (non-integer, empty, irregular, out-of-range, etc.).
    """
    # 1. Basic validation
    if not matrix or not isinstance(matrix, list):
        raise ValueError("Matrix must be a non-empty list of rows.")

    rows = len(matrix)
    if rows == 0:
        raise ValueError("Matrix must not be empty.")

    if not isinstance(matrix[0], list):
        raise ValueError("Matrix rows must be lists.")

    cols = len(matrix[0])
    if cols == 0:
        raise ValueError("Matrix rows must contain at least one column.")

    if rows > cols:
        raise ValueError(
            f"Invalid matrix dimensions: number of basis vectors ({rows}) cannot exceed "
            f"ambient space dimension ({cols})."
        )

    if rows > 64 or cols > 64:
        raise ValueError("Matrix dimension is unsupported (maximum dimension is 64x64).")

    # 2. Row length and entry type validation
    MAX_ENTRY = 2147483647  # 2^31 - 1
    flat_data: List[int] = []

    for r_idx, row in enumerate(matrix):
        if not isinstance(row, list):
            raise ValueError(f"Row {r_idx} is not a valid list.")
        if len(row) != cols:
            raise ValueError("All rows must have the same number of columns.")

        for c_idx, val in enumerate(row):
            # Strict integer check: reject bool, float, str, etc.
            if isinstance(val, bool) or not isinstance(val, int):
                raise ValueError(
                    f"Matrix must contain integers. Found non-integer value '{val}' "
                    f"at row {r_idx}, column {c_idx}."
                )
            if val > MAX_ENTRY or val < -MAX_ENTRY:
                raise ValueError(
                    f"Input exceeds supported numeric range (|entry| <= 2^31 - 1). "
                    f"Value {val} at row {r_idx}, column {c_idx} exceeds bounds."
                )
            flat_data.append(val)

    # 3. Delta validation
    if not isinstance(delta, (int, float)) or delta <= 0.25 or delta > 1.0:
        raise ValueError("Lovasz parameter delta must satisfy 0.25 < delta <= 1.0.")

    # 4. Prepare ctypes contiguous array
    c_array_type = ctypes.c_int64 * (rows * cols)
    c_matrix = c_array_type(*flat_data)
    c_result = C_LLLResult()

    # 5. Invoke native C LLL engine
    lib = get_lib()
    status = lib.lll_reduce(rows, cols, c_matrix, float(delta), ctypes.byref(c_result))

    error_msg = c_result.error_message.decode("utf-8", errors="replace")

    if status != 0:
        raise ValueError(f"LLL Reduction failed: {error_msg}")

    # 6. Unmarshal reduced basis back to Python list
    reduced_matrix: List[List[int]] = []
    for r in range(rows):
        row_vals = [c_matrix[r * cols + c] for c in range(cols)]
        reduced_matrix.append(row_vals)

    # 7. Compute Euclidean norms
    orig_norms = [
        round(math.sqrt(sum(x * x for x in row)), 3) for row in matrix
    ]
    red_norms = [
        round(math.sqrt(sum(x * x for x in row)), 3) for row in reduced_matrix
    ]

    return {
        "status": "success",
        "reduction_status": "LLL REDUCTION COMPLETED",
        "rows": rows,
        "cols": cols,
        "delta": delta,
        "iterations": c_result.iterations,
        "swaps": c_result.swaps,
        "execution_time_ms": round(c_result.execution_time_ms, 3),
        "original_basis": matrix,
        "reduced_basis": reduced_matrix,
        "original_norms": orig_norms,
        "reduced_norms": red_norms,
        "disclaimer": (
            "LLL reduction is demonstrated as a lattice-analysis technique. "
            "Private-key recovery is outside the scope of this implementation."
        ),
    }
