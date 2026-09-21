"""
Lattice Operations and Sample Basis Generation Module.
Provides test matrices, random lattice generation, norm calculations,
and educational RSA-related lattice representations.
"""

import math
import random
from typing import List, Dict, Any


def compute_vector_norms(matrix: List[List[int]]) -> List[float]:
    """Compute Euclidean norms ||v|| for each row vector in the matrix."""
    return [
        round(math.sqrt(sum(x * x for x in row)), 3) for row in matrix
    ]


def generate_sample_matrix(sample_type: str = "textbook_3x3") -> Dict[str, Any]:
    """
    Generate preset sample matrices for academic demonstration.

    Args:
        sample_type: 'textbook_3x3', 'skewed_2x2', 'dimension_4x4', or 'rsa_analysis_basis'.

    Returns:
        Dict with sample name, description, and matrix data.
    """
    samples = {
        "textbook_3x3": {
            "name": "Textbook 3x3 Lattice",
            "description": "Standard benchmark basis demonstrating orthogonalization and size reduction.",
            "matrix": [
                [105, 821, 404],
                [31, 57, 91],
                [12, 34, 77],
            ],
        },
        "skewed_2x2": {
            "name": "Skewed 2D Lattice",
            "description": "Highly non-orthogonal 2D basis illustrating Gauss-reduction / 2D LLL equivalence.",
            "matrix": [
                [1, 100],
                [0, 2],
            ],
        },
        "dimension_4x4": {
            "name": "4x4 Structured Basis",
            "description": "Higher dimensional integer basis testing multiple Lovasz swap stages.",
            "matrix": [
                [15, 23, 11, 4],
                [2, 18, 9, 21],
                [8, 5, 27, 13],
                [19, 14, 6, 25],
            ],
        },
        "modular_relation_basis": {
            "name": "Educational Modular-Relation Lattice Basis",
            "description": (
                "Demonstration of representing a toy modular integer relation as a lattice basis "
                "for structural analysis. This is not an encryption or cryptanalysis algorithm."
            ),
            # Toy educational structural basis for a modular relation with modulus 899.
            "matrix": [
                [899, 0],
                [17, 1],
            ],
        },
    }

    # Preserve the existing lookup for clients while using the generic canonical name.
    samples["rsa_analysis_basis"] = samples["modular_relation_basis"]

    if sample_type not in samples:
        sample_type = "textbook_3x3"

    return samples[sample_type]


def generate_random_matrix(rows: int, cols: int, min_val: int = -50, max_val: int = 50) -> List[List[int]]:
    """
    Generate a random integer lattice basis of given dimensions with non-zero determinant.
    """
    if rows <= 0 or cols < rows:
        raise ValueError("Invalid dimensions: rows must be <= cols and positive.")

    for _ in range(100):
        mat = []
        for _ in range(rows):
            row = [random.randint(min_val, max_val) for _ in range(cols)]
            # Ensure not all zeroes
            if all(x == 0 for x in row):
                row[0] = random.choice([1, 2, -1, -2])
            mat.append(row)
        return mat

    return mat
