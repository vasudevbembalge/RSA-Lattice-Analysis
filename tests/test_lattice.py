import pytest
import math
from backend.lattice.lll_interface import run_lll_reduction
from backend.lattice.lattice_operations import (
    generate_sample_matrix,
    generate_random_matrix,
    compute_vector_norms,
)


def determinant_2x2(m):
    return m[0][0] * m[1][1] - m[0][1] * m[1][0]


def determinant_3x3(m):
    return (
        m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
        - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
        + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0])
    )


def test_lll_identity_matrix():
    mat = [[1, 0, 0], [0, 1, 0], [0, 0, 1]]
    res = run_lll_reduction(mat, delta=0.75)
    assert res["status"] == "success"
    assert res["reduced_basis"] == mat
    assert res["swaps"] == 0
    assert res["original_norms"] == res["reduced_norms"]


def test_lll_textbook_3x3_basis():
    mat = [
        [105, 821, 404],
        [31, 57, 91],
        [12, 34, 77],
    ]
    res = run_lll_reduction(mat, delta=0.75)

    assert res["status"] == "success"
    assert res["reduction_status"] == "LLL REDUCTION COMPLETED"
    assert res["rows"] == 3
    assert res["cols"] == 3
    assert res["iterations"] > 0
    assert res["swaps"] > 0

    # Exact expected reduced basis from C LLL core
    expected = [
        [-19, -23, -14],
        [-26, -12, 49],
        [-292, 282, -93],
    ]
    assert res["reduced_basis"] == expected

    # Determinant invariant check (unimodular transformation preserves lattice volume)
    det_orig = abs(determinant_3x3(mat))
    det_red = abs(determinant_3x3(res["reduced_basis"]))
    assert det_orig == det_red, f"Lattice determinant must be preserved: {det_orig} != {det_red}"

    # First vector Euclidean norm strictly reduced
    assert res["reduced_norms"][0] < res["original_norms"][0]
    assert "Private-key recovery is outside the scope" in res["disclaimer"]


def test_lll_skewed_2x2():
    mat = [[1, 100], [0, 2]]
    res = run_lll_reduction(mat, delta=0.75)
    assert res["status"] == "success"
    assert res["reduced_basis"] == [[1, 0], [0, 2]]
    assert abs(determinant_2x2(mat)) == abs(determinant_2x2(res["reduced_basis"]))


def test_lll_4x4_structured():
    sample = generate_sample_matrix("dimension_4x4")
    res = run_lll_reduction(sample["matrix"], delta=0.75)
    assert res["status"] == "success"
    assert len(res["reduced_basis"]) == 4
    assert len(res["reduced_basis"][0]) == 4
    assert res["iterations"] > 0


def test_lll_rsa_analysis_sample():
    sample = generate_sample_matrix("rsa_analysis_basis")
    res = run_lll_reduction(sample["matrix"], delta=0.75)
    assert res["status"] == "success"
    assert len(res["reduced_basis"]) == 2
    assert "Private-key recovery is outside the scope" in res["disclaimer"]


def test_lll_random_matrix_reduction():
    mat = generate_random_matrix(3, 3, min_val=-20, max_val=20)
    try:
        res = run_lll_reduction(mat, delta=0.75)
        assert res["status"] == "success"
        assert len(res["reduced_basis"]) == 3
    except ValueError as exc:
        # If random matrix happens to be singular, it must raise the singular matrix error cleanly
        assert "linearly dependent" in str(exc)


@pytest.mark.parametrize("invalid_entry", [3.14, "text", None, [1], True])
def test_lll_reject_non_integers(invalid_entry):
    mat = [[1, invalid_entry], [0, 2]]
    with pytest.raises(ValueError, match="Matrix must contain integers"):
        run_lll_reduction(mat)


def test_lll_reject_irregular_columns():
    mat = [[1, 2, 3], [4, 5]]
    with pytest.raises(ValueError, match="All rows must have the same number of columns"):
        run_lll_reduction(mat)


def test_lll_reject_oversized_entries():
    mat = [[3000000000, 1], [0, 2]]
    with pytest.raises(ValueError, match="Input exceeds supported numeric range"):
        run_lll_reduction(mat)


def test_lll_reject_singular_matrix():
    # Linearly dependent: Row 2 is 2 * Row 1
    mat = [[3, 6], [6, 12]]
    with pytest.raises(ValueError, match="Basis is linearly dependent"):
        run_lll_reduction(mat)


@pytest.mark.parametrize("bad_delta", [0.0, 0.25, -0.5, 1.1, 2.0])
def test_lll_reject_invalid_delta(bad_delta):
    mat = [[1, 2], [3, 4]]
    with pytest.raises(ValueError, match="Lovasz parameter delta must satisfy"):
        run_lll_reduction(mat, delta=bad_delta)