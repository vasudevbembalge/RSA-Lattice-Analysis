#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "lll.h"

static void print_matrix(const char *label, const int64_t *matrix, int rows, int cols) {
    printf("%s (%d x %d):\n", label, rows, cols);
    for (int i = 0; i < rows; i++) {
        printf("  [ ");
        for (int j = 0; j < cols; j++) {
            printf("%8lld ", matrix[i * cols + j]);
        }
        printf("]  (norm: %.2f)\n", sqrt(lll_vector_norm_squared(&matrix[i * cols], cols)));
    }
}

int main(void) {
    int total_tests = 0;
    int passed_tests = 0;

    printf("==================================================\n");
    printf("        INDEPENDENT C LLL ENGINE TEST SUITE       \n");
    printf("==================================================\n\n");

    /* TEST 1: Identity Matrix (Already Reduced) */
    {
        total_tests++;
        printf("TEST 1: 3x3 Identity Matrix (Already Reduced)\n");
        int64_t mat[9] = {
            1, 0, 0,
            0, 1, 0,
            0, 0, 1
        };
        LLLResult res;
        int status = lll_reduce(3, 3, mat, 0.75, &res);
        if (status == LLL_SUCCESS && res.swaps == 0) {
            printf("[PASS] Identity matrix preserved. Swaps: %d, Iterations: %d, Time: %.3f ms\n\n",
                   res.swaps, res.iterations, res.execution_time_ms);
            passed_tests++;
        } else {
            printf("[FAIL] Status: %d, Message: %s\n\n", status, res.error_message);
        }
    }

    /* TEST 2: Textbook 3x3 Lattice from Specification */
    {
        total_tests++;
        printf("TEST 2: Textbook 3x3 Lattice from Specification\n");
        int64_t mat[9] = {
            105, 821, 404,
            31,   57,  91,
            12,   34,  77
        };
        int64_t orig[9];
        memcpy(orig, mat, sizeof(orig));

        print_matrix("Original Basis B", mat, 3, 3);

        LLLResult res;
        int status = lll_reduce(3, 3, mat, 0.75, &res);

        if (status == LLL_SUCCESS) {
            print_matrix("Reduced Basis B'", mat, 3, 3);
            printf("Iterations: %d, Swaps: %d, Execution Time: %.3f ms\n",
                   res.iterations, res.swaps, res.execution_time_ms);

            double orig_norm0 = sqrt(lll_vector_norm_squared(&orig[0], 3));
            double red_norm0 = sqrt(lll_vector_norm_squared(&mat[0], 3));

            if (red_norm0 < orig_norm0) {
                printf("[PASS] LLL reduction successfully reduced vector lengths (%.2f -> %.2f)\n\n",
                       orig_norm0, red_norm0);
                passed_tests++;
            } else {
                printf("[FAIL] Expected reduced norm to be smaller: %.2f vs %.2f\n\n", red_norm0, orig_norm0);
            }
        } else {
            printf("[FAIL] Status: %d, Message: %s\n\n", status, res.error_message);
        }
    }

    /* TEST 3: 2D Highly Skewed Lattice */
    {
        total_tests++;
        printf("TEST 3: 2D Highly Skewed Lattice\n");
        int64_t mat[4] = {
            1, 100,
            0, 2
        };
        LLLResult res;
        int status = lll_reduce(2, 2, mat, 0.75, &res);
        if (status == LLL_SUCCESS) {
            print_matrix("Reduced 2D Basis", mat, 2, 2);
            printf("[PASS] 2D reduction succeeded in %d iterations, %.3f ms\n\n",
                   res.iterations, res.execution_time_ms);
            passed_tests++;
        } else {
            printf("[FAIL] 2D reduction failed: %s\n\n", res.error_message);
        }
    }

    /* TEST 4: Singular / Linearly Dependent Matrix */
    {
        total_tests++;
        printf("TEST 4: Singular Matrix Detection (Linearly Dependent)\n");
        int64_t mat[9] = {
            1, 2, 3,
            4, 5, 6,
            5, 7, 9  /* Row 3 = Row 1 + Row 2 */
        };
        LLLResult res;
        int status = lll_reduce(3, 3, mat, 0.75, &res);
        if (status == LLL_ERR_SINGULAR_MATRIX) {
            printf("[PASS] Correctly rejected singular matrix: %s\n\n", res.error_message);
            passed_tests++;
        } else {
            printf("[FAIL] Expected LLL_ERR_SINGULAR_MATRIX, got %d\n\n", status);
        }
    }

    /* TEST 5: Dimension Bounds Validation */
    {
        total_tests++;
        printf("TEST 5: Dimension Bounds Validation (rows > cols)\n");
        int64_t mat[6] = { 1, 2, 3, 4, 5, 6 };
        LLLResult res;
        int status = lll_reduce(3, 2, mat, 0.75, &res);
        if (status == LLL_ERR_INVALID_DIMENSIONS) {
            printf("[PASS] Correctly rejected rows > cols: %s\n\n", res.error_message);
            passed_tests++;
        } else {
            printf("[FAIL] Expected LLL_ERR_INVALID_DIMENSIONS, got %d\n\n", status);
        }
    }

    /* TEST 6: Numerical Range Bound Check */
    {
        total_tests++;
        printf("TEST 6: Numerical Range Bounds Check (entry > 2^31 - 1)\n");
        int64_t mat[4] = {
            3000000000LL, 1,
            0, 2
        };
        LLLResult res;
        int status = lll_reduce(2, 2, mat, 0.75, &res);
        if (status == LLL_ERR_INPUT_RANGE_EXCEEDED) {
            printf("[PASS] Correctly caught input range violation: %s\n\n", res.error_message);
            passed_tests++;
        } else {
            printf("[FAIL] Expected LLL_ERR_INPUT_RANGE_EXCEEDED, got %d\n\n", status);
        }
    }

    /* TEST 7: Invalid Delta Parameter */
    {
        total_tests++;
        printf("TEST 7: Invalid Delta Parameter (delta = 0.20)\n");
        int64_t mat[4] = { 1, 2, 3, 4 };
        LLLResult res;
        int status = lll_reduce(2, 2, mat, 0.20, &res);
        if (status == LLL_ERR_INVALID_DELTA) {
            printf("[PASS] Correctly rejected invalid delta: %s\n\n", res.error_message);
            passed_tests++;
        } else {
            printf("[FAIL] Expected LLL_ERR_INVALID_DELTA, got %d\n\n", status);
        }
    }

    printf("==================================================\n");
    printf("TEST RESULTS: %d / %d PASSED\n", passed_tests, total_tests);
    printf("==================================================\n");

    return (passed_tests == total_tests) ? 0 : 1;
}