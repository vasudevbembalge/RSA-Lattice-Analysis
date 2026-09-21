/**
 * LLL Lattice Reduction Algorithm Implementation in C
 *
 * Mathematical Foundations:
 * 1. Basis: b_0, b_1, ..., b_{n-1} in Z^m
 * 2. Gram-Schmidt Orthogonalization (GSO):
 *      b_i* = b_i - sum_{j=0}^{i-1} mu_{i,j} b_j*
 *      mu_{i,j} = <b_i, b_j*> / <b_j*, b_j*>
 * 3. Size Reduction:
 *      For j = k-1 down to 0:
 *        if |mu_{k,j}| > 0.5:
 *          q = round(mu_{k,j})
 *          b_k = b_k - q * b_j
 * 4. Lovasz Condition:
 *      ||b_k*||^2 >= (delta - mu_{k,k-1}^2) * ||b_{k-1}*||^2
 *      If failed: swap b_k and b_{k-1}, k = max(k-1, 1).
 */

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <limits.h>

#define LLL_EXPORTS
#include "../include/lll.h"

#ifdef _WIN32
#include <windows.h>
static double get_high_precision_time_ms(void) {
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (double)(counter.QuadPart * 1000.0) / (double)freq.QuadPart;
}
#else
static double get_high_precision_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000.0) + (ts.tv_nsec / 1000000.0);
}
#endif

const char* lll_strerror(int err_code) {
    switch (err_code) {
        case LLL_SUCCESS:
            return "LLL reduction completed successfully.";
        case LLL_ERR_INVALID_DIMENSIONS:
            return "Invalid matrix dimensions: rows must be <= cols and within [1, 64].";
        case LLL_ERR_NULL_POINTER:
            return "Null pointer supplied for matrix or result parameter.";
        case LLL_ERR_INPUT_RANGE_EXCEEDED:
            return "Input exceeds supported numeric range (|entry| <= 2^31 - 1).";
        case LLL_ERR_SINGULAR_MATRIX:
            return "Basis is linearly dependent (singular matrix); LLL requires full rank.";
        case LLL_ERR_INTEGER_OVERFLOW:
            return "Integer overflow detected during basis vector transformation.";
        case LLL_ERR_MAX_ITERATIONS:
            return "Maximum iteration count exceeded without convergence.";
        case LLL_ERR_INVALID_DELTA:
            return "Invalid Lovasz parameter: delta must satisfy 0.25 < delta <= 1.0.";
        default:
            return "Unknown LLL algorithm error.";
    }
}

double lll_vector_norm_squared(const int64_t *vec, int cols) {
    double sum = 0.0;
    for (int j = 0; j < cols; j++) {
        double val = (double)vec[j];
        sum += val * val;
    }
    return sum;
}

/**
 * Recompute Gram-Schmidt orthogonalization up to index 'upto' (inclusive).
 * Uses stable double precision for b_star and mu coefficients.
 */
static int compute_gso(
    int rows,
    int cols,
    int64_t *matrix,
    double b_star[LLL_MAX_DIM][LLL_MAX_DIM],
    double mu[LLL_MAX_DIM][LLL_MAX_DIM],
    double B[LLL_MAX_DIM],
    int upto
) {
    (void)rows;
    for (int i = 0; i <= upto; i++) {
        /* Initialize b_i* = b_i */
        int64_t *bi = &matrix[i * cols];
        for (int c = 0; c < cols; c++) {
            b_star[i][c] = (double)bi[c];
        }

        /* Subtract projections onto prior orthogonal vectors */
        for (int j = 0; j < i; j++) {
            if (B[j] < 1e-12) {
                return LLL_ERR_SINGULAR_MATRIX;
            }
            double dot = 0.0;
            for (int c = 0; c < cols; c++) {
                dot += (double)bi[c] * b_star[j][c];
            }
            mu[i][j] = dot / B[j];
            for (int c = 0; c < cols; c++) {
                b_star[i][c] -= mu[i][j] * b_star[j][c];
            }
        }

        /* Compute B[i] = ||b_i*||^2 */
        double norm_sq = 0.0;
        for (int c = 0; c < cols; c++) {
            norm_sq += b_star[i][c] * b_star[i][c];
        }
        if (norm_sq < 1e-12) {
            return LLL_ERR_SINGULAR_MATRIX;
        }
        B[i] = norm_sq;
        mu[i][i] = 1.0;
    }
    return LLL_SUCCESS;
}

/**
 * Safe 64-bit integer multiplication and subtraction:
 * res = a - q * b with overflow detection.
 */
static int safe_sub_mul(int64_t a, int64_t q, int64_t b, int64_t *out) {
    if (q == 0 || b == 0) {
        *out = a;
        return 0;
    }
    /* Check multiplication overflow: q * b */
    if (q > 0) {
        if (b > 0 && q > (LLONG_MAX / b)) return 1;
        if (b < 0 && b < (LLONG_MIN / q)) return 1;
    } else { /* q < 0 */
        if (b > 0 && q < (LLONG_MIN / b)) return 1;
        if (b < 0 && q < (LLONG_MAX / b)) return 1;
    }
    int64_t prod = q * b;

    /* Check subtraction overflow: a - prod */
    if ((prod > 0 && a < LLONG_MIN + prod) ||
        (prod < 0 && a > LLONG_MAX + prod)) {
        return 1;
    }
    *out = a - prod;
    return 0;
}

/**
 * Size reduction of vector k with respect to vector j.
 */
static int size_reduce_step(
    int cols,
    int64_t *matrix,
    double mu[LLL_MAX_DIM][LLL_MAX_DIM],
    int k,
    int j
) {
    if (fabs(mu[k][j]) > 0.5000000000001) {
        int64_t q = (int64_t)floor(mu[k][j] + 0.5);
        if (q != 0) {
            int64_t *bk = &matrix[k * cols];
            int64_t *bj = &matrix[j * cols];

            for (int c = 0; c < cols; c++) {
                int64_t next_val;
                if (safe_sub_mul(bk[c], q, bj[c], &next_val)) {
                    return LLL_ERR_INTEGER_OVERFLOW;
                }
                bk[c] = next_val;
            }

            for (int l = 0; l < j; l++) {
                mu[k][l] -= (double)q * mu[j][l];
            }
            mu[k][j] -= (double)q;
        }
    }
    return LLL_SUCCESS;
}

int lll_reduce(
    int rows,
    int cols,
    int64_t *matrix,
    double delta,
    LLLResult *result
) {
    double start_time = get_high_precision_time_ms();

    /* 1. Null pointer validation */
    if (!matrix) {
        if (result) {
            result->status_code = LLL_ERR_NULL_POINTER;
            strncpy(result->error_message, lll_strerror(LLL_ERR_NULL_POINTER), 255);
        }
        return LLL_ERR_NULL_POINTER;
    }

    /* 2. Dimension validation */
    if (rows <= 0 || cols <= 0 || rows > cols || rows > LLL_MAX_DIM || cols > LLL_MAX_DIM) {
        if (result) {
            result->status_code = LLL_ERR_INVALID_DIMENSIONS;
            strncpy(result->error_message, lll_strerror(LLL_ERR_INVALID_DIMENSIONS), 255);
        }
        return LLL_ERR_INVALID_DIMENSIONS;
    }

    /* 3. Delta validation: 0.25 < delta <= 1.0 */
    if (delta <= 0.25 || delta > 1.0) {
        if (result) {
            result->status_code = LLL_ERR_INVALID_DELTA;
            strncpy(result->error_message, lll_strerror(LLL_ERR_INVALID_DELTA), 255);
        }
        return LLL_ERR_INVALID_DELTA;
    }

    /* 4. Numerical range bounds check on input elements */
    for (int i = 0; i < rows * cols; i++) {
        if (matrix[i] > LLL_MAX_INPUT_ENTRY || matrix[i] < -LLL_MAX_INPUT_ENTRY) {
            if (result) {
                result->status_code = LLL_ERR_INPUT_RANGE_EXCEEDED;
                strncpy(result->error_message, lll_strerror(LLL_ERR_INPUT_RANGE_EXCEEDED), 255);
            }
            return LLL_ERR_INPUT_RANGE_EXCEEDED;
        }
    }

    /* Gram-Schmidt buffers */
    double b_star[LLL_MAX_DIM][LLL_MAX_DIM];
    double mu[LLL_MAX_DIM][LLL_MAX_DIM];
    double B[LLL_MAX_DIM];

    memset(b_star, 0, sizeof(b_star));
    memset(mu, 0, sizeof(mu));
    memset(B, 0, sizeof(B));

    /* Initial GSO computation */
    int gso_status = compute_gso(rows, cols, matrix, b_star, mu, B, rows - 1);
    if (gso_status != LLL_SUCCESS) {
        if (result) {
            result->status_code = gso_status;
            strncpy(result->error_message, lll_strerror(gso_status), 255);
        }
        return gso_status;
    }

    int k = 1;
    int iterations = 0;
    int swaps = 0;

    /* Main LLL Reduction Loop */
    while (k < rows) {
        iterations++;
        if (iterations > LLL_MAX_ITERATIONS) {
            if (result) {
                result->status_code = LLL_ERR_MAX_ITERATIONS;
                result->iterations = iterations;
                result->swaps = swaps;
                strncpy(result->error_message, lll_strerror(LLL_ERR_MAX_ITERATIONS), 255);
            }
            return LLL_ERR_MAX_ITERATIONS;
        }

        /* Step A: Size reduction of b_k against b_{k-1} */
        int sr_err = size_reduce_step(cols, matrix, mu, k, k - 1);
        if (sr_err != LLL_SUCCESS) {
            if (result) {
                result->status_code = sr_err;
                strncpy(result->error_message, lll_strerror(sr_err), 255);
            }
            return sr_err;
        }

        /* Step B: Check Lovasz Condition
         * B[k] >= (delta - mu_{k,k-1}^2) * B[k-1]
         */
        double lovasz_bound = (delta - (mu[k][k-1] * mu[k][k-1])) * B[k-1];

        if (B[k] < lovasz_bound - 1e-10) {
            /* Lovasz condition failed -> Swap b_k and b_{k-1} */
            int64_t *bk = &matrix[k * cols];
            int64_t *bk_prev = &matrix[(k - 1) * cols];

            for (int c = 0; c < cols; c++) {
                int64_t temp = bk[c];
                bk[c] = bk_prev[c];
                bk_prev[c] = temp;
            }
            swaps++;

            /* Recompute GSO from k-1 */
            gso_status = compute_gso(rows, cols, matrix, b_star, mu, B, rows - 1);
            if (gso_status != LLL_SUCCESS) {
                if (result) {
                    result->status_code = gso_status;
                    strncpy(result->error_message, lll_strerror(gso_status), 255);
                }
                return gso_status;
            }

            if (k > 1) {
                k = k - 1;
            }
        } else {
            /* Lovasz condition satisfied -> Size reduce against all remaining earlier vectors */
            for (int j = k - 2; j >= 0; j--) {
                sr_err = size_reduce_step(cols, matrix, mu, k, j);
                if (sr_err != LLL_SUCCESS) {
                    if (result) {
                        result->status_code = sr_err;
                        strncpy(result->error_message, lll_strerror(sr_err), 255);
                    }
                    return sr_err;
                }
            }
            k = k + 1;
        }
    }

    double end_time = get_high_precision_time_ms();

    if (result) {
        result->iterations = iterations;
        result->swaps = swaps;
        result->execution_time_ms = end_time - start_time;
        result->status_code = LLL_SUCCESS;
        strncpy(result->error_message, lll_strerror(LLL_SUCCESS), 255);
    }

    return LLL_SUCCESS;
}