/**
 * LLL Lattice Reduction Algorithm
 * Academic Demonstration and Computational Framework
 *
 * Header file defining data structures, limits, error codes, and API declarations.
 */

#ifndef LLL_H
#define LLL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
  #ifdef LLL_EXPORTS
    #define LLL_API __declspec(dllexport)
  #else
    #define LLL_API __declspec(dllimport)
  #endif
#else
  #define LLL_API __attribute__((visibility("default")))
#endif

/* Maximum matrix dimensions for the bounded integer implementation */
#define LLL_MAX_DIM 64

/* Maximum absolute value for input matrix elements (bounded integer safety) */
#define LLL_MAX_INPUT_ENTRY 2147483647LL  /* 2^31 - 1 */

/* Maximum iterations safety guard */
#define LLL_MAX_ITERATIONS 1000000

/* Status and Error Codes */
#define LLL_SUCCESS                     0
#define LLL_ERR_INVALID_DIMENSIONS     -1
#define LLL_ERR_NULL_POINTER           -2
#define LLL_ERR_INPUT_RANGE_EXCEEDED   -3
#define LLL_ERR_SINGULAR_MATRIX        -4
#define LLL_ERR_INTEGER_OVERFLOW       -5
#define LLL_ERR_MAX_ITERATIONS         -6
#define LLL_ERR_INVALID_DELTA          -7

/**
 * Execution telemetry and metadata structure.
 */
typedef struct {
    int iterations;
    int swaps;
    double execution_time_ms;
    int status_code;
    char error_message[256];
} LLLResult;

/**
 * Reduce an integer lattice basis using the Lenstra-Lenstra-Lovasz (LLL) algorithm.
 *
 * @param rows Number of basis vectors (lattice rank n).
 * @param cols Dimension of the ambient space (m >= n).
 * @param matrix Contiguous array of size rows * cols in row-major order.
 *               Input: original basis B. Output: reduced basis B'.
 * @param delta Lovasz parameter, typically 0.75 (must satisfy 0.25 < delta <= 1.0).
 * @param result Pointer to LLLResult structure to receive execution telemetry.
 *
 * @return LLL_SUCCESS (0) on success, or a negative error code on failure.
 */
LLL_API int lll_reduce(
    int rows,
    int cols,
    int64_t *matrix,
    double delta,
    LLLResult *result
);

/**
 * Compute the squared Euclidean norm of a vector: ||v||^2 = <v, v>.
 */
LLL_API double lll_vector_norm_squared(
    const int64_t *vec,
    int cols
);

/**
 * Get human-readable description for an LLL error code.
 */
LLL_API const char* lll_strerror(int err_code);

#ifdef __cplusplus
}
#endif

#endif /* LLL_H */