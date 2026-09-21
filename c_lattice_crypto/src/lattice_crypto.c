#include "lattice_crypto.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

static LatticeRandomSource g_random_source = {0};

static int secure_random_u64(uint64_t *out)
{
    if (g_random_source.next_u64 != NULL) {
        *out = g_random_source.next_u64(g_random_source.context);
        return 1;
    }

#if defined(_WIN32)
    if (BCryptGenRandom(NULL, (PUCHAR)out, (ULONG)sizeof(uint64_t), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return 0;
    }
    return 1;
#else
    return 0;
#endif
}

static int64_t mod_reduce(int64_t value, int64_t modulus)
{
    int64_t r = value % modulus;
    if (r < 0) {
        r += modulus;
    }
    return r;
}

static int64_t centered_residue(int64_t value, int64_t modulus)
{
    int64_t residue = mod_reduce(value, modulus);
    return residue > (modulus / 2) ? residue - modulus : residue;
}

static int64_t random_int_range(int64_t low, int64_t high)
{
    uint64_t span = (uint64_t)(high - low + 1);
    uint64_t raw = 0;
    if (!secure_random_u64(&raw)) {
        return low;
    }
    return low + (int64_t)(raw % span);
}

static int64_t random_small_value(int64_t bound)
{
    return random_int_range(-bound, bound);
}

static int64_t random_binary_value(void)
{
    uint64_t raw = 0;
    if (!secure_random_u64(&raw)) {
        return 0;
    }
    return (raw & 1ULL) ? 1LL : 0LL;
}

static int safe_integer_multiply(int64_t a, int64_t b, int64_t *out)
{
    if (a == 0 || b == 0) {
        *out = 0;
        return 1;
    }

    if (a > 0 && b > 0 && a > INT64_MAX / b) {
        return 0;
    }
    if (a > 0 && b < 0 && b < INT64_MIN / a) {
        return 0;
    }
    if (a < 0 && b > 0 && a < INT64_MIN / b) {
        return 0;
    }
    if (a < 0 && b < 0 && a < INT64_MIN / b) {
        return 0;
    }

    *out = a * b;
    return 1;
}

static int64_t mod_mul(int64_t a, int64_t b, int64_t modulus)
{
    int64_t product = 0;
    if (!safe_integer_multiply(a, b, &product)) {
        return 0;
    }
    return mod_reduce(product, modulus);
}

static int64_t mod_add(int64_t a, int64_t b, int64_t modulus)
{
    return mod_reduce(a + b, modulus);
}

static int64_t mod_inner_product(const int64_t *lhs, const int64_t *rhs, int32_t length, int64_t modulus)
{
    int64_t total = 0;
    int32_t i;

    if (lhs == NULL || rhs == NULL || length <= 0 || modulus <= 0) {
        return 0;
    }

    for (i = 0; i < length; ++i) {
        int64_t term = mod_mul(lhs[i], rhs[i], modulus);
        total = mod_add(total, term, modulus);
    }
    return total;
}

static int matrix_vector_product_transpose(
    const int64_t *matrix,
    int32_t rows,
    int32_t cols,
    const int64_t *vector,
    int64_t modulus,
    int64_t *out
)
{
    int32_t col;
    int32_t row;

    if (matrix == NULL || vector == NULL || out == NULL) {
        return LATTICE_INVALID_ARGUMENT;
    }
    if (rows <= 0 || cols <= 0 || modulus <= 0) {
        return LATTICE_INVALID_PARAMETER;
    }

    for (col = 0; col < cols; ++col) {
        int64_t total = 0;
        for (row = 0; row < rows; ++row) {
            int64_t term = mod_mul(matrix[row * cols + col], vector[row], modulus);
            total = mod_add(total, term, modulus);
        }
        out[col] = total;
    }

    return LATTICE_SUCCESS;
}

static int normalize_symbol(int32_t symbol, int32_t modulus)
{
    int32_t normalized = symbol % modulus;
    if (normalized < 0) {
        normalized += modulus;
    }
    return normalized;
}

static int64_t rounded_division(int64_t numerator, int64_t denominator)
{
    double quotient = (double)numerator / (double)denominator;
    if (quotient >= 0.0) {
        return (int64_t)floor(quotient + 0.5);
    }
    return (int64_t)ceil(quotient - 0.5);
}

const char *lattice_crypto_strerror(int code)
{
    switch (code) {
        case LATTICE_SUCCESS:
            return "LATTICE_SUCCESS";
        case LATTICE_INVALID_ARGUMENT:
            return "LATTICE_INVALID_ARGUMENT";
        case LATTICE_INVALID_DIMENSION:
            return "LATTICE_INVALID_DIMENSION";
        case LATTICE_INVALID_PARAMETER:
            return "LATTICE_INVALID_PARAMETER";
        case LATTICE_INVALID_KEY:
            return "LATTICE_INVALID_KEY";
        case LATTICE_INVALID_CIPHERTEXT:
            return "LATTICE_INVALID_CIPHERTEXT";
        case LATTICE_BUFFER_TOO_SMALL:
            return "LATTICE_BUFFER_TOO_SMALL";
        case LATTICE_RANDOM_FAILURE:
            return "LATTICE_RANDOM_FAILURE";
        case LATTICE_ARITHMETIC_ERROR:
            return "LATTICE_ARITHMETIC_ERROR";
        case LATTICE_INTERNAL_ERROR:
            return "LATTICE_INTERNAL_ERROR";
        case LATTICE_MEMORY_ERROR:
            return "LATTICE_MEMORY_ERROR";
        default:
            return "LATTICE_UNKNOWN_ERROR";
    }
}

int lattice_validate_params(const LatticeParams *params)
{
    if (params == NULL) {
        return LATTICE_INVALID_ARGUMENT;
    }

    if (params->dimension <= 1 || params->dimension > LATTICE_MAX_DIMENSION) {
        return LATTICE_INVALID_DIMENSION;
    }
    if (params->modulus <= 1 || params->modulus > LATTICE_MAX_SAFE_MODULUS || (params->modulus % 2LL) == 0LL) {
        return LATTICE_INVALID_PARAMETER;
    }
    if (params->message_modulus <= 1) {
        return LATTICE_INVALID_PARAMETER;
    }
    if (params->message_modulus >= params->modulus) {
        return LATTICE_INVALID_PARAMETER;
    }
    if (params->noise_bound < 1) {
        return LATTICE_INVALID_PARAMETER;
    }
    if (params->samples < params->dimension) {
        return LATTICE_INVALID_PARAMETER;
    }

    int64_t scale = params->modulus / params->message_modulus;
    int64_t max_decryption_noise =
        ((int64_t)params->samples * params->noise_bound) +
        params->noise_bound +
        ((int64_t)params->dimension * params->noise_bound * params->noise_bound);
    if (scale <= 0 || (max_decryption_noise * 2LL) >= scale) {
        return LATTICE_INVALID_PARAMETER;
    }

    return LATTICE_SUCCESS;
}

void lattice_free_public_key(LatticePublicKey *key)
{
    if (key == NULL) {
        return;
    }
    free(key->matrix_a);
    free(key->vector_b);
    key->matrix_a = NULL;
    key->vector_b = NULL;
    key->dimension = 0;
    key->samples = 0;
    key->modulus = 0;
}

void lattice_free_private_key(LatticePrivateKey *key)
{
    if (key == NULL) {
        return;
    }
    free(key->secret);
    key->secret = NULL;
    key->dimension = 0;
    key->modulus = 0;
}

void lattice_free_ciphertext_block(LatticeCiphertextBlock *block)
{
    int32_t i;
    if (block == NULL) {
        return;
    }
    if (block->samples != NULL) {
        for (i = 0; i < block->count; ++i) {
            free(block->samples[i].u);
            block->samples[i].u = NULL;
        }
        free(block->samples);
    }
    block->samples = NULL;
    block->count = 0;
}

void lattice_free_ciphertext(LatticeCiphertext *ciphertext)
{
    int32_t i;
    if (ciphertext == NULL) {
        return;
    }

    if (ciphertext->blocks != NULL) {
        for (i = 0; i < ciphertext->count; ++i) {
            int32_t j;
            if (ciphertext->blocks[i].samples != NULL) {
                for (j = 0; j < ciphertext->blocks[i].count; ++j) {
                    free(ciphertext->blocks[i].samples[j].u);
                    ciphertext->blocks[i].samples[j].u = NULL;
                }
                free(ciphertext->blocks[i].samples);
                ciphertext->blocks[i].samples = NULL;
            }
        }
        free(ciphertext->blocks);
        ciphertext->blocks = NULL;
    }
    ciphertext->count = 0;
}

int lattice_set_random_source(LatticeRandomFn fn, void *context)
{
    if (fn == NULL) {
        memset(&g_random_source, 0, sizeof(g_random_source));
        return LATTICE_SUCCESS;
    }
    g_random_source.next_u64 = fn;
    g_random_source.context = context;
    return LATTICE_SUCCESS;
}

int lattice_generate_keypair(
    const LatticeParams *params,
    LatticePublicKey *public_key_out,
    LatticePrivateKey *private_key_out
)
{
    int32_t i;
    int32_t j;
    int32_t total_count;
    int result;

    if (params == NULL || public_key_out == NULL || private_key_out == NULL) {
        return LATTICE_INVALID_ARGUMENT;
    }

    result = lattice_validate_params(params);
    if (result != LATTICE_SUCCESS) {
        return result;
    }

    memset(public_key_out, 0, sizeof(*public_key_out));
    memset(private_key_out, 0, sizeof(*private_key_out));

    public_key_out->dimension = params->dimension;
    public_key_out->samples = params->samples;
    public_key_out->modulus = params->modulus;
    public_key_out->message_modulus = params->message_modulus;
    public_key_out->noise_bound = params->noise_bound;

    total_count = params->samples * params->dimension;
    public_key_out->matrix_a = (int64_t *)calloc((size_t)total_count, sizeof(int64_t));
    if (public_key_out->matrix_a == NULL) {
        return LATTICE_MEMORY_ERROR;
    }

    public_key_out->vector_b = (int64_t *)calloc((size_t)params->samples, sizeof(int64_t));
    if (public_key_out->vector_b == NULL) {
        lattice_free_public_key(public_key_out);
        return LATTICE_MEMORY_ERROR;
    }

    private_key_out->dimension = params->dimension;
    private_key_out->modulus = params->modulus;
    private_key_out->message_modulus = params->message_modulus;
    private_key_out->noise_bound = params->noise_bound;
    private_key_out->secret = (int64_t *)calloc((size_t)params->dimension, sizeof(int64_t));
    if (private_key_out->secret == NULL) {
        lattice_free_public_key(public_key_out);
        return LATTICE_MEMORY_ERROR;
    }

    for (i = 0; i < params->samples; ++i) {
        for (j = 0; j < params->dimension; ++j) {
            int64_t value = random_int_range(0, params->modulus - 1);
            public_key_out->matrix_a[i * params->dimension + j] = value;
        }
    }

    for (j = 0; j < params->dimension; ++j) {
        private_key_out->secret[j] = random_small_value(params->noise_bound);
    }

    for (i = 0; i < params->samples; ++i) {
        int64_t total = 0;
        for (j = 0; j < params->dimension; ++j) {
            int64_t term = mod_mul(public_key_out->matrix_a[i * params->dimension + j], private_key_out->secret[j], params->modulus);
            total = mod_add(total, term, params->modulus);
        }
        public_key_out->vector_b[i] = mod_add(total, random_small_value(params->noise_bound), params->modulus);
    }

    return LATTICE_SUCCESS;
}

int lattice_encrypt_block(
    const LatticePublicKey *public_key,
    const int32_t *message_block,
    int32_t message_block_len,
    LatticeCiphertextBlock *ciphertext_out
)
{
    int32_t idx;
    int64_t *r = NULL;
    int64_t *e1 = NULL;
    int64_t *u = NULL;
    int64_t scale = 0;
    int64_t q = 0;
    int64_t p = 0;

    if (public_key == NULL || message_block == NULL || ciphertext_out == NULL) {
        return LATTICE_INVALID_ARGUMENT;
    }
    if (message_block_len <= 0 || message_block_len != public_key->dimension) {
        return LATTICE_INVALID_DIMENSION;
    }
    if (public_key->matrix_a == NULL || public_key->vector_b == NULL) {
        return LATTICE_INVALID_KEY;
    }

    q = public_key->modulus;
    p = public_key->message_modulus;
    if (p <= 1 || p >= q) {
        return LATTICE_INVALID_PARAMETER;
    }

    memset(ciphertext_out, 0, sizeof(*ciphertext_out));
    ciphertext_out->count = message_block_len;
    ciphertext_out->samples = (LatticeCiphertextSample *)calloc((size_t)message_block_len, sizeof(LatticeCiphertextSample));
    if (ciphertext_out->samples == NULL) {
        return LATTICE_MEMORY_ERROR;
    }

    scale = q / p;
    r = (int64_t *)calloc((size_t)public_key->samples, sizeof(int64_t));
    e1 = (int64_t *)calloc((size_t)public_key->dimension, sizeof(int64_t));
    u = (int64_t *)calloc((size_t)public_key->dimension, sizeof(int64_t));
    if (r == NULL || e1 == NULL || u == NULL) {
        free(r);
        free(e1);
        free(u);
        for (idx = 0; idx < ciphertext_out->count; ++idx) {
            free(ciphertext_out->samples[idx].u);
        }
        free(ciphertext_out->samples);
        ciphertext_out->samples = NULL;
        ciphertext_out->count = 0;
        return LATTICE_MEMORY_ERROR;
    }

    for (idx = 0; idx < message_block_len; ++idx) {
        int32_t symbol = normalize_symbol(message_block[idx], (int32_t)p);
        int32_t i;
        int64_t e2 = random_small_value(public_key->noise_bound);
        int64_t row_total = 0;

        for (i = 0; i < public_key->samples; ++i) {
            r[i] = random_binary_value();
        }
        for (i = 0; i < public_key->dimension; ++i) {
            e1[i] = random_small_value(public_key->noise_bound);
        }

        if (matrix_vector_product_transpose(public_key->matrix_a, public_key->samples, public_key->dimension, r, q, u) != LATTICE_SUCCESS) {
            free(r);
            free(e1);
            free(u);
            for (i = 0; i < ciphertext_out->count; ++i) {
                free(ciphertext_out->samples[i].u);
            }
            free(ciphertext_out->samples);
            ciphertext_out->samples = NULL;
            ciphertext_out->count = 0;
            return LATTICE_ARITHMETIC_ERROR;
        }

        for (i = 0; i < public_key->dimension; ++i) {
            u[i] = mod_add(u[i], e1[i], q);
        }
        for (i = 0; i < public_key->samples; ++i) {
            row_total = mod_add(row_total, mod_mul(public_key->vector_b[i], r[i], q), q);
        }

        ciphertext_out->samples[idx].dimension = public_key->dimension;
        ciphertext_out->samples[idx].u = (int64_t *)calloc((size_t)public_key->dimension, sizeof(int64_t));
        if (ciphertext_out->samples[idx].u == NULL) {
            free(r);
            free(e1);
            free(u);
            for (i = 0; i < ciphertext_out->count; ++i) {
                free(ciphertext_out->samples[i].u);
            }
            free(ciphertext_out->samples);
            ciphertext_out->samples = NULL;
            ciphertext_out->count = 0;
            return LATTICE_MEMORY_ERROR;
        }

        memcpy(ciphertext_out->samples[idx].u, u, (size_t)public_key->dimension * sizeof(int64_t));
        ciphertext_out->samples[idx].symbol = symbol;
        ciphertext_out->samples[idx].v = mod_add(row_total, mod_mul(scale, symbol, q), q);
        ciphertext_out->samples[idx].v = mod_add(ciphertext_out->samples[idx].v, e2, q);
    }

    free(r);
    free(e1);
    free(u);
    return LATTICE_SUCCESS;
}

int lattice_decrypt_block(
    const LatticePrivateKey *private_key,
    const LatticeCiphertextBlock *ciphertext_block,
    int32_t *recovered_block,
    int32_t recovered_block_len
)
{
    int32_t i;
    int64_t q;
    int64_t p;
    int64_t scale;

    if (private_key == NULL || ciphertext_block == NULL || recovered_block == NULL) {
        return LATTICE_INVALID_ARGUMENT;
    }
    if (ciphertext_block->count <= 0 || recovered_block_len != ciphertext_block->count) {
        return LATTICE_INVALID_CIPHERTEXT;
    }
    if (private_key->secret == NULL) {
        return LATTICE_INVALID_KEY;
    }

    q = private_key->modulus;
    p = private_key->message_modulus;
    if (p <= 1 || p >= q) {
        return LATTICE_INVALID_PARAMETER;
    }
    scale = q / p;

    for (i = 0; i < ciphertext_block->count; ++i) {
        int64_t dot = 0;
        int64_t t = 0;
        int64_t symbol = 0;
        int32_t j;

        if (ciphertext_block->samples[i].u == NULL) {
            return LATTICE_INVALID_CIPHERTEXT;
        }

        for (j = 0; j < private_key->dimension; ++j) {
            int64_t term = mod_mul(ciphertext_block->samples[i].u[j], private_key->secret[j], q);
            dot = mod_add(dot, term, q);
        }

        t = centered_residue((int64_t)ciphertext_block->samples[i].v - dot, q);
        symbol = rounded_division(t, scale);
        symbol = symbol % (int64_t)p;
        if (symbol < 0) {
            symbol += p;
        }
        recovered_block[i] = (int32_t)symbol;
    }

    return LATTICE_SUCCESS;
}

