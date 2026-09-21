#ifndef LATTICE_CRYPTO_H
#define LATTICE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#  if defined(LATTICE_CRYPTO_BUILD)
#    define LATTICE_API __declspec(dllexport)
#  else
#    define LATTICE_API __declspec(dllimport)
#  endif
#else
#  define LATTICE_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define LATTICE_SUCCESS 0
#define LATTICE_INVALID_ARGUMENT (-1)
#define LATTICE_INVALID_DIMENSION (-2)
#define LATTICE_INVALID_PARAMETER (-3)
#define LATTICE_INVALID_KEY (-4)
#define LATTICE_INVALID_CIPHERTEXT (-5)
#define LATTICE_BUFFER_TOO_SMALL (-6)
#define LATTICE_RANDOM_FAILURE (-7)
#define LATTICE_ARITHMETIC_ERROR (-8)
#define LATTICE_INTERNAL_ERROR (-9)
#define LATTICE_MEMORY_ERROR (-10)

#define LATTICE_MAX_DIMENSION 64
#define LATTICE_MAX_SAFE_MODULUS 1000000000LL

typedef struct {
    int32_t dimension;
    int64_t modulus;
    int32_t message_modulus;
    int32_t noise_bound;
    int32_t samples;
} LatticeParams;

typedef struct {
    int32_t dimension;
    int32_t samples;
    int64_t modulus;
    int32_t message_modulus;
    int32_t noise_bound;
    int64_t *matrix_a;
    int64_t *vector_b;
} LatticePublicKey;

typedef struct {
    int32_t dimension;
    int64_t modulus;
    int32_t message_modulus;
    int32_t noise_bound;
    int64_t *secret;
} LatticePrivateKey;

typedef struct {
    int32_t dimension;
    int64_t *u;
    int64_t v;
    int32_t symbol;
} LatticeCiphertextSample;

typedef struct {
    int32_t count;
    LatticeCiphertextSample *samples;
} LatticeCiphertextBlock;

typedef struct {
    int32_t count;
    LatticeCiphertextBlock *blocks;
} LatticeCiphertext;

typedef uint64_t (*LatticeRandomFn)(void *context);

typedef struct {
    LatticeRandomFn next_u64;
    void *context;
    uint64_t state;
} LatticeRandomSource;

LATTICE_API const char *lattice_crypto_strerror(int code);

LATTICE_API int lattice_validate_params(const LatticeParams *params);

LATTICE_API void lattice_free_public_key(LatticePublicKey *key);
LATTICE_API void lattice_free_private_key(LatticePrivateKey *key);
LATTICE_API void lattice_free_ciphertext_block(LatticeCiphertextBlock *block);
LATTICE_API void lattice_free_ciphertext(LatticeCiphertext *ciphertext);

LATTICE_API int lattice_set_random_source(LatticeRandomFn fn, void *context);

LATTICE_API int lattice_generate_keypair(
    const LatticeParams *params,
    LatticePublicKey *public_key_out,
    LatticePrivateKey *private_key_out
);

LATTICE_API int lattice_encrypt_block(
    const LatticePublicKey *public_key,
    const int32_t *message_block,
    int32_t message_block_len,
    LatticeCiphertextBlock *ciphertext_out
);

LATTICE_API int lattice_decrypt_block(
    const LatticePrivateKey *private_key,
    const LatticeCiphertextBlock *ciphertext_block,
    int32_t *recovered_block,
    int32_t recovered_block_len
);

#ifdef __cplusplus
}
#endif

#endif
