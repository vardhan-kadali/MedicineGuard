#ifndef MEDICINEGUARD_SHA256_H
#define MEDICINEGUARD_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_BLOCK_SIZE  64  /* 512 bits = 64 bytes */
#define SHA256_DIGEST_SIZE 32  /* 256 bits = 32 bytes */

/**
 * @brief SHA-256 calculation context.
 *
 * Implements FIPS PUB 180-4 standard specification.
 */
typedef struct {
    uint32_t state[8];                 /* Current intermediate hash state (H0..H7) */
    uint64_t bit_count;                /* Total number of bits processed */
    uint8_t  buffer[SHA256_BLOCK_SIZE];/* 64-byte chunk buffer */
    size_t   buffer_len;               /* Number of unhashed bytes currently in buffer */
} sha256_ctx_t;

/**
 * @brief Initialize a SHA-256 context with standard FIPS 180-4 initial vector.
 *
 * @param ctx Pointer to the context structure.
 */
void sha256_init(sha256_ctx_t *ctx);

/**
 * @brief Ingest arbitrary data bytes into the SHA-256 context.
 *
 * @param ctx Pointer to initialized context.
 * @param data Pointer to input data buffer.
 * @param len Number of bytes to process.
 */
void sha256_update(sha256_ctx_t *ctx, const void *data, size_t len);

/**
 * @brief Finalize the hash computation, applying padding and writing the 32-byte digest.
 *
 * @param ctx Pointer to context. Zeroed upon completion.
 * @param hash_out Buffer of at least 32 bytes to receive the final digest.
 */
void sha256_final(sha256_ctx_t *ctx, uint8_t hash_out[SHA256_DIGEST_SIZE]);

/**
 * @brief One-shot utility function to hash a buffer in a single call.
 *
 * @param data Pointer to input data.
 * @param len Number of bytes.
 * @param hash_out Buffer of at least 32 bytes to receive the final digest.
 */
void sha256_hash(const void *data, size_t len, uint8_t hash_out[SHA256_DIGEST_SIZE]);

/**
 * @brief Convert a 32-byte binary digest into a null-terminated 64-character lowercase hex string.
 *
 * @param hash_in 32-byte binary digest.
 * @param hex_out Buffer of at least 65 bytes (64 hex characters + null terminator).
 */
void sha256_to_hex(const uint8_t hash_in[SHA256_DIGEST_SIZE], char hex_out[65]);

/**
 * @brief Constant-time memory comparison to mitigate timing side-channel attacks.
 *
 * @param a First memory buffer.
 * @param b Second memory buffer.
 * @param len Number of bytes to compare.
 * @return 0 if buffers are identical, non-zero if they differ.
 */
int crypto_memcmp(const void *a, const void *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* MEDICINEGUARD_SHA256_H */
