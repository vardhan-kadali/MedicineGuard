#ifndef MEDICINEGUARD_MERKLE_H
#define MEDICINEGUARD_MERKLE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "sha256.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Magic header for canonical serialization: "MG01" */
#define MG_SERIALIZATION_MAGIC 0x4D473031U
#define MG_DOMAIN_LEAF   0x00U
#define MG_DOMAIN_PARENT 0x01U

/* Maximum tree depth (32 levels can support over 4 billion units) */
#define MERKLE_MAX_DEPTH 32

/* Return error codes */
typedef enum {
    MERKLE_SUCCESS                  =  0,
    MERKLE_ERR_NULL_POINTER         = -1,
    MERKLE_ERR_INVALID_RECORD       = -2,
    MERKLE_ERR_EMPTY_BATCH          = -3,
    MERKLE_ERR_MIXED_BATCH          = -4,
    MERKLE_ERR_DUPLICATE_UNIT       = -5,
    MERKLE_ERR_OUT_OF_BOUNDS        = -6,
    MERKLE_ERR_ALLOCATION_FAILED    = -7,
    MERKLE_ERR_INVALID_PROOF        = -8,
    MERKLE_ERR_ROOT_MISMATCH        = -9,
    MERKLE_ERR_SERIALIZATION_FAILED = -10
} merkle_error_t;

/**
 * @brief Represents an individual medicine unit in a batch.
 */
typedef struct {
    char *batch_id;           /* e.g. "BATCH101" */
    char *unit_id;            /* e.g. "MED00001" */
    char *medicine_name;      /* e.g. "Paracetamol 500mg" */
    char *manufacturing_date; /* e.g. "2026-11-13" (YYYY-MM-DD) */
    char *expiry_date;        /* e.g. "2028-11-13" (YYYY-MM-DD) */
} medicine_record_t;

/**
 * @brief Direction of sibling node in Merkle path.
 */
typedef enum {
    SIBLING_LEFT  = 0, /* Sibling is to the left of the current node: H(sibling || current) */
    SIBLING_RIGHT = 1  /* Sibling is to the right of the current node: H(current || sibling) */
} sibling_direction_t;

/**
 * @brief Single step in a Merkle Proof.
 */
typedef struct {
    uint8_t hash[SHA256_DIGEST_SIZE];
    sibling_direction_t direction;
} merkle_proof_step_t;

/**
 * @brief Complete Merkle Proof for an individual medicine unit.
 */
typedef struct {
    uint32_t leaf_index;
    uint32_t total_leaves;
    uint32_t step_count;
    merkle_proof_step_t steps[MERKLE_MAX_DEPTH];
} merkle_proof_t;

/**
 * @brief Single level inside an in-memory Merkle Tree.
 */
typedef struct {
    size_t count;
    uint8_t (*hashes)[SHA256_DIGEST_SIZE];
} merkle_level_t;

/**
 * @brief In-memory Merkle Tree data structure.
 */
typedef struct {
    char *batch_id;
    size_t leaf_count;
    size_t height;               /* Number of levels in tree (1 when leaf_count == 1) */
    merkle_level_t *levels;      /* Array of levels: levels[0] is leaves, levels[height-1] is root */
    uint8_t root[SHA256_DIGEST_SIZE];
} merkle_tree_t;

/* --- Core Record Validation & Serialization --- */

/**
 * @brief Validate individual medicine record fields for completeness and format.
 */
merkle_error_t merkle_validate_record(const medicine_record_t *record);

/**
 * @brief Validate an array of records: must have same batch_id, unique unit_ids, valid fields.
 */
merkle_error_t merkle_validate_batch(const medicine_record_t *records, size_t count);

/**
 * @brief Deterministically serialize a medicine record into canonical binary format:
 *        [MG01][len(batch_id)][batch_id]...[len(expiry_date)][expiry_date]
 *
 * @param record Input record.
 * @param out_bytes Output buffer allocated with malloc (caller must free()).
 * @param out_len Output byte length.
 */
merkle_error_t merkle_serialize_record(const medicine_record_t *record,
                                       uint8_t **out_bytes,
                                       size_t *out_len);

/* --- Cryptographic Hashing Functions --- */

/**
 * @brief Compute domain-separated leaf hash: SHA256(0x00 || serialized_record)
 */
merkle_error_t merkle_compute_leaf_hash(const medicine_record_t *record,
                                        uint8_t leaf_hash[SHA256_DIGEST_SIZE]);

/**
 * @brief Compute domain-separated parent hash: SHA256(0x01 || left_hash || right_hash)
 */
void merkle_compute_parent_hash(const uint8_t left[SHA256_DIGEST_SIZE],
                                const uint8_t right[SHA256_DIGEST_SIZE],
                                uint8_t parent_hash[SHA256_DIGEST_SIZE]);

/* --- Tree Construction, Proof Generation & Verification --- */

/**
 * @brief Build a complete Merkle Tree from an array of validated medicine records.
 *
 * @param records Array of medicine records.
 * @param count Number of records (must be >= 1).
 * @param out_tree Pointer to receive allocated tree structure (free with merkle_tree_free).
 */
merkle_error_t merkle_tree_build(const medicine_record_t *records,
                                 size_t count,
                                 merkle_tree_t **out_tree);

/**
 * @brief Retrieve the 32-byte Merkle Root from a built tree.
 */
merkle_error_t merkle_tree_get_root(const merkle_tree_t *tree,
                                    uint8_t root_out[SHA256_DIGEST_SIZE]);

/**
 * @brief Generate a Merkle Proof for a leaf at a specified index.
 *
 * @param tree Built Merkle Tree.
 * @param leaf_index Index of the leaf (0 <= leaf_index < leaf_count).
 * @param proof_out Output proof structure.
 */
merkle_error_t merkle_proof_generate(const merkle_tree_t *tree,
                                     size_t leaf_index,
                                     merkle_proof_t *proof_out);

/**
 * @brief Verify a Merkle Proof against an expected trusted Merkle Root and record.
 *
 * @param record The claimed medicine record.
 * @param proof The Merkle Proof for this record.
 * @param expected_root The trusted 32-byte batch Merkle Root.
 * @return MERKLE_SUCCESS (0) if proof and record are valid, or an error code.
 */
merkle_error_t merkle_proof_verify(const medicine_record_t *record,
                                   const merkle_proof_t *proof,
                                   const uint8_t expected_root[SHA256_DIGEST_SIZE]);

/**
 * @brief Verify a pre-computed leaf hash against a Merkle Proof and trusted root.
 */
merkle_error_t merkle_proof_verify_leaf_hash(const uint8_t leaf_hash[SHA256_DIGEST_SIZE],
                                            const merkle_proof_t *proof,
                                            const uint8_t expected_root[SHA256_DIGEST_SIZE]);

/**
 * @brief Free all memory allocated for a Merkle Tree.
 */
void merkle_tree_free(merkle_tree_t *tree);

/**
 * @brief Human-readable string for error code.
 */
const char *merkle_error_string(merkle_error_t err);

#ifdef __cplusplus
}
#endif

#endif /* MEDICINEGUARD_MERKLE_H */
