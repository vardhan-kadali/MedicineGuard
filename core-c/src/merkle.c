#include "merkle.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int compare_strings(const void *a, const void *b) {
    const char *str_a = *(const char * const *)a;
    const char *str_b = *(const char * const *)b;
    return strcmp(str_a, str_b);
}

static bool is_valid_date(const char *date_str) {
    if (!date_str || strlen(date_str) != 10) return false;
    /* Basic YYYY-MM-DD pattern validation */
    for (int i = 0; i < 10; i++) {
        if (i == 4 || i == 7) {
            if (date_str[i] != '-') return false;
        } else {
            if (date_str[i] < '0' || date_str[i] > '9') return false;
        }
    }
    return true;
}

merkle_error_t merkle_validate_record(const medicine_record_t *record) {
    if (!record) return MERKLE_ERR_NULL_POINTER;
    if (!record->batch_id || strlen(record->batch_id) == 0) return MERKLE_ERR_INVALID_RECORD;
    if (!record->unit_id || strlen(record->unit_id) == 0) return MERKLE_ERR_INVALID_RECORD;
    if (!record->medicine_name || strlen(record->medicine_name) == 0) return MERKLE_ERR_INVALID_RECORD;
    if (!is_valid_date(record->manufacturing_date)) return MERKLE_ERR_INVALID_RECORD;
    if (!is_valid_date(record->expiry_date)) return MERKLE_ERR_INVALID_RECORD;

    return MERKLE_SUCCESS;
}

merkle_error_t merkle_validate_batch(const medicine_record_t *records, size_t count) {
    if (!records) return MERKLE_ERR_NULL_POINTER;
    if (count == 0) return MERKLE_ERR_EMPTY_BATCH;

    const char *batch_id = records[0].batch_id;

    /* Validate every record and verify uniform batch_id */
    for (size_t i = 0; i < count; i++) {
        merkle_error_t err = merkle_validate_record(&records[i]);
        if (err != MERKLE_SUCCESS) return err;

        if (strcmp(records[i].batch_id, batch_id) != 0) {
            return MERKLE_ERR_MIXED_BATCH;
        }
    }

    /* Check for duplicate unit IDs in O(N log N) using pointer sort */
    if (count > 1) {
        const char **unit_ptrs = (const char **)malloc(count * sizeof(const char *));
        if (!unit_ptrs) return MERKLE_ERR_ALLOCATION_FAILED;

        for (size_t i = 0; i < count; i++) {
            unit_ptrs[i] = records[i].unit_id;
        }

        qsort(unit_ptrs, count, sizeof(const char *), compare_strings);

        for (size_t i = 0; i < count - 1; i++) {
            if (strcmp(unit_ptrs[i], unit_ptrs[i + 1]) == 0) {
                free(unit_ptrs);
                return MERKLE_ERR_DUPLICATE_UNIT;
            }
        }
        free(unit_ptrs);
    }

    return MERKLE_SUCCESS;
}

merkle_error_t merkle_serialize_record(const medicine_record_t *record,
                                       uint8_t **out_bytes,
                                       size_t *out_len) {
    if (!record || !out_bytes || !out_len) return MERKLE_ERR_NULL_POINTER;
    merkle_error_t err = merkle_validate_record(record);
    if (err != MERKLE_SUCCESS) return err;

    uint32_t len_batch = (uint32_t)strlen(record->batch_id);
    uint32_t len_unit  = (uint32_t)strlen(record->unit_id);
    uint32_t len_name  = (uint32_t)strlen(record->medicine_name);
    uint32_t len_mfg   = (uint32_t)strlen(record->manufacturing_date);
    uint32_t len_exp   = (uint32_t)strlen(record->expiry_date);

    /* Total size: 4-byte magic + 5 fields * (4-byte length + field_bytes) */
    size_t total_size = 4 + (4 + len_batch) + (4 + len_unit) + (4 + len_name) +
                            (4 + len_mfg) + (4 + len_exp);

    uint8_t *buffer = (uint8_t *)malloc(total_size);
    if (!buffer) return MERKLE_ERR_ALLOCATION_FAILED;

    size_t offset = 0;

    /* 1. Header magic: "MG01" (0x4D, 0x47, 0x30, 0x31) */
    buffer[offset++] = 'M';
    buffer[offset++] = 'G';
    buffer[offset++] = '0';
    buffer[offset++] = '1';

    /* Helper macro to encode big-endian uint32 length + field bytes */
#define ENCODE_FIELD(field_ptr, field_len) do { \
        buffer[offset++] = (uint8_t)(((field_len) >> 24) & 0xFF); \
        buffer[offset++] = (uint8_t)(((field_len) >> 16) & 0xFF); \
        buffer[offset++] = (uint8_t)(((field_len) >> 8)  & 0xFF); \
        buffer[offset++] = (uint8_t)((field_len)         & 0xFF); \
        memcpy(buffer + offset, (field_ptr), (field_len)); \
        offset += (field_len); \
    } while (0)

    ENCODE_FIELD(record->batch_id, len_batch);
    ENCODE_FIELD(record->unit_id, len_unit);
    ENCODE_FIELD(record->medicine_name, len_name);
    ENCODE_FIELD(record->manufacturing_date, len_mfg);
    ENCODE_FIELD(record->expiry_date, len_exp);

#undef ENCODE_FIELD

    *out_bytes = buffer;
    *out_len = total_size;
    return MERKLE_SUCCESS;
}

merkle_error_t merkle_compute_leaf_hash(const medicine_record_t *record,
                                        uint8_t leaf_hash[SHA256_DIGEST_SIZE]) {
    if (!record || !leaf_hash) return MERKLE_ERR_NULL_POINTER;

    uint8_t *serialized = NULL;
    size_t serialized_len = 0;
    merkle_error_t err = merkle_serialize_record(record, &serialized, &serialized_len);
    if (err != MERKLE_SUCCESS) return err;

    sha256_ctx_t ctx;
    sha256_init(&ctx);

    /* Domain separation prefix for leaf: 0x00 */
    uint8_t prefix = MG_DOMAIN_LEAF;
    sha256_update(&ctx, &prefix, 1);
    sha256_update(&ctx, serialized, serialized_len);
    sha256_final(&ctx, leaf_hash);

    free(serialized);
    return MERKLE_SUCCESS;
}

void merkle_compute_parent_hash(const uint8_t left[SHA256_DIGEST_SIZE],
                                const uint8_t right[SHA256_DIGEST_SIZE],
                                uint8_t parent_hash[SHA256_DIGEST_SIZE]) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);

    /* Domain separation prefix for internal node: 0x01 */
    uint8_t prefix = MG_DOMAIN_PARENT;
    sha256_update(&ctx, &prefix, 1);
    sha256_update(&ctx, left, SHA256_DIGEST_SIZE);
    sha256_update(&ctx, right, SHA256_DIGEST_SIZE);
    sha256_final(&ctx, parent_hash);
}

merkle_error_t merkle_tree_build(const medicine_record_t *records,
                                 size_t count,
                                 merkle_tree_t **out_tree) {
    if (!records || !out_tree) return MERKLE_ERR_NULL_POINTER;
    if (count == 0) return MERKLE_ERR_EMPTY_BATCH;

    merkle_error_t val_err = merkle_validate_batch(records, count);
    if (val_err != MERKLE_SUCCESS) return val_err;

    /* Calculate tree height: count levels until 1 node remains */
    size_t height = 1;
    size_t nodes_at_level = count;
    while (nodes_at_level > 1) {
        nodes_at_level = (nodes_at_level + 1) / 2;
        height++;
    }

    merkle_tree_t *tree = (merkle_tree_t *)calloc(1, sizeof(merkle_tree_t));
    if (!tree) return MERKLE_ERR_ALLOCATION_FAILED;

    tree->batch_id = (char *)malloc(strlen(records[0].batch_id) + 1);
    if (!tree->batch_id) {
        free(tree);
        return MERKLE_ERR_ALLOCATION_FAILED;
    }
    strcpy(tree->batch_id, records[0].batch_id);

    tree->leaf_count = count;
    tree->height = height;
    tree->levels = (merkle_level_t *)calloc(height, sizeof(merkle_level_t));
    if (!tree->levels) {
        free(tree->batch_id);
        free(tree);
        return MERKLE_ERR_ALLOCATION_FAILED;
    }

    /* Level 0: Leaf Hashes */
    tree->levels[0].count = count;
    tree->levels[0].hashes = malloc(count * sizeof(*tree->levels[0].hashes));
    if (!tree->levels[0].hashes) {
        merkle_tree_free(tree);
        return MERKLE_ERR_ALLOCATION_FAILED;
    }

    for (size_t i = 0; i < count; i++) {
        merkle_error_t err = merkle_compute_leaf_hash(&records[i], tree->levels[0].hashes[i]);
        if (err != MERKLE_SUCCESS) {
            merkle_tree_free(tree);
            return err;
        }
    }

    /* Levels 1 .. height - 1: Internal Nodes with Odd-Promotion */
    for (size_t k = 1; k < height; k++) {
        size_t prev_count = tree->levels[k - 1].count;
        size_t next_count = (prev_count + 1) / 2;

        tree->levels[k].count = next_count;
        tree->levels[k].hashes = malloc(next_count * sizeof(*tree->levels[k].hashes));
        if (!tree->levels[k].hashes) {
            merkle_tree_free(tree);
            return MERKLE_ERR_ALLOCATION_FAILED;
        }

        /* Hash adjacent pairs */
        for (size_t i = 0; i < prev_count / 2; i++) {
            merkle_compute_parent_hash(
                tree->levels[k - 1].hashes[2 * i],
                tree->levels[k - 1].hashes[2 * i + 1],
                tree->levels[k].hashes[i]
            );
        }

        /* If odd, promote the unpaired last node directly without hashing */
        if (prev_count % 2 != 0) {
            memcpy(tree->levels[k].hashes[next_count - 1],
                   tree->levels[k - 1].hashes[prev_count - 1],
                   SHA256_DIGEST_SIZE);
        }
    }

    /* Final root is the single hash in top level */
    memcpy(tree->root, tree->levels[height - 1].hashes[0], SHA256_DIGEST_SIZE);

    *out_tree = tree;
    return MERKLE_SUCCESS;
}

merkle_error_t merkle_tree_get_root(const merkle_tree_t *tree,
                                    uint8_t root_out[SHA256_DIGEST_SIZE]) {
    if (!tree || !root_out) return MERKLE_ERR_NULL_POINTER;
    memcpy(root_out, tree->root, SHA256_DIGEST_SIZE);
    return MERKLE_SUCCESS;
}

merkle_error_t merkle_proof_generate(const merkle_tree_t *tree,
                                     size_t leaf_index,
                                     merkle_proof_t *proof_out) {
    if (!tree || !proof_out) return MERKLE_ERR_NULL_POINTER;
    if (leaf_index >= tree->leaf_count) return MERKLE_ERR_OUT_OF_BOUNDS;

    proof_out->leaf_index = (uint32_t)leaf_index;
    proof_out->total_leaves = (uint32_t)tree->leaf_count;
    proof_out->step_count = 0;

    size_t curr_idx = leaf_index;

    /* Traverse from leaf level up to the level just below root */
    for (size_t k = 0; k < tree->height - 1; k++) {
        size_t count_k = tree->levels[k].count;

        if (curr_idx % 2 == 0) {
            if (curr_idx + 1 < count_k) {
                /* Even node with a right sibling */
                if (proof_out->step_count >= MERKLE_MAX_DEPTH) return MERKLE_ERR_OUT_OF_BOUNDS;
                proof_out->steps[proof_out->step_count].direction = SIBLING_RIGHT;
                memcpy(proof_out->steps[proof_out->step_count].hash,
                       tree->levels[k].hashes[curr_idx + 1],
                       SHA256_DIGEST_SIZE);
                proof_out->step_count++;
            }
            /* Else: curr_idx + 1 == count_k.
             * Unpaired odd node promoted unchanged.
             * Rule: Do not add a proof step for this level. */
        } else {
            /* Odd node with a left sibling */
            if (proof_out->step_count >= MERKLE_MAX_DEPTH) return MERKLE_ERR_OUT_OF_BOUNDS;
            proof_out->steps[proof_out->step_count].direction = SIBLING_LEFT;
            memcpy(proof_out->steps[proof_out->step_count].hash,
                   tree->levels[k].hashes[curr_idx - 1],
                   SHA256_DIGEST_SIZE);
            proof_out->step_count++;
        }

        curr_idx /= 2;
    }

    return MERKLE_SUCCESS;
}

merkle_error_t merkle_proof_verify_leaf_hash(const uint8_t leaf_hash[SHA256_DIGEST_SIZE],
                                            const merkle_proof_t *proof,
                                            const uint8_t expected_root[SHA256_DIGEST_SIZE]) {
    if (!leaf_hash || !proof || !expected_root) return MERKLE_ERR_NULL_POINTER;
    if (proof->total_leaves == 0) return MERKLE_ERR_INVALID_PROOF;
    if (proof->leaf_index >= proof->total_leaves) return MERKLE_ERR_INVALID_PROOF;

    uint8_t current_hash[SHA256_DIGEST_SIZE];
    memcpy(current_hash, leaf_hash, SHA256_DIGEST_SIZE);

    size_t curr_idx = proof->leaf_index;
    size_t current_count = proof->total_leaves;
    uint32_t steps_consumed = 0;

    while (current_count > 1) {
        if (curr_idx % 2 == 0) {
            if (curr_idx + 1 < current_count) {
                /* Expect right sibling */
                if (steps_consumed >= proof->step_count) {
                    return MERKLE_ERR_INVALID_PROOF; /* Missing step */
                }
                if (proof->steps[steps_consumed].direction != SIBLING_RIGHT) {
                    return MERKLE_ERR_INVALID_PROOF; /* Direction mismatch */
                }
                merkle_compute_parent_hash(current_hash,
                                           proof->steps[steps_consumed].hash,
                                           current_hash);
                steps_consumed++;
            }
            /* Else: unpaired odd node promoted unchanged; no step consumed */
        } else {
            /* Expect left sibling */
            if (steps_consumed >= proof->step_count) {
                return MERKLE_ERR_INVALID_PROOF; /* Missing step */
            }
            if (proof->steps[steps_consumed].direction != SIBLING_LEFT) {
                return MERKLE_ERR_INVALID_PROOF; /* Direction mismatch */
            }
            merkle_compute_parent_hash(proof->steps[steps_consumed].hash,
                                       current_hash,
                                       current_hash);
            steps_consumed++;
        }

        curr_idx /= 2;
        current_count = (current_count + 1) / 2;
    }

    /* Ensure exactly all proof steps were consumed (no extra trailing steps) */
    if (steps_consumed != proof->step_count) {
        return MERKLE_ERR_INVALID_PROOF;
    }

    /* Constant-time comparison against expected root */
    if (crypto_memcmp(current_hash, expected_root, SHA256_DIGEST_SIZE) != 0) {
        return MERKLE_ERR_ROOT_MISMATCH;
    }

    return MERKLE_SUCCESS;
}

merkle_error_t merkle_proof_verify(const medicine_record_t *record,
                                   const merkle_proof_t *proof,
                                   const uint8_t expected_root[SHA256_DIGEST_SIZE]) {
    if (!record || !proof || !expected_root) return MERKLE_ERR_NULL_POINTER;

    uint8_t leaf_hash[SHA256_DIGEST_SIZE];
    merkle_error_t err = merkle_compute_leaf_hash(record, leaf_hash);
    if (err != MERKLE_SUCCESS) return err;

    return merkle_proof_verify_leaf_hash(leaf_hash, proof, expected_root);
}

void merkle_tree_free(merkle_tree_t *tree) {
    if (!tree) return;

    if (tree->levels) {
        for (size_t k = 0; k < tree->height; k++) {
            if (tree->levels[k].hashes) {
                free(tree->levels[k].hashes);
            }
        }
        free(tree->levels);
    }

    if (tree->batch_id) {
        free(tree->batch_id);
    }

    free(tree);
}

const char *merkle_error_string(merkle_error_t err) {
    switch (err) {
        case MERKLE_SUCCESS:                  return "Success";
        case MERKLE_ERR_NULL_POINTER:         return "Null pointer argument";
        case MERKLE_ERR_INVALID_RECORD:       return "Invalid record field or format";
        case MERKLE_ERR_EMPTY_BATCH:          return "Batch is empty";
        case MERKLE_ERR_MIXED_BATCH:          return "Records contain mixed batch IDs";
        case MERKLE_ERR_DUPLICATE_UNIT:       return "Duplicate unit ID detected";
        case MERKLE_ERR_OUT_OF_BOUNDS:        return "Index out of bounds";
        case MERKLE_ERR_ALLOCATION_FAILED:    return "Memory allocation failed";
        case MERKLE_ERR_INVALID_PROOF:        return "Invalid proof structure or path";
        case MERKLE_ERR_ROOT_MISMATCH:        return "Calculated root does not match expected root";
        case MERKLE_ERR_SERIALIZATION_FAILED: return "Record serialization failed";
        default:                              return "Unknown Merkle error";
    }
}
