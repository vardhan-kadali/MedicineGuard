#include "wasm_bridge.h"
#include "sha256.h"
#include "merkle.h"

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifdef __EMSCRIPTEN__
#include <emscripten/heap.h>
#endif

/* --- Memory Range Validation --- */

static inline bool is_valid_memory_range(uint32_t offset, uint32_t len) {
    if (len == 0) return true;
    if (offset == 0) return false;
    /* Check for integer overflow in 32-bit offset + len */
    if (offset > UINT32_MAX - len) return false;

#ifdef __EMSCRIPTEN__
    size_t heap_size = emscripten_get_heap_size();
    if ((uint64_t)offset + (uint64_t)len > (uint64_t)heap_size) {
        return false;
    }
#endif

    return true;
}

static inline void *offset_to_ptr(uint32_t offset) {
    if (offset == 0) return NULL;
    return (void *)(uintptr_t)offset;
}

static inline uint32_t ptr_to_offset(void *ptr) {
    return (uint32_t)(uintptr_t)ptr;
}

/* --- Memory Management Interface --- */

MG_WASM_EXPORT uint32_t mg_wasm_malloc(uint32_t size) {
    if (size == 0) return 0;
    void *ptr = malloc((size_t)size);
    if (!ptr) return 0;
    return (uint32_t)(uintptr_t)ptr;
}

MG_WASM_EXPORT void mg_wasm_free(uint32_t ptr) {
    if (ptr != 0) {
        free(offset_to_ptr(ptr));
    }
}

/* --- Primitive SHA-256 --- */

MG_WASM_EXPORT int32_t mg_wasm_sha256(uint32_t data_ptr, uint32_t len, uint32_t out_hash_ptr) {
    if (!is_valid_memory_range(data_ptr, len) || !is_valid_memory_range(out_hash_ptr, SHA256_DIGEST_SIZE)) {
        return MG_WASM_ERR_NULL_POINTER;
    }
    const uint8_t *data = (const uint8_t *)offset_to_ptr(data_ptr);
    uint8_t *out_hash = (uint8_t *)offset_to_ptr(out_hash_ptr);
    if (!out_hash) return MG_WASM_ERR_NULL_POINTER;

    sha256_hash(data ? data : (const uint8_t *)"", len, out_hash);
    return MG_WASM_SUCCESS;
}

/* --- MG01 Deserializer & Memory Helpers --- */

static void free_medicine_record_fields(medicine_record_t *rec) {
    if (!rec) return;
    if (rec->batch_id)           free(rec->batch_id);
    if (rec->unit_id)            free(rec->unit_id);
    if (rec->medicine_name)      free(rec->medicine_name);
    if (rec->manufacturing_date) free(rec->manufacturing_date);
    if (rec->expiry_date)        free(rec->expiry_date);
    memset(rec, 0, sizeof(*rec));
}

static int32_t parse_mg01_record(const uint8_t *bytes, size_t len, medicine_record_t *out_rec) {
    if (!bytes || !out_rec) return MG_WASM_ERR_NULL_POINTER;
    memset(out_rec, 0, sizeof(*out_rec));

    /* Minimum length: 4 (magic) + 5 fields * 4 (lengths) = 24 bytes */
    if (len < 24) return MG_WASM_ERR_INVALID_MG01_RECORD;

    /* Check magic: "MG01" (0x4D, 0x47, 0x30, 0x31) */
    if (bytes[0] != 'M' || bytes[1] != 'G' || bytes[2] != '0' || bytes[3] != '1') {
        return MG_WASM_ERR_INVALID_MG01_RECORD;
    }

    size_t offset = 4;
    char *fields[5] = { NULL, NULL, NULL, NULL, NULL };

    for (int i = 0; i < 5; i++) {
        if (offset + 4 > len) goto fail;

        /* Decode 4-byte big-endian field length */
        uint32_t f_len = ((uint32_t)bytes[offset]     << 24) |
                         ((uint32_t)bytes[offset + 1] << 16) |
                         ((uint32_t)bytes[offset + 2] <<  8) |
                         ((uint32_t)bytes[offset + 3]);
        offset += 4;

        /* Field cannot be empty */
        if (f_len == 0) goto fail;

        /* Boundary check */
        if (offset + f_len > len) goto fail;

        const uint8_t *f_bytes = bytes + offset;

        /* Reject embedded null bytes */
        for (size_t b = 0; b < f_len; b++) {
            if (f_bytes[b] == '\0') goto fail;
        }

        /* Dates (index 3 and 4) must be exactly 10 bytes: YYYY-MM-DD */
        if ((i == 3 || i == 4) && f_len != 10) goto fail;

        /* Allocate string: f_len + 1 for null terminator */
        fields[i] = (char *)malloc(f_len + 1);
        if (!fields[i]) goto fail_alloc;

        memcpy(fields[i], f_bytes, f_len);
        fields[i][f_len] = '\0';

        offset += f_len;
    }

    /* Reject unexpected trailing bytes */
    if (offset != len) goto fail;

    out_rec->batch_id           = fields[0];
    out_rec->unit_id            = fields[1];
    out_rec->medicine_name      = fields[2];
    out_rec->manufacturing_date = fields[3];
    out_rec->expiry_date        = fields[4];

    /* Run native C validation */
    merkle_error_t verr = merkle_validate_record(out_rec);
    if (verr != MERKLE_SUCCESS) {
        goto fail;
    }

    return MG_WASM_SUCCESS;

fail_alloc:
    for (int i = 0; i < 5; i++) {
        if (fields[i]) free(fields[i]);
    }
    memset(out_rec, 0, sizeof(*out_rec));
    return MG_WASM_ERR_ALLOCATION_FAILED;

fail:
    for (int i = 0; i < 5; i++) {
        if (fields[i]) free(fields[i]);
    }
    memset(out_rec, 0, sizeof(*out_rec));
    return MG_WASM_ERR_INVALID_MG01_RECORD;
}

/* --- MGP1 Wire Serializer & Deserializer --- */

static size_t get_mgp1_wire_size(uint32_t step_count) {
    return 14 + (33 * (size_t)step_count);
}

static int32_t serialize_mgp1_proof(const merkle_proof_t *proof, uint8_t *out_buf, size_t out_cap, size_t *out_len) {
    if (!proof || !out_buf || !out_len) return MG_WASM_ERR_NULL_POINTER;
    if (proof->step_count > MERKLE_MAX_DEPTH) return MG_WASM_ERR_INVALID_MGP1_PROOF;

    size_t req_size = get_mgp1_wire_size(proof->step_count);
    if (out_cap < req_size) return MG_WASM_ERR_BUFFER_TOO_SMALL;

    size_t offset = 0;
    /* Magic "MGP1" (0x4D, 0x47, 0x50, 0x31) */
    out_buf[offset++] = 'M';
    out_buf[offset++] = 'G';
    out_buf[offset++] = 'P';
    out_buf[offset++] = '1';

    /* Leaf index uint32 BE */
    out_buf[offset++] = (uint8_t)((proof->leaf_index >> 24) & 0xFF);
    out_buf[offset++] = (uint8_t)((proof->leaf_index >> 16) & 0xFF);
    out_buf[offset++] = (uint8_t)((proof->leaf_index >>  8) & 0xFF);
    out_buf[offset++] = (uint8_t)((proof->leaf_index)       & 0xFF);

    /* Total leaves uint32 BE */
    out_buf[offset++] = (uint8_t)((proof->total_leaves >> 24) & 0xFF);
    out_buf[offset++] = (uint8_t)((proof->total_leaves >> 16) & 0xFF);
    out_buf[offset++] = (uint8_t)((proof->total_leaves >>  8) & 0xFF);
    out_buf[offset++] = (uint8_t)((proof->total_leaves)       & 0xFF);

    /* Step count uint16 BE */
    out_buf[offset++] = (uint8_t)((proof->step_count >> 8) & 0xFF);
    out_buf[offset++] = (uint8_t)((proof->step_count)      & 0xFF);

    /* Steps */
    for (uint32_t i = 0; i < proof->step_count; i++) {
        memcpy(out_buf + offset, proof->steps[i].hash, SHA256_DIGEST_SIZE);
        offset += SHA256_DIGEST_SIZE;
        out_buf[offset++] = (proof->steps[i].direction == SIBLING_RIGHT) ? 0x01 : 0x00;
    }

    *out_len = offset;
    return MG_WASM_SUCCESS;
}

static int32_t parse_mgp1_proof(const uint8_t *bytes, size_t len, merkle_proof_t *out_proof) {
    if (!bytes || !out_proof) return MG_WASM_ERR_NULL_POINTER;
    memset(out_proof, 0, sizeof(*out_proof));

    /* Header is 14 bytes */
    if (len < 14) return MG_WASM_ERR_INVALID_MGP1_PROOF;

    /* Magic check */
    if (bytes[0] != 'M' || bytes[1] != 'G' || bytes[2] != 'P' || bytes[3] != '1') {
        return MG_WASM_ERR_INVALID_MGP1_PROOF;
    }

    uint32_t leaf_idx = ((uint32_t)bytes[4] << 24) |
                        ((uint32_t)bytes[5] << 16) |
                        ((uint32_t)bytes[6] <<  8) |
                        ((uint32_t)bytes[7]);

    uint32_t total =    ((uint32_t)bytes[8] << 24) |
                        ((uint32_t)bytes[9] << 16) |
                        ((uint32_t)bytes[10] << 8) |
                        ((uint32_t)bytes[11]);

    uint16_t steps =    ((uint16_t)bytes[12] << 8) |
                        ((uint16_t)bytes[13]);

    if (total == 0) return MG_WASM_ERR_INVALID_MGP1_PROOF;
    if (leaf_idx >= total) return MG_WASM_ERR_INVALID_MGP1_PROOF;
    if (steps > MERKLE_MAX_DEPTH) return MG_WASM_ERR_INVALID_MGP1_PROOF;

    size_t expected_len = 14 + (33 * (size_t)steps);
    if (len != expected_len) return MG_WASM_ERR_INVALID_MGP1_PROOF;

    out_proof->leaf_index = leaf_idx;
    out_proof->total_leaves = total;
    out_proof->step_count = steps;

    size_t offset = 14;
    for (uint16_t i = 0; i < steps; i++) {
        memcpy(out_proof->steps[i].hash, bytes + offset, SHA256_DIGEST_SIZE);
        offset += SHA256_DIGEST_SIZE;

        uint8_t dir = bytes[offset++];
        if (dir == 0x00) {
            out_proof->steps[i].direction = SIBLING_LEFT;
        } else if (dir == 0x01) {
            out_proof->steps[i].direction = SIBLING_RIGHT;
        } else {
            /* Invalid direction flag */
            memset(out_proof, 0, sizeof(*out_proof));
            return MG_WASM_ERR_INVALID_MGP1_PROOF;
        }
    }

    return MG_WASM_SUCCESS;
}

/* --- Context Handle Pool --- */

typedef struct {
    uint32_t is_active;
    uint32_t generation;
    medicine_record_t *records;
    size_t record_count;
    size_t record_capacity;
    merkle_tree_t *tree;
    bool is_built;
    char batch_id[128];
} wasm_batch_context_t;

static wasm_batch_context_t g_contexts[MG_WASM_MAX_CONTEXTS];
static bool g_context_pool_init = false;

static void ensure_pool_init(void) {
    if (!g_context_pool_init) {
        memset(g_contexts, 0, sizeof(g_contexts));
        for (int i = 0; i < MG_WASM_MAX_CONTEXTS; i++) {
            g_contexts[i].generation = 1;
        }
        g_context_pool_init = true;
    }
}

static uint32_t make_handle(uint32_t slot_idx, uint32_t gen) {
    return ((gen & 0x07FFFFFFU) << 5) | (slot_idx & 0x1FU);
}

static wasm_batch_context_t *resolve_context(uint32_t handle) {
    if (handle == 0) return NULL;
    ensure_pool_init();

    uint32_t slot_idx = handle & 0x1FU;
    uint32_t gen = (handle >> 5) & 0x07FFFFFFU;

    if (slot_idx >= MG_WASM_MAX_CONTEXTS) return NULL;
    wasm_batch_context_t *ctx = &g_contexts[slot_idx];

    if (!ctx->is_active) return NULL;
    if (ctx->generation != gen) return NULL;

    return ctx;
}

/* --- Batch Lifecycle Operations --- */

MG_WASM_EXPORT uint32_t mg_wasm_batch_create(void) {
    ensure_pool_init();
    for (uint32_t i = 0; i < MG_WASM_MAX_CONTEXTS; i++) {
        if (!g_contexts[i].is_active) {
            wasm_batch_context_t *ctx = &g_contexts[i];
            ctx->is_active = 1;
            ctx->record_count = 0;
            ctx->record_capacity = 32;
            ctx->records = (medicine_record_t *)malloc(ctx->record_capacity * sizeof(medicine_record_t));
            if (!ctx->records) {
                ctx->is_active = 0;
                return 0;
            }
            ctx->tree = NULL;
            ctx->is_built = false;
            ctx->batch_id[0] = '\0';
            return make_handle(i, ctx->generation);
        }
    }
    return 0; /* Context pool full */
}

MG_WASM_EXPORT int32_t mg_wasm_batch_add_record(uint32_t ctx_handle, uint32_t mg01_ptr, uint32_t len) {
    wasm_batch_context_t *ctx = resolve_context(ctx_handle);
    if (!ctx) return MG_WASM_ERR_INVALID_HANDLE;
    if (ctx->is_built) return MG_WASM_ERR_INVALID_STATE;
    if (ctx->record_count >= MG_WASM_MAX_BATCH_RECORDS) return MG_WASM_ERR_LIMIT_EXCEEDED;

    if (!is_valid_memory_range(mg01_ptr, len)) return MG_WASM_ERR_NULL_POINTER;
    const uint8_t *mg01_bytes = (const uint8_t *)offset_to_ptr(mg01_ptr);

    medicine_record_t rec;
    int32_t parse_res = parse_mg01_record(mg01_bytes, len, &rec);
    if (parse_res != MG_WASM_SUCCESS) return parse_res;

    /* Batch ID consistency */
    if (ctx->record_count == 0) {
        strncpy(ctx->batch_id, rec.batch_id, sizeof(ctx->batch_id) - 1);
        ctx->batch_id[sizeof(ctx->batch_id) - 1] = '\0';
    } else {
        if (strcmp(ctx->batch_id, rec.batch_id) != 0) {
            free_medicine_record_fields(&rec);
            return MG_WASM_ERR_MIXED_BATCH;
        }
    }

    /* Grow records array capacity if needed */
    if (ctx->record_count >= ctx->record_capacity) {
        size_t new_cap = ctx->record_capacity * 2;
        if (new_cap > MG_WASM_MAX_BATCH_RECORDS) new_cap = MG_WASM_MAX_BATCH_RECORDS;
        medicine_record_t *new_recs = (medicine_record_t *)realloc(ctx->records, new_cap * sizeof(medicine_record_t));
        if (!new_recs) {
            free_medicine_record_fields(&rec);
            return MG_WASM_ERR_ALLOCATION_FAILED;
        }
        ctx->records = new_recs;
        ctx->record_capacity = new_cap;
    }

    ctx->records[ctx->record_count++] = rec;
    return MG_WASM_SUCCESS;
}

MG_WASM_EXPORT int32_t mg_wasm_batch_build_tree(uint32_t ctx_handle) {
    wasm_batch_context_t *ctx = resolve_context(ctx_handle);
    if (!ctx) return MG_WASM_ERR_INVALID_HANDLE;
    if (ctx->is_built) return MG_WASM_ERR_INVALID_STATE;
    if (ctx->record_count == 0) return MG_WASM_ERR_EMPTY_BATCH;

    merkle_tree_t *tree = NULL;
    merkle_error_t err = merkle_tree_build(ctx->records, ctx->record_count, &tree);
    if (err != MERKLE_SUCCESS || !tree) {
        if (err == MERKLE_ERR_DUPLICATE_UNIT) return MG_WASM_ERR_DUPLICATE_UNIT;
        if (err == MERKLE_ERR_MIXED_BATCH) return MG_WASM_ERR_MIXED_BATCH;
        if (err == MERKLE_ERR_EMPTY_BATCH) return MG_WASM_ERR_EMPTY_BATCH;
        if (err == MERKLE_ERR_ALLOCATION_FAILED) return MG_WASM_ERR_ALLOCATION_FAILED;
        return MG_WASM_ERR_INVALID_ARGUMENT;
    }

    ctx->tree = tree;
    ctx->is_built = true;
    return MG_WASM_SUCCESS;
}

MG_WASM_EXPORT int32_t mg_wasm_batch_get_root(uint32_t ctx_handle, uint32_t out_root_ptr) {
    wasm_batch_context_t *ctx = resolve_context(ctx_handle);
    if (!ctx) return MG_WASM_ERR_INVALID_HANDLE;
    if (!ctx->is_built || !ctx->tree) return MG_WASM_ERR_INVALID_STATE;
    if (!is_valid_memory_range(out_root_ptr, SHA256_DIGEST_SIZE)) return MG_WASM_ERR_NULL_POINTER;

    uint8_t *out_root = (uint8_t *)offset_to_ptr(out_root_ptr);
    if (!out_root) return MG_WASM_ERR_NULL_POINTER;

    return (merkle_tree_get_root(ctx->tree, out_root) == MERKLE_SUCCESS)
           ? MG_WASM_SUCCESS : MG_WASM_ERR_INVALID_STATE;
}

MG_WASM_EXPORT uint32_t mg_wasm_batch_get_leaf_count(uint32_t ctx_handle) {
    wasm_batch_context_t *ctx = resolve_context(ctx_handle);
    return ctx ? (uint32_t)ctx->record_count : 0;
}

MG_WASM_EXPORT uint32_t mg_wasm_batch_get_height(uint32_t ctx_handle) {
    wasm_batch_context_t *ctx = resolve_context(ctx_handle);
    return (ctx && ctx->is_built && ctx->tree) ? (uint32_t)ctx->tree->height : 0;
}

MG_WASM_EXPORT uint32_t mg_wasm_batch_get_proof_size(uint32_t ctx_handle, uint32_t leaf_index) {
    wasm_batch_context_t *ctx = resolve_context(ctx_handle);
    if (!ctx || !ctx->is_built || !ctx->tree) return 0;
    if (leaf_index >= ctx->record_count) return 0;

    merkle_proof_t proof;
    if (merkle_proof_generate(ctx->tree, leaf_index, &proof) != MERKLE_SUCCESS) {
        return 0;
    }
    return (uint32_t)get_mgp1_wire_size(proof.step_count);
}

MG_WASM_EXPORT int32_t mg_wasm_batch_generate_proof(uint32_t ctx_handle, uint32_t leaf_index,
                                                     uint32_t out_buf_ptr, uint32_t out_cap,
                                                     uint32_t out_written_ptr) {
    wasm_batch_context_t *ctx = resolve_context(ctx_handle);
    if (!ctx) return MG_WASM_ERR_INVALID_HANDLE;
    if (!ctx->is_built || !ctx->tree) return MG_WASM_ERR_INVALID_STATE;
    if (leaf_index >= ctx->record_count) return MG_WASM_ERR_INVALID_ARGUMENT;

    if (!is_valid_memory_range(out_buf_ptr, out_cap) ||
        !is_valid_memory_range(out_written_ptr, sizeof(uint32_t))) {
        return MG_WASM_ERR_NULL_POINTER;
    }

    uint8_t *out_buf = (uint8_t *)offset_to_ptr(out_buf_ptr);
    uint32_t *out_written = (uint32_t *)offset_to_ptr(out_written_ptr);
    if (!out_buf || !out_written) return MG_WASM_ERR_NULL_POINTER;

    merkle_proof_t proof;
    merkle_error_t perr = merkle_proof_generate(ctx->tree, leaf_index, &proof);
    if (perr != MERKLE_SUCCESS) return MG_WASM_ERR_INVALID_ARGUMENT;

    size_t written = 0;
    int32_t ser_err = serialize_mgp1_proof(&proof, out_buf, out_cap, &written);
    if (ser_err != MG_WASM_SUCCESS) return ser_err;

    *out_written = (uint32_t)written;
    return MG_WASM_SUCCESS;
}

MG_WASM_EXPORT void mg_wasm_batch_destroy(uint32_t ctx_handle) {
    wasm_batch_context_t *ctx = resolve_context(ctx_handle);
    if (!ctx) return;

    if (ctx->records) {
        for (size_t i = 0; i < ctx->record_count; i++) {
            free_medicine_record_fields(&ctx->records[i]);
        }
        free(ctx->records);
        ctx->records = NULL;
    }

    if (ctx->tree) {
        merkle_tree_free(ctx->tree);
        ctx->tree = NULL;
    }

    ctx->record_count = 0;
    ctx->record_capacity = 0;
    ctx->is_built = false;
    ctx->is_active = 0;
    ctx->batch_id[0] = '\0';

    /* Advance generation counter */
    ctx->generation++;
    if (ctx->generation == 0 || ctx->generation >= 0x07FFFFFFU) {
        ctx->generation = 1;
    }
}

/* --- Pharmacist / Customer Verification Operations --- */

MG_WASM_EXPORT int32_t mg_wasm_verify_record(uint32_t mg01_ptr, uint32_t rec_len,
                                              uint32_t proof_ptr, uint32_t proof_len,
                                              uint32_t expected_root_ptr) {
    if (!is_valid_memory_range(mg01_ptr, rec_len) ||
        !is_valid_memory_range(proof_ptr, proof_len) ||
        !is_valid_memory_range(expected_root_ptr, SHA256_DIGEST_SIZE)) {
        return MG_WASM_ERR_NULL_POINTER;
    }

    const uint8_t *mg01_bytes = (const uint8_t *)offset_to_ptr(mg01_ptr);
    const uint8_t *proof_bytes = (const uint8_t *)offset_to_ptr(proof_ptr);
    const uint8_t *expected_root = (const uint8_t *)offset_to_ptr(expected_root_ptr);
    if (!mg01_bytes || !proof_bytes || !expected_root) return MG_WASM_ERR_NULL_POINTER;

    medicine_record_t record;
    int32_t parse_rec_err = parse_mg01_record(mg01_bytes, rec_len, &record);
    if (parse_rec_err != MG_WASM_SUCCESS) return parse_rec_err;

    merkle_proof_t proof;
    int32_t parse_proof_err = parse_mgp1_proof(proof_bytes, proof_len, &proof);
    if (parse_proof_err != MG_WASM_SUCCESS) {
        free_medicine_record_fields(&record);
        return parse_proof_err;
    }

    merkle_error_t verr = merkle_proof_verify(&record, &proof, expected_root);
    free_medicine_record_fields(&record);

    if (verr == MERKLE_SUCCESS) return MG_WASM_SUCCESS;
    if (verr == MERKLE_ERR_ROOT_MISMATCH) return MG_WASM_ERR_ROOT_MISMATCH;
    if (verr == MERKLE_ERR_INVALID_PROOF) return MG_WASM_ERR_INVALID_MGP1_PROOF;
    return MG_WASM_ERR_INVALID_ARGUMENT;
}

MG_WASM_EXPORT int32_t mg_wasm_verify_leaf_hash(uint32_t leaf_hash_ptr,
                                                 uint32_t proof_ptr, uint32_t proof_len,
                                                 uint32_t expected_root_ptr) {
    if (!is_valid_memory_range(leaf_hash_ptr, SHA256_DIGEST_SIZE) ||
        !is_valid_memory_range(proof_ptr, proof_len) ||
        !is_valid_memory_range(expected_root_ptr, SHA256_DIGEST_SIZE)) {
        return MG_WASM_ERR_NULL_POINTER;
    }

    const uint8_t *leaf_hash = (const uint8_t *)offset_to_ptr(leaf_hash_ptr);
    const uint8_t *proof_bytes = (const uint8_t *)offset_to_ptr(proof_ptr);
    const uint8_t *expected_root = (const uint8_t *)offset_to_ptr(expected_root_ptr);
    if (!leaf_hash || !proof_bytes || !expected_root) return MG_WASM_ERR_NULL_POINTER;

    merkle_proof_t proof;
    int32_t parse_proof_err = parse_mgp1_proof(proof_bytes, proof_len, &proof);
    if (parse_proof_err != MG_WASM_SUCCESS) return parse_proof_err;

    merkle_error_t verr = merkle_proof_verify_leaf_hash(leaf_hash, &proof, expected_root);
    if (verr == MERKLE_SUCCESS) return MG_WASM_SUCCESS;
    if (verr == MERKLE_ERR_ROOT_MISMATCH) return MG_WASM_ERR_ROOT_MISMATCH;
    if (verr == MERKLE_ERR_INVALID_PROOF) return MG_WASM_ERR_INVALID_MGP1_PROOF;
    return MG_WASM_ERR_INVALID_ARGUMENT;
}

/* --- Diagnostics and Error Strings --- */

MG_WASM_EXPORT const char *mg_wasm_status_string(int32_t status) {
    switch (status) {
        case MG_WASM_SUCCESS:                 return "Success";
        case MG_WASM_ERR_NULL_POINTER:        return "Null pointer or invalid memory range";
        case MG_WASM_ERR_INVALID_ARGUMENT:    return "Invalid argument or out of bounds index";
        case MG_WASM_ERR_INVALID_HANDLE:      return "Invalid or stale batch context handle";
        case MG_WASM_ERR_INVALID_STATE:       return "Operation not permitted in current context state";
        case MG_WASM_ERR_INVALID_MG01_RECORD: return "Invalid or malformed MG01 record";
        case MG_WASM_ERR_INVALID_MGP1_PROOF:  return "Invalid or malformed MGP1 proof";
        case MG_WASM_ERR_BUFFER_TOO_SMALL:    return "Output buffer capacity is insufficient";
        case MG_WASM_ERR_LIMIT_EXCEEDED:      return "Context capacity limit exceeded (max 100,000)";
        case MG_WASM_ERR_ALLOCATION_FAILED:   return "Memory allocation failed";
        case MG_WASM_ERR_ROOT_MISMATCH:       return "Root mismatch: record/proof does not match expected root";
        case MG_WASM_ERR_DUPLICATE_UNIT:      return "Batch contains duplicate medicine unit ID";
        case MG_WASM_ERR_MIXED_BATCH:         return "Batch contains conflicting batch IDs";
        case MG_WASM_ERR_EMPTY_BATCH:         return "Batch is empty";
        default:                              return "Unknown WebAssembly bridge error";
    }
}

MG_WASM_EXPORT uint32_t mg_wasm_get_error_string(int32_t err_code, uint32_t out_buf_ptr, uint32_t capacity) {
    if (capacity == 0 || !is_valid_memory_range(out_buf_ptr, capacity)) return 0;
    char *out_buf = (char *)offset_to_ptr(out_buf_ptr);
    if (!out_buf) return 0;

    const char *msg = mg_wasm_status_string(err_code);
    size_t len = strlen(msg);
    if (len >= capacity) len = capacity - 1;
    memcpy(out_buf, msg, len);
    out_buf[len] = '\0';
    return (uint32_t)len;
}

