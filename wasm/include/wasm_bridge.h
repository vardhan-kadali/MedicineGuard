#ifndef MEDICINEGUARD_WASM_BRIDGE_H
#define MEDICINEGUARD_WASM_BRIDGE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#define MG_WASM_EXPORT EMSCRIPTEN_KEEPALIVE
#else
#define MG_WASM_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Bridge Status Codes */
typedef enum {
    MG_WASM_SUCCESS                   =   0,
    MG_WASM_ERR_NULL_POINTER          =  -1,
    MG_WASM_ERR_INVALID_ARGUMENT      =  -2,
    MG_WASM_ERR_INVALID_HANDLE        =  -3,
    MG_WASM_ERR_INVALID_STATE         =  -4,
    MG_WASM_ERR_INVALID_MG01_RECORD   =  -5,
    MG_WASM_ERR_INVALID_MGP1_PROOF    =  -6,
    MG_WASM_ERR_BUFFER_TOO_SMALL      =  -7,
    MG_WASM_ERR_LIMIT_EXCEEDED        =  -8,
    MG_WASM_ERR_ALLOCATION_FAILED     =  -9,
    MG_WASM_ERR_ROOT_MISMATCH         = -10,
    MG_WASM_ERR_DUPLICATE_UNIT        = -11,
    MG_WASM_ERR_MIXED_BATCH           = -12,
    MG_WASM_ERR_EMPTY_BATCH           = -13
} mg_wasm_status_t;

/* Magic Headers */
#define MGP1_MAGIC 0x4D475031U  /* "MGP1" */

/* Max batch records supported per context */
#define MG_WASM_MAX_BATCH_RECORDS 100000

/* Max concurrent active contexts in handle pool */
#define MG_WASM_MAX_CONTEXTS 32

/* --- Memory Management Interface --- */
MG_WASM_EXPORT uint32_t mg_wasm_malloc(uint32_t size);
MG_WASM_EXPORT void     mg_wasm_free(uint32_t ptr);

/* --- Primitive SHA-256 Utility --- */
MG_WASM_EXPORT int32_t  mg_wasm_sha256(uint32_t data_ptr, uint32_t len, uint32_t out_hash_ptr);

/* --- Manufacturer Batch Context Lifecycle --- */
MG_WASM_EXPORT uint32_t mg_wasm_batch_create(void);
MG_WASM_EXPORT int32_t  mg_wasm_batch_add_record(uint32_t ctx_handle, uint32_t mg01_ptr, uint32_t len);
MG_WASM_EXPORT int32_t  mg_wasm_batch_build_tree(uint32_t ctx_handle);
MG_WASM_EXPORT int32_t  mg_wasm_batch_get_root(uint32_t ctx_handle, uint32_t out_root_ptr);
MG_WASM_EXPORT uint32_t mg_wasm_batch_get_leaf_count(uint32_t ctx_handle);
MG_WASM_EXPORT uint32_t mg_wasm_batch_get_height(uint32_t ctx_handle);
MG_WASM_EXPORT uint32_t mg_wasm_batch_get_proof_size(uint32_t ctx_handle, uint32_t leaf_index);
MG_WASM_EXPORT int32_t  mg_wasm_batch_generate_proof(uint32_t ctx_handle, uint32_t leaf_index,
                                                     uint32_t out_buf_ptr, uint32_t out_cap,
                                                     uint32_t out_written_ptr);
MG_WASM_EXPORT void     mg_wasm_batch_destroy(uint32_t ctx_handle);

/* --- Pharmacist / Customer Independent Verification --- */
MG_WASM_EXPORT int32_t  mg_wasm_verify_record(uint32_t mg01_ptr, uint32_t rec_len,
                                              uint32_t proof_ptr, uint32_t proof_len,
                                              uint32_t expected_root_ptr);
MG_WASM_EXPORT int32_t  mg_wasm_verify_leaf_hash(uint32_t leaf_hash_ptr,
                                                 uint32_t proof_ptr, uint32_t proof_len,
                                                 uint32_t expected_root_ptr);

/* --- Diagnostics and Human-Readable Errors --- */
MG_WASM_EXPORT const char *mg_wasm_status_string(int32_t status);
MG_WASM_EXPORT uint32_t    mg_wasm_get_error_string(int32_t err_code, uint32_t out_buf_ptr, uint32_t capacity);

#ifdef __cplusplus
}
#endif

#endif /* MEDICINEGUARD_WASM_BRIDGE_H */

