# MedicineGuard — WebAssembly ABI & Integration Specification (Phase 2)

This document specifies the complete WebAssembly Application Binary Interface (ABI), wire protocols, memory management models, and JavaScript integration layer for the **MedicineGuard** cryptographic engine.

---

## 1. Architecture Overview

MedicineGuard executes its core cryptographic and Data Structures and Algorithms (DAA) workloads using a single native C implementation compiled to both:
1. Native machine code (`gcc -O3`) for backend batch processing and verification benchmarks.
2. WebAssembly (`emcc -O3`) for zero-installation, client-side execution in modern web browsers and edge Node.js runtimes.

```
+-------------------------------------------------------------------------+
|                          Web Application Layer                          |
|   Manufacturer Portal      |  Pharmacist Dashboard  |  Consumer QR Scanner |
+-------------------------------------------------------------------------+
                                    |
                    JavaScript ES Module Wrapper
                     (public/js/wasm-loader.js)
            - Canonical MG01 record serialization
            - Binary MGP1 proof parsing & traversal
            - Dynamic HEAPU8 tracking (detached ArrayBuffer safe)
            - Object-oriented Batch & Verification APIs
                                    |
+-------------------------------------------------------------------------+
|                  WebAssembly C Bridge (wasm_bridge.c)                   |
|   - Generational Handle Pool (32 slots, 27-bit generation counter)     |
|   - Bounded memory range verification (emscripten_get_heap_size)        |
|   - Wire format parsers & error boundary translation                    |
+-------------------------------------------------------------------------+
                                    |
+-------------------------------------------------------------------------+
|                   Core C Algorithms (core-c/src/)                       |
|   - Standalone SHA-256 Engine (sha256.c)                               |
|   - Binary Merkle Tree with Odd-Node Promotion (merkle.c)              |
+-------------------------------------------------------------------------+
```

---

## 2. Status Codes & Error Mapping

All WebAssembly bridge functions return standard 32-bit signed integer status codes (`int32_t`):

| Code | Enumeration Constant | Diagnostic Description |
|:---:|:---|:---|
| `0` | `MG_WASM_SUCCESS` | Operation completed successfully |
| `-1` | `MG_WASM_ERR_NULL_POINTER` | Null pointer passed to bridge API |
| `-2` | `MG_WASM_ERR_INVALID_ARGUMENT` | Argument value out of permissible bounds |
| `-3` | `MG_WASM_ERR_INVALID_HANDLE` | Handle does not exist, was recycled, or generation mismatch |
| `-4` | `MG_WASM_ERR_INVALID_STATE` | Context operation called in invalid state (e.g. add after build) |
| `-5` | `MG_WASM_ERR_INVALID_MG01_RECORD`| Malformed MG01 record or string validation failed |
| `-6` | `MG_WASM_ERR_INVALID_MGP1_PROOF` | Malformed MGP1 proof wire format, bad magic, or direction error |
| `-7` | `MG_WASM_ERR_BUFFER_TOO_SMALL` | Caller-provided output buffer capacity is insufficient |
| `-8` | `MG_WASM_ERR_LIMIT_EXCEEDED` | Exceeded tree capacity or max active context slots |
| `-9` | `MG_WASM_ERR_ALLOCATION_FAILED`| WebAssembly heap allocation failed (`malloc` returned NULL) |
| `-10`| `MG_WASM_ERR_ROOT_MISMATCH` | Computed root hash does not match trusted expected root |
| `-11`| `MG_WASM_ERR_DUPLICATE_UNIT` | Batch contains duplicate medicine unit ID |
| `-12`| `MG_WASM_ERR_MIXED_BATCH` | Batch contains records with conflicting batch IDs |
| `-13`| `MG_WASM_ERR_EMPTY_BATCH` | Tree build requested on empty batch (0 records) |

---

## 3. Wire Formats

### 3.1 Canonical `MG01` Medicine Record Wire Format

Medicine records are serialized into a deterministic, canonical byte stream before leaf hashing. Every string field is prefixed with an unsigned 32-bit big-endian length.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   'M' (0x4D)  |   'G' (0x47)  |   '0' (0x30)  |   '1' (0x31)  | Magic (4 bytes)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      batch_id Length (uint32 BE)              | Field 0 Length
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      batch_id UTF-8 Bytes ...                 | Field 0 Bytes
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      unit_id Length (uint32 BE)               | Field 1 Length
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      unit_id UTF-8 Bytes ...                  | Field 1 Bytes
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   medicine_name Length (uint32 BE)            | Field 2 Length
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   medicine_name UTF-8 Bytes ...               | Field 2 Bytes
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                manufacturing_date Length (uint32 BE = 10)     | Field 3 Length
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                manufacturing_date ("YYYY-MM-DD", 10 bytes)    | Field 3 Bytes
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    expiry_date Length (uint32 BE = 10)        | Field 4 Length
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    expiry_date ("YYYY-MM-DD", 10 bytes)       | Field 4 Bytes
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Leaf Hashing Rule**:
$$\text{LeafHash} = \text{SHA-256}(0\text{x}00 \mathbin{\Vert} \text{MG01\_Bytes})$$

---

### 3.2 Canonical `MGP1` Merkle Proof Wire Format

Merkle proofs are transmitted as compact binary payloads consisting of a 14-byte header followed by $K$ proof steps of 33 bytes each ($32\text{ bytes hash} + 1\text{ byte direction}$).

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   'M' (0x4D)  |   'G' (0x47)  |   'P' (0x50)  |   '1' (0x31)  | Magic (4 bytes)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      leaf_index (uint32 BE)                   | Leaf index (0..N-1)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     total_leaves (uint32 BE)                  | Batch leaf count (N)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         step_count (uint16 BE)| Sibling Hash (0..1)           | Header ends at byte 14
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sibling Hash [0..31]                       | 32 bytes SHA-256
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Direction(1B) |                                               | 0x00=LEFT, 0x01=RIGHT
+-+-+-+-+-+-+-+-+                                               +
|                    Next Step (if step_count > 1)...           |
```

**Wire Size Formula**:
$$\text{WireSize}(\text{steps}) = 14 + (33 \times \text{steps}) \text{ bytes}$$

---

## 4. Generational Context Handle Pool

To protect against use-after-free, stale handle reuse, and resource leaks across asynchronous JavaScript operations, contexts are managed via a generation-indexed handle pool.

```
 31                                       5   4           0
+------------------------------------------+---------------+
|        Generation Counter (27 bits)      | Slot ID (5 b) |
+------------------------------------------+---------------+
```

1. **Slot Identification**: Lower 5 bits ($0\dots 31$) identify the physical slot within `g_contexts[32]`.
2. **Generation Validation**: Upper 27 bits store the slot's generation counter.
3. **Recycling Security**: Each time a slot is freed and subsequently re-allocated, its generation increments by 1. A stale JavaScript reference retaining an old handle is rejected immediately with `MG_WASM_ERR_INVALID_HANDLE` (-3).

---

## 5. WebAssembly Exported Functions

### 5.1 Memory Management

```c
uint32_t mg_wasm_malloc(uint32_t size);
void     mg_wasm_free(uint32_t ptr);
```
- Allocates and releases linear memory inside the WebAssembly heap.
- Bounds are actively verified against `emscripten_get_heap_size()`.

### 5.2 Cryptographic Primitive

```c
int32_t mg_wasm_sha256(uint32_t data_ptr, uint32_t len, uint32_t out_hash_ptr);
```
- Performs a domain-unseparated, raw SHA-256 computation over `len` bytes.
- Writes 32 bytes of output to `out_hash_ptr`.

### 5.3 Batch Creation & Tree Construction

```c
uint32_t mg_wasm_batch_create(void);
int32_t  mg_wasm_batch_add_record(uint32_t ctx_handle, uint32_t mg01_ptr, uint32_t len);
int32_t  mg_wasm_batch_build_tree(uint32_t ctx_handle);
int32_t  mg_wasm_batch_get_root(uint32_t ctx_handle, uint32_t out_root_ptr);
uint32_t mg_wasm_batch_get_leaf_count(uint32_t ctx_handle);
uint32_t mg_wasm_batch_get_height(uint32_t ctx_handle);
uint32_t mg_wasm_batch_get_proof_size(uint32_t ctx_handle, uint32_t leaf_index);
int32_t  mg_wasm_batch_generate_proof(uint32_t ctx_handle, uint32_t leaf_index,
                                     uint32_t out_buf_ptr, uint32_t out_cap,
                                     uint32_t out_written_ptr);
void     mg_wasm_batch_destroy(uint32_t ctx_handle);
```

### 5.4 Pharmacist & Consumer Verification

```c
int32_t mg_wasm_verify_record(uint32_t mg01_ptr, uint32_t rec_len,
                              uint32_t proof_ptr, uint32_t proof_len,
                              uint32_t expected_root_ptr);

int32_t mg_wasm_verify_leaf_hash(uint32_t leaf_hash_ptr,
                                 uint32_t proof_ptr, uint32_t proof_len,
                                 uint32_t expected_root_ptr);
```

---

## 6. Dynamic Memory Safety & Heap Tracking

When building with `-s ALLOW_MEMORY_GROWTH=1`, the WebAssembly runtime expands its memory dynamically when batch allocations exceed the initial 16 MB threshold.

> [!WARNING]
> In modern JavaScript runtimes (V8/SpiderMonkey/JavaScriptCore), growing a WebAssembly memory buffer **detaches** the existing `ArrayBuffer`. Any cached typed array view (`HEAPU8`, `DataView`) becomes detached and throws a `TypeError: Cannot perform %TypedArray%.prototype.set on a neutered ArrayBuffer`.

**MedicineGuard Solution**:
`public/js/wasm-loader.js` guarantees that `HEAPU8` is queried on-demand dynamically at the exact point of buffer manipulation:
```javascript
get heapU8() {
    return this._module.HEAPU8;
}
```
All allocations and deallocations are encapsulated in `withAllocatedBuffer(bytes, fn)`, ensuring complete memory reclamation in a `finally` block even under thrown JavaScript exceptions.

---

## 7. Native GCC & WebAssembly Parity Verification

The WebAssembly engine was verified against the native GCC 16.2.0 binary across batch sizes from $N=1$ to $N=10,000$.

| Batch Size ($N$) | Tree Height | Native GCC Root Hex | WASM Root Hex | Bit-for-Bit Match |
|:---|:---:|:---|:---|:---:|
| **1** | 1 | `5d761d5f85dfe7c4b8bc8bec332649908458bd83e6a34cea9265608ac0e94bbb` | `5d761d5f85dfe7c4b8bc8bec332649908458bd83e6a34cea9265608ac0e94bbb` | **PASS** (100%) |
| **2** | 2 | `af02709fa129af36821633b77b837c1a6a0efd8205594c4f50663cb88f8d5e52` | `af02709fa129af36821633b77b837c1a6a0efd8205594c4f50663cb88f8d5e52` | **PASS** (100%) |
| **3** | 3 | `5da0c7409089f6e7983ffd458e565e7c29f9b48b937e82a171c5973e9b7eb152` | `5da0c7409089f6e7983ffd458e565e7c29f9b48b937e82a171c5973e9b7eb152` | **PASS** (100%) |
| **5** | 4 | `a343d4ec527cb9b28072e451d492bf563c70de09d821b968c3a129e1b4a33c86` | `a343d4ec527cb9b28072e451d492bf563c70de09d821b968c3a129e1b4a33c86` | **PASS** (100%) |
| **7** | 4 | `1b5230d15958d1e7c02d70c076c1a9bec783af1031ea79462ede7a2095f6c988` | `1b5230d15958d1e7c02d70c076c1a9bec783af1031ea79462ede7a2095f6c988` | **PASS** (100%) |
| **8** | 4 | `1724712c9d47c22951d3d2c7403cfdcf0659c58b1b6f2330c178c7decd3f4274` | `1724712c9d47c22951d3d2c7403cfdcf0659c58b1b6f2330c178c7decd3f4274` | **PASS** (100%) |
| **100** | 8 | `49b79857a4ae9e544d87aa0b723382494dcd5f68775958d8a8affa735a6a01f0` | `49b79857a4ae9e544d87aa0b723382494dcd5f68775958d8a8affa735a6a01f0` | **PASS** (100%) |
| **1,000** | 11 | `f95ddec8799732ab9093cd5a94a13ce6795b6774bde436a7d9df8972b030e080` | `f95ddec8799732ab9093cd5a94a13ce6795b6774bde436a7d9df8972b030e080` | **PASS** (100%) |
| **10,000** | 15 | `9fadfeef96fcde03f86dbe6c2cabf987c3287c86d7ccaf65bb8ac05b18d8e8e8` | `9fadfeef96fcde03f86dbe6c2cabf987c3287c86d7ccaf65bb8ac05b18d8e8e8` | **PASS** (100%) |

---

## 8. Build & Test Commands

### 8.1 Rebuilding the WebAssembly Module
```powershell
.\scripts\build_wasm.bat
```
Produces:
- `public/wasm/medicineguard.js` (11,593 bytes)
- `public/wasm/medicineguard.wasm` (24,935 bytes)

### 8.2 Running the Automated Node.js Test Suite
```powershell
.\scripts\test_wasm.bat
```
Executes 314 automated assertions covering NIST SHA-256 test vectors, MG01 serialization, golden parity vectors, Merkle proof traversal, negative tamper-resistance scenarios, handle recycling, and 100-cycle stress tests.

### 8.3 Browser Test Suite
Start a static web server:
```powershell
npx serve public
```
Navigate to:
`http://localhost:3000/tests/test_wasm.html`

