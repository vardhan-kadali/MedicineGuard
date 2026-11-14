/**
 * MedicineGuard - WebAssembly JavaScript Loader & High-Level API
 * 
 * Provides an idiomatic JavaScript/TypeScript-friendly wrapper around the
 * native C SHA-256 and Merkle Tree WebAssembly engine.
 * 
 * Complies with:
 *   - MG01 Medicine Record Binary Serialization
 *   - MGP1 Merkle Proof Binary Format
 *   - Memory-safe allocation and dynamic HEAPU8 tracking
 */

import createMedicineGuardModule from '../wasm/medicineguard.js';

/* =========================================================================
 * Utility Functions: Hex & Byte Conversions
 * ========================================================================= */

const HEX_CHARS = '0123456789abcdef';

/**
 * Convert a Uint8Array to a lowercase hex string.
 * @param {Uint8Array} bytes 
 * @returns {string}
 */
export function bytesToHex(bytes) {
    if (!(bytes instanceof Uint8Array)) {
        throw new TypeError('Expected Uint8Array');
    }
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i];
        hex += HEX_CHARS[(b >> 4) & 0x0f] + HEX_CHARS[b & 0x0f];
    }
    return hex;
}

/**
 * Convert a hex string to a Uint8Array.
 * @param {string} hex 
 * @returns {Uint8Array}
 */
export function hexToBytes(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError('Expected hex string');
    }
    const cleanHex = hex.trim().toLowerCase();
    if (cleanHex.length % 2 !== 0) {
        throw new Error(`Invalid hex string length: ${cleanHex.length}`);
    }
    const len = cleanHex.length / 2;
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        const byteVal = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
        if (Number.isNaN(byteVal)) {
            throw new Error(`Invalid hex character at position ${i * 2}`);
        }
        out[i] = byteVal;
    }
    return out;
}

/* =========================================================================
 * Status Code Mapping
 * ========================================================================= */

export const StatusCode = Object.freeze({
    SUCCESS: 0,
    ERR_NULL_POINTER: -1,
    ERR_INVALID_ARGUMENT: -2,
    ERR_INVALID_HANDLE: -3,
    ERR_INVALID_STATE: -4,
    ERR_INVALID_MG01_RECORD: -5,
    ERR_INVALID_MGP1_PROOF: -6,
    ERR_BUFFER_TOO_SMALL: -7,
    ERR_LIMIT_EXCEEDED: -8,
    ERR_ALLOCATION_FAILED: -9,
    ERR_ROOT_MISMATCH: -10,
    ERR_DUPLICATE_UNIT: -11,
    ERR_MIXED_BATCH: -12,
    ERR_EMPTY_BATCH: -13
});

/* =========================================================================
 * MG01 Record Serialization
 * ========================================================================= */

const DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Validate and serialize a medicine record into canonical MG01 binary format.
 * 
 * Wire Format:
 *   [0..3]   Magic: "MG01" (0x4D, 0x47, 0x30, 0x31)
 *   [4..7]   batch_id length (uint32 big-endian)
 *   [...]    batch_id UTF-8 bytes
 *   [..+4]   unit_id length (uint32 big-endian)
 *   [...]    unit_id UTF-8 bytes
 *   [..+4]   medicine_name length (uint32 big-endian)
 *   [...]    medicine_name UTF-8 bytes
 *   [..+4]   manufacturing_date length (uint32 big-endian, exactly 10)
 *   [...]    manufacturing_date UTF-8 bytes ("YYYY-MM-DD")
 *   [..+4]   expiry_date length (uint32 big-endian, exactly 10)
 *   [...]    expiry_date UTF-8 bytes ("YYYY-MM-DD")
 * 
 * @param {Object} record
 * @returns {Uint8Array}
 */
export function serializeMedicineRecord(record) {
    if (!record || typeof record !== 'object') {
        throw new TypeError('Record must be a valid object');
    }

    // Support flexible property names
    const batchId = String(record.batch_id ?? record.batchId ?? '');
    const unitId = String(record.unit_id ?? record.unitId ?? '');
    const medicineName = String(record.medicine_name ?? record.medicineName ?? '');
    const mfgDate = String(record.manufacturing_date ?? record.manufacturingDate ?? record.manufacture_date ?? record.manufactureDate ?? '');
    const expDate = String(record.expiry_date ?? record.expiryDate ?? '');

    // Validate fields
    if (!batchId || batchId.length === 0) {
        throw new Error('batch_id cannot be empty');
    }
    if (!unitId || unitId.length === 0) {
        throw new Error('unit_id cannot be empty');
    }
    if (!medicineName || medicineName.length === 0) {
        throw new Error('medicine_name cannot be empty');
    }
    if (!DATE_REGEX.test(mfgDate)) {
        throw new Error(`Invalid manufacturing_date format: "${mfgDate}". Must be YYYY-MM-DD`);
    }
    if (!DATE_REGEX.test(expDate)) {
        throw new Error(`Invalid expiry_date format: "${expDate}". Must be YYYY-MM-DD`);
    }

    // Reject embedded null bytes in strings
    if (batchId.includes('\0') || unitId.includes('\0') || medicineName.includes('\0') || mfgDate.includes('\0') || expDate.includes('\0')) {
        throw new Error('Strings must not contain embedded null characters');
    }

    const encoder = new TextEncoder();
    const batchIdBytes = encoder.encode(batchId);
    const unitIdBytes = encoder.encode(unitId);
    const medicineNameBytes = encoder.encode(medicineName);
    const mfgDateBytes = encoder.encode(mfgDate);
    const expDateBytes = encoder.encode(expDate);

    // Total size: 4 (magic) + 5 * 4 (field lengths) + sum(field bytes)
    const totalSize = 4 + 4 * 5 +
        batchIdBytes.length +
        unitIdBytes.length +
        medicineNameBytes.length +
        mfgDateBytes.length +
        expDateBytes.length;

    const buffer = new Uint8Array(totalSize);
    const view = new DataView(buffer.buffer);
    let offset = 0;

    // Magic: "MG01"
    buffer[0] = 0x4d; // 'M'
    buffer[1] = 0x47; // 'G'
    buffer[2] = 0x30; // '0'
    buffer[3] = 0x31; // '1'
    offset += 4;

    const fields = [batchIdBytes, unitIdBytes, medicineNameBytes, mfgDateBytes, expDateBytes];
    for (let i = 0; i < fields.length; i++) {
        const fieldBytes = fields[i];
        view.setUint32(offset, fieldBytes.length, false);
        offset += 4;
        buffer.set(fieldBytes, offset);
        offset += fieldBytes.length;
    }

    return buffer;
}

/* =========================================================================
 * MGP1 Proof Parser & Utilities
 * ========================================================================= */

/**
 * Parse an MGP1 binary proof buffer into a structured JavaScript object.
 * 
 * Wire format:
 *   [0..3]   Magic: "MGP1" (0x4D, 0x47, 0x50, 0x31)
 *   [4..7]   leaf_index (uint32 big-endian)
 *   [8..11]  total_leaves (uint32 big-endian)
 *   [12..13] step_count (uint16 big-endian)
 *   [14..]   Steps (each 33 bytes: 32 bytes hash + 1 byte direction 0=LEFT, 1=RIGHT)
 * 
 * @param {Uint8Array} proofBytes 
 * @returns {Object}
 */
export function parseProof(proofBytes) {
    if (!(proofBytes instanceof Uint8Array)) {
        throw new TypeError('Expected proofBytes to be Uint8Array');
    }
    if (proofBytes.length < 14) {
        throw new Error(`Proof buffer too short: ${proofBytes.length} bytes (minimum 14 bytes)`);
    }

    const view = new DataView(proofBytes.buffer, proofBytes.byteOffset, proofBytes.byteLength);

    // Magic check: "MGP1"
    const magic0 = proofBytes[0];
    const magic1 = proofBytes[1];
    const magic2 = proofBytes[2];
    const magic3 = proofBytes[3];
    if (magic0 !== 0x4d || magic1 !== 0x47 || magic2 !== 0x50 || magic3 !== 0x31) {
        throw new Error('Invalid proof magic: expected "MGP1"');
    }

    const leafIndex = view.getUint32(4, false);
    const totalLeaves = view.getUint32(8, false);
    const stepCount = view.getUint16(12, false);

    const expectedTotalSize = 14 + stepCount * 33;
    if (proofBytes.length !== expectedTotalSize) {
        throw new Error(`Proof size mismatch: expected ${expectedTotalSize} bytes for ${stepCount} steps, got ${proofBytes.length}`);
    }

    const steps = [];
    let offset = 14;
    for (let i = 0; i < stepCount; i++) {
        const hashBytes = proofBytes.subarray(offset, offset + 32);
        const direction = proofBytes[offset + 32];
        if (direction !== 0 && direction !== 1) {
            throw new Error(`Invalid direction byte 0x${direction.toString(16)} at step ${i}`);
        }
        steps.push({
            stepIndex: i,
            siblingHash: new Uint8Array(hashBytes),
            siblingHashHex: bytesToHex(hashBytes),
            direction: direction, // 0 = SIBLING_LEFT (node is right), 1 = SIBLING_RIGHT (node is left)
            directionName: direction === 0 ? 'left' : 'right'
        });
        offset += 33;
    }

    return {
        magic: 'MGP1',
        leafIndex,
        totalLeaves,
        stepCount,
        steps
    };
}

/* =========================================================================
 * MedicineGuardBatchContext Class
 * ========================================================================= */

export class MedicineGuardBatchContext {
    /**
     * @private
     * @param {MedicineGuard} engine 
     * @param {number} handle 
     */
    constructor(engine, handle) {
        this._engine = engine;
        this._handle = handle;
        this._isDestroyed = false;
        this._isBuilt = false;
    }

    /**
     * Context handle id.
     */
    get handle() {
        return this._handle;
    }

    /**
     * Whether the batch has already been finalized/built.
     */
    get isBuilt() {
        return this._isBuilt;
    }

    /**
     * Whether this context has been destroyed.
     */
    get isDestroyed() {
        return this._isDestroyed;
    }

    _assertActive() {
        if (this._isDestroyed) {
            throw new Error('Batch context has already been destroyed');
        }
    }

    /**
     * Add a medicine record to this batch.
     * @param {Object|Uint8Array} record Either a medicine record object or serialized MG01 Uint8Array.
     */
    addRecord(record) {
        this._assertActive();
        if (this._isBuilt) {
            throw new Error('Cannot add records to a batch that has already been built');
        }

        const mg01Bytes = (record instanceof Uint8Array)
            ? record
            : serializeMedicineRecord(record);

        const status = this._engine.withAllocatedBuffer(mg01Bytes, (ptr, len) => {
            return this._engine.module._mg_wasm_batch_add_record(this._handle, ptr, len);
        });

        if (status !== StatusCode.SUCCESS) {
            const errStr = this._engine.getStatusMessage(status);
            throw new Error(`Failed to add record to batch: ${errStr} (code ${status})`);
        }
    }

    /**
     * Add multiple records sequentially.
     * @param {Array<Object|Uint8Array>} records 
     */
    addRecords(records) {
        if (!Array.isArray(records)) {
            throw new TypeError('Expected an array of records');
        }
        for (let i = 0; i < records.length; i++) {
            this.addRecord(records[i]);
        }
    }

    /**
     * Finalize the batch and build the Merkle Tree.
     */
    buildTree() {
        this._assertActive();
        if (this._isBuilt) {
            return;
        }

        const status = this._engine.module._mg_wasm_batch_build_tree(this._handle);
        if (status !== StatusCode.SUCCESS) {
            const errStr = this._engine.getStatusMessage(status);
            throw new Error(`Failed to build Merkle tree: ${errStr} (code ${status})`);
        }
        this._isBuilt = true;
    }

    /**
     * Retrieve the 32-byte Merkle root as a Uint8Array.
     * @returns {Uint8Array}
     */
    getRoot() {
        this._assertActive();
        if (!this._isBuilt) {
            throw new Error('Tree must be built before getting the Merkle Root');
        }

        const outRoot = new Uint8Array(32);
        const status = this._engine.withAllocatedBuffer(outRoot, (ptr) => {
            const res = this._engine.module._mg_wasm_batch_get_root(this._handle, ptr);
            if (res === StatusCode.SUCCESS) {
                // Copy bytes out from heap
                outRoot.set(this._engine.heapU8.subarray(ptr, ptr + 32));
            }
            return res;
        });

        if (status !== StatusCode.SUCCESS) {
            const errStr = this._engine.getStatusMessage(status);
            throw new Error(`Failed to get Merkle Root: ${errStr} (code ${status})`);
        }

        return outRoot;
    }

    /**
     * Retrieve the Merkle root as a 64-character lowercase hexadecimal string.
     * @returns {string}
     */
    getRootHex() {
        return bytesToHex(this.getRoot());
    }

    /**
     * Get the number of leaves in the tree.
     * @returns {number}
     */
    getLeafCount() {
        this._assertActive();
        return this._engine.module._mg_wasm_batch_get_leaf_count(this._handle);
    }

    /**
     * Get the height of the tree.
     * @returns {number}
     */
    getHeight() {
        this._assertActive();
        return this._engine.module._mg_wasm_batch_get_height(this._handle);
    }

    /**
     * Get the required binary proof size in bytes for a given leaf index.
     * @param {number} leafIndex 
     * @returns {number}
     */
    getProofSize(leafIndex) {
        this._assertActive();
        if (!Number.isInteger(leafIndex) || leafIndex < 0) {
            throw new TypeError('leafIndex must be a non-negative integer');
        }
        return this._engine.module._mg_wasm_batch_get_proof_size(this._handle, leafIndex);
    }

    /**
     * Generate an MGP1 binary proof for a specific leaf index.
     * @param {number} leafIndex 
     * @returns {Uint8Array}
     */
    generateProof(leafIndex) {
        this._assertActive();
        if (!this._isBuilt) {
            throw new Error('Tree must be built before generating proofs');
        }
        if (!Number.isInteger(leafIndex) || leafIndex < 0) {
            throw new TypeError('leafIndex must be a non-negative integer');
        }

        const proofSize = this.getProofSize(leafIndex);
        if (proofSize === 0) {
            throw new Error(`Invalid leaf index ${leafIndex} or proof generation failed`);
        }

        // Allocate proof buffer and a 4-byte slot for out_written
        const proofBufferPtr = this._engine.malloc(proofSize);
        const writtenPtr = this._engine.malloc(4);

        try {
            const status = this._engine.module._mg_wasm_batch_generate_proof(
                this._handle,
                leafIndex,
                proofBufferPtr,
                proofSize,
                writtenPtr
            );

            if (status !== StatusCode.SUCCESS) {
                const errStr = this._engine.getStatusMessage(status);
                throw new Error(`Failed to generate proof for leaf ${leafIndex}: ${errStr} (code ${status})`);
            }

            const writtenLen = this._engine.module.getValue(writtenPtr, 'i32');
            const proofBytes = new Uint8Array(writtenLen);
            proofBytes.set(this._engine.heapU8.subarray(proofBufferPtr, proofBufferPtr + writtenLen));
            return proofBytes;
        } finally {
            this._engine.free(writtenPtr);
            this._engine.free(proofBufferPtr);
        }
    }

    /**
     * Destroy this batch context and release native C resources.
     */
    destroy() {
        if (!this._isDestroyed) {
            this._engine.module._mg_wasm_batch_destroy(this._handle);
            this._isDestroyed = true;
        }
    }

    /**
     * Symbol.dispose support for explicit resource management.
     */
    [Symbol.dispose]() {
        this.destroy();
    }
}

/* =========================================================================
 * MedicineGuard Main Class
 * ========================================================================= */

export class MedicineGuard {
    /**
     * @private
     * @param {Object} module Emscripten initialized module instance
     */
    constructor(module) {
        this._module = module;
    }

    /**
     * Initialize the MedicineGuard WebAssembly module.
     * @param {Object} [options] Custom configuration options for Emscripten module
     * @returns {Promise<MedicineGuard>}
     */
    static async init(options = {}) {
        const moduleInstance = await createMedicineGuardModule(options);
        return new MedicineGuard(moduleInstance);
    }

    /**
     * Underlying Emscripten module.
     */
    get module() {
        return this._module;
    }

    /**
     * Dynamic getter for HEAPU8.
     * CRITICAL: Never cache HEAPU8 because WebAssembly memory growth
     * detaches the underlying ArrayBuffer!
     */
    get heapU8() {
        return this._module.HEAPU8;
    }

    /**
     * Allocate memory inside the WebAssembly heap.
     * @param {number} size 
     * @returns {number} pointer
     */
    malloc(size) {
        const ptr = this._module._mg_wasm_malloc(size);
        if (ptr === 0 && size > 0) {
            throw new Error(`Failed to allocate ${size} bytes in WebAssembly heap`);
        }
        return ptr;
    }

    /**
     * Free memory inside the WebAssembly heap.
     * @param {number} ptr 
     */
    free(ptr) {
        if (ptr !== 0) {
            this._module._mg_wasm_free(ptr);
        }
    }

    /**
     * Execute a callback function with temporary buffer allocated in WASM memory.
     * Safely frees the allocated memory even if an exception is thrown.
     * 
     * @template T
     * @param {Uint8Array} inputBytes Data to copy into WASM memory.
     * @param {(ptr: number, len: number) => T} callback 
     * @returns {T}
     */
    withAllocatedBuffer(inputBytes, callback) {
        const len = inputBytes.length;
        const ptr = this.malloc(len);
        try {
            if (len > 0) {
                this.heapU8.set(inputBytes, ptr);
            }
            return callback(ptr, len);
        } finally {
            this.free(ptr);
        }
    }

    /**
     * Compute SHA-256 hash of arbitrary bytes or string.
     * @param {Uint8Array|string} data 
     * @returns {Uint8Array} 32-byte hash
     */
    sha256(data) {
        const inputBytes = typeof data === 'string'
            ? new TextEncoder().encode(data)
            : data;

        if (!(inputBytes instanceof Uint8Array)) {
            throw new TypeError('Data must be a Uint8Array or string');
        }

        const outHash = new Uint8Array(32);
        const outPtr = this.malloc(32);

        try {
            const status = this.withAllocatedBuffer(inputBytes, (dataPtr, len) => {
                return this._module._mg_wasm_sha256(dataPtr, len, outPtr);
            });

            if (status !== StatusCode.SUCCESS) {
                const errStr = this.getStatusMessage(status);
                throw new Error(`SHA-256 computation failed: ${errStr} (code ${status})`);
            }

            outHash.set(this.heapU8.subarray(outPtr, outPtr + 32));
            return outHash;
        } finally {
            this.free(outPtr);
        }
    }

    /**
     * Compute SHA-256 hash and return as lowercase 64-character hexadecimal string.
     * @param {Uint8Array|string} data 
     * @returns {string}
     */
    sha256Hex(data) {
        return bytesToHex(this.sha256(data));
    }

    /**
     * Create a new batch context for Merkle tree construction.
     * @returns {MedicineGuardBatchContext}
     */
    createBatch() {
        const handle = this._module._mg_wasm_batch_create();
        if (handle === 0) {
            throw new Error('Failed to create batch context: handle pool exhausted or allocation failed');
        }
        return new MedicineGuardBatchContext(this, handle);
    }

    /**
     * Verify an individual medicine record against a Merkle Proof and Expected Root.
     * 
     * @param {Object|Uint8Array} record Medicine record object or MG01 binary Uint8Array.
     * @param {Uint8Array} proofBytes Binary MGP1 proof bytes.
     * @param {Uint8Array|string} expectedRoot 32-byte Uint8Array or 64-char hex string.
     * @returns {{ valid: boolean, status: number, statusMessage: string }}
     */
    verifyRecord(record, proofBytes, expectedRoot) {
        if (!(proofBytes instanceof Uint8Array)) {
            throw new TypeError('proofBytes must be a Uint8Array');
        }

        const rootBytes = typeof expectedRoot === 'string'
            ? hexToBytes(expectedRoot)
            : expectedRoot;

        if (!(rootBytes instanceof Uint8Array) || rootBytes.length !== 32) {
            throw new Error('expectedRoot must be a 32-byte Uint8Array or 64-character hex string');
        }

        const mg01Bytes = (record instanceof Uint8Array)
            ? record
            : serializeMedicineRecord(record);

        return this.withAllocatedBuffer(mg01Bytes, (recPtr, recLen) => {
            return this.withAllocatedBuffer(proofBytes, (proofPtr, proofLen) => {
                return this.withAllocatedBuffer(rootBytes, (rootPtr) => {
                    const status = this._module._mg_wasm_verify_record(
                        recPtr, recLen,
                        proofPtr, proofLen,
                        rootPtr
                    );

                    const valid = (status === StatusCode.SUCCESS);
                    const statusMessage = this.getStatusMessage(status);
                    return { valid, status, statusMessage };
                });
            });
        });
    }

    /**
     * Verify a leaf hash against an MGP1 proof and expected root without having the original record.
     * 
     * @param {Uint8Array|string} leafHash 32-byte leaf hash Uint8Array or 64-char hex string.
     * @param {Uint8Array} proofBytes Binary MGP1 proof bytes.
     * @param {Uint8Array|string} expectedRoot 32-byte expected root Uint8Array or 64-char hex string.
     * @returns {{ valid: boolean, status: number, statusMessage: string }}
     */
    verifyLeafHash(leafHash, proofBytes, expectedRoot) {
        const leafBytes = typeof leafHash === 'string'
            ? hexToBytes(leafHash)
            : leafHash;

        const rootBytes = typeof expectedRoot === 'string'
            ? hexToBytes(expectedRoot)
            : expectedRoot;

        if (!(leafBytes instanceof Uint8Array) || leafBytes.length !== 32) {
            throw new Error('leafHash must be a 32-byte Uint8Array or 64-character hex string');
        }
        if (!(proofBytes instanceof Uint8Array)) {
            throw new TypeError('proofBytes must be a Uint8Array');
        }
        if (!(rootBytes instanceof Uint8Array) || rootBytes.length !== 32) {
            throw new Error('expectedRoot must be a 32-byte Uint8Array or 64-character hex string');
        }

        return this.withAllocatedBuffer(leafBytes, (leafPtr) => {
            return this.withAllocatedBuffer(proofBytes, (proofPtr, proofLen) => {
                return this.withAllocatedBuffer(rootBytes, (rootPtr) => {
                    const status = this._module._mg_wasm_verify_leaf_hash(
                        leafPtr,
                        proofPtr, proofLen,
                        rootPtr
                    );

                    const valid = (status === StatusCode.SUCCESS);
                    const statusMessage = this.getStatusMessage(status);
                    return { valid, status, statusMessage };
                });
            });
        });
    }

    /**
     * Get human-readable description for a bridge status code.
     * @param {number} statusCode 
     * @returns {string}
     */
    getStatusMessage(statusCode) {
        const ptr = this._module._mg_wasm_status_string(statusCode);
        if (ptr === 0) {
            return `Unknown status code (${statusCode})`;
        }
        return this._module.UTF8ToString(ptr);
    }
}

export default MedicineGuard;
