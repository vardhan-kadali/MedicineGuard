// MedicineGuard Web Crypto Merkle Verifier
// Bit-for-bit exact match to Phase 1 C implementation (core-c/src/merkle.c & sha256.c)

const MG01_MAGIC = new Uint8Array([0x4D, 0x47, 0x30, 0x31]); // 'MG01'
const MGP1_MAGIC = new Uint8Array([0x4D, 0x47, 0x50, 0x31]); // 'MGP1'

const SIBLING_LEFT = 0x00;
const SIBLING_RIGHT = 0x01;

const textEncoder = new TextEncoder();

/**
 * Convert Uint8Array to lowercase hex string
 */
export function toHex(uint8Array) {
  let hex = '';
  for (let i = 0; i < uint8Array.length; i++) {
    hex += uint8Array[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Convert hex string to Uint8Array
 */
export function fromHex(hexStr) {
  const clean = hexStr.trim();
  if (clean.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Convert base64 string to Uint8Array
 */
export function fromBase64(b64) {
  if (typeof atob === 'function') {
    const binStr = atob(b64);
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
      bytes[i] = binStr.charCodeAt(i);
    }
    return bytes;
  } else if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }
  throw new Error('No base64 decoding implementation available');
}

/**
 * Convert Uint8Array to base64 string
 */
export function toBase64(bytes) {
  if (typeof btoa === 'function') {
    let binStr = '';
    for (let i = 0; i < bytes.length; i++) {
      binStr += String.fromCharCode(bytes[i]);
    }
    return btoa(binStr);
  } else if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  throw new Error('No base64 encoding implementation available');
}

/**
 * Canonical MG01 serialization of a medicine record
 * @param {Object} record - { batch_id, unit_id, medicine_name, manufacturing_date, expiry_date }
 * @returns {Uint8Array} canonical MG01 serialized bytes
 */
export function serializeMG01Record(record) {
  const fields = [
    textEncoder.encode(record.batch_id || ''),
    textEncoder.encode(record.unit_id || ''),
    textEncoder.encode(record.medicine_name || ''),
    textEncoder.encode(record.manufacturing_date || ''),
    textEncoder.encode(record.expiry_date || '')
  ];

  let totalLen = 4; // 'MG01'
  for (const f of fields) {
    totalLen += 4 + f.length; // 4 bytes uint32 BE length + data
  }

  const out = new Uint8Array(totalLen);
  out.set(MG01_MAGIC, 0);

  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  let offset = 4;

  for (const f of fields) {
    view.setUint32(offset, f.length, false); // Big-endian
    offset += 4;
    out.set(f, offset);
    offset += f.length;
  }

  return out;
}

/**
 * Compute leaf hash with domain separation prefix 0x00
 * leaf_hash = SHA-256(0x00 || mg01_bytes)
 * @param {Uint8Array} mg01Bytes
 * @returns {Promise<Uint8Array>} 32-byte leaf hash
 */
export async function hashLeaf(mg01Bytes) {
  const buffer = new Uint8Array(1 + mg01Bytes.length);
  buffer[0] = 0x00; // Domain separation: leaf
  buffer.set(mg01Bytes, 1);

  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return new Uint8Array(hashBuffer);
}

/**
 * Compute parent hash with domain separation prefix 0x01
 * parent_hash = SHA-256(0x01 || left_hash || right_hash)
 * @param {Uint8Array} leftHash - 32 bytes
 * @param {Uint8Array} rightHash - 32 bytes
 * @returns {Promise<Uint8Array>} 32-byte parent hash
 */
export async function hashParent(leftHash, rightHash) {
  if (leftHash.length !== 32 || rightHash.length !== 32) {
    throw new Error('Parent hash inputs must both be exactly 32 bytes');
  }
  const buffer = new Uint8Array(1 + 32 + 32);
  buffer[0] = 0x01; // Domain separation: parent
  buffer.set(leftHash, 1);
  buffer.set(rightHash, 33);

  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return new Uint8Array(hashBuffer);
}

/**
 * Parse MGP1 binary proof bytes
 * @param {Uint8Array} proofBytes
 * @returns {Object} { leafIndex, totalLeaves, stepCount, steps: [{ siblingHash, direction }] }
 */
export function parseMGP1Proof(proofBytes) {
  if (proofBytes.length < 14) {
    throw new Error(`Proof byte length ${proofBytes.length} is too short (min 14 bytes)`);
  }

  // Check magic 'MGP1'
  if (
    proofBytes[0] !== MGP1_MAGIC[0] ||
    proofBytes[1] !== MGP1_MAGIC[1] ||
    proofBytes[2] !== MGP1_MAGIC[2] ||
    proofBytes[3] !== MGP1_MAGIC[3]
  ) {
    throw new Error('Invalid proof header: missing MGP1 magic');
  }

  const view = new DataView(proofBytes.buffer, proofBytes.byteOffset, proofBytes.byteLength);
  const leafIndex = view.getUint32(4, false);
  const totalLeaves = view.getUint32(8, false);
  const stepCount = view.getUint16(12, false);

  const expectedLength = 14 + stepCount * 33;
  if (proofBytes.length !== expectedLength) {
    throw new Error(`Invalid proof length: expected ${expectedLength} bytes for ${stepCount} steps, got ${proofBytes.length}`);
  }

  const steps = [];
  let offset = 14;
  for (let i = 0; i < stepCount; i++) {
    const siblingHash = proofBytes.slice(offset, offset + 32);
    offset += 32;
    const direction = proofBytes[offset];
    offset += 1;

    if (direction !== SIBLING_LEFT && direction !== SIBLING_RIGHT) {
      throw new Error(`Invalid direction byte 0x${direction.toString(16)} at step ${i}`);
    }

    steps.push({
      siblingHash,
      direction
    });
  }

  return {
    leafIndex,
    totalLeaves,
    stepCount,
    steps
  };
}

/**
 * Verify a record against an MGP1 proof and expected Merkle root
 * @param {Object} record - { batch_id, unit_id, medicine_name, manufacturing_date, expiry_date }
 * @param {Uint8Array|string} proofBytesOrB64 - raw bytes or base64 string
 * @param {string} expectedRootHex - 64-char lowercase hex
 * @returns {Promise<Object>} { valid, computedRootHex, leafIndex, totalLeaves, stepCount, error }
 */
export async function verifyRecordProof(record, proofBytesOrB64, expectedRootHex) {
  try {
    const proofBytes = typeof proofBytesOrB64 === 'string'
      ? fromBase64(proofBytesOrB64)
      : proofBytesOrB64;

    const parsedProof = parseMGP1Proof(proofBytes);
    const mg01Bytes = serializeMG01Record(record);
    let currentHash = await hashLeaf(mg01Bytes);

    for (let i = 0; i < parsedProof.steps.length; i++) {
      const step = parsedProof.steps[i];
      if (step.direction === SIBLING_LEFT) {
        currentHash = await hashParent(step.siblingHash, currentHash);
      } else if (step.direction === SIBLING_RIGHT) {
        currentHash = await hashParent(currentHash, step.siblingHash);
      } else {
        return {
          valid: false,
          error: `Invalid direction byte at step ${i}`,
          computedRootHex: toHex(currentHash)
        };
      }
    }

    const computedRootHex = toHex(currentHash).toLowerCase();
    const cleanExpectedRoot = expectedRootHex.trim().toLowerCase();
    const valid = computedRootHex === cleanExpectedRoot;

    return {
      valid,
      computedRootHex,
      leafIndex: parsedProof.leafIndex,
      totalLeaves: parsedProof.totalLeaves,
      stepCount: parsedProof.stepCount,
      error: valid ? null : `Root mismatch: computed ${computedRootHex}, expected ${cleanExpectedRoot}`
    };
  } catch (err) {
    return {
      valid: false,
      error: err.message,
      computedRootHex: null
    };
  }
}

