// GET /api/public/verify?reference=UNIQUE_REFERENCE
// Public, unauthenticated medicine verification endpoint using server-side Merkle proof verification

import { verifyRecordProof } from '../../_shared/merkle-verifier.js';

const MANDATORY_TRUST_DISCLAIMER =
  "MedicineGuard verifies the digital medicine record against a registered Merkle Tree commitment. This does not independently establish the physical medicine's chemical composition, safety, storage conditions, manufacturer legitimacy or guarantee that the QR code has not been copied.";

/**
 * Compute SHA-256 hash of IP address for privacy-preserving audit logging
 */
async function hashIp(ip) {
  try {
    const enc = new TextEncoder().encode(ip || 'unknown');
    const digest = await crypto.subtle.digest('SHA-256', enc);
    const arr = Array.from(new Uint8Array(digest));
    return arr.map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return 'ip-hash-error';
  }
}

/**
 * In-memory sliding-window failure tracker to protect against unbounded audit table write exhaustion
 */
const FAILED_LOOKUPS = new Map(); // ipHash -> { count, windowStart }
const ABUSE_WINDOW_MS = 60 * 1000; // 60 seconds
const MAX_FAILED_PER_WINDOW = 10; // Max 10 failed lookups per minute before throttling

/**
 * Check and record failed lookup attempt for IP hash
 * Returns true if allowed, false if throttled
 */
function recordFailedAttempt(ipHash) {
  const now = Date.now();
  const entry = FAILED_LOOKUPS.get(ipHash);
  if (!entry || now - entry.windowStart > ABUSE_WINDOW_MS) {
    FAILED_LOOKUPS.set(ipHash, { count: 1, windowStart: now });
    return true;
  }
  if (entry.count >= MAX_FAILED_PER_WINDOW) {
    return false; // Throttled
  }
  entry.count++;
  return true;
}

/**
 * Helper to build JSON responses with security headers
 */
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
      'Pragma': 'no-cache',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    }
  });
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    }
  });
}

export async function onRequestGet(context) {
  const db = context.env.DB;
  const url = new URL(context.request.url);
  const rawRef = (url.searchParams.get('reference') || '').trim();
  const nowIso = new Date().toISOString();

  // Extract IP & User Agent for audit logging (IP is hashed before storage)
  const clientIp =
    context.request.headers.get('cf-connecting-ip') ||
    context.request.headers.get('x-forwarded-for') ||
    '127.0.0.1';
  const ipHash = await hashIp(clientIp);
  const userAgent = context.request.headers.get('user-agent') || '';

  // 1. Validate reference format (32 hex characters)
  if (!rawRef || !/^[0-9a-fA-F]{32}$/.test(rawRef)) {
    return jsonResponse(
      {
        verified: false,
        status: 'INVALID_REFERENCE',
        error: {
          code: 'INVALID_REFERENCE_FORMAT',
          message: 'Verification reference must be a 32-character hexadecimal string.'
        },
        trust_disclaimer: MANDATORY_TRUST_DISCLAIMER
      },
      400
    );
  }

  const cleanRef = rawRef.toLowerCase();

  try {
    // 2. Query unit joined with parent batch
    const unit = await db
      .prepare(
        `SELECT u.id as unit_db_id, u.batch_db_id, u.batch_id, u.unit_id, u.leaf_index,
                u.medicine_name, u.manufacturing_date, u.expiry_date,
                u.proof_data, u.verification_reference, u.created_at as unit_created_at,
                b.merkle_root, b.publication_status, b.published_at, b.revoked_at, b.revocation_reason
         FROM medicine_units u
         JOIN batches b ON u.batch_db_id = b.id
         WHERE u.verification_reference = ?`
      )
      .bind(cleanRef)
      .first();

    // 3. Handle Record Not Found
    if (!unit) {
      const allowed = recordFailedAttempt(ipHash);
      if (!allowed) {
        // Abuse mitigation: skip D1 audit write to prevent exhaustion, return 429
        return jsonResponse(
          {
            verified: false,
            status: 'RATE_LIMITED',
            error: {
              code: 'RATE_LIMIT_EXCEEDED',
              message: 'Too many invalid verification attempts. Please wait before attempting further lookups.'
            },
            trust_disclaimer: MANDATORY_TRUST_DISCLAIMER
          },
          429
        );
      }

      await db
        .prepare(
          `INSERT INTO customer_verifications (id, verification_reference, unit_db_id, batch_db_id, verification_result, timestamp, ip_hash, user_agent)
           VALUES (?, ?, NULL, NULL, 'NOT_FOUND', ?, ?, ?)`
        )
        .bind(crypto.randomUUID(), cleanRef, nowIso, ipHash, userAgent)
        .run()
        .catch(() => {});

      return jsonResponse(
        {
          verified: false,
          status: 'NOT_FOUND',
          error: {
            code: 'RECORD_NOT_FOUND',
            message: 'No medicine record found matching the provided verification reference.'
          },
          trust_disclaimer: MANDATORY_TRUST_DISCLAIMER
        },
        404
      );
    }

    // 4. Handle Batch Revocation
    if (unit.publication_status === 'revoked') {
      await db
        .prepare(
          `INSERT INTO customer_verifications (id, verification_reference, unit_db_id, batch_db_id, verification_result, timestamp, ip_hash, user_agent)
           VALUES (?, ?, ?, ?, 'REVOKED', ?, ?, ?)`
        )
        .bind(crypto.randomUUID(), cleanRef, unit.unit_db_id, unit.batch_db_id, nowIso, ipHash, userAgent)
        .run()
        .catch(() => {});

      return jsonResponse(
        {
          verified: false,
          status: 'REVOKED',
          message: 'This medicine batch has been revoked and is no longer authorized for patient distribution.',
          revocation_reason: unit.revocation_reason || 'Batch revoked by manufacturer or regulatory authority.',
          revoked_at: unit.revoked_at,
          record: {
            medicine_name: unit.medicine_name,
            batch_id: unit.batch_id,
            unit_id: unit.unit_id,
            manufacturing_date: unit.manufacturing_date,
            expiry_date: unit.expiry_date
          },
          trust_disclaimer: MANDATORY_TRUST_DISCLAIMER
        },
        403
      );
    }

    // 5. Handle Unpublished / Incomplete Batch
    if (unit.publication_status !== 'published') {
      await db
        .prepare(
          `INSERT INTO customer_verifications (id, verification_reference, unit_db_id, batch_db_id, verification_result, timestamp, ip_hash, user_agent)
           VALUES (?, ?, ?, ?, 'UNPUBLISHED', ?, ?, ?)`
        )
        .bind(crypto.randomUUID(), cleanRef, unit.unit_db_id, unit.batch_db_id, nowIso, ipHash, userAgent)
        .run()
        .catch(() => {});

      return jsonResponse(
        {
          verified: false,
          status: 'UNPUBLISHED',
          error: {
            code: 'BATCH_NOT_PUBLISHED',
            message: `Parent batch "${unit.batch_id}" has not been finalized or published to the trusted registry (status: ${unit.publication_status}).`
          },
          trust_disclaimer: MANDATORY_TRUST_DISCLAIMER
        },
        400
      );
    }

    // 6. Cryptographic Proof Verification via Web Crypto
    const unitRecord = {
      batch_id: unit.batch_id,
      unit_id: unit.unit_id,
      medicine_name: unit.medicine_name,
      manufacturing_date: unit.manufacturing_date,
      expiry_date: unit.expiry_date
    };

    const proofResult = await verifyRecordProof(unitRecord, unit.proof_data, unit.merkle_root);

    if (!proofResult.valid) {
      await db
        .prepare(
          `INSERT INTO customer_verifications (id, verification_reference, unit_db_id, batch_db_id, verification_result, timestamp, ip_hash, user_agent)
           VALUES (?, ?, ?, ?, 'INVALID_PROOF', ?, ?, ?)`
        )
        .bind(crypto.randomUUID(), cleanRef, unit.unit_db_id, unit.batch_db_id, nowIso, ipHash, userAgent)
        .run()
        .catch(() => {});

      return jsonResponse(
        {
          verified: false,
          status: 'INVALID_PROOF',
          error: {
            code: 'INTEGRITY_VERIFICATION_FAILED',
            message: `Cryptographic Merkle proof verification failed: ${proofResult.error || 'Root mismatch'}`
          },
          trust_disclaimer: MANDATORY_TRUST_DISCLAIMER
        },
        400
      );
    }

    // 7. Success: Log and return Verified result
    await db
      .prepare(
        `INSERT INTO customer_verifications (id, verification_reference, unit_db_id, batch_db_id, verification_result, timestamp, ip_hash, user_agent)
         VALUES (?, ?, ?, ?, 'VERIFIED', ?, ?, ?)`
      )
      .bind(crypto.randomUUID(), cleanRef, unit.unit_db_id, unit.batch_db_id, nowIso, ipHash, userAgent)
      .run()
      .catch(() => {});

    return jsonResponse({
      verified: true,
      status: 'VERIFIED',
      message: 'Digital medicine record verified against the registered batch commitment.',
      record: {
        medicine_name: unit.medicine_name,
        batch_id: unit.batch_id,
        unit_id: unit.unit_id,
        manufacturing_date: unit.manufacturing_date,
        expiry_date: unit.expiry_date,
        leaf_index: unit.leaf_index,
        published_at: unit.published_at,
        verification_timestamp: nowIso
      },
      trust_disclaimer: MANDATORY_TRUST_DISCLAIMER
    });
  } catch (err) {
    return jsonResponse(
      {
        verified: false,
        status: 'SERVER_ERROR',
        error: {
          code: 'SERVER_ERROR',
          message: `Public verification service error: ${err.message}`
        },
        trust_disclaimer: MANDATORY_TRUST_DISCLAIMER
      },
      500
    );
  }
}

