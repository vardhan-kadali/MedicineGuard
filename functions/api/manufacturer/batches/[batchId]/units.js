// POST /api/manufacturer/batches/[batchId]/units
// Upload a chunk of medicine units with proofs, verifying each proof server-side against the batch Merkle root

import { jsonOk, jsonError, jsonNotFound, jsonForbidden } from '../../../../_shared/responses.js';
import { requireAuth } from '../../../../_shared/auth.js';
import { verifyRecordProof, toHex } from '../../../../_shared/merkle-verifier.js';

export async function onRequestPost(context) {
  try {
    const authResult = await requireAuth(context, ['manufacturer']);
    if (!authResult.authorized) {
      return authResult.response;
    }

    const db = context.env.DB;
    const { user } = authResult;
    const batchIdParam = context.params.batchId;

    // Lookup batch
    const batch = await db
      .prepare('SELECT * FROM batches WHERE batch_id = ?')
      .bind(batchIdParam)
      .first();

    if (!batch) {
      return jsonNotFound(`Batch "${batchIdParam}" not found`);
    }

    if (batch.manufacturer_user_id !== user.userId) {
      return jsonForbidden('You are not authorized to upload units for this batch');
    }

    if (batch.publication_status !== 'uploading') {
      return jsonForbidden(`Cannot upload units: batch is in "${batch.publication_status}" status`);
    }

    let body;
    try {
      body = await context.request.json();
    } catch {
      return jsonError('Invalid JSON request body');
    }

    const { units } = body || {};

    if (!Array.isArray(units) || units.length === 0) {
      return jsonError('Request must include a non-empty array of units');
    }

    // Verify all units before inserting
    const verifiedUnits = [];

    for (let i = 0; i < units.length; i++) {
      const u = units[i];
      if (!u.unit_id || typeof u.unit_id !== 'string') {
        return jsonError(`Unit at index ${i} missing unit_id`);
      }
      if (typeof u.leaf_index !== 'number' || u.leaf_index < 0) {
        return jsonError(`Unit "${u.unit_id}" has invalid leaf_index`);
      }
      if (!u.proof_data || typeof u.proof_data !== 'string') {
        return jsonError(`Unit "${u.unit_id}" missing base64 proof_data`);
      }

      const unitRecord = {
        batch_id: batch.batch_id,
        unit_id: u.unit_id.trim(),
        medicine_name: u.medicine_name || batch.medicine_name,
        manufacturing_date: u.manufacturing_date || batch.manufacturing_date,
        expiry_date: u.expiry_date || batch.expiry_date
      };

      // Ensure record consistency with batch metadata
      if (unitRecord.medicine_name !== batch.medicine_name) {
        return jsonError(`Unit "${u.unit_id}" medicine_name does not match batch medicine_name`);
      }
      if (unitRecord.manufacturing_date !== batch.manufacturing_date) {
        return jsonError(`Unit "${u.unit_id}" manufacturing_date does not match batch manufacturing_date`);
      }
      if (unitRecord.expiry_date !== batch.expiry_date) {
        return jsonError(`Unit "${u.unit_id}" expiry_date does not match batch expiry_date`);
      }

      // Web Crypto Server-side Merkle Proof Verification
      const proofResult = await verifyRecordProof(unitRecord, u.proof_data, batch.merkle_root);
      if (!proofResult.valid) {
        return jsonError(
          `Cryptographic Merkle proof verification failed for unit "${u.unit_id}": ${proofResult.error}`,
          'INVALID_MERKLE_PROOF',
          400
        );
      }

      // Check leaf index alignment with proof header
      if (proofResult.leafIndex !== u.leaf_index) {
        return jsonError(
          `Unit "${u.unit_id}" leaf_index ${u.leaf_index} does not match proof header index ${proofResult.leafIndex}`,
          'LEAF_INDEX_MISMATCH',
          400
        );
      }

      // Check total leaves matches batch total_units
      if (proofResult.totalLeaves !== batch.total_units) {
        return jsonError(
          `Unit "${u.unit_id}" proof total_leaves ${proofResult.totalLeaves} does not match batch total_units ${batch.total_units}`,
          'TOTAL_LEAVES_MISMATCH',
          400
        );
      }

      // Generate secure unique verification_reference (32-char hex token)
      const refBytes = new Uint8Array(16);
      crypto.getRandomValues(refBytes);
      const verificationRef = toHex(refBytes);

      verifiedUnits.push({
        ...unitRecord,
        leaf_index: u.leaf_index,
        proof_data: u.proof_data,
        verification_reference: verificationRef
      });
    }

    // Insert all verified units in a batch query
    const nowIso = new Date().toISOString();
    const stmts = verifiedUnits.map((u) => {
      return db
        .prepare(
          `INSERT INTO medicine_units (
             batch_db_id, batch_id, unit_id, leaf_index, medicine_name,
             manufacturing_date, expiry_date, proof_data, verification_reference, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          batch.id,
          u.batch_id,
          u.unit_id,
          u.leaf_index,
          u.medicine_name,
          u.manufacturing_date,
          u.expiry_date,
          u.proof_data,
          u.verification_reference,
          nowIso
        );
    });

    await db.batch(stmts);

    // Get current total uploaded units
    const countResult = await db
      .prepare('SELECT COUNT(*) as total FROM medicine_units WHERE batch_db_id = ?')
      .bind(batch.id)
      .first();

    const totalUploaded = countResult ? countResult.total : 0;

    // Log CHUNK_UPLOADED event
    await db
      .prepare(
        `INSERT INTO batch_events (event_id, batch_db_id, event_type, actor_user_id, details, created_at)
         VALUES (?, ?, 'CHUNK_UPLOADED', ?, ?, ?)`
      )
      .bind(
        crypto.randomUUID(),
        batch.id,
        user.userId,
        JSON.stringify({ chunk_size: verifiedUnits.length, total_uploaded: totalUploaded }),
        nowIso
      )
      .run();

    return jsonOk({
      message: `Successfully verified and uploaded ${verifiedUnits.length} units`,
      uploadedCount: verifiedUnits.length,
      totalUploadedSoFar: totalUploaded,
      batchTotalUnits: batch.total_units
    });
  } catch (err) {
    if (err.message && err.message.includes('UNIQUE constraint failed')) {
      return jsonError(`Duplicate unit or leaf index in batch: ${err.message}`, 'DUPLICATE_UNIT', 409);
    }
    return jsonError(`Failed to upload units: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

export async function onRequestGet(context) {
  try {
    const authResult = await requireAuth(context, ['manufacturer', 'admin']);
    if (!authResult.authorized) {
      return authResult.response;
    }

    const db = context.env.DB;
    const { user } = authResult;
    const batchIdParam = context.params.batchId;

    const batch = await db
      .prepare('SELECT * FROM batches WHERE batch_id = ?')
      .bind(batchIdParam)
      .first();

    if (!batch) {
      return jsonNotFound(`Batch "${batchIdParam}" not found`);
    }

    if (user.role !== 'admin' && batch.manufacturer_user_id !== user.userId) {
      return jsonForbidden('You are not authorized to view units for this batch');
    }

    const url = new URL(context.request.url);
    const search = (url.searchParams.get('search') || '').trim();
    const all = url.searchParams.get('all') === 'true';
    let page = parseInt(url.searchParams.get('page') || '1', 10);
    if (isNaN(page) || page < 1) page = 1;
    let limit = parseInt(url.searchParams.get('limit') || '20', 10);
    if (isNaN(limit) || limit < 1) limit = 20;
    if (limit > 500) limit = 500;

    let countQuery = 'SELECT COUNT(*) as total FROM medicine_units WHERE batch_db_id = ?';
    const countParams = [batch.id];

    if (search) {
      countQuery += ' AND unit_id LIKE ?';
      countParams.push(`%${search}%`);
    }

    const countRes = await db.prepare(countQuery).bind(...countParams).first();
    const total = countRes ? countRes.total : 0;

    let dataQuery = `
      SELECT unit_id, leaf_index, medicine_name, manufacturing_date, expiry_date, verification_reference, created_at
      FROM medicine_units
      WHERE batch_db_id = ?
    `;
    const dataParams = [batch.id];

    if (search) {
      dataQuery += ' AND unit_id LIKE ?';
      dataParams.push(`%${search}%`);
    }

    dataQuery += ' ORDER BY leaf_index ASC';

    if (!all) {
      const offset = (page - 1) * limit;
      dataQuery += ` LIMIT ? OFFSET ?`;
      dataParams.push(limit, offset);
    }

    const { results } = await db.prepare(dataQuery).bind(...dataParams).all();
    const totalPages = all ? 1 : Math.max(1, Math.ceil(total / limit));

    return jsonOk({
      batch: {
        batch_id: batch.batch_id,
        medicine_name: batch.medicine_name,
        manufacturing_date: batch.manufacturing_date,
        expiry_date: batch.expiry_date,
        total_units: batch.total_units,
        publication_status: batch.publication_status,
        merkle_root: batch.merkle_root,
        published_at: batch.published_at,
        revoked_at: batch.revoked_at,
        revocation_reason: batch.revocation_reason
      },
      units: results || [],
      pagination: {
        page: all ? 1 : page,
        limit: all ? total : limit,
        total,
        totalPages
      }
    });
  } catch (err) {
    return jsonError(`Failed to fetch units: ${err.message}`, 'SERVER_ERROR', 500);
  }
}


