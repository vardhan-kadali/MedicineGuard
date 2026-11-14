// /api/manufacturer/batches
// GET: List manufacturer batches
// POST: Initiate new batch in 'uploading' status

import { jsonOk, jsonError, jsonConflict } from '../../../_shared/responses.js';
import { requireAuth } from '../../../_shared/auth.js';
import { validateDateRange, isValidHex64 } from '../../../_shared/validation.js';

export async function onRequestGet(context) {
  try {
    const authResult = await requireAuth(context, ['manufacturer', 'admin']);
    if (!authResult.authorized) {
      return authResult.response;
    }

    const db = context.env.DB;
    const { user } = authResult;

    let query = `
      SELECT b.id, b.batch_id, b.manufacturer_user_id, b.medicine_name,
             b.manufacturing_date, b.expiry_date, b.total_units, b.merkle_root,
             b.publication_status, b.created_at, b.published_at, b.revoked_at, b.revocation_reason,
             (SELECT COUNT(*) FROM medicine_units u WHERE u.batch_db_id = b.id) as uploaded_units
      FROM batches b
    `;
    const params = [];

    if (user.role !== 'admin') {
      query += ' WHERE b.manufacturer_user_id = ?';
      params.push(user.userId);
    }

    query += ' ORDER BY b.created_at DESC';

    const { results } = await db.prepare(query).bind(...params).all();
    return jsonOk({ batches: results || [] });
  } catch (err) {
    return jsonError(`Failed to fetch batches: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

export async function onRequestPost(context) {
  try {
    const authResult = await requireAuth(context, ['manufacturer']);
    if (!authResult.authorized) {
      return authResult.response;
    }

    const db = context.env.DB;
    const { user } = authResult;

    let body;
    try {
      body = await context.request.json();
    } catch {
      return jsonError('Invalid JSON request body');
    }

    const {
      batch_id,
      medicine_name,
      manufacturing_date,
      expiry_date,
      total_units,
      merkle_root
    } = body || {};

    if (!batch_id || typeof batch_id !== 'string' || batch_id.trim().length === 0) {
      return jsonError('batch_id is required');
    }
    const cleanBatchId = batch_id.trim();

    if (!medicine_name || typeof medicine_name !== 'string' || medicine_name.trim().length === 0) {
      return jsonError('medicine_name is required');
    }
    const cleanMedicineName = medicine_name.trim();

    const dateCheck = validateDateRange(manufacturing_date, expiry_date);
    if (!dateCheck.valid) {
      return jsonError(dateCheck.error);
    }

    const totalUnitsNum = parseInt(total_units, 10);
    if (!Number.isInteger(totalUnitsNum) || totalUnitsNum <= 0) {
      return jsonError('total_units must be a positive integer');
    }

    if (!isValidHex64(merkle_root)) {
      return jsonError('merkle_root must be a valid 64-character lowercase hex string');
    }
    const cleanMerkleRoot = merkle_root.trim().toLowerCase();

    // Check if batch_id already exists
    const existing = await db
      .prepare('SELECT id, publication_status FROM batches WHERE batch_id = ?')
      .bind(cleanBatchId)
      .first();

    if (existing) {
      return jsonConflict(`Batch "${cleanBatchId}" already exists with status: ${existing.publication_status}`);
    }

    const nowIso = new Date().toISOString();

    const insertResult = await db
      .prepare(
        `INSERT INTO batches (
           batch_id, manufacturer_user_id, medicine_name, manufacturing_date,
           expiry_date, total_units, merkle_root, publication_status, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, 'uploading', ?)`
      )
      .bind(
        cleanBatchId,
        user.userId,
        cleanMedicineName,
        manufacturing_date,
        expiry_date,
        totalUnitsNum,
        cleanMerkleRoot,
        nowIso
      )
      .run();

    const batchDbId = insertResult.meta.last_row_id;

    // Log CREATED event
    await db
      .prepare(
        `INSERT INTO batch_events (event_id, batch_db_id, event_type, actor_user_id, details, created_at)
         VALUES (?, ?, 'CREATED', ?, ?, ?)`
      )
      .bind(
        crypto.randomUUID(),
        batchDbId,
        user.userId,
        JSON.stringify({ total_units: totalUnitsNum, merkle_root: cleanMerkleRoot }),
        nowIso
      )
      .run();

    return jsonOk(
      {
        message: 'Batch initiated successfully',
        batch: {
          id: batchDbId,
          batch_id: cleanBatchId,
          medicine_name: cleanMedicineName,
          manufacturing_date,
          expiry_date,
          total_units: totalUnitsNum,
          merkle_root: cleanMerkleRoot,
          publication_status: 'uploading',
          created_at: nowIso
        }
      },
      201
    );
  } catch (err) {
    return jsonError(`Failed to initiate batch: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

