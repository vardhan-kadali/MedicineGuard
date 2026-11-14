// /api/pharmacist/verifications
// POST: Submit a pharmacist verification audit entry
// GET: Retrieve recent verification logs

import { jsonOk, jsonError, jsonNotFound } from '../../_shared/responses.js';
import { requireAuth, sha256Hex } from '../../_shared/auth.js';
import { verifyRecordProof } from '../../_shared/merkle-verifier.js';

export async function onRequestPost(context) {
  try {
    const authResult = await requireAuth(context, ['pharmacist', 'admin']);
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
      unit_id,
      batch_id,
      client_verification_result,
      client_status_code
    } = body || {};

    if (!unit_id || !batch_id) {
      return jsonError('Both unit_id and batch_id are required');
    }

    if (!client_verification_result) {
      return jsonError('client_verification_result is required');
    }

    // Lookup unit and batch in database
    const unit = await db
      .prepare(
        `SELECT u.id as unit_db_id, u.batch_db_id, u.batch_id, u.unit_id,
                u.medicine_name, u.manufacturing_date, u.expiry_date,
                u.proof_data, b.merkle_root
         FROM medicine_units u
         JOIN batches b ON u.batch_db_id = b.id
         WHERE u.unit_id = ? AND b.batch_id = ?`
      )
      .bind(unit_id.trim(), batch_id.trim())
      .first();

    if (!unit) {
      return jsonNotFound(`Unit "${unit_id}" in batch "${batch_id}" not found`);
    }

    // Execute server-side cryptographic verification
    const record = {
      batch_id: unit.batch_id,
      unit_id: unit.unit_id,
      medicine_name: unit.medicine_name,
      manufacturing_date: unit.manufacturing_date,
      expiry_date: unit.expiry_date
    };

    const serverProof = await verifyRecordProof(record, unit.proof_data, unit.merkle_root);
    const serverResult = serverProof.valid ? 'VALID' : 'INVALID';

    // Compute IP hash for privacy-preserving audit trail
    const clientIp = context.request.headers.get('cf-connecting-ip') ||
      context.request.headers.get('x-forwarded-for') ||
      '127.0.0.1';
    const ipHash = await sha256Hex(clientIp);
    const userAgent = (context.request.headers.get('user-agent') || '').slice(0, 255);

    const verificationId = crypto.randomUUID();
    const timestamp = new Date().toISOString();

    await db
      .prepare(
        `INSERT INTO verification_logs (
           verification_id, unit_db_id, batch_db_id, pharmacist_user_id,
           client_verification_result, client_status_code, server_verification_result,
           timestamp, ip_hash, user_agent
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        verificationId,
        unit.unit_db_id,
        unit.batch_db_id,
        user.userId,
        client_verification_result,
        typeof client_status_code === 'number' ? client_status_code : null,
        serverResult,
        timestamp,
        ipHash,
        userAgent
      )
      .run();

    return jsonOk(
      {
        message: 'Verification recorded in audit trail',
        verification_id: verificationId,
        server_verification_result: serverResult,
        client_verification_result,
        results_match: serverResult === client_verification_result,
        timestamp
      },
      201
    );
  } catch (err) {
    return jsonError(`Failed to log verification: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

export async function onRequestGet(context) {
  try {
    const authResult = await requireAuth(context, ['pharmacist', 'admin']);
    if (!authResult.authorized) {
      return authResult.response;
    }

    const db = context.env.DB;
    const { results } = await db
      .prepare(
        `SELECT v.verification_id, v.client_verification_result, v.client_status_code,
                v.server_verification_result, v.timestamp, v.user_agent,
                u.unit_id, b.batch_id, b.medicine_name,
                usr.email as pharmacist_email
         FROM verification_logs v
         LEFT JOIN medicine_units u ON v.unit_db_id = u.id
         LEFT JOIN batches b ON v.batch_db_id = b.id
         LEFT JOIN users usr ON v.pharmacist_user_id = usr.user_id
         ORDER BY v.timestamp DESC
         LIMIT 50`
      )
      .all();

    return jsonOk({ verifications: results || [] });
  } catch (err) {
    return jsonError(`Failed to fetch verification logs: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

