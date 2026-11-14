// GET /api/pharmacist/lookup?unit_id=...&batch_id=...
// Lookup a medicine unit by unit_id with optional batch_id scope.
// Handles single match, 404, or 409 AMBIGUOUS_UNIT_ID if unit exists in multiple published batches.

import { jsonOk, jsonError, jsonNotFound, jsonAmbiguous } from '../../_shared/responses.js';
import { requireAuth } from '../../_shared/auth.js';

export async function onRequestGet(context) {
  try {
    const authResult = await requireAuth(context, ['pharmacist', 'admin', 'manufacturer']);
    if (!authResult.authorized) {
      return authResult.response;
    }

    const db = context.env.DB;
    const url = new URL(context.request.url);
    const unitId = (url.searchParams.get('unit_id') || '').trim();
    const batchId = (url.searchParams.get('batch_id') || '').trim();

    if (!unitId) {
      return jsonError('Query parameter "unit_id" is required');
    }

    if (batchId) {
      // Scoped lookup to a specific batch
      const unit = await db
        .prepare(
          `SELECT u.id, u.batch_db_id, u.batch_id, u.unit_id, u.leaf_index,
                  u.medicine_name, u.manufacturing_date, u.expiry_date,
                  u.proof_data, u.verification_reference, u.created_at,
                  b.merkle_root, b.published_at
           FROM medicine_units u
           JOIN batches b ON u.batch_db_id = b.id
           WHERE u.unit_id = ? AND b.batch_id = ? AND b.publication_status = 'published'`
        )
        .bind(unitId, batchId)
        .first();

      if (!unit) {
        return jsonNotFound(`Unit "${unitId}" was not found in published batch "${batchId}"`);
      }

      return jsonOk({ unit });
    }

    // Unscoped lookup across all published batches
    const { results } = await db
      .prepare(
        `SELECT u.id, u.batch_db_id, u.batch_id, u.unit_id, u.leaf_index,
                u.medicine_name, u.manufacturing_date, u.expiry_date,
                u.proof_data, u.verification_reference, u.created_at,
                b.merkle_root, b.published_at
         FROM medicine_units u
         JOIN batches b ON u.batch_db_id = b.id
         WHERE u.unit_id = ? AND b.publication_status = 'published'`
      )
      .bind(unitId)
      .all();

    if (!results || results.length === 0) {
      return jsonNotFound(`Unit "${unitId}" was not found in any published batch`);
    }

    if (results.length === 1) {
      return jsonOk({ unit: results[0] });
    }

    // Ambiguous Unit ID: present in multiple published batches
    const matches = results.map((r) => ({
      batch_id: r.batch_id,
      medicine_name: r.medicine_name,
      manufacturing_date: r.manufacturing_date,
      expiry_date: r.expiry_date,
      leaf_index: r.leaf_index,
      published_at: r.published_at
    }));

    return jsonAmbiguous(
      `Unit ID "${unitId}" appears in ${results.length} published batches. Please select a specific Batch ID to verify.`,
      matches
    );
  } catch (err) {
    return jsonError(`Lookup failed: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

