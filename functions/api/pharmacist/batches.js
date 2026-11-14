// GET /api/pharmacist/batches
// List all published batches available in the shared registry

import { jsonOk, jsonError } from '../../_shared/responses.js';
import { requireAuth } from '../../_shared/auth.js';

export async function onRequestGet(context) {
  try {
    const authResult = await requireAuth(context, ['pharmacist', 'admin', 'manufacturer']);
    if (!authResult.authorized) {
      return authResult.response;
    }

    const db = context.env.DB;
    const { results } = await db
      .prepare(
        `SELECT id, batch_id, medicine_name, manufacturing_date, expiry_date,
                total_units, merkle_root, algorithm_version, published_at
         FROM batches
         WHERE publication_status = 'published'
         ORDER BY published_at DESC`
      )
      .all();

    return jsonOk({ batches: results || [] });
  } catch (err) {
    return jsonError(`Failed to fetch published batches: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

