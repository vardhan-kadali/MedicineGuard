// POST /api/manufacturer/batches/[batchId]/publish
// Finalize and publish batch to shared trusted registry

import { jsonOk, jsonError, jsonNotFound, jsonForbidden } from '../../../../_shared/responses.js';
import { requireAuth } from '../../../../_shared/auth.js';

export async function onRequestPost(context) {
  try {
    const authResult = await requireAuth(context, ['manufacturer']);
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

    if (batch.manufacturer_user_id !== user.userId) {
      return jsonForbidden('You are not authorized to publish this batch');
    }

    if (batch.publication_status === 'published') {
      return jsonForbidden('Batch has already been published and is immutable', 'ALREADY_PUBLISHED');
    }

    if (batch.publication_status !== 'uploading') {
      return jsonForbidden(`Cannot publish batch in "${batch.publication_status}" status`);
    }

    // Verify all units have been uploaded
    const countResult = await db
      .prepare('SELECT COUNT(*) as count FROM medicine_units WHERE batch_db_id = ?')
      .bind(batch.id)
      .first();

    const actualCount = countResult ? countResult.count : 0;
    if (actualCount !== batch.total_units) {
      return jsonError(
        `Cannot publish batch: expected ${batch.total_units} units, but only ${actualCount} have been uploaded`,
        'INCOMPLETE_BATCH',
        400
      );
    }

    const nowIso = new Date().toISOString();

    // Mark as published
    await db
      .prepare(
        `UPDATE batches
         SET publication_status = 'published', published_at = ?
         WHERE id = ?`
      )
      .bind(nowIso, batch.id)
      .run();

    // Log PUBLISHED event
    await db
      .prepare(
        `INSERT INTO batch_events (event_id, batch_db_id, event_type, actor_user_id, details, created_at)
         VALUES (?, ?, 'PUBLISHED', ?, ?, ?)`
      )
      .bind(
        crypto.randomUUID(),
        batch.id,
        user.userId,
        JSON.stringify({ total_units: batch.total_units, merkle_root: batch.merkle_root }),
        nowIso
      )
      .run();

    return jsonOk({
      message: `Batch "${batch.batch_id}" published successfully to shared trusted registry`,
      batch: {
        batch_id: batch.batch_id,
        medicine_name: batch.medicine_name,
        total_units: batch.total_units,
        merkle_root: batch.merkle_root,
        publication_status: 'published',
        published_at: nowIso
      }
    });
  } catch (err) {
    return jsonError(`Failed to publish batch: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

