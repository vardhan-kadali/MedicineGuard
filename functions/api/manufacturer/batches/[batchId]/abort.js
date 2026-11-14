// POST /api/manufacturer/batches/[batchId]/abort
// Abort an incomplete batch upload (forbidden on published batches)

import { jsonOk, jsonError, jsonNotFound, jsonForbidden } from '../../../../_shared/responses.js';
import { requireAuth } from '../../../../_shared/auth.js';

export async function onRequestPost(context) {
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
      return jsonForbidden('You are not authorized to abort this batch');
    }

    if (batch.publication_status === 'published') {
      return jsonForbidden('Published batches are immutable and cannot be aborted', 'IMMUTABLE_BATCH');
    }

    const nowIso = new Date().toISOString();

    // Delete any partially uploaded units
    await db.prepare('DELETE FROM medicine_units WHERE batch_db_id = ?').bind(batch.id).run();

    // Mark batch aborted
    await db
      .prepare("UPDATE batches SET publication_status = 'aborted' WHERE id = ?")
      .bind(batch.id)
      .run();

    // Log ABORTED event
    await db
      .prepare(
        `INSERT INTO batch_events (event_id, batch_db_id, event_type, actor_user_id, details, created_at)
         VALUES (?, ?, 'ABORTED', ?, ?, ?)`
      )
      .bind(
        crypto.randomUUID(),
        batch.id,
        user.userId,
        JSON.stringify({ reason: 'Manufacturer aborted upload' }),
        nowIso
      )
      .run();

    return jsonOk({
      message: `Batch "${batch.batch_id}" has been aborted`,
      batch_id: batch.batch_id,
      publication_status: 'aborted'
    });
  } catch (err) {
    return jsonError(`Failed to abort batch: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

