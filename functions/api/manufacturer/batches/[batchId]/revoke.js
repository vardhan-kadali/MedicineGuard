// POST /api/manufacturer/batches/[batchId]/revoke
// Revoke a published medicine batch (e.g. for recall or defect)

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
      return jsonForbidden('You are not authorized to revoke this batch');
    }

    if (batch.publication_status === 'revoked') {
      return jsonForbidden('Batch has already been revoked', 'ALREADY_REVOKED');
    }

    if (batch.publication_status !== 'published') {
      return jsonForbidden(
        `Cannot revoke batch in "${batch.publication_status}" status. Only published batches can be revoked.`,
        'INVALID_STATUS_FOR_REVOCATION'
      );
    }

    let body = {};
    try {
      body = await context.request.json();
    } catch {
      // Body is optional
    }

    const reason = (body?.reason || 'Batch revoked by manufacturer or regulatory authority.').trim();
    const nowIso = new Date().toISOString();

    // Update batch to revoked
    await db
      .prepare(
        `UPDATE batches
         SET publication_status = 'revoked', revoked_at = ?, revocation_reason = ?
         WHERE id = ?`
      )
      .bind(nowIso, reason, batch.id)
      .run();

    // Log REVOKED in batch_events
    await db
      .prepare(
        `INSERT INTO batch_events (event_id, batch_db_id, event_type, actor_user_id, details, created_at)
         VALUES (?, ?, 'REVOKED', ?, ?, ?)`
      )
      .bind(
        crypto.randomUUID(),
        batch.id,
        user.userId,
        JSON.stringify({ reason, previous_status: batch.publication_status }),
        nowIso
      )
      .run();

    return jsonOk({
      message: `Batch "${batch.batch_id}" has been revoked successfully`,
      batch: {
        batch_id: batch.batch_id,
        medicine_name: batch.medicine_name,
        total_units: batch.total_units,
        publication_status: 'revoked',
        revoked_at: nowIso,
        revocation_reason: reason
      }
    });
  } catch (err) {
    return jsonError(`Failed to revoke batch: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

