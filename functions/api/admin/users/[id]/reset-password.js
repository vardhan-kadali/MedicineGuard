// POST /api/admin/users/[id]/reset-password
// Administrative password reset (admin only)

import { jsonOk, jsonError, jsonNotFound } from '../../../../_shared/responses.js';
import { requireAuth, hashPassword } from '../../../../_shared/auth.js';

export async function onRequestPost(context) {
  try {
    const authResult = await requireAuth(context, ['admin']);
    if (!authResult.authorized) {
      return authResult.response;
    }

    const db = context.env.DB;
    const targetUserId = context.params.id;

    let body;
    try {
      body = await context.request.json();
    } catch {
      return jsonError('Invalid JSON request body');
    }

    const { newPassword } = body || {};

    if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 8) {
      return jsonError('New password must be at least 8 characters long');
    }

    const targetUser = await db
      .prepare('SELECT user_id FROM users WHERE user_id = ?')
      .bind(targetUserId)
      .first();

    if (!targetUser) {
      return jsonNotFound('User not found');
    }

    const { password_hash, password_salt, password_algorithm, password_iterations } = await hashPassword(newPassword);
    const nowIso = new Date().toISOString();

    await db
      .prepare(
        `UPDATE users
         SET password_hash = ?, password_salt = ?, password_algorithm = ?, password_iterations = ?, updated_at = ?
         WHERE user_id = ?`
      )
      .bind(password_hash, password_salt, password_algorithm, password_iterations, nowIso, targetUserId)
      .run();

    // Revoke any active sessions so target user must log in with new password
    await db
      .prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL')
      .bind(nowIso, targetUserId)
      .run();

    return jsonOk({ message: 'Password reset successfully' });
  } catch (err) {
    return jsonError(`Failed to reset password: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

