// POST /api/auth/change-password
// Authenticated user password update

import { jsonOk, jsonError, jsonUnauthorized } from '../../_shared/responses.js';
import { requireAuth, verifyPassword, hashPassword } from '../../_shared/auth.js';

export async function onRequestPost(context) {
  try {
    const authResult = await requireAuth(context);
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

    const { currentPassword, newPassword } = body || {};

    if (!currentPassword || !newPassword) {
      return jsonError('Both current password and new password are required');
    }

    if (typeof newPassword !== 'string' || newPassword.length < 8) {
      return jsonError('New password must be at least 8 characters long');
    }

    // Fetch existing password hash for user
    const dbUser = await db
      .prepare('SELECT password_hash, password_salt, password_iterations FROM users WHERE user_id = ?')
      .bind(user.userId)
      .first();

    if (!dbUser) {
      return jsonUnauthorized('User not found');
    }

    const isMatch = await verifyPassword(
      currentPassword,
      dbUser.password_hash,
      dbUser.password_salt,
      dbUser.password_iterations
    );

    if (!isMatch) {
      return jsonError('Incorrect current password', 'INVALID_CREDENTIALS', 400);
    }

    const { password_hash, password_salt, password_algorithm, password_iterations } = await hashPassword(newPassword);
    const nowIso = new Date().toISOString();

    await db
      .prepare(
        `UPDATE users
         SET password_hash = ?, password_salt = ?, password_algorithm = ?, password_iterations = ?, updated_at = ?
         WHERE user_id = ?`
      )
      .bind(password_hash, password_salt, password_algorithm, password_iterations, nowIso, user.userId)
      .run();

    return jsonOk({ message: 'Password updated successfully' });
  } catch (err) {
    return jsonError(`Failed to update password: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

