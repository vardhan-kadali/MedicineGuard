// PATCH /api/admin/users/[id]
// Update user status or role (admin only)

import { jsonOk, jsonError, jsonNotFound, jsonForbidden } from '../../../_shared/responses.js';
import { requireAuth } from '../../../_shared/auth.js';

export async function onRequestPatch(context) {
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

    const { account_status, role } = body || {};

    const targetUser = await db
      .prepare('SELECT user_id, email, role, account_status FROM users WHERE user_id = ?')
      .bind(targetUserId)
      .first();

    if (!targetUser) {
      return jsonNotFound('User not found');
    }

    // Safety: prevent admin from disabling their own account
    if (targetUserId === authResult.user.userId && account_status === 'disabled') {
      return jsonForbidden('Administrators cannot disable their own account');
    }

    const updates = [];
    const values = [];

    if (account_status !== undefined) {
      if (!['active', 'disabled'].includes(account_status)) {
        return jsonError('Invalid account_status. Must be "active" or "disabled"');
      }
      updates.push('account_status = ?');
      values.push(account_status);
    }

    if (role !== undefined) {
      if (!['admin', 'manufacturer', 'pharmacist'].includes(role)) {
        return jsonError('Invalid role. Must be "admin", "manufacturer", or "pharmacist"');
      }
      updates.push('role = ?');
      values.push(role);
    }

    if (updates.length === 0) {
      return jsonError('No fields provided to update');
    }

    const nowIso = new Date().toISOString();
    updates.push('updated_at = ?');
    values.push(nowIso);
    values.push(targetUserId);

    await db
      .prepare(`UPDATE users SET ${updates.join(', ')} WHERE user_id = ?`)
      .bind(...values)
      .run();

    // If account was disabled, revoke all active sessions for this user
    if (account_status === 'disabled') {
      await db
        .prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL')
        .bind(nowIso, targetUserId)
        .run();
    }

    return jsonOk({
      message: 'User updated successfully',
      user: {
        userId: targetUserId,
        accountStatus: account_status || targetUser.account_status,
        role: role || targetUser.role
      }
    });
  } catch (err) {
    return jsonError(`Failed to update user: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

