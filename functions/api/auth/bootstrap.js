// POST /api/auth/bootstrap
// One-time initialization of initial Admin account using BOOTSTRAP_ADMIN_SECRET

import { jsonOk, jsonError, jsonForbidden } from '../../_shared/responses.js';
import { hashPassword, timingSafeEqualStrings } from '../../_shared/auth.js';
import { isValidEmail } from '../../_shared/validation.js';

export async function onRequestPost(context) {
  try {
    const db = context.env.DB;
    const expectedSecret = context.env.BOOTSTRAP_ADMIN_SECRET;

    if (!expectedSecret) {
      return jsonError('BOOTSTRAP_ADMIN_SECRET environment variable is not configured', 'SERVER_MISCONFIG', 500);
    }

    let body;
    try {
      body = await context.request.json();
    } catch {
      return jsonError('Invalid JSON request body');
    }

    const { secret, email, password } = body || {};

    if (!secret || !timingSafeEqualStrings(secret, expectedSecret)) {
      return jsonForbidden('Invalid bootstrap secret', 'INVALID_BOOTSTRAP_SECRET');
    }

    if (!isValidEmail(email)) {
      return jsonError('A valid email address is required');
    }

    if (!password || typeof password !== 'string' || password.length < 8) {
      return jsonError('Password must be at least 8 characters long');
    }

    // Check if an admin user already exists
    const adminCheck = await db
      .prepare("SELECT COUNT(*) as count FROM users WHERE role = 'admin'")
      .first();

    if (adminCheck && adminCheck.count > 0) {
      return jsonForbidden('Admin account has already been bootstrapped. Subsequent accounts must be created by an Admin.', 'ADMIN_ALREADY_EXISTS');
    }

    const userId = crypto.randomUUID();
    const nowIso = new Date().toISOString();
    const { password_hash, password_salt, password_iterations, password_algorithm } = await hashPassword(password);

    await db
      .prepare(
        `INSERT INTO users (user_id, email, password_hash, password_salt, password_algorithm, password_iterations, role, account_status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, 'admin', 'active', ?, ?)`
      )
      .bind(
        userId,
        email.trim().toLowerCase(),
        password_hash,
        password_salt,
        password_algorithm,
        password_iterations,
        nowIso,
        nowIso
      )
      .run();

    return jsonOk({
      message: 'Admin account bootstrapped successfully',
      user: {
        userId,
        email: email.trim().toLowerCase(),
        role: 'admin'
      }
    }, 201);
  } catch (err) {
    return jsonError(`Bootstrap failed: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

