// /api/admin/users
// GET: List all users (admin only)
// POST: Create a new user (admin only)

import { jsonOk, jsonError, jsonConflict } from '../../../_shared/responses.js';
import { requireAuth, hashPassword } from '../../../_shared/auth.js';
import { isValidEmail } from '../../../_shared/validation.js';

export async function onRequestGet(context) {
  try {
    const authResult = await requireAuth(context, ['admin']);
    if (!authResult.authorized) {
      return authResult.response;
    }

    const db = context.env.DB;
    const { results } = await db
      .prepare(
        `SELECT user_id, email, role, account_status, created_at, updated_at
         FROM users
         ORDER BY created_at DESC`
      )
      .all();

    return jsonOk({ users: results || [] });
  } catch (err) {
    return jsonError(`Failed to fetch users: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

export async function onRequestPost(context) {
  try {
    const authResult = await requireAuth(context, ['admin']);
    if (!authResult.authorized) {
      return authResult.response;
    }

    const db = context.env.DB;

    let body;
    try {
      body = await context.request.json();
    } catch {
      return jsonError('Invalid JSON request body');
    }

    const { email, password, role } = body || {};

    if (!isValidEmail(email)) {
      return jsonError('A valid email address is required');
    }

    if (!password || typeof password !== 'string' || password.length < 8) {
      return jsonError('Password must be at least 8 characters long');
    }

    const validRoles = ['admin', 'manufacturer', 'pharmacist'];
    if (!role || !validRoles.includes(role)) {
      return jsonError(`Invalid role. Must be one of: ${validRoles.join(', ')}`);
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Check if user already exists
    const existing = await db
      .prepare('SELECT user_id FROM users WHERE email = ?')
      .bind(normalizedEmail)
      .first();

    if (existing) {
      return jsonConflict(`User with email "${normalizedEmail}" already exists`);
    }

    const userId = crypto.randomUUID();
    const nowIso = new Date().toISOString();
    const { password_hash, password_salt, password_algorithm, password_iterations } = await hashPassword(password);

    await db
      .prepare(
        `INSERT INTO users (user_id, email, password_hash, password_salt, password_algorithm, password_iterations, role, account_status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`
      )
      .bind(
        userId,
        normalizedEmail,
        password_hash,
        password_salt,
        password_algorithm,
        password_iterations,
        role,
        nowIso,
        nowIso
      )
      .run();

    return jsonOk(
      {
        message: 'User created successfully',
        user: {
          userId,
          email: normalizedEmail,
          role,
          accountStatus: 'active',
          createdAt: nowIso
        }
      },
      201
    );
  } catch (err) {
    return jsonError(`Failed to create user: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

