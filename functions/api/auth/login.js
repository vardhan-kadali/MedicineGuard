// POST /api/auth/login
// User authentication, issuing HttpOnly session cookie and CSRF token

import { jsonOk, jsonError, jsonUnauthorized } from '../../_shared/responses.js';
import { verifyPassword, createSession, createSessionCookie } from '../../_shared/auth.js';
import { isValidEmail } from '../../_shared/validation.js';

export async function onRequestPost(context) {
  try {
    const db = context.env.DB;

    let body;
    try {
      body = await context.request.json();
    } catch {
      return jsonError('Invalid JSON request body');
    }

    const { email, password } = body || {};

    if (!isValidEmail(email) || !password) {
      return jsonUnauthorized('Invalid email or password', 'INVALID_CREDENTIALS');
    }

    const normalizedEmail = email.trim().toLowerCase();
    const user = await db
      .prepare('SELECT user_id, email, password_hash, password_salt, password_iterations, role, account_status FROM users WHERE email = ?')
      .bind(normalizedEmail)
      .first();

    if (!user) {
      return jsonUnauthorized('Invalid email or password', 'INVALID_CREDENTIALS');
    }

    if (user.account_status !== 'active') {
      return jsonUnauthorized('Account is disabled. Please contact an administrator.', 'ACCOUNT_DISABLED');
    }

    const isMatch = await verifyPassword(
      password,
      user.password_hash,
      user.password_salt,
      user.password_iterations
    );

    if (!isMatch) {
      return jsonUnauthorized('Invalid email or password', 'INVALID_CREDENTIALS');
    }

    // Create session
    const { sessionToken, csrfToken } = await createSession(db, user.user_id);
    const isHttps = new URL(context.request.url).protocol === 'https:';
    const cookieHeader = createSessionCookie(sessionToken, 86400, isHttps);

    return jsonOk(
      {
        message: 'Login successful',
        user: {
          userId: user.user_id,
          email: user.email,
          role: user.role
        },
        csrfToken
      },
      200,
      {
        'Set-Cookie': cookieHeader
      }
    );
  } catch (err) {
    return jsonError(`Login failed: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

