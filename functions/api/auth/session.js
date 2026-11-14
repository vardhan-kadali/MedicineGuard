// GET /api/auth/session
// Check current session, returning user details and fresh CSRF token

import { jsonOk, jsonError } from '../../_shared/responses.js';
import { getSessionAndUser, randomBytes, sha256Hex } from '../../_shared/auth.js';
import { toHex } from '../../_shared/merkle-verifier.js';

export async function onRequestGet(context) {
  try {
    const db = context.env.DB;
    const auth = await getSessionAndUser(context.request, db);

    if (!auth) {
      return jsonOk({
        authenticated: false,
        user: null,
        csrfToken: null
      });
    }

    // Refresh and issue a fresh CSRF token for this active session
    const freshCsrf = toHex(randomBytes(32));
    const freshCsrfHash = await sha256Hex(freshCsrf);

    await db
      .prepare('UPDATE sessions SET csrf_token_hash = ? WHERE session_id = ?')
      .bind(freshCsrfHash, auth.session.sessionId)
      .run();

    return jsonOk({
      authenticated: true,
      user: {
        userId: auth.user.userId,
        email: auth.user.email,
        role: auth.user.role
      },
      csrfToken: freshCsrf
    });
  } catch (err) {
    return jsonError(`Session check failed: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

