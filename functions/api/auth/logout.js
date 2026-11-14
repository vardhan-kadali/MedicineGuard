// POST /api/auth/logout
// Revoke session and clear session cookie

import { jsonOk, jsonError } from '../../_shared/responses.js';
import { parseCookies, sha256Hex, clearSessionCookie, COOKIE_NAME } from '../../_shared/auth.js';

export async function onRequestPost(context) {
  try {
    const db = context.env.DB;
    const cookies = parseCookies(context.request);
    const token = cookies[COOKIE_NAME];

    if (token) {
      const tokenHash = await sha256Hex(token);
      const nowIso = new Date().toISOString();
      await db
        .prepare('UPDATE sessions SET revoked_at = ? WHERE token_hash = ?')
        .bind(nowIso, tokenHash)
        .run();
    }

    const isHttps = new URL(context.request.url).protocol === 'https:';
    const clearCookie = clearSessionCookie(isHttps);

    return jsonOk(
      { message: 'Logged out successfully' },
      200,
      { 'Set-Cookie': clearCookie }
    );
  } catch (err) {
    return jsonError(`Logout failed: ${err.message}`, 'SERVER_ERROR', 500);
  }
}

