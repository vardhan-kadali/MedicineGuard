// MedicineGuard Server-side Authentication & Session Management
// Uses PBKDF2-HMAC-SHA256 (600,000 iterations), Web Crypto, HttpOnly cookies, and CSRF tokens.

import { toHex, fromHex } from './merkle-verifier.js';
import { jsonUnauthorized, jsonForbidden } from './responses.js';

export const PBKDF2_ITERATIONS = 600000;
export const PBKDF2_ALGORITHM = 'PBKDF2-SHA256';
export const SESSION_DURATION_SECONDS = 86400; // 24 hours
export const COOKIE_NAME = 'mg_session';

const textEncoder = new TextEncoder();

/**
 * SHA-256 hash of a string, returning lowercase hex string
 */
export async function sha256Hex(str) {
  const data = textEncoder.encode(str);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return toHex(new Uint8Array(digest));
}

/**
 * Generate cryptographically secure random bytes
 */
export function randomBytes(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Hash a password using PBKDF2-HMAC-SHA256 with 600,000 iterations
 * @param {string} password 
 * @param {Uint8Array|null} customSalt 
 * @returns {Promise<{ password_hash: string, password_salt: string, password_iterations: number, password_algorithm: string }>}
 */
export async function hashPassword(password, customSalt = null) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new Error('Password must be a non-empty string');
  }

  const salt = customSalt || randomBytes(16);
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    passwordKey,
    256 // 32 bytes
  );

  return {
    password_hash: toHex(new Uint8Array(derivedBits)),
    password_salt: toHex(salt),
    password_iterations: PBKDF2_ITERATIONS,
    password_algorithm: PBKDF2_ALGORITHM
  };
}

/**
 * Constant-time string equality comparison to prevent timing side-channel attacks
 */
export function timingSafeEqualStrings(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = textEncoder.encode(a);
  const bufB = textEncoder.encode(b);
  if (bufA.length !== bufB.length) return false;
  let diff = 0;
  for (let i = 0; i < bufA.length; i++) {
    diff |= bufA[i] ^ bufB[i];
  }
  return diff === 0;
}

/**
 * Verify a candidate password against stored hash, salt, and iterations
 */
export async function verifyPassword(password, storedHashHex, storedSaltHex, iterations = PBKDF2_ITERATIONS) {
  try {
    const salt = fromHex(storedSaltHex);
    const passwordKey = await crypto.subtle.importKey(
      'raw',
      textEncoder.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations: Number(iterations) || PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      passwordKey,
      256
    );

    const candidateHashHex = toHex(new Uint8Array(derivedBits));
    return timingSafeEqualStrings(candidateHashHex.toLowerCase(), storedHashHex.trim().toLowerCase());
  } catch (err) {
    return false;
  }
}

/**
 * Parse cookies from Request
 */
export function parseCookies(request) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const cookies = {};
  cookieHeader.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx > -1) {
      const key = pair.slice(0, idx).trim();
      const val = pair.slice(idx + 1).trim();
      if (key) cookies[key] = decodeURIComponent(val);
    }
  });
  return cookies;
}

/**
 * Create a Set-Cookie header value
 */
export function createSessionCookie(token, maxAge = SESSION_DURATION_SECONDS, isHttps = false) {
  let cookie = `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
  if (isHttps) {
    cookie += '; Secure';
  }
  return cookie;
}

/**
 * Create a Set-Cookie header value to clear session
 */
export function clearSessionCookie(isHttps = false) {
  let cookie = `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
  if (isHttps) {
    cookie += '; Secure';
  }
  return cookie;
}

/**
 * Create a new user session in the database
 */
export async function createSession(db, userId) {
  const sessionId = crypto.randomUUID();
  const sessionToken = toHex(randomBytes(32));
  const csrfToken = toHex(randomBytes(32));
  const tokenHash = await sha256Hex(sessionToken);
  const csrfTokenHash = await sha256Hex(csrfToken);

  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_DURATION_SECONDS * 1000).toISOString();
  const createdAt = now.toISOString();

  await db
    .prepare(
      `INSERT INTO sessions (session_id, user_id, token_hash, csrf_token_hash, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
    .bind(sessionId, userId, tokenHash, csrfTokenHash, expiresAt, createdAt)
    .run();

  return {
    sessionId,
    sessionToken,
    csrfToken,
    expiresAt
  };
}

/**
 * Retrieve session and user from request, verifying expiration and active account status
 */
export async function getSessionAndUser(request, db) {
  const cookies = parseCookies(request);
  const token = cookies[COOKIE_NAME];
  if (!token) return null;

  const tokenHash = await sha256Hex(token);
  const nowIso = new Date().toISOString();

  const record = await db
    .prepare(
      `SELECT s.session_id, s.user_id, s.csrf_token_hash, s.expires_at, s.created_at,
              u.email, u.role, u.account_status
       FROM sessions s
       JOIN users u ON s.user_id = u.user_id
       WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ?`
    )
    .bind(tokenHash, nowIso)
    .first();

  if (!record) return null;
  if (record.account_status !== 'active') return null;

  return {
    session: {
      sessionId: record.session_id,
      userId: record.user_id,
      csrfTokenHash: record.csrf_token_hash,
      expiresAt: record.expires_at
    },
    user: {
      userId: record.user_id,
      email: record.email,
      role: record.role,
      accountStatus: record.account_status
    },
    sessionToken: token
  };
}

/**
 * Verify CSRF token against active session
 */
export async function verifyCsrf(request, session) {
  const csrfHeader = request.headers.get('X-CSRF-Token');
  if (!csrfHeader) return false;
  const hash = await sha256Hex(csrfHeader);
  return hash === session.csrfTokenHash;
}

/**
 * Enforce authentication and optional role-based access control
 */
export async function requireAuth(context, allowedRoles = []) {
  const auth = await getSessionAndUser(context.request, context.env.DB);
  if (!auth) {
    return { authorized: false, response: jsonUnauthorized('Active session required', 'SESSION_REQUIRED') };
  }

  const { session, user } = auth;

  // Check CSRF on state-changing methods
  const method = context.request.method.toUpperCase();
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const csrfOk = await verifyCsrf(context.request, session);
    if (!csrfOk) {
      return { authorized: false, response: jsonForbidden('Invalid or missing CSRF token', 'INVALID_CSRF') };
    }
  }

  // Check role authorization
  if (allowedRoles.length > 0 && !allowedRoles.includes(user.role)) {
    return {
      authorized: false,
      response: jsonForbidden(`Role '${user.role}' is not authorized to access this resource`, 'ROLE_FORBIDDEN')
    };
  }

  return { authorized: true, user, session };
}

