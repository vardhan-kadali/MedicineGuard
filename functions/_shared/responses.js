// MedicineGuard API Response Helpers

const SECURITY_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin'
};

export function jsonResponse(payload, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      ...SECURITY_HEADERS,
      ...extraHeaders
    }
  });
}

export function jsonOk(data = {}, status = 200, extraHeaders = {}) {
  return jsonResponse({
    success: true,
    ...data
  }, status, extraHeaders);
}

export function jsonError(message, code = 'BAD_REQUEST', status = 400, details = null) {
  const body = {
    success: false,
    error: {
      code,
      message
    }
  };
  if (details !== null && details !== undefined) {
    body.error.details = details;
  }
  return jsonResponse(body, status);
}

export function jsonUnauthorized(message = 'Authentication required', code = 'UNAUTHORIZED') {
  return jsonError(message, code, 401);
}

export function jsonForbidden(message = 'Access denied', code = 'FORBIDDEN') {
  return jsonError(message, code, 403);
}

export function jsonNotFound(message = 'Resource not found', code = 'NOT_FOUND') {
  return jsonError(message, code, 404);
}

export function jsonConflict(message = 'Conflict', code = 'CONFLICT', details = null) {
  return jsonError(message, code, 409, details);
}

export function jsonAmbiguous(message, matches = []) {
  return jsonResponse({
    success: false,
    error: {
      code: 'AMBIGUOUS_UNIT_ID',
      message
    },
    matches
  }, 409);
}

