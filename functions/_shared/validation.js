// MedicineGuard Server-side Input Validation Utilities

export function isLeapYear(year) {
  return (year % 4 === 0 && year % 100 !== 0) || (year % 400 === 0);
}

export function isValidDateString(str) {
  if (typeof str !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(str)) {
    return false;
  }
  const parts = str.split('-').map((p) => parseInt(p, 10));
  const year = parts[0];
  const month = parts[1];
  const day = parts[2];

  if (year < 1900 || year > 2100) return false;
  if (month < 1 || month > 12) return false;

  const daysInMonth = [
    31,
    isLeapYear(year) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31
  ];

  return day >= 1 && day <= daysInMonth[month - 1];
}

export function validateDateRange(mfgDate, expDate) {
  if (!isValidDateString(mfgDate)) {
    return { valid: false, error: `Invalid manufacturing date: "${mfgDate}". Expected valid YYYY-MM-DD calendar date.` };
  }
  if (!isValidDateString(expDate)) {
    return { valid: false, error: `Invalid expiry date: "${expDate}". Expected valid YYYY-MM-DD calendar date.` };
  }
  if (expDate <= mfgDate) {
    return { valid: false, error: `Expiry date (${expDate}) must be strictly later than manufacturing date (${mfgDate}).` };
  }
  return { valid: true };
}

export function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  const trimmed = email.trim();
  if (trimmed.length < 5 || trimmed.length > 254) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed);
}

export function isValidHex64(hex) {
  return typeof hex === 'string' && /^[0-9a-f]{64}$/i.test(hex);
}

export function sanitizeString(val, maxLen = 255) {
  if (typeof val !== 'string') return '';
  return val.trim().slice(0, maxLen);
}

