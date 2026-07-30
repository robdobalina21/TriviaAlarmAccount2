import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const SESSION_MAX_AGE = 60 * 60 * 24 * 30; // 30 days, in seconds

export function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

export function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const hashBuffer = Buffer.from(hash, 'hex');
  const candidate = scryptSync(password, salt, 64);
  if (candidate.length !== hashBuffer.length) return false;
  return timingSafeEqual(candidate, hashBuffer);
}

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function base64urlDecode(input) {
  return Buffer.from(input, 'base64url').toString('utf8');
}

export function signSession(payload, secret) {
  const body = base64url(JSON.stringify(payload));
  const sig = createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${sig}`;
}

export function verifySession(token, secret) {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expectedSig = createHmac('sha256', secret).update(body).digest('base64url');
  const sigBuffer = Buffer.from(sig);
  const expectedBuffer = Buffer.from(expectedSig);
  if (sigBuffer.length !== expectedBuffer.length || !timingSafeEqual(sigBuffer, expectedBuffer)) {
    return null;
  }
  const payload = JSON.parse(base64urlDecode(body));
  if (payload.exp && Date.now() > payload.exp) return null;
  return payload;
}

export function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  });
  return out;
}

export function makeSessionCookie(token, isHttps) {
  const parts = ['session=' + token, 'HttpOnly', 'Path=/', 'SameSite=Lax', 'Max-Age=' + SESSION_MAX_AGE];
  if (isHttps) parts.push('Secure');
  return parts.join('; ');
}

export function clearSessionCookie(isHttps) {
  const parts = ['session=', 'HttpOnly', 'Path=/', 'SameSite=Lax', 'Max-Age=0'];
  if (isHttps) parts.push('Secure');
  return parts.join('; ');
}

export function json(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders }
  });
}

export const SESSION_LIFETIME_MS = SESSION_MAX_AGE * 1000;
export const CATEGORIES = ['general', 'geography', 'science', 'history', 'pop-culture', 'surprise'];
