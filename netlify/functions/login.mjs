import { getStore } from '@netlify/blobs';
import { verifyPassword, signSession, makeSessionCookie, json } from './lib/session.mjs';

export default async (req) => {
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405);

  let body;
  try {
    body = await req.json();
  } catch {
    return json({ error: 'Invalid request body' }, 400);
  }

  const email = (body.email || '').toString().trim().toLowerCase();
  const password = (body.password || '').toString();

  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) {
    return json({ error: 'Server is not configured (missing SESSION_SECRET)' }, 500);
  }

  const store = getStore('users');
  const user = await store.get(email, { type: 'json' });

  if (!user || !verifyPassword(password, user.passwordHash)) {
    return json({ error: 'Incorrect email or password' }, 401);
  }

  const isHttps = new URL(req.url).protocol === 'https:';
  const token = signSession({ email, exp: Date.now() + 1000 * 60 * 60 * 24 * 30 }, sessionSecret);

  return json(
    { ok: true, name: user.name, settings: user.settings },
    200,
    { 'Set-Cookie': makeSessionCookie(token, isHttps) }
  );
};
