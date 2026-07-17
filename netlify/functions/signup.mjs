import { getStore } from '@netlify/blobs';
import { hashPassword, signSession, makeSessionCookie, json, CATEGORIES } from './lib/session.mjs';

export default async (req) => {
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405);

  let body;
  try {
    body = await req.json();
  } catch {
    return json({ error: 'Invalid request body' }, 400);
  }

  const name = (body.name || '').toString().trim().slice(0, 100);
  const email = (body.email || '').toString().trim().toLowerCase().slice(0, 200);
  const password = (body.password || '').toString();
  const alarmTime = /^\d{2}:\d{2}$/.test(body.alarmTime) ? body.alarmTime : '07:00';
  const category = CATEGORIES.includes(body.category) ? body.category : 'general';
  const botField = (body.botField || '').toString().trim();

  // Honeypot: real users never fill this field in; silently no-op for bots
  if (botField) return json({ ok: true });

  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!name || !emailPattern.test(email)) {
    return json({ error: 'Please provide a valid name and email' }, 400);
  }
  if (!password || password.length < 8) {
    return json({ error: 'Password must be at least 8 characters' }, 400);
  }

  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) {
    return json({ error: 'Server is not configured (missing SESSION_SECRET)' }, 500);
  }

  const store = getStore('users');
  const existing = await store.get(email, { type: 'json' });
  if (existing) {
    return json({ error: 'An account with that email already exists' }, 409);
  }

  const user = {
    name,
    email,
    passwordHash: hashPassword(password),
    createdAt: new Date().toISOString(),
    settings: { alarmTime, category }
  };
  await store.setJSON(email, user);

  const isHttps = new URL(req.url).protocol === 'https:';
  const token = signSession({ email, exp: Date.now() + 1000 * 60 * 60 * 24 * 30 }, sessionSecret);

  return json(
    { ok: true, name: user.name, settings: user.settings },
    200,
    { 'Set-Cookie': makeSessionCookie(token, isHttps) }
  );
};
