import { getStore } from '@netlify/blobs';
import { parseCookies, verifySession, json, CATEGORIES } from './lib/session.mjs';

export default async (req) => {
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405);

  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) return json({ error: 'Server is not configured' }, 500);

  const cookies = parseCookies(req.headers.get('cookie'));
  const payload = verifySession(cookies.session, sessionSecret);
  if (!payload) return json({ error: 'Not signed in' }, 401);

  let body;
  try {
    body = await req.json();
  } catch {
    return json({ error: 'Invalid request body' }, 400);
  }

  const alarmTime = /^\d{2}:\d{2}$/.test(body.alarmTime) ? body.alarmTime : '07:00';
  const category = CATEGORIES.includes(body.category) ? body.category : 'general';

  const store = getStore('users');
  const user = await store.get(payload.email, { type: 'json' });
  if (!user) return json({ error: 'Not signed in' }, 401);

  user.settings = { alarmTime, category };
  await store.setJSON(payload.email, user);

  return json({ ok: true, settings: user.settings });
};
