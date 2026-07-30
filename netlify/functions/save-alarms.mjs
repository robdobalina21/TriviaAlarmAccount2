import { getStore } from '@netlify/blobs';
import { parseCookies, verifySession, json, CATEGORIES } from './lib/session.mjs';

const MAX_ALARMS = 10;

function makeId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

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

  const incoming = Array.isArray(body.alarms) ? body.alarms : [];
  if (incoming.length > MAX_ALARMS) {
    return json({ error: `You can have up to ${MAX_ALARMS} alarms` }, 400);
  }

  const alarms = incoming.map((a) => ({
    id: (a.id && typeof a.id === 'string') ? a.id.slice(0, 40) : makeId(),
    time: /^\d{2}:\d{2}$/.test(a.time) ? a.time : '07:00',
    category: CATEGORIES.includes(a.category) ? a.category : 'general',
    label: (a.label || '').toString().trim().slice(0, 40),
    enabled: a.enabled !== false
  }));

  const store = getStore('users');
  const user = await store.get(payload.email, { type: 'json' });
  if (!user) return json({ error: 'Not signed in' }, 401);

  user.alarms = alarms;
  await store.setJSON(payload.email, user);

  return json({ ok: true, alarms: user.alarms });
};
