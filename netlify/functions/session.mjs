import { getStore } from '@netlify/blobs';
import { parseCookies, verifySession, json } from './lib/session.mjs';

export default async (req) => {
  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) return json({ error: 'Server is not configured' }, 500);

  const cookies = parseCookies(req.headers.get('cookie'));
  const payload = verifySession(cookies.session, sessionSecret);
  if (!payload) return json({ error: 'Not signed in' }, 401);

  const store = getStore('users');
  const user = await store.get(payload.email, { type: 'json' });
  if (!user) return json({ error: 'Not signed in' }, 401);

  return json({ name: user.name, email: user.email, settings: user.settings });
};
