import { getStore } from '@netlify/blobs';
import { json } from './lib/session.mjs';

export default async (req) => {
  const url = new URL(req.url);
  const key = req.headers.get('x-admin-key') || url.searchParams.get('key') || '';

  const adminKey = process.env.ADMIN_KEY;
  if (!adminKey) return json({ error: 'ADMIN_KEY is not configured on this site' }, 500);
  if (key !== adminKey) return json({ error: 'Unauthorized' }, 401);

  const store = getStore('users');
  const { blobs } = await store.list();

  const entries = await Promise.all(
    blobs.map(async (b) => {
      const value = await store.get(b.key, { type: 'json' });
      if (!value) return null;
      const { passwordHash, ...safe } = value;
      return safe;
    })
  );

  const users = entries.filter(Boolean).sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));

  return json({ count: users.length, users });
};
