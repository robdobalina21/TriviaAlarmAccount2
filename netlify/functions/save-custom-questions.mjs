import { getStore } from '@netlify/blobs';
import { parseCookies, verifySession, json } from './lib/session.mjs';

const MAX_QUESTIONS = 50;

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

  const incoming = Array.isArray(body.questions) ? body.questions : [];
  if (incoming.length > MAX_QUESTIONS) {
    return json({ error: `You can have up to ${MAX_QUESTIONS} custom questions` }, 400);
  }

  const questions = [];
  for (const q of incoming) {
    const text = (q.text || '').toString().trim().slice(0, 200);
    const rawOptions = Array.isArray(q.options) ? q.options.slice(0, 3) : [];
    const options = rawOptions.map((o) => (o || '').toString().trim().slice(0, 100));
    while (options.length < 3) options.push('');
    const correctNum = Number(q.correct);
    const correct = [0, 1, 2].includes(correctNum) ? correctNum : 0;

    // Skip incomplete entries rather than erroring the whole save
    if (!text || options.some((o) => !o)) continue;

    questions.push({
      id: (q.id && typeof q.id === 'string') ? q.id.slice(0, 40) : makeId(),
      text,
      options,
      correct
    });
  }

  const store = getStore('users');
  const user = await store.get(payload.email, { type: 'json' });
  if (!user) return json({ error: 'Not signed in' }, 401);

  user.customQuestions = questions;
  await store.setJSON(payload.email, user);

  return json({ ok: true, questions: user.customQuestions });
};
