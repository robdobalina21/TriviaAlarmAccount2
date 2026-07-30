import { clearSessionCookie, json } from './lib/session.mjs';

export default async (req) => {
  const isHttps = new URL(req.url).protocol === 'https:';
  return json({ ok: true }, 200, { 'Set-Cookie': clearSessionCookie(isHttps) });
};
