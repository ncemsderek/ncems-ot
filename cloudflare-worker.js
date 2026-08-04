// NCEMS OT — Cloudflare Worker storage + auth API (v2, app v5.0)
// KV binding: OT_KV. Secret binding: AUTH_SECRET (Settings > Variables & Secrets).
// Public:  GET /bin/{long|short|longlog|shortlog}   GET /auth/users
// Auth:    POST /auth/login  /auth/adminlogin  /auth/changepin  /auth/seed (one-time)
//          POST /auth/setpin (admin token)      PUT /bin/* (any valid token)
// Legacy mode: until /auth/seed runs, PUTs fall back to the old origin-only gate.

const APP_ORIGIN = 'https://overtime.northcountryems.org';
const KEYS = ['long', 'short', 'longlog', 'shortlog'];
const AUTH_KEY = 'auth'; // never served by /bin
const SESSION_MS = 3600000;

const te = new TextEncoder();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
async function sha256(s) { return hex(await crypto.subtle.digest('SHA-256', te.encode(s))); }
async function hmac(secret, msg) {
  const k = await crypto.subtle.importKey('raw', te.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, te.encode(msg)));
}
function b64e(s) { return btoa(unescape(encodeURIComponent(s))); }
function b64d(s) { return decodeURIComponent(escape(atob(s))); }

async function makeToken(env, name, role) {
  const payload = JSON.stringify({ n: name, r: role, exp: Date.now() + SESSION_MS });
  const p = b64e(payload);
  return p + '.' + await hmac(env.AUTH_SECRET, p);
}
async function verifyToken(env, header) {
  if (!header || !header.startsWith('Bearer ')) return null;
  const t = header.slice(7); const i = t.lastIndexOf('.');
  if (i < 0) return null;
  const p = t.slice(0, i), sig = t.slice(i + 1);
  if (await hmac(env.AUTH_SECRET, p) !== sig) return null;
  try { const pl = JSON.parse(b64d(p)); if (pl.exp < Date.now()) return null; return pl; } catch (e) { return null; }
}
async function getAuth(env) { const v = await env.OT_KV.get(AUTH_KEY); return v ? JSON.parse(v) : null; }
async function putAuth(env, a) { await env.OT_KV.put(AUTH_KEY, JSON.stringify(a)); }
async function checkPin(rec, pin) { return rec && (await sha256(rec.salt + String(pin))) === rec.hash; }
async function pinRec(pin) { const salt = hex(crypto.getRandomValues(new Uint8Array(16)).buffer); return { salt, hash: await sha256(salt + String(pin)) }; }
const J = (o, s, cors) => new Response(JSON.stringify(o), { status: s || 200, headers: { ...cors, 'Content-Type': 'application/json' } });

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const cors = {
      'Access-Control-Allow-Origin': APP_ORIGIN,
      'Access-Control-Allow-Methods': 'GET,PUT,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'Vary': 'Origin'
    };
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    // ---------- /bin ----------
    const m = url.pathname.match(/^\/bin\/([a-z]+)$/);
    if (m) {
      const key = m[1];
      if (!KEYS.includes(key)) return J({ error: 'not found' }, 404, cors);
      if (req.method === 'GET') {
        const v = await env.OT_KV.get(key);
        return new Response(v === null ? 'null' : v, { headers: { ...cors, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
      }
      if (req.method === 'PUT') {
        const auth = await getAuth(env);
        if (auth) {
          const tk = await verifyToken(env, req.headers.get('Authorization'));
          if (!tk) return J({ error: 'auth required' }, 401, cors);
        } else if (req.headers.get('Origin') !== APP_ORIGIN) {
          return J({ error: 'forbidden' }, 403, cors); // legacy mode, pre-seed
        }
        const body = await req.text();
        if (body.length > 200000) return J({ error: 'too large' }, 413, cors);
        let parsed; try { parsed = JSON.parse(body); } catch (e) { return J({ error: 'bad json' }, 400, cors); }
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return J({ error: 'bad shape' }, 400, cors);
        await env.OT_KV.put(key, body);
        return J({ ok: true }, 200, cors);
      }
      return J({ error: 'method' }, 405, cors);
    }

    // ---------- /auth ----------
    const a = url.pathname.match(/^\/auth\/([a-z]+)$/);
    if (!a) return J({ error: 'not found' }, 404, cors);
    const action = a[1];

    if (action === 'users' && req.method === 'GET') {
      const auth = await getAuth(env);
      const users = auth ? Object.entries(auth.users || {}).map(([name, u]) => ({ name, role: u.role, mustChange: !!u.mustChange })) : [];
      return J({ users, initialized: !!auth }, 200, cors);
    }
    if (req.method !== 'POST') return J({ error: 'method' }, 405, cors);
    if (req.headers.get('Origin') !== APP_ORIGIN) return J({ error: 'forbidden' }, 403, cors);
    let body; try { body = await req.json(); } catch (e) { return J({ error: 'bad json' }, 400, cors); }

    if (action === 'seed') {
      if (await getAuth(env)) return J({ error: 'already initialized' }, 409, cors);
      const users = {};
      for (const [name, u] of Object.entries(body.users || {})) {
        if (!/^\d{4}$/.test(String(u.pin))) return J({ error: 'bad pin for ' + name }, 400, cors);
        users[name] = { role: u.role === 'admin' ? 'admin' : (u.role === 'crew' ? 'crew' : 'officer'), mustChange: !!u.mustChange, ...(await pinRec(u.pin)) };
      }
      const admin = body.adminPassword ? await pinRec(body.adminPassword) : null;
      await putAuth(env, { users, admin, created: Date.now() });
      return J({ ok: true, count: Object.keys(users).length }, 200, cors);
    }

    const auth = await getAuth(env);
    if (!auth) return J({ error: 'not initialized' }, 409, cors);

    if (action === 'login') {
      const u = auth.users[body.name];
      if (!u || !(await checkPin(u, body.pin))) return J({ error: 'bad credentials' }, 401, cors);
      u.lastLogin = Date.now(); await putAuth(env, auth);
      return J({ ok: true, token: await makeToken(env, body.name, u.role), role: u.role, mustChange: !!u.mustChange }, 200, cors);
    }
    if (action === 'adminlogin') {
      if (!auth.admin || !(await checkPin(auth.admin, body.password))) return J({ error: 'bad credentials' }, 401, cors);
      return J({ ok: true, token: await makeToken(env, 'Admin', 'admin'), role: 'admin', mustChange: false }, 200, cors);
    }
    if (action === 'changepin') {
      const u = auth.users[body.name];
      if (!u || !(await checkPin(u, body.oldPin))) return J({ error: 'bad credentials' }, 401, cors);
      if (!/^\d{4}$/.test(String(body.newPin))) return J({ error: 'PIN must be 4 digits' }, 400, cors);
      Object.assign(u, await pinRec(body.newPin)); u.mustChange = false;
      await putAuth(env, auth);
      return J({ ok: true }, 200, cors);
    }
    if (action === 'setpin') { // admin: create user / reset pin / set role
      const tk = await verifyToken(env, req.headers.get('Authorization'));
      if (!tk || tk.r !== 'admin') return J({ error: 'admin required' }, 401, cors);
      if (!/^\d{4}$/.test(String(body.pin))) return J({ error: 'PIN must be 4 digits' }, 400, cors);
      const role = ['admin', 'officer', 'crew'].includes(body.role) ? body.role : (auth.users[body.name] ? auth.users[body.name].role : 'crew');
      auth.users[body.name] = { ...(auth.users[body.name] || {}), role, mustChange: body.mustChange !== false, ...(await pinRec(body.pin)) };
      await putAuth(env, auth);
      return J({ ok: true }, 200, cors);
    }
    if (action === 'setadmin') {
      const tk = await verifyToken(env, req.headers.get('Authorization'));
      if (!tk || tk.r !== 'admin') return J({ error: 'admin required' }, 401, cors);
      if (!body.password || String(body.password).length < 4) return J({ error: 'min 4 chars' }, 400, cors);
      auth.admin = await pinRec(body.password); await putAuth(env, auth);
      return J({ ok: true }, 200, cors);
    }
    if (action === 'removeuser') {
      const tk = await verifyToken(env, req.headers.get('Authorization'));
      if (!tk || tk.r !== 'admin') return J({ error: 'admin required' }, 401, cors);
      delete auth.users[body.name]; await putAuth(env, auth);
      return J({ ok: true }, 200, cors);
    }
    return J({ error: 'not found' }, 404, cors);
  }
};
