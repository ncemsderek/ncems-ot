// NCEMS OT — Cloudflare Worker storage + auth API (v3.0, app v6.0)
// Bindings: KV = OT_KV, D1 = OT_DB, Secret = AUTH_SECRET (Settings > Variables & Secrets).
// Public:  GET /bin/{long|short|longlog|shortlog}   GET /auth/users   GET /log/count
// Auth:    POST /auth/login /adminlogin /changepin /seed (one-time)
//          POST /auth/setpin /setadmin /renameuser /removeuser (admin token)
//          POST /log/append (any token)  /log/clear (admin)  /log/migrate (admin, one-time)
//          PUT /bin/* (any valid token)
//
// v3.0: the LOG moved from KV to D1. KV allowed 1,000 writes/day and forced a rolling
// 300-entry cap that silently ate history. D1 gives 100k row writes/day and 5 GB, so the
// overtime log is now a complete record — it is the evidence trail for CBA Art. 15.
// /bin/longlog and /bin/shortlog keep their old shape ({log:[...]}) and are backed by D1.
// Writes are append-only. Nothing in this Worker ever deletes a log row except /log/clear.

const APP_ORIGIN = 'https://overtime.northcountryems.org';
const KEYS = ['long', 'short', 'longlog', 'shortlog'];
const LOG_KEYS = { longlog: 'long', shortlog: 'short' };   // /bin key -> list value in D1
const AUTH_KEY = 'auth'; // never served by /bin
const SESSION_MS = 3600000;
const LOG_COLS = ['list', 'name', 'action', 'shift', 'shiftDate', 'supervisor', 'reason', 'notes', 'ts'];

// --- D1 log helpers -------------------------------------------------------
let schemaReady = false;
async function ensureLogSchema(env) {
  if (schemaReady) return;
  await env.OT_DB.batch([
    env.OT_DB.prepare(`CREATE TABLE IF NOT EXISTS ot_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      list TEXT NOT NULL, name TEXT, action TEXT, shift TEXT, shiftDate TEXT,
      supervisor TEXT, reason TEXT, notes TEXT, ts INTEGER NOT NULL)`),
    env.OT_DB.prepare(`CREATE INDEX IF NOT EXISTS idx_ot_log_ts ON ot_log(ts)`),
    env.OT_DB.prepare(`CREATE INDEX IF NOT EXISTS idx_ot_log_list_ts ON ot_log(list, ts)`),
    // makes every write idempotent, so a retry or a stale client cannot duplicate history
    env.OT_DB.prepare(`CREATE UNIQUE INDEX IF NOT EXISTS idx_ot_log_uniq ON ot_log(list, ts, name, action)`)
  ]);
  schemaReady = true;
}
// v6.0 vocabulary fixes, applied to everything on the way in so no stale client can
// reintroduce the old words: 'skip' collided with CBA 15.7 "skipped overtime opportunity",
// and a timed-out offer was being recorded as a refusal.
function normalizeEntry(e) {
  let action = String(e.action || '');
  const reason = e.reason == null ? '' : String(e.reason);
  if (action === 'skip') action = 'unavailable';
  if (action === 'pass' && /^no response$/i.test(reason.trim())) action = 'noresponse';
  return {
    name: e.name == null ? '' : String(e.name),
    action,
    shift: e.shift == null ? '' : String(e.shift),
    shiftDate: e.shiftDate == null ? '' : String(e.shiftDate),
    supervisor: e.supervisor == null ? '' : String(e.supervisor),
    reason,
    notes: e.notes == null ? '' : String(e.notes),
    ts: Number(e.ts) || Date.now()
  };
}
async function readLog(env, list) {
  await ensureLogSchema(env);
  const r = await env.OT_DB.prepare(
    `SELECT name, action, shift, shiftDate, supervisor, reason, notes, ts
       FROM ot_log WHERE list = ? ORDER BY ts ASC, id ASC`).bind(list).all();
  return r.results || [];
}
async function appendLog(env, list, entries) {
  await ensureLogSchema(env);
  const rows = (entries || []).filter(e => e && typeof e === 'object').map(normalizeEntry);
  if (!rows.length) return 0;
  const sql = `INSERT OR IGNORE INTO ot_log (list, name, action, shift, shiftDate, supervisor, reason, notes, ts)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
  let written = 0;
  for (let i = 0; i < rows.length; i += 100) {
    const chunk = rows.slice(i, i + 100);
    const res = await env.OT_DB.batch(chunk.map(e => env.OT_DB.prepare(sql)
      .bind(list, e.name, e.action, e.shift, e.shiftDate, e.supervisor, e.reason, e.notes, e.ts)));
    res.forEach(x => { written += (x.meta && x.meta.changes) || 0; });
  }
  return written;
}

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

    // ---------- /log (D1) ----------
    const lg = url.pathname.match(/^\/log\/([a-z]+)$/);
    if (lg) {
      const op = lg[1];
      if (op === 'count' && req.method === 'GET') {
        await ensureLogSchema(env);
        const r = await env.OT_DB.prepare(
          `SELECT list, COUNT(*) AS n, MIN(ts) AS oldest, MAX(ts) AS newest FROM ot_log GROUP BY list`).all();
        return J({ ok: true, lists: r.results || [] }, 200, cors);
      }
      if (req.method !== 'POST') return J({ error: 'method' }, 405, cors);
      if (req.headers.get('Origin') !== APP_ORIGIN) return J({ error: 'forbidden' }, 403, cors);
      const tk = await verifyToken(env, req.headers.get('Authorization'));
      if (!tk) return J({ error: 'auth required' }, 401, cors);
      let b; try { b = await req.json(); } catch (e) { return J({ error: 'bad json' }, 400, cors); }

      if (op === 'append') {
        const list = b.list === 'short' ? 'short' : 'long';
        if (!Array.isArray(b.entries)) return J({ error: 'entries must be an array' }, 400, cors);
        if (b.entries.length > 500) return J({ error: 'too many entries' }, 413, cors);
        const n = await appendLog(env, list, b.entries);
        return J({ ok: true, inserted: n }, 200, cors);
      }
      if (op === 'clear') { // admin only — the ONLY path that deletes log rows
        if (tk.r !== 'admin') return J({ error: 'admin required' }, 401, cors);
        const list = b.list === 'short' ? 'short' : 'long';
        await ensureLogSchema(env);
        const r = await env.OT_DB.prepare(`DELETE FROM ot_log WHERE list = ?`).bind(list).run();
        return J({ ok: true, deleted: (r.meta && r.meta.changes) || 0 }, 200, cors);
      }
      if (op === 'migrate') { // one-time KV -> D1 import, admin only
        if (tk.r !== 'admin') return J({ error: 'admin required' }, 401, cors);
        await ensureLogSchema(env);
        const out = {};
        for (const [kvKey, list] of Object.entries(LOG_KEYS)) {
          const have = await env.OT_DB.prepare(`SELECT COUNT(*) AS n FROM ot_log WHERE list = ?`).bind(list).first();
          if (have && have.n > 0 && !b.force) { out[list] = { skipped: 'already has ' + have.n + ' rows' }; continue; }
          const raw = await env.OT_KV.get(kvKey);
          let entries = [];
          try { const p = JSON.parse(raw || 'null'); entries = (p && Array.isArray(p.log)) ? p.log : []; } catch (e) { entries = []; }
          const before = entries.length;
          const renamed = entries.filter(e => e && (e.action === 'skip' || (e.action === 'pass' && /^no response$/i.test(String(e.reason || '').trim())))).length;
          const n = await appendLog(env, list, entries);
          out[list] = { read: before, inserted: n, rewritten: renamed };
        }
        return J({ ok: true, ...out }, 200, cors);
      }
      return J({ error: 'not found' }, 404, cors);
    }

    // ---------- /bin ----------
    const m = url.pathname.match(/^\/bin\/([a-z]+)$/);
    if (m) {
      const key = m[1];
      if (!KEYS.includes(key)) return J({ error: 'not found' }, 404, cors);
      const logList = LOG_KEYS[key] || null;   // longlog/shortlog are D1-backed

      if (req.method === 'GET') {
        if (logList) {
          const log = await readLog(env, logList);
          return new Response(JSON.stringify({ log }), { headers: { ...cors, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
        }
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
        if (body.length > 400000) return J({ error: 'too large' }, 413, cors);
        let parsed; try { parsed = JSON.parse(body); } catch (e) { return J({ error: 'bad json' }, 400, cors); }
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return J({ error: 'bad shape' }, 400, cors);
        if (logList) {
          // Compatibility path for clients older than v6.0, which PUT the whole array.
          // MERGE, never replace: the unique index drops what is already there and a short
          // stale array can therefore never truncate the record.
          const n = await appendLog(env, logList, Array.isArray(parsed.log) ? parsed.log : []);
          return J({ ok: true, merged: n }, 200, cors);
        }
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
    if (action === 'renameuser') {
      const tk = await verifyToken(env, req.headers.get('Authorization'));
      if (!tk || (tk.r !== 'admin' && tk.r !== 'officer')) return J({ error: 'officer required' }, 401, cors);
      const from = String(body.from || ''), to = String(body.to || '').trim();
      if (!from || !to) return J({ error: 'from and to required' }, 400, cors);
      if (!auth.users[from]) return J({ error: 'no such user' }, 404, cors);
      if (auth.users[to]) return J({ error: 'target name already has a login' }, 409, cors);
      auth.users[to] = auth.users[from]; delete auth.users[from];
      await putAuth(env, auth);
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
