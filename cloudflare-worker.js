// NCEMS OT — Cloudflare Worker storage API (v1)
// Deployed at Cloudflare Workers; KV namespace bound as OT_KV.
// Bins: /bin/long  /bin/short  /bin/longlog  /bin/shortlog
// This file is a reference copy; the live code lives in the Cloudflare dashboard.

const APP_ORIGIN = 'https://overtime.northcountryems.org';
const KEYS = ['long', 'short', 'longlog', 'shortlog'];

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const cors = {
      'Access-Control-Allow-Origin': APP_ORIGIN,
      'Access-Control-Allow-Methods': 'GET,PUT,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Vary': 'Origin'
    };
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    const m = url.pathname.match(/^\/bin\/([a-z]+)$/);
    if (!m || !KEYS.includes(m[1])) return new Response('Not found', { status: 404, headers: cors });
    const key = m[1];

    if (req.method === 'GET') {
      const v = await env.OT_KV.get(key);
      return new Response(v === null ? 'null' : v, {
        headers: { ...cors, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
      });
    }

    if (req.method === 'PUT') {
      // Interim write gate until crew-login auth lands: browser writes must come from the app.
      const origin = req.headers.get('Origin');
      if (origin !== APP_ORIGIN) return new Response('Forbidden', { status: 403, headers: cors });
      const body = await req.text();
      if (body.length > 200000) return new Response('Too large', { status: 413, headers: cors });
      let parsed;
      try { parsed = JSON.parse(body); } catch (e) { return new Response('Bad JSON', { status: 400, headers: cors }); }
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return new Response('Bad shape', { status: 400, headers: cors });
      await env.OT_KV.put(key, body);
      return new Response('{"ok":true}', { headers: { ...cors, 'Content-Type': 'application/json' } });
    }

    return new Response('Method not allowed', { status: 405, headers: cors });
  }
};
