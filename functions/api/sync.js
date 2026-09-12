/**
 * Cloudflare Pages Function: POST /api/sync
 *
 * Contract expected by the client in index.html:
 *   request  { changes: [record, ...] }
 *   response { email, records: [record, ...], rejected: [id, ...] }
 *
 * Identity comes from Cloudflare Access only. The request body is never trusted
 * for identity, and every query is filtered on the verified email.
 *
 * Bindings / vars required:
 *   DB                  D1 database binding
 *   ACCESS_TEAM_DOMAIN  e.g. yourteam.cloudflareaccess.com
 *   ACCESS_AUD          Application Audience tag from the Access app
 */

const MAX_CHANGES = 500;
const MAX_RECORD_BYTES = 16 * 1024;
const TYPES = new Set(["brew", "bag", "settings"]);

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

// Plain text (not JSON) on purpose: the client reads a non-JSON reply as
// "there is no sync server here" and stays in local-only mode.
const notConfigured = (msg) =>
  new Response(`sync not configured: ${msg}\n`, { status: 503, headers: { "content-type": "text/plain" } });

// ---------------------------------------------------------------- JWT verify

let certsCache = { keys: null, at: 0 };

async function jwks(teamDomain) {
  if (certsCache.keys && Date.now() - certsCache.at < 3600e3) return certsCache.keys;
  const res = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`, { cf: { cacheTtl: 3600 } });
  if (!res.ok) throw new Error("could not fetch Access signing keys");
  const { keys } = await res.json();
  certsCache = { keys, at: Date.now() };
  return keys;
}

const b64urlToBytes = (s) => {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "="));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
};
const b64urlToText = (s) => new TextDecoder().decode(b64urlToBytes(s));

/** Verifies the Access JWT and returns the identity, or null. */
async function identity(request, env) {
  const token =
    request.headers.get("cf-access-jwt-assertion") ||
    (request.headers.get("cookie") || "").match(/(?:^|;\s*)CF_Authorization=([^;]+)/)?.[1];
  if (!token) return null;

  const [h, p, sig] = token.split(".");
  if (!h || !p || !sig) return null;

  let header, payload;
  try { header = JSON.parse(b64urlToText(h)); payload = JSON.parse(b64urlToText(p)); } catch { return null; }
  if (header.alg !== "RS256") return null;

  const key = (await jwks(env.ACCESS_TEAM_DOMAIN)).find((k) => k.kid === header.kid);
  if (!key) return null;

  const pub = await crypto.subtle.importKey(
    "jwk", { kty: key.kty, n: key.n, e: key.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"],
  );
  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", pub, b64urlToBytes(sig), new TextEncoder().encode(`${h}.${p}`),
  );
  if (!ok) return null;

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now - 60) return null;
  if (payload.nbf && payload.nbf > now + 60) return null;
  if (payload.iss !== `https://${env.ACCESS_TEAM_DOMAIN}`) return null;

  const aud = [].concat(payload.aud || []);
  if (!aud.includes(env.ACCESS_AUD)) return null;

  const email = String(payload.email || "").trim().toLowerCase();
  return email ? { email } : null;
}

// ------------------------------------------------------------------ handlers

function validate(r) {
  if (!r || typeof r !== "object") return "not an object";
  if (typeof r.id !== "string" || !r.id || r.id.length > 64) return "bad id";
  if (!TYPES.has(r.type)) return "bad type";
  if (!Number.isFinite(r.updatedAt)) return "bad updatedAt";
  // Ignore any identity the client tries to assert.
  delete r.email;
  if (JSON.stringify(r).length > MAX_RECORD_BYTES) return "too large";
  return null;
}

export async function onRequestPost({ request, env }) {
  if (!env.DB) return notConfigured("no D1 binding named DB");
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return notConfigured("ACCESS_TEAM_DOMAIN / ACCESS_AUD not set");

  let who;
  try { who = await identity(request, env); } catch (e) { return json({ error: String(e.message || e) }, 500); }
  if (!who) return json({ error: "not signed in" }, 401);

  let body = {};
  try { body = await request.json(); } catch {}
  const changes = Array.isArray(body.changes) ? body.changes.slice(0, MAX_CHANGES) : [];

  const rejected = [];
  const writes = [];
  for (const r of changes) {
    const bad = validate(r);
    if (bad) { if (r && typeof r.id === "string") rejected.push(r.id); continue; }
    writes.push(
      env.DB.prepare(
        `INSERT INTO records (email, id, type, updated_at, data)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (email, id) DO UPDATE SET
           type = excluded.type, updated_at = excluded.updated_at, data = excluded.data
         WHERE excluded.updated_at > records.updated_at`,
      ).bind(who.email, r.id, r.type, Math.round(r.updatedAt), JSON.stringify(r)),
    );
  }

  try {
    if (writes.length) await env.DB.batch(writes);
    const { results } = await env.DB.prepare(`SELECT data FROM records WHERE email = ?1`).bind(who.email).all();
    const records = (results || []).map((row) => { try { return JSON.parse(row.data); } catch { return null; } }).filter(Boolean);
    return json({ email: who.email, records, rejected });
  } catch (e) {
    return json({ error: String(e.message || e) }, 500);
  }
}

// Handy for checking the setup from a browser address bar.
export async function onRequestGet({ request, env }) {
  if (!env.DB) return notConfigured("no D1 binding named DB");
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return notConfigured("ACCESS_TEAM_DOMAIN / ACCESS_AUD not set");
  const who = await identity(request, env).catch(() => null);
  if (!who) return json({ error: "not signed in" }, 401);
  const row = await env.DB.prepare(`SELECT COUNT(*) AS n FROM records WHERE email = ?1`).bind(who.email).first();
  return json({ email: who.email, records: row?.n ?? 0, ok: true });
}
