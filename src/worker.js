// Dialed — Cloudflare Worker (the display name lives in public/index.html and manifest.webmanifest)
// Serves the app from /public and exposes one API route: POST /api/sync.
// Each user's data is one KV value keyed by their verified Access email.
// Records merge one at a time (newest updatedAt wins), so two devices
// adding different brews never overwrite each other.

const SCHEMA = 1;
const MAX_CHANGES = 500;
const MAX_RECORD_BYTES = 16 * 1024;
const MAX_BODY_BYTES = 4 * 1024 * 1024;
const TYPES = new Set(["bag", "brew", "settings"]);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try {
        return await handleApi(request, env, url);
      } catch (err) {
        return json({ error: err.message || "Server error" }, err.status || 500);
      }
    }
    return env.ASSETS.fetch(request);
  },
};

async function handleApi(request, env, url) {
  const email = await identify(request, env, url);

  if (url.pathname === "/api/sync" && request.method === "POST") {
    const text = await request.text();
    if (text.length > MAX_BODY_BYTES) throw httpError(413, "Upload too large");
    let body;
    try {
      body = JSON.parse(text || "{}");
    } catch {
      throw httpError(400, "Invalid JSON");
    }
    const changes = Array.isArray(body.changes) ? body.changes.slice(0, MAX_CHANGES) : [];

    const key = `user:${email}`;
    const blob = (await env.BREWLOG.get(key, "json")) || { schema: SCHEMA, records: {} };
    const rejected = [];
    let changed = false;

    for (const rec of changes) {
      if (!valid(rec)) {
        if (rec && typeof rec.id === "string") rejected.push(rec.id);
        continue;
      }
      const cur = blob.records[rec.id];
      if (!cur || rec.updatedAt > cur.updatedAt) {
        blob.records[rec.id] = rec;
        changed = true;
      }
    }

    if (changed) {
      blob.schema = SCHEMA;
      blob.savedAt = Date.now();
      await env.BREWLOG.put(key, JSON.stringify(blob));
    }

    return json({ email, schema: SCHEMA, records: Object.values(blob.records), rejected });
  }

  throw httpError(404, "Not found");
}

function valid(rec) {
  if (!rec || typeof rec !== "object") return false;
  if (typeof rec.id !== "string" || !rec.id || rec.id.length > 64) return false;
  if (!TYPES.has(rec.type)) return false;
  if (typeof rec.updatedAt !== "number" || !isFinite(rec.updatedAt)) return false;
  if (JSON.stringify(rec).length > MAX_RECORD_BYTES) return false;
  return true;
}

// ---------- Identity (Cloudflare Access) ----------

async function identify(request, env, url) {
  // Local development only: `wrangler dev` with DEV_EMAIL set in .dev.vars
  if (env.DEV_EMAIL && (url.hostname === "localhost" || url.hostname === "127.0.0.1")) {
    return env.DEV_EMAIL.toLowerCase();
  }
  if (!env.TEAM_DOMAIN || !env.POLICY_AUD || env.POLICY_AUD.startsWith("PASTE")) {
    throw httpError(500, "Access isn't configured yet. See SETUP.md, step 5.");
  }
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) throw httpError(401, "Sign in required");
  const payload = await verifyAccessJwt(token, env);
  if (!payload.email) throw httpError(401, "Sign in required");
  return String(payload.email).toLowerCase();
}

let certCache = { at: 0, keys: [] };

async function getCerts(env, force = false) {
  const teamDomain = env.TEAM_DOMAIN.replace(/\/+$/, "");
  if (!force && certCache.keys.length && Date.now() - certCache.at < 3600_000) return certCache.keys;
  const res = await fetch(`${teamDomain}/cdn-cgi/access/certs`);
  if (!res.ok) throw httpError(500, "Couldn't load Access signing keys");
  const data = await res.json();
  certCache = { at: Date.now(), keys: data.keys || [] };
  return certCache.keys;
}

async function verifyAccessJwt(token, env) {
  const parts = token.split(".");
  if (parts.length !== 3) throw httpError(401, "Invalid token");
  const [h, p, s] = parts;
  const header = JSON.parse(b64urlText(h));
  const payload = JSON.parse(b64urlText(p));

  let keys = await getCerts(env);
  let jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) {
    keys = await getCerts(env, true);
    jwk = keys.find((k) => k.kid === header.kid);
  }
  if (!jwk) throw httpError(401, "Unknown signing key");

  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    b64urlBytes(s),
    new TextEncoder().encode(`${h}.${p}`)
  );
  if (!ok) throw httpError(401, "Invalid token signature");

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) throw httpError(401, "Session expired");
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(env.POLICY_AUD)) throw httpError(401, "Token is for a different app");
  const iss = env.TEAM_DOMAIN.replace(/\/+$/, "");
  if (payload.iss && payload.iss !== iss) throw httpError(401, "Token from a different team");
  return payload;
}

// ---------- Helpers ----------

function b64urlBytes(str) {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((str.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlText(str) {
  return new TextDecoder().decode(b64urlBytes(str));
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}
