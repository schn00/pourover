// Dialed — Cloudflare Worker (the display name lives in public/index.html and manifest.webmanifest)
// Serves the app from /public and exposes: GET /api/config, POST /api/session,
// POST /api/signout, POST /api/sync.
//
// Identity: Google Sign-In. The browser gets an ID token from Google, posts it
// once to /api/session, and the worker verifies it and hands back a long-lived
// session cookie. Every later request is just the cookie — no Google round trip,
// no Cloudflare Access, and no domain of your own required.
//
// Storage: each user's data is one KV value keyed by their verified email.
// Records merge one at a time (newest updatedAt wins), so two devices adding
// different brews never overwrite each other.

const SCHEMA = 1;
const MAX_CHANGES = 500;
const MAX_RECORD_BYTES = 16 * 1024;
const MAX_BODY_BYTES = 4 * 1024 * 1024;
const TYPES = new Set(["bag", "brew", "settings"]);

const SESSION_COOKIE = "dialed_session";
const SESSION_TTL = 90 * 24 * 3600; // seconds
const SESSION_REFRESH_AFTER = 7 * 24 * 3600 * 1000; // ms; re-stamp a cookie older than this

const GOOGLE_CERTS = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUERS = new Set(["accounts.google.com", "https://accounts.google.com"]);

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
  // Public: lets the client know which Google client id to sign in with.
  if (url.pathname === "/api/config") {
    return json({ clientId: env.GOOGLE_CLIENT_ID || null });
  }

  // Public: trade a Google ID token for a session cookie.
  if (url.pathname === "/api/session" && request.method === "POST") {
    const body = await readJson(request);
    const credential = String(body.credential || "");
    if (!credential) throw httpError(400, "No credential");
    if (!env.GOOGLE_CLIENT_ID) throw httpError(500, "Sign-in isn't configured yet. See SETUP.md.");

    const payload = await verifyGoogleToken(credential, env);
    const email = String(payload.email || "").toLowerCase();
    if (!email) throw httpError(401, "That account has no email address");
    if (payload.email_verified === false) throw httpError(401, "Google hasn't verified that email");

    const token = newToken();
    await env.BREWLOG.put(`sess:${token}`, JSON.stringify({ email, at: Date.now() }), {
      expirationTtl: SESSION_TTL,
    });
    return json({ email }, 200, { "set-cookie": sessionCookie(token, SESSION_TTL) });
  }

  if (url.pathname === "/api/signout" && request.method === "POST") {
    const token = cookie(request, SESSION_COOKIE);
    if (token) await env.BREWLOG.delete(`sess:${token}`);
    return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });
  }

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

// ---------- Identity (session cookie, issued after Google Sign-In) ----------

async function identify(request, env, url) {
  // Local development only: `wrangler dev` with DEV_EMAIL set in .dev.vars
  if (env.DEV_EMAIL && (url.hostname === "localhost" || url.hostname === "127.0.0.1")) {
    return env.DEV_EMAIL.toLowerCase();
  }

  const token = cookie(request, SESSION_COOKIE);
  if (!token) throw httpError(401, "Sign in required");

  const sess = await env.BREWLOG.get(`sess:${token}`, "json");
  if (!sess || !sess.email) throw httpError(401, "Sign in required");

  // Slide the expiry for active users, but only about once a week so this
  // doesn't cost a KV write on every sync.
  if (Date.now() - (sess.at || 0) > SESSION_REFRESH_AFTER) {
    await env.BREWLOG.put(`sess:${token}`, JSON.stringify({ email: sess.email, at: Date.now() }), {
      expirationTtl: SESSION_TTL,
    });
  }

  return String(sess.email).toLowerCase();
}

function newToken() {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function sessionCookie(value, maxAge) {
  return `${SESSION_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}

function cookie(request, name) {
  const raw = request.headers.get("cookie") || "";
  const m = raw.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return m ? m[1] : null;
}

// ---------- Google ID token verification ----------

let certCache = { at: 0, keys: [] };

async function getCerts(force = false) {
  if (!force && certCache.keys.length && Date.now() - certCache.at < 3600_000) return certCache.keys;
  const res = await fetch(GOOGLE_CERTS);
  if (!res.ok) throw httpError(500, "Couldn't load Google signing keys");
  const data = await res.json();
  certCache = { at: Date.now(), keys: data.keys || [] };
  return certCache.keys;
}

async function verifyGoogleToken(token, env) {
  const parts = token.split(".");
  if (parts.length !== 3) throw httpError(401, "Invalid token");
  const [h, p, s] = parts;

  let header, payload;
  try {
    header = JSON.parse(b64urlText(h));
    payload = JSON.parse(b64urlText(p));
  } catch {
    throw httpError(401, "Invalid token");
  }
  if (header.alg !== "RS256") throw httpError(401, "Unexpected token algorithm");

  let keys = await getCerts();
  let jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) {
    keys = await getCerts(true); // Google rotates keys; refetch once before giving up
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
  if (payload.exp && payload.exp < now - 60) throw httpError(401, "Token expired");
  if (!GOOGLE_ISSUERS.has(payload.iss)) throw httpError(401, "Token from an unexpected issuer");
  if (payload.aud !== env.GOOGLE_CLIENT_ID) throw httpError(401, "Token is for a different app");

  return payload;
}

// ---------- Helpers ----------

async function readJson(request) {
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) throw httpError(413, "Upload too large");
  try {
    return JSON.parse(text || "{}");
  } catch {
    throw httpError(400, "Invalid JSON");
  }
}

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

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...extraHeaders },
  });
}

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

