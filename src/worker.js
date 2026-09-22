// Dialed — Cloudflare Worker (the display name lives in public/index.html and manifest.webmanifest)
// Serves the app from /public and exposes: GET /api/config, POST /api/session,
// POST /api/signout, POST /api/sync, POST /api/bag/scan, POST /api/bag/link.
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
const TYPES = new Set(["bag", "brew", "settings" , "recipe"]);

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
        return json({ error: err.message || "Server error", ...(err.code ? { code: err.code } : {}) }, err.status || 500);
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

  if (url.pathname === "/api/bag/scan" && request.method === "POST") {
    return json(await scanBag(await readJson(request), env));
  }

  if (url.pathname === "/api/bag/link" && request.method === "POST") {
    return json(await fillFromLink(await readJson(request), env));
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

// ---------- Bag reader: fill a bag from a photo or a product page ----------
//
// POST /api/bag/scan  { images: [dataURL, ...] }            -> { fields, url, domain }
// POST /api/bag/link  { url } | { domain, beans } | { roaster, beans } -> { link, fields, note? }
//
// Runs on Workers AI (the "AI" binding in wrangler.jsonc), inside the free
// 10,000 Neurons a day. One model per scan; the second is only tried when the
// first errors or comes back nearly empty.

const SCAN_MODELS = ["@cf/meta/llama-4-scout-17b-16e-instruct", "@cf/google/gemma-3-12b-it"];
const PAGE_MODELS = ["@cf/google/gemma-3-12b-it", "@cf/meta/llama-3.1-8b-instruct-fp8-fast"]; // reading product pages
const SITE_MODELS = ["@cf/meta/llama-3.1-8b-instruct-fp8-fast", "@cf/google/gemma-3-12b-it"]; // naming a roaster's website
const MAX_SCAN_IMAGES = 2;
const MAX_IMAGE_CHARS = 3 * 1024 * 1024;
const MAX_PAGE_TEXT = 10000;
const ROAST_TYPES = ["Light", "Medium-light", "Medium", "Medium-dark", "Dark"];
const CAP_MESSAGE = "Scanning is used up for today. It resets at 00:00 UTC (8 p.m. in New York). Fill this one in by hand for now.";
const PAGE_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";

async function scanBag(body, env) {
  if (!env.AI) throw httpError(500, "Scanning isn't set up yet: add the AI binding to wrangler.jsonc.");
  const images = (Array.isArray(body.images) ? body.images : [])
    .filter((u) => typeof u === "string" && /^data:image\/(jpeg|png|webp);base64,/.test(u) && u.length <= MAX_IMAGE_CHARS)
    .slice(0, MAX_SCAN_IMAGES);
  if (!images.length) throw httpError(400, "No photo came through. Try again.");

  const today = new Date().toISOString().slice(0, 10);
  const prompt = `These are photos of a bag of specialty coffee beans (front and/or back). Report only what is printed on the bag.
Today is ${today}.
Return only a JSON object with these keys:
"beans": the coffee's name as printed (for example "Ethiopia Guji Hambela"), not the roaster's name
"roaster": the roasting company
"roastType": one of ${ROAST_TYPES.join(", ")}, or "" if not shown
"roastDate": the roast date as YYYY-MM-DD, or "". Ignore best-by, packed-on and expiry dates. If no year is printed, use the most recent date that is not in the future.
"roastDateText": the roast date exactly as printed, or ""
"notes": the tasting notes, comma-separated
"origin": the country
"region": the region
"process": the processing method
"variety": the coffee variety or varieties
"producer": the farm, producer, cooperative or washing station
"elevation": the elevation in meters above sea level as a number, or ""
"decaf": true or false
"brewNotes": a brew recipe printed on the bag, in one short line with its numbers, or "". If there are several, use the pour-over one.
"url": a full web address printed on the bag, or ""
"website": the roaster's website domain printed on the bag (for example "example.com"), or ""
Use "" for anything that isn't visible. Do not guess.`;

  const content = [{ type: "text", text: prompt }, ...images.map((u) => ({ type: "image_url", image_url: { url: u } }))];
  let best = null;
  for (const model of SCAN_MODELS) {
    try {
      const raw = await env.AI.run(model, { messages: [{ role: "user", content }], max_tokens: 700, temperature: 0.1 });
      const obj = parseModelJson(raw);
      const fields = cleanFields(obj);
      const link = cleanLink(obj.url, obj.website);
      const result = { fields, url: link.url, domain: link.domain, model };
      if (countFields(fields) >= 2) return result;
      if (!best || countFields(fields) > countFields(best.fields)) best = result;
    } catch (err) {
      if (isCapError(err)) throw capError();
      console.log(`bag scan: ${model} failed: ${err && err.message}`);
    }
  }
  if (best && (countFields(best.fields) || best.url || best.domain)) return best;
  throw httpError(502, "Couldn't read the bag. Try a closer, sharper photo in good light.");
}

async function fillFromLink(body, env) {
  if (!env.AI) throw httpError(500, "Scanning isn't set up yet: add the AI binding to wrangler.jsonc.");
  const beans = String(body.beans || "").slice(0, 160);
  let target = null;
  let domain = "";

  if (body.url) {
    const u = safeUrl(body.url);
    if (!u) throw httpError(400, "That doesn't look like a web address.");
    // A QR code or printed link that only goes to the home page: search the site instead.
    if (u.pathname.replace(/\/+$/, "") === "") domain = u.hostname;
    else target = u.href;
  } else if (body.domain) {
    domain = cleanDomain(body.domain);
    if (!domain) throw httpError(400, "No web address to look up.");
  } else if (body.roaster) {
    // Nothing on the bag points to a website: work it out from the roaster's name.
    const roaster = str(body.roaster, 80);
    domain = roaster ? await findRoasterSite(roaster, env) : "";
    if (!domain) return { link: null, fields: {}, note: `Couldn't find ${roaster || "the roaster"}'s website. Paste the product link to fill the rest.` };
  } else {
    throw httpError(400, "No web address to look up.");
  }

  if (!target) {
    if (!beans) return { link: null, fields: {}, note: `Found ${domain} but not the coffee's name, so paste the product link to fill the rest.` };
    target = await findShopifyProduct(domain, beans);
    if (!target) return { link: null, fields: {}, note: `Couldn't find this coffee on ${domain}. Paste the product link to fill the rest.` };
  }

  const page = await readProductPage(target);
  const fields = await extractFromPage(page, env);
  if (!fields.beans && page.title) fields.beans = page.title.slice(0, 160);
  if (!fields.roaster && page.brand) fields.roaster = page.brand.slice(0, 160);
  return { link: page.url, fields };
}

// ----- finding a roaster's website from its name -----
//
// The text model answers from what it learned in training (it can't browse), so
// every answer is checked: the site has to open and its title or site name has
// to carry the roaster's name. A wrong or made-up domain fails that and is skipped.

const ROASTER_GENERIC = new Set(["coffee", "coffees", "roasters", "roaster", "roasting", "roastery", "co", "company", "the", "cafe", "and", "espresso", "inc", "llc"]);
function roasterTokens(s) {
  const all = String(s || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").split(/[^a-z0-9]+/).filter((w) => w.length > 1);
  const distinct = all.filter((w) => !ROASTER_GENERIC.has(w));
  return distinct.length ? distinct : all;
}

async function findRoasterSite(roaster, env) {
  const tried = new Set();
  for (const model of SITE_MODELS) {
    let answer = "";
    try {
      const raw = await env.AI.run(model, {
        messages: [
          { role: "system", content: 'You know specialty coffee roasters. Reply with only a domain name, like example.com, or the word unknown. No other words.' },
          { role: "user", content: `What is the official website of the coffee roaster "${roaster}"?` },
        ],
        max_tokens: 20,
        temperature: 0,
      });
      answer = String(modelText(raw) || "");
    } catch (err) {
      if (isCapError(err)) throw capError();
      console.log(`roaster site: ${model} failed: ${err && err.message}`);
      continue;
    }
    const m = answer.toLowerCase().match(/[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}/);
    const domain = m ? cleanDomain(m[0]) : "";
    if (!domain || tried.has(domain)) continue;
    tried.add(domain);
    const site = await verifyRoasterSite(domain, roaster);
    if (site) return site;
  }
  return "";
}

async function verifyRoasterSite(domain, roaster) {
  let res;
  try {
    res = await fetchWithTimeout(`https://${domain}/`, "text/html,application/xhtml+xml", 6000);
  } catch {
    return "";
  }
  if (!res.ok) return "";
  const html = (await res.text()).slice(0, 500_000);
  const meta = metaTags(html);
  const title = decodeEntities((html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || "");
  const label = [title, meta["og:site_name"], meta["og:title"], meta["application-name"]].filter(Boolean).join(" ");
  if (!label || /for sale|domain (is )?(parked|available)|buy this domain|parked free|coming soon/i.test(label)) return "";
  const have = new Set(roasterTokens(label));
  const want = roasterTokens(roaster);
  const hits = want.filter((w) => have.has(w)).length;
  if (!hits || hits < Math.ceil(want.length / 2)) return "";
  try {
    return new URL(res.url).hostname || domain;
  } catch {
    return domain;
  }
}

// ----- product pages -----

async function readProductPage(href) {
  const u = safeUrl(href);
  if (!u) throw httpError(400, "That doesn't look like a web address.");

  // Shopify's product data carries only the main description; many themes put
  // origin, elevation, process and brew recipes in page sections outside it.
  // So read both and combine them.
  const [shop, pageRes] = await Promise.all([
    shopifyProduct(u),
    fetchWithTimeout(u.href, "text/html,application/xhtml+xml").catch(() => null),
  ]);

  let html = "";
  let finalUrl = u;
  if (pageRes && pageRes.ok) {
    html = (await pageRes.text()).slice(0, 2_000_000);
    finalUrl = safeUrl(pageRes.url) || u;
  }
  let shop2 = shop;
  // Redirected (a QR short link, say) onto a Shopify product page.
  if (!shop2 && html && finalUrl.href !== u.href && /cdn\.shopify\.com|Shopify\./.test(html)) shop2 = await shopifyProduct(finalUrl);

  if (!html && !shop2) {
    if (!pageRes) throw httpError(422, "That page took too long to open. Fill the rest in by hand.");
    throw httpError(422, `That page wouldn't open for the app (error ${pageRes.status}). Fill the rest in by hand.`);
  }

  const meta = html ? metaTags(html) : {};
  const p = (html && jsonLdProducts(html)[0]) || {};
  const brand = (shop2 && shop2.brand) || (typeof p.brand === "string" ? p.brand : (p.brand && p.brand.name) || meta["og:site_name"] || "");
  const title = String((shop2 && shop2.title) || p.name || meta["og:title"] || "").trim();
  const props = [].concat(p.additionalProperty || []).map((x) => (x && x.name && x.value != null ? `${x.name}: ${x.value}` : "")).filter(Boolean);

  let pageText = "";
  if (html) {
    let mainHtml = html;
    const m = html.match(/<main[\s\S]*?<\/main>/i);
    if (m && m[0].length > 500) mainHtml = m[0];
    mainHtml = mainHtml.replace(/<(header|footer|nav)\b[\s\S]*?<\/\1>/gi, " ");
    pageText = htmlToText(mainHtml);
  }
  const details = detailLines([pageText, props.join("\n"), shop2 ? shop2.description : ""].join("\n"));
  const summary = meta["og:description"] || meta.description || "";

  const text = [
    title && `Title: ${title}`,
    brand && `Roaster: ${brand}`,
    shop2 && shop2.tags && `Tags: ${shop2.tags}`,
    details && `Key details:\n${details}`,
    shop2 && shop2.description ? `Description:\n${shop2.description}` : p.description ? `Description: ${htmlToText(String(p.description))}` : summary && `Summary: ${summary}`,
    pageText && `Page text:\n${pageText}`,
  ].filter(Boolean).join("\n").slice(0, MAX_PAGE_TEXT);

  if (text.replace(/\s/g, "").length < 200) throw httpError(422, "That page didn't have readable details. Fill the rest in by hand.");
  return { url: shop2 ? shop2.url : cleanProductUrl(finalUrl), title, brand, text };
}

// Lines that name a coffee detail, each with the two lines after it (pages often
// put the label and its value on separate lines, like "ELEVATION" then "2100 MASL").
// These go first so they can't be cut off by the text limit.
const DETAIL_WORDS = /\b(origin|country|region|zone|elevation|altitude|masl|m\.a\.s\.l|process(ing)?|variet(y|ies|al)|cultivar|producer|farm|estate|washing station|cooperative|co-op|tasting|notes|flavou?r|cup profile|recipe|brew|reccs?|grind|dose|ratio|v60|chemex|kalita|origami|pour[- ]?over|filter|aeropress|espresso|decaf|roast)\b/i;
function detailLines(text) {
  const lines = String(text || "").split("\n").map((l) => l.trim()).filter(Boolean);
  const keep = new Set();
  lines.forEach((l, i) => {
    if (l.length > 240 || !DETAIL_WORDS.test(l)) return;
    for (let j = i; j <= Math.min(i + 2, lines.length - 1); j++) if (lines[j].length <= 240) keep.add(j);
  });
  const out = [];
  const seen = new Set();
  for (const i of [...keep].sort((a, b) => a - b)) {
    const k = lines[i].toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(lines[i]);
  }
  return out.join("\n").slice(0, 3000);
}

async function shopifyProduct(u) {
  if (!/\/products\/[^/]+/.test(u.pathname)) return null;
  const path = u.pathname.replace(/\/+$/, "").replace(/\.(json|js)$/, "");
  try {
    const res = await fetchWithTimeout(`${u.origin}${path}.json`, "application/json");
    if (!res.ok || !(res.headers.get("content-type") || "").includes("json")) return null;
    const data = await res.json();
    const p = data && data.product;
    if (!p || !p.title) return null;
    const handle = path.split("/products/")[1];
    return {
      url: `${u.origin}/products/${handle}`,
      title: String(p.title),
      brand: String(p.vendor || ""),
      tags: Array.isArray(p.tags) ? p.tags.join(", ") : String(p.tags || ""),
      description: htmlToText(String(p.body_html || "")),
    };
  } catch {
    return null;
  }
}

// Only a domain on the bag: look the coffee up with the roaster site's own search.
async function findShopifyProduct(domain, beans) {
  const origin = `https://${domain}`;
  const found = [];
  try {
    const q = encodeURIComponent(beans);
    const res = await fetchWithTimeout(`${origin}/search/suggest.json?q=${q}&resources[type]=product&resources[limit]=10`, "application/json");
    if (res.ok) {
      const data = await res.json();
      const list = (data && data.resources && data.resources.results && data.resources.results.products) || [];
      for (const p of list) if (p && p.title && p.url) found.push({ title: p.title, url: new URL(p.url, origin) });
    }
  } catch {}
  let pick = bestMatch(found, beans);
  if (pick) return cleanProductUrl(pick.url);

  // Search came up empty (or only matched part of the name): check the whole catalog.
  const all = [];
  for (const page of [1, 2]) {
    try {
      const res = await fetchWithTimeout(`${origin}/products.json?limit=250&page=${page}`, "application/json");
      if (!res.ok) break;
      const data = await res.json();
      const list = (data && data.products) || [];
      for (const p of list) if (p && p.title && p.handle) all.push({ title: p.title, url: new URL(`/products/${p.handle}`, origin) });
      if (list.length < 250) break;
    } catch {
      break;
    }
  }
  pick = bestMatch(all, beans);
  return pick ? cleanProductUrl(pick.url) : null;
}

const MATCH_STOP = new Set(["coffee", "the", "and", "of", "a", "by", "whole", "bean", "beans", "roast", "roasted", "g", "oz", "lb", "kg", "single", "origin", "bag"]);
function matchTokens(s) {
  return String(s || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .split(/[^a-z0-9]+/).filter((w) => w.length > 1 && !MATCH_STOP.has(w) && !/^\d+(g|kg|oz|lbs?|ml)?$/.test(w));
}
const ORIGIN_WORDS = new Set(["ethiopia", "kenya", "colombia", "brazil", "guatemala", "honduras", "peru", "rwanda", "burundi", "uganda", "tanzania", "panama", "costa", "rica", "el", "salvador", "nicaragua", "mexico", "bolivia", "ecuador", "yemen", "indonesia", "sumatra", "java", "papua", "guinea", "china", "india", "congo", "washed", "natural", "honey", "anaerobic", "decaf"]);
function bestMatch(items, want) {
  const w = [...new Set(matchTokens(want))];
  if (!w.length || !items.length) return null;
  // Words that show up across much of the catalog (a country, a process) say little about which coffee it is.
  const freq = {};
  for (const it of items) for (const x of new Set(matchTokens(it.title))) freq[x] = (freq[x] || 0) + 1;
  const weight = (x) => (ORIGIN_WORDS.has(x) ? 0.35 : 1) * (items.length >= 5 && (freq[x] || 0) / items.length > 0.3 ? 0.4 : 1);
  const wantW = w.reduce((a, x) => a + weight(x), 0);
  let best = null;
  for (const it of items) {
    const t = new Set(matchTokens(it.title));
    if (!t.size) continue;
    const hit = w.filter((x) => t.has(x)).reduce((a, x) => a + weight(x), 0);
    if (!hit) continue;
    const titleW = [...t].reduce((a, x) => a + weight(x), 0);
    const extra = [...t].filter((x) => !w.includes(x)).length;
    const rank = hit - 0.4 * extra;
    if (hit / Math.min(wantW, titleW) >= 0.6 && (!best || rank > best.rank)) best = { ...it, rank };
  }
  return best;
}

async function extractFromPage(page, env) {
  const instructions = `Extract the details of the coffee sold on this roaster's product page.
Return only a JSON object with these keys: beans, roaster, roastType, notes, origin, region, process, variety, producer, elevation, decaf, brewNotes.
beans: the coffee's name (the product title without size or weight).
roaster: the roasting company.
roastType: one of ${ROAST_TYPES.join(", ")}, or "".
notes: the tasting notes, comma-separated.
origin: the country. If the page's "origin" is a region or town, put that in region and take the country from the title or elsewhere on the page.
region: the region, zone or town.
process: the processing method, as written.
variety: the coffee variety or varieties.
producer: the farm, producer, cooperative or washing station.
elevation: as written on the page, with its units (for example "2100 MASL" or "6,000 ft").
decaf: true or false.
brewNotes: if the page gives brew recipes, the pour-over one (V60, Chemex, Kalita, Origami, April, Orea, or any pour-over or filter recipe), in one short line with its numbers (for example "V60: 20 g coffee, 300 g water, 205°F, grind 0.475 mm, 3:06"). Use an espresso or immersion recipe only if there's no pour-over one. "" if none.
Use "" for anything the page doesn't say. Do not guess.

Page:
`;
  for (const model of PAGE_MODELS) {
    try {
      const raw = await env.AI.run(model, {
        messages: [{ role: "user", content: instructions + page.text }],
        max_tokens: 600,
        temperature: 0.1,
      });
      const fields = cleanFields(parseModelJson(raw), { page: true, title: page.title });
      if (countFields(fields)) return fields;
    } catch (err) {
      if (isCapError(err)) throw capError();
      console.log(`bag page: ${model} failed: ${err && err.message}`);
    }
  }
  return {};
}

// ----- cleaning model output -----

function modelText(raw) {
  if (raw == null) return "";
  if (typeof raw === "string") return raw;
  if (raw.response && typeof raw.response === "object") return raw.response;
  if (typeof raw.response === "string") return raw.response;
  const c = raw.choices && raw.choices[0] && raw.choices[0].message && raw.choices[0].message.content;
  return c || "";
}

function parseModelJson(raw) {
  const t = modelText(raw);
  if (t && typeof t === "object") return t;
  const s = String(t);
  const a = s.indexOf("{"), b = s.lastIndexOf("}");
  if (a < 0 || b <= a) return {};
  try {
    return JSON.parse(s.slice(a, b + 1));
  } catch {
    return {};
  }
}

const EMPTY_WORDS = /^(unknown|n\/?a|none|null|not (visible|shown|stated|listed|specified|available)|-|—)$/i;
function str(v, max = 160) {
  if (Array.isArray(v)) v = v.filter((x) => typeof x === "string" || typeof x === "number").join(", ");
  if (typeof v !== "string" && typeof v !== "number") return "";
  const s = String(v).replace(/\s+/g, " ").trim();
  return EMPTY_WORDS.test(s) ? "" : s.slice(0, max);
}

const COUNTRIES = ["Ethiopia", "Kenya", "Colombia", "Brazil", "Guatemala", "Honduras", "Peru", "Rwanda", "Burundi", "Uganda", "Tanzania", "Panama", "Costa Rica", "El Salvador", "Nicaragua", "Mexico", "Bolivia", "Ecuador", "Yemen", "Indonesia", "Papua New Guinea", "China", "India", "Vietnam", "Thailand", "Myanmar", "Laos", "Timor-Leste", "East Timor", "Congo", "DR Congo", "Democratic Republic of the Congo", "Malawi", "Zambia", "Zimbabwe", "Cameroon", "Jamaica", "Haiti", "Dominican Republic", "Cuba", "Hawaii", "Taiwan", "Philippines", "Australia", "Venezuela"];
const findCountry = (s) => COUNTRIES.find((c) => new RegExp(`\\b${c.replace(/ /g, "\\s+")}\\b`, "i").test(String(s || ""))) || "";

function cleanFields(o, { page = false, title = "" } = {}) {
  o = o && typeof o === "object" ? o : {};
  const f = {};
  for (const k of ["beans", "roaster", "notes", "origin", "region", "process", "variety", "producer"]) {
    const v = str(o[k], k === "notes" ? 240 : 160);
    if (v) f[k] = v;
  }
  const bn = str(o.brewNotes, 500);
  if (bn) f.brewNotes = bn;
  const rt = roastType(o.roastType);
  if (rt) f.roastType = rt;
  if (!page) {
    const rd = roastDate(o.roastDate, o.roastDateText);
    if (rd) f.roastDate = rd;
  }
  const el = elevation(o.elevation);
  if (el) f.elevation = el;
  // "Origin" given as a region or town: keep it as the region, and take the country from the title.
  if (f.origin && !findCountry(f.origin)) {
    if (!f.region) f.region = f.origin;
    delete f.origin;
  }
  if (!f.origin) {
    const c = findCountry(title) || findCountry(f.beans) || findCountry(f.region);
    if (c) f.origin = c;
  }
  if (o.decaf === true || /^(true|yes)$/i.test(String(o.decaf))) f.decaf = true;
  return f;
}

function countFields(f) {
  return Object.keys(f || {}).length;
}

function roastType(v) {
  const s = str(v).toLowerCase().replace(/\s*roast$/, "").replace(/[\s_]+/g, "-");
  if (!s) return "";
  if (s === "light-medium") return "Medium-light";
  if (s === "dark-medium") return "Medium-dark";
  return ROAST_TYPES.find((r) => r.toLowerCase() === s) || "";
}

function elevation(v) {
  const s = String(v ?? "").toLowerCase().replace(/(\d),(\d{3})/g, "$1$2");
  const nums = s.match(/\d{3,5}/g);
  if (!nums) return null;
  const n = nums.slice(0, 2).map(Number);
  let m = n.reduce((a, b) => a + b, 0) / n.length;
  // Feet, whether labeled or not: no coffee grows above about 3,000 m.
  if (/\b(ft|feet|foot)\b|\d\s*['’]/.test(s) || (m > 3000 && m <= 10000)) m *= 0.3048;
  m = Math.round(m);
  return m >= 200 && m <= 3000 ? m : null;
}

const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };
function roastDate(iso, text) {
  const now = Date.now();
  const ok = (y, m, d) => {
    if (!(m >= 1 && m <= 12 && d >= 1 && d <= 31)) return "";
    const t = Date.UTC(y, m - 1, d);
    if (new Date(t).getUTCDate() !== d) return "";
    if (t > now + 2 * 86400000 || t < now - 400 * 86400000) return "";
    return `${y}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
  };
  const noYear = (m, d) => {
    const y = new Date().getUTCFullYear();
    return Date.UTC(y, m - 1, d) > now + 2 * 86400000 ? ok(y - 1, m, d) : ok(y, m, d);
  };
  const fullYear = (y) => (y < 100 ? 2000 + y : y);

  let mm = String(iso || "").match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (mm) {
    const r = ok(+mm[1], +mm[2], +mm[3]);
    if (r) return r;
  }
  const s = String(text || "").toLowerCase();
  if (!s) return "";
  if ((mm = s.match(/(\d{4})[./-](\d{1,2})[./-](\d{1,2})/))) return ok(+mm[1], +mm[2], +mm[3]);
  if ((mm = s.match(/(\d{1,2})[./-](\d{1,2})[./-](\d{2,4})/))) {
    const a = +mm[1], b = +mm[2], y = fullYear(+mm[3]);
    return a > 12 ? ok(y, b, a) : ok(y, a, b); // US month/day unless the first number can't be a month
  }
  if ((mm = s.match(/([a-z]{3})[a-z]*\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s*(\d{2,4})?/)) && MONTHS[mm[1]]) {
    return mm[3] ? ok(fullYear(+mm[3]), MONTHS[mm[1]], +mm[2]) : noYear(MONTHS[mm[1]], +mm[2]);
  }
  if ((mm = s.match(/(\d{1,2})(?:st|nd|rd|th)?\s+([a-z]{3})[a-z]*\.?,?\s*(\d{2,4})?/)) && MONTHS[mm[2]]) {
    return mm[3] ? ok(fullYear(+mm[3]), MONTHS[mm[2]], +mm[1]) : noYear(MONTHS[mm[2]], +mm[1]);
  }
  if ((mm = s.match(/(\d{1,2})[./-](\d{1,2})/))) {
    const a = +mm[1], b = +mm[2];
    return a > 12 ? noYear(b, a) : noYear(a, b);
  }
  return "";
}

// ----- URLs and pages -----

function safeUrl(v) {
  let s = String(v || "").trim();
  if (!s) return null;
  if (!/^https?:\/\//i.test(s)) {
    if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+(\/|$)/i.test(s)) return null;
    s = `https://${s}`;
  }
  try {
    const u = new URL(s);
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    if (!/\.[a-z]{2,}$/i.test(u.hostname) || /^(localhost|\d+\.\d+\.\d+\.\d+)$/i.test(u.hostname)) return null;
    u.hash = "";
    return u;
  } catch {
    return null;
  }
}

function cleanDomain(v) {
  const s = String(v || "").trim().toLowerCase().replace(/^https?:\/\//, "").split(/[/?#]/)[0];
  return /^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/.test(s) ? s : "";
}

function cleanLink(url, website) {
  const u = safeUrl(url);
  if (u && u.pathname.replace(/\/+$/, "")) return { url: u.href, domain: u.hostname };
  return { url: "", domain: cleanDomain(website) || (u ? u.hostname : "") };
}

function cleanProductUrl(u) {
  const x = new URL(u.href || u);
  x.search = "";
  x.hash = "";
  return x.href;
}

async function fetchWithTimeout(href, accept, ms = 8000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try {
    return await fetch(href, {
      headers: { "user-agent": PAGE_UA, accept, "accept-language": "en-US,en;q=0.9" },
      redirect: "follow",
      signal: ctl.signal,
      cf: { cacheTtl: 3600 },
    });
  } finally {
    clearTimeout(t);
  }
}

function metaTags(html) {
  const out = {};
  for (const m of html.matchAll(/<meta\b[^>]*>/gi)) {
    const attrs = {};
    for (const a of m[0].matchAll(/([a-z:-]+)\s*=\s*("([^"]*)"|'([^']*)')/gi)) attrs[a[1].toLowerCase()] = a[3] ?? a[4] ?? "";
    const key = (attrs.property || attrs.name || "").toLowerCase();
    if (key && attrs.content && !out[key]) out[key] = decodeEntities(attrs.content).trim();
  }
  return out;
}

function jsonLdProducts(html) {
  const out = [];
  const walk = (o) => {
    if (!o || typeof o !== "object") return;
    if (Array.isArray(o)) return o.forEach(walk);
    const t = [].concat(o["@type"] || []);
    if (t.includes("Product")) out.push(o);
    if (o["@graph"]) walk(o["@graph"]);
  };
  for (const m of html.matchAll(/<script[^>]*application\/ld\+json[^>]*>([\s\S]*?)<\/script>/gi)) {
    try {
      walk(JSON.parse(m[1].trim()));
    } catch {}
  }
  return out;
}

function decodeEntities(s) {
  return String(s)
    .replace(/&nbsp;/g, " ").replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&#39;|&apos;|&rsquo;|&lsquo;/g, "'").replace(/&ldquo;|&rdquo;/g, '"').replace(/&deg;/g, "°")
    .replace(/&ndash;/g, "–").replace(/&mdash;/g, "—")
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&amp;/g, "&");
}

function htmlToText(html) {
  return decodeEntities(
    String(html)
      .replace(/<(script|style|noscript|svg|template|iframe)\b[\s\S]*?<\/\1>/gi, " ")
      .replace(/<br\s*\/?>|<\/(p|div|li|h[1-6]|tr|dd|dt|section)>/gi, "\n")
      .replace(/<[^>]+>/g, " ")
  )
    .replace(/[ \t\f\r\v]+/g, " ")
    .replace(/ *\n\s*/g, "\n")
    .trim();
}

function isCapError(err) {
  return /4006|daily free allocation|neurons/i.test(String((err && err.message) || err));
}

function capError() {
  const e = httpError(429, CAP_MESSAGE);
  e.code = "cap";
  return e;
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
