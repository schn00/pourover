// Offline shell: network first, fall back to the cached page when there's no signal.
// Data lives in the page's local storage, so brews logged offline upload later.
const CACHE = "dialed-v3";
const SHELL = ["/", "/index.html", "/icon.svg", "/apple-touch-icon.png", "/icon-192.png", "/manifest.webmanifest"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL).catch(() => {})).then(() => self.skipWaiting()));
});
self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== location.origin || url.pathname.startsWith("/api/") || url.pathname.startsWith("/cdn-cgi/")) return;
  e.respondWith(
    fetch(e.request).then((res) => {
      if (res.ok && res.type === "basic") {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(e.request.mode === "navigate" ? "/" : e.request, copy));
      }
      return res;
    }).catch(() => caches.match(e.request.mode === "navigate" ? "/" : e.request).then((r) => r || caches.match("/")))
  );
});
