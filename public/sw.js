// eShipper+ RFS service worker — offline shell + asset cache.
// Bump CACHE when shipping a release to force old workers to drop their cache.
const CACHE = 'rfs-v3-2026-05-08';
const STATIC = ['/'];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(STATIC)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);

  // Never intercept Firebase Auth, our APIs, non-GET requests, or upload streams.
  if (
    e.request.method !== 'GET' ||
    url.pathname.startsWith('/api/') ||
    url.hostname.includes('firebase') ||
    url.hostname.includes('googleapis') ||
    url.hostname.includes('google') ||
    url.hostname.includes('gstatic')
  ) {
    return;
  }

  // Network-first for HTML so the app shell stays fresh; fall back to cached / on offline.
  if (e.request.headers.get('accept')?.includes('text/html')) {
    e.respondWith(
      fetch(e.request)
        .then((res) => {
          const clone = res.clone();
          caches.open(CACHE).then((c) => c.put(e.request, clone));
          return res;
        })
        .catch(() => caches.match('/'))
    );
    return;
  }

  // Cache-first for everything else (JS/CSS/images/icons).
  e.respondWith(
    caches.match(e.request).then((cached) => {
      if (cached) return cached;
      return fetch(e.request).then((res) => {
        if (res.ok) {
          const clone = res.clone();
          caches.open(CACHE).then((c) => c.put(e.request, clone));
        }
        return res;
      });
    })
  );
});
