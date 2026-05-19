// eShipper+ RFS service worker — offline shell + asset cache.
// Bump CACHE when shipping a release to force old workers to drop their cache.
const CACHE = 'rfs-v11-2026-05-19g';
const STATIC = ['/'];

// Treat HTML AND JS as network-first so a deploy is reflected on the next
// page load instead of requiring a second refresh. Static assets (icons,
// images, etc.) stay cache-first for speed.
function isDynamic(url, accept) {
  const p = url.pathname;
  return p === '/' || p.endsWith('.html') || p.endsWith('.js') || (accept && accept.includes('text/html'));
}

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

  // Network-first for HTML + JS so a deploy is reflected immediately. Falls back
  // to cache only if the network is unreachable (true offline).
  if (isDynamic(url, e.request.headers.get('accept'))) {
    e.respondWith(
      fetch(e.request)
        .then((res) => {
          const clone = res.clone();
          caches.open(CACHE).then((c) => c.put(e.request, clone));
          return res;
        })
        .catch(() => caches.match(e.request).then(c => c || caches.match('/')))
    );
    return;
  }

  // Cache-first for everything else (CSS/images/icons/fonts).
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
