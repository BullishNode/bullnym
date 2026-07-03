// bullnym service worker. Served at ROOT scope (GET /sw.js — see the
// backend contract in plans/pos/08-implementation-sequence.md Milestone 6)
// so it can control /<nym> pages. Kept intentionally small: one file, no
// Workbox, no build tool runtime baked in.
//
// PRECACHE_URLS is injected at build time by vite.config.ts's writeBundle
// hook, which lists every hashed /pwa-assets/assets/* file emitted for
// both entry points. This file as committed has an empty array — a real
// build always overwrites this line in dist/sw.js.
const CACHE_VERSION = 'bullnym-shell-v1'
// Bumped v1 -> v2 to purge any invoice/private pages the previous, overly
// broad navigation cache may have stored (review item 8): the old SW cached
// EVERY successful navigation, including /invoice/:id and /:nym/i/:id. On
// activate, the v1 pages cache is no longer in `keep` and gets deleted.
const PAGES_CACHE_VERSION = 'bullnym-pages-v2'
const PRECACHE_URLS = /*BULLNYM_PRECACHE_URLS*/ [] /*END_BULLNYM_PRECACHE_URLS*/

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE_VERSION)
      .then((cache) => cache.addAll(PRECACHE_URLS))
      .then(() => self.skipWaiting())
      .catch(() => {
        /* a missing/renamed asset shouldn't brick install — offline just
           won't be fully warm until the next successful fetch */
      }),
  )
})

self.addEventListener('activate', (event) => {
  const keep = new Set([CACHE_VERSION, PAGES_CACHE_VERSION])
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => !keep.has(k)).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  )
})

self.addEventListener('fetch', (event) => {
  const req = event.request
  if (req.method !== 'GET') return

  const url = new URL(req.url)
  if (url.origin !== self.location.origin) return

  // HTML navigations for /<nym> — network-first, with a same-URL cached
  // copy as an offline fallback. A terminal typically only ever navigates
  // to its own one or two nym URLs, so no eviction logic beyond the
  // version-bump cleanup above is needed. Staleness offline is fine: the
  // injected config (nym/mode/header) is stable per nym, the injected
  // rate re-fetches once connectivity returns, and Charge is gated on
  // rate freshness anyway. Never-visited nyms simply fall through to the
  // browser's native offline page — acceptable, there's nothing to serve.
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then((res) => {
          // Only cache installable PWA shell navigations. The server marks
          // exactly those responses with `x-bullnym-pwa-shell` (pos|donation)
          // — see src/donation_render.rs. Private/one-off pages like
          // /invoice/:id and /:nym/i/:id are served WITHOUT the header and
          // must never be persisted offline (review item 8). Header-marker
          // gating is robust to URL shape (no path heuristics to keep in sync).
          if (res.ok && res.headers.get('x-bullnym-pwa-shell')) {
            const copy = res.clone()
            caches.open(PAGES_CACHE_VERSION).then((cache) => cache.put(req, copy))
          }
          return res
        })
        .catch(() => caches.match(req).then((cached) => cached || Promise.reject(new Error('offline, no cached page')))),
    )
    return
  }

  // Never cache: this file, the API, invoice creation, or the manifest.
  if (
    url.pathname === '/sw.js' ||
    url.pathname.startsWith('/api/') ||
    url.pathname.endsWith('/invoice') ||
    url.pathname.endsWith('/manifest.webmanifest')
  ) {
    return
  }

  // App shell assets: cache-first, falling back to network and warming
  // the cache with anything not already precached.
  if (url.pathname.startsWith('/pwa-assets/')) {
    event.respondWith(
      caches.match(req).then((cached) => {
        if (cached) return cached
        return fetch(req).then((res) => {
          if (res.ok) {
            const copy = res.clone()
            caches.open(CACHE_VERSION).then((cache) => cache.put(req, copy))
          }
          return res
        })
      }),
    )
  }
})
