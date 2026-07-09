// bullnym service worker. Served at ROOT scope (GET /sw.js) so it can control
// /<nym> and /<nym>/pos pages. Kept intentionally small: one file, no Workbox,
// no build tool runtime baked in.
//
// PRECACHE_URLS is injected at build time by vite.config.ts's writeBundle
// hook, which lists every hashed /pwa-assets/assets/* file emitted for
// both entry points. This file as committed has an empty array — a real
// build always overwrites this line in dist/sw.js.
const CACHE_VERSION = 'bullnym-shell-v1'
// Bumped v1 -> v2 to purge invoice/private pages cached by older builds.
// Only responses marked with x-bullnym-pwa-shell are cached now.
const PAGES_CACHE_VERSION = 'bullnym-pages-v2'
const PRECACHE_URLS = ["/pwa-assets/assets/PayFlow-Cq65mcrJ.css","/pwa-assets/assets/donation-DMNc9L4p.js","/pwa-assets/assets/pos-D5spcM1r.js","/pwa-assets/assets/PayFlow-BOcB8wj-.js"]
// Synthetic cache entry recording the PREVIOUS deploy's precache list. Never
// requested by a page (not under /pwa-assets/), so no fetch handler serves it.
const PREV_PRECACHE_SENTINEL = '/__bullnym/prev-precache'

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
      // Prune is best-effort: a rejection (quota pressure, storage errors)
      // must never abort clients.claim(), or open tabs stay pinned to the
      // outdated worker until the app is force-closed.
      .then(() => pruneStaleHashedAssets().catch(() => {}))
      .then(() => self.clients.claim()),
  )
})

async function pruneStaleHashedAssets() {
  // An uninjected/stale sw.js ships the raw empty placeholder array, and
  // `[].every(Boolean)` is vacuously true — without this guard a malformed
  // deploy would pass the completeness gate and wipe the entire asset cache.
  if (PRECACHE_URLS.length === 0) return

  const cache = await caches.open(CACHE_VERSION)
  const matches = await Promise.all(PRECACHE_URLS.map((url) => cache.match(url)))
  if (!matches.every(Boolean)) return

  // Keep the current AND previous generation of hashed assets. skipWaiting()
  // hands this SW tabs still running the previous deploy's shell, and
  // deploy.sh replaces dist wholesale — so pruning down to only the current
  // precache would 404 that live tab's next lazy chunk import mid-session.
  // Two generations bounds cache growth without breaking open sessions.
  const prev = await cache
    .match(PREV_PRECACHE_SENTINEL)
    .then((res) => (res ? res.json() : []))
    .catch(() => [])
  const keep = new Set([...PRECACHE_URLS, ...prev])

  const keys = await cache.keys()
  await Promise.all(
    keys.map((req) => {
      const url = new URL(req.url)
      if (url.pathname.startsWith('/pwa-assets/assets/') && !keep.has(url.pathname)) {
        return cache.delete(req)
      }
      return undefined
    }),
  )
  await cache.put(PREV_PRECACHE_SENTINEL, new Response(JSON.stringify(PRECACHE_URLS)))
}

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
          // must never be persisted offline. Header-marker gating is robust
          // to URL shape (no path heuristics to keep in sync).
          if (res.ok && res.headers.get('x-bullnym-pwa-shell')) {
            const copy = res.clone()
            caches.open(PAGES_CACHE_VERSION).then((cache) => cache.put(req, copy))
          }
          return res
        })
        .catch(() =>
          // Shell query params are non-semantic in production. The old
          // ?nym= dev-only fallback is ignored in production builds, so
          // offline navigation can match the installed shell by path.
          caches
            .match(req, { ignoreSearch: true })
            .then((cached) => cached || Promise.reject(new Error('offline, no cached page'))),
        ),
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
  // the cache with anything not already precached. Root-level font/logo/icon
  // assets are treated as immutable: if one ever changes, ship it under a
  // new filename. Installed terminals won't otherwise refresh unhashed names.
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
