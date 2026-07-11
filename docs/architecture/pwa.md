# PWA Runtime

Bullnym serves two Svelte 5 PWA entry points from `pwa/dist`:

| Entry point | Public route | Purpose |
|---|---|---|
| `apps/donation` | `/:nym` or `/a/:alias` | Payment Page amount entry and payment flow. |
| `apps/pos` | `/:nym/pos` or `/a/:alias/pos` | POS keypad, payment flow, receipts, history, settings. |

Built assets are served from `/pwa-assets/`. The root service worker is served
from `/sw.js` so installed shells can control nym- and alias-selected Payment
Page and POS routes.

## Build

Run from `pwa/`:

```bash
npm run build
npm run check:dist
```

The Vite build writes both entry points, injects hashed asset URLs into
`dist/sw.js`, and produces `.gz` files for hashed assets and the service
worker.

## Server Injection

The Rust server reads the built HTML shell and replaces placeholders with:

- `bullnym-config` JSON
- manifest link
- OpenGraph metadata

Injected config includes `invoice_base`, `page_key`, mode, display currency,
public copy, social links, current or last-known rate, Liquid asset id, and
domain. `nym` remains present on nym routes for installed-PWA compatibility but
is omitted entirely on alias routes. Browser clients append `/invoice` and
`/i/<id>` to `invoice_base` instead of rebuilding paths from the nym.

## Caching

The service worker has three rules:

- PWA assets under `/pwa-assets/` are cache-first.
- HTML navigations are network-first with offline fallback only when the
  response has `x-bullnym-pwa-shell`.
- API calls, invoice creation, manifests, `/sw.js`, and one-off invoice pages
  are not cached.

This prevents private invoice pages from being stored offline while still
allowing installed Payment Page and POS shells to reopen without network.

## Proxy Requirements

The reverse proxy must serve `/pwa-assets/*` and `/sw.js` with correct content
types. If precompressed assets are enabled, responses must vary on
`Accept-Encoding`.
