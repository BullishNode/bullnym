# PWA Runtime

Bullnym serves three Svelte 5 UI entry points from `pwa/dist`:

| Entry point | Public route | Purpose |
|---|---|---|
| `apps/donation` | `/:nym` | Payment Page amount entry and payment flow. |
| `apps/pos` | `/:nym/pos` | POS keypad, payment flow, receipts, history, settings. |
| `apps/invoice` | `/invoice/:id`, `/:nym/i/:id`, `/a/:slug/i/:id` | One-off invoice payment flow and optional private invoice presentation. |

Built assets are served from `/pwa-assets/`. The root service worker is served
from `/sw.js` so installed shells can control `/:nym` and `/:nym/pos`.

## Build

Run from `pwa/`:

```bash
npm run build
npm run check:dist
```

The Vite build writes all three entry points, injects hashed asset URLs into
`dist/sw.js`, and produces `.gz` files for hashed assets and the service
worker.

## Server Injection

For Payment Page and POS, the Rust server reads the built HTML shell and
replaces placeholders with:

- `bullnym-config` JSON
- manifest link
- OpenGraph metadata

Their config includes nym, mode, display currency, public copy, social links,
current or last-known rate, Liquid asset id, and domain. The invoice shell has
one separate config placeholder containing only the invoice id and whether the
payer may decrypt a private presentation.

## Caching

The service worker has three rules:

- PWA assets under `/pwa-assets/` are cache-first.
- Installable Payment Page and POS navigations are network-first with offline
  fallback only when the response has `x-bullnym-pwa-shell`.
- API calls, invoice creation, manifests, `/sw.js`, and one-off invoice pages
  are not cached.

Invoice responses deliberately omit that header and remain private/no-store.
This prevents one-off invoice pages from being stored offline while still
allowing installed Payment Page and POS shells to reopen without network.

## Payment-state truth

The live payment screen combines server-owned `presentation_status` with
`settlement_status`; accounting `status` remains available but cannot declare a
payment final by itself. Verified partial evidence keeps top-up rails visible.
Sufficient or overpaid pending evidence hides rails and shows calm settlement
support. `resolution_pending` shows a visible payment issue. Unknown wire values
are non-final, non-cancellable, hide rails, and keep polling rather than being
treated as not-found or unpaid.

One idempotently managed detail interval polls through pending, resolution,
unknown, and settled-partial states because the latter remains payable. It
stops on settled sufficient/overpaid projections or existing stop-polling
incidents. Network failure retains the last trustworthy state, and only a real
not-found response contributes to the not-found streak. The Liquid WebSocket
remains a refresh trigger; it is not chain authority. History remains local
load/manual/route-return refresh and does not gain background list polling.

## Proxy Requirements

The reverse proxy must serve `/pwa-assets/*` and `/sw.js` with correct content
types. If precompressed assets are enabled, responses must vary on
`Accept-Encoding`.
